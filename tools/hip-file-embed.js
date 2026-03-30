// ============================================================
// HIP FILE METADATA EMBEDDING — Universal Client-Side Library
// Embeds HIP proof metadata into files of any supported type.
// Supports: JPEG (XMP), PNG (iTXt), WebP (XMP), PDF (Info Dict),
//           Office OOXML (custom.xml), MP3 (ID3v2 TXXX), FLAC (Vorbis),
//           WAV (LIST/INFO), MP4/MOV (udta), AVI (LIST/INFO)
//
// Usage:
//   const result = HipFileEmbed.embed(fileArrayBuffer, {
//     content_hash: "401aa25f...",
//     credential_id: "abc123...",
//     classification: "CompleteHumanOrigin",
//     attested_at: "2026-03-28T12:00:00Z",
//     short_url: "https://hipprotocol.org/p/6scFFgqq",
//     signature: "deadbeef...",
//     protocol_version: "1.2"
//   }, "myfile.pdf");
//   // result = { buffer: ArrayBuffer, filename: "myfile_hip.pdf", mimeType: "application/pdf", format: "pdf" }
//
// Async usage (required for Office docs due to CompressionStream):
//   const result = await HipFileEmbed.embedAsync(fileArrayBuffer, meta, "doc.docx");
//
// All processing is local. File bytes never leave the browser.
// ============================================================

var HipFileEmbed = (function() {

  var CLS_LABELS = {
    CompleteHumanOrigin: "Complete Human Origin",
    HumanOriginAssisted: "Human Origin Assisted",
    HumanDirectedCollaborative: "Human-Directed Collaborative"
  };

  function strB(s) { return new TextEncoder().encode(s); }
  function u32be(n) { return new Uint8Array([(n>>>24)&0xFF,(n>>>16)&0xFF,(n>>>8)&0xFF,n&0xFF]); }
  function u32le(n) { return new Uint8Array([n&0xFF,(n>>>8)&0xFF,(n>>>16)&0xFF,(n>>>24)&0xFF]); }

  // ── Format detection ──
  function detectFormat(buf, filename) {
    var u = new Uint8Array(buf, 0, Math.min(buf.byteLength, 16));

    // Image formats
    if (u[0]===0xFF && u[1]===0xD8 && u[2]===0xFF) return "jpeg";
    if (u[0]===0x89 && u[1]===0x50 && u[2]===0x4E && u[3]===0x47) return "png";
    if (u[0]===0x52 && u[1]===0x49 && u[2]===0x46 && u[3]===0x46 &&
        u[8]===0x57 && u[9]===0x45 && u[10]===0x42 && u[11]===0x50) return "webp";

    // PDF: %PDF
    if (u[0]===0x25 && u[1]===0x50 && u[2]===0x44 && u[3]===0x46) return "pdf";

    // ZIP-based (Office OOXML): PK\x03\x04
    if (u[0]===0x50 && u[1]===0x4B && u[2]===0x03 && u[3]===0x04) {
      var ext = filename ? filename.toLowerCase().split(".").pop() : "";
      if (ext === "docx" || ext === "xlsx" || ext === "pptx") return "ooxml";
      return "zip"; // Generic ZIP — not embeddable
    }

    // MP3: ID3v2 header or MPEG sync
    if (u[0]===0x49 && u[1]===0x44 && u[2]===0x33) return "mp3";
    if (u[0]===0xFF && (u[1]&0xE0)===0xE0) return "mp3"; // MPEG sync word

    // FLAC: fLaC
    if (u[0]===0x66 && u[1]===0x4C && u[2]===0x61 && u[3]===0x43) return "flac";

    // WAV: RIFF....WAVE
    if (u[0]===0x52 && u[1]===0x49 && u[2]===0x46 && u[3]===0x46 &&
        u[8]===0x57 && u[9]===0x41 && u[10]===0x56 && u[11]===0x45) return "wav";

    // OGG: OggS
    if (u[0]===0x4F && u[1]===0x67 && u[2]===0x67 && u[3]===0x53) return "ogg";

    // MP4/MOV: check for ftyp box
    if (buf.byteLength > 8) {
      var ftyp = String.fromCharCode(u[4],u[5],u[6],u[7]);
      if (ftyp === "ftyp") return "mp4";
    }
    // Also check by extension for MP4/MOV/M4A
    if (filename) {
      var ext = filename.toLowerCase().split(".").pop();
      if (ext === "mp4" || ext === "mov" || ext === "m4v" || ext === "m4a" || ext === "m4b") return "mp4";
      if (ext === "avi") return "avi";
      if (ext === "mkv" || ext === "webm") return "mkv";
    }

    // AVI: RIFF....AVI
    if (u[0]===0x52 && u[1]===0x49 && u[2]===0x46 && u[3]===0x46 &&
        u[8]===0x41 && u[9]===0x56 && u[10]===0x49) return "avi";

    return null;
  }

  // ── Shared: Build HIP JSON metadata string ──
  function buildHipJSON(meta) {
    var pu = meta.short_url || ("https://hipprotocol.org/proof.html?hash=" + meta.content_hash);
    return JSON.stringify({
      protocol: "HIP", version: meta.protocol_version || "1.2",
      content_hash: meta.content_hash, credential_id: meta.credential_id,
      classification: meta.classification,
      classification_label: CLS_LABELS[meta.classification] || meta.classification,
      attested_at: meta.attested_at, signature: meta.signature, proof_url: pu
    });
  }

  // ── Shared: Build XMP packet (for JPEG, WebP, PDF) ──
  function buildXMP(meta) {
    var cl = CLS_LABELS[meta.classification] || meta.classification;
    var pu = meta.short_url || ("https://hipprotocol.org/proof.html?hash=" + meta.content_hash);
    return ['<?xpacket begin="\uFEFF" id="W5M0MpCehiHzreSzNTczkc9d"?>',
      '<x:xmpmeta xmlns:x="adobe:ns:meta/">', '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">',
      '<rdf:Description rdf:about=""', '  xmlns:dc="http://purl.org/dc/elements/1.1/"',
      '  xmlns:hip="https://hipprotocol.org/ns/1.0/"',
      '  hip:Protocol="HIP"', '  hip:ProtocolVersion="' + (meta.protocol_version||"1.2") + '"',
      '  hip:ContentHash="' + meta.content_hash + '"', '  hip:CredentialID="' + meta.credential_id + '"',
      '  hip:Classification="' + meta.classification + '"', '  hip:ClassificationLabel="' + cl + '"',
      '  hip:AttestedAt="' + meta.attested_at + '"', '  hip:Signature="' + meta.signature + '"',
      '  hip:ProofURL="' + pu + '">', '<dc:description><rdf:Alt><rdf:li xml:lang="x-default">HIP Attested: ' + cl + ' | Proof: ' + pu + '</rdf:li></rdf:Alt></dc:description>',
      '</rdf:Description>', '</rdf:RDF>', '</x:xmpmeta>', '<?xpacket end="w"?>'].join("\n");
  }

  // ── CRC32 for PNG ──
  var _crcTable = null;
  function crc32(data) {
    if (!_crcTable) { _crcTable = new Uint32Array(256); for (var n=0;n<256;n++){var c=n;for(var k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);_crcTable[n]=c;}}
    var crc = 0xFFFFFFFF; for (var i=0;i<data.length;i++) crc=_crcTable[(crc^data[i])&0xFF]^(crc>>>8); return (crc^0xFFFFFFFF)>>>0;
  }

  // ============================================================
  // IMAGE EMBEDDERS (delegated to HipImageEmbed if available,
  // otherwise inline implementations)
  // ============================================================
  function embedJPEG(buf, meta) {
    if (typeof HipImageEmbed !== "undefined") return HipImageEmbed.embed(buf, meta).buffer;
    var src = new Uint8Array(buf); var xmpStr = buildXMP(meta); var xmpBytes = strB(xmpStr);
    var nsBytes = strB("http://ns.adobe.com/xap/1.0/\0");
    var segLen = 2 + nsBytes.length + xmpBytes.length;
    var existingStart=-1, existingEnd=-1, pos=2;
    while(pos<src.length-1){if(src[pos]!==0xFF)break;var marker=src[pos+1];if(marker===0xD9||marker===0xDA)break;
      var mLen=(src[pos+2]<<8)|src[pos+3];if(marker===0xE1&&mLen>nsBytes.length+2){var isXMP=true;
      for(var i=0;i<nsBytes.length;i++){if(src[pos+4+i]!==nsBytes[i]){isXMP=false;break}}
      if(isXMP){existingStart=pos;existingEnd=pos+2+mLen;break}}pos+=2+mLen;}
    var newSeg=new Uint8Array(2+2+nsBytes.length+xmpBytes.length);
    newSeg[0]=0xFF;newSeg[1]=0xE1;newSeg[2]=(segLen>>>8)&0xFF;newSeg[3]=segLen&0xFF;
    newSeg.set(nsBytes,4);newSeg.set(xmpBytes,4+nsBytes.length);
    var result;
    if(existingStart>=0){result=new Uint8Array(src.length-(existingEnd-existingStart)+newSeg.length);result.set(src.subarray(0,existingStart),0);result.set(newSeg,existingStart);result.set(src.subarray(existingEnd),existingStart+newSeg.length);}
    else{result=new Uint8Array(src.length+newSeg.length);result.set(src.subarray(0,2),0);result.set(newSeg,2);result.set(src.subarray(2),2+newSeg.length);}
    return result.buffer;
  }

  function embedPNG(buf, meta) {
    if (typeof HipImageEmbed !== "undefined") return HipImageEmbed.embed(buf, meta).buffer;
    var src=new Uint8Array(buf);var jsonStr=buildHipJSON(meta);var pu=meta.short_url||("https://hipprotocol.org/proof.html?hash="+meta.content_hash);
    var cl=CLS_LABELS[meta.classification]||meta.classification;
    var kw=strB("HIP:Proof");var textBytes=strB(jsonStr);
    var iTXtData=new Uint8Array(kw.length+1+1+1+1+1+textBytes.length);var off=0;
    iTXtData.set(kw,off);off+=kw.length;iTXtData[off++]=0;iTXtData[off++]=0;iTXtData[off++]=0;iTXtData[off++]=0;iTXtData[off++]=0;
    iTXtData.set(textBytes,off);
    function makePNGChunk(type,data){var typeB=strB(type);var len=u32be(data.length);var crcIn=new Uint8Array(4+data.length);crcIn.set(typeB,0);crcIn.set(data,4);var crcVal=u32be(crc32(crcIn));var chunk=new Uint8Array(4+4+data.length+4);chunk.set(len,0);chunk.set(typeB,4);chunk.set(data,8);chunk.set(crcVal,8+data.length);return chunk;}
    var iTXtChunk=makePNGChunk("iTXt",iTXtData);
    var parts=[];parts.push(src.slice(0,8));var p=8;
    while(p<src.length){var chunkLen=(src[p]<<24)|(src[p+1]<<16)|(src[p+2]<<8)|src[p+3];var ct=String.fromCharCode(src[p+4],src[p+5],src[p+6],src[p+7]);var fs=12+chunkLen;
    var skip=false;if(ct==="iTXt"){var kwS="HIP:Proof";var match=true;for(var i=0;i<kwS.length;i++){if(src[p+8+i]!==kwS.charCodeAt(i)){match=false;break}}if(match&&src[p+8+kwS.length]===0)skip=true;}
    if(!skip)parts.push(src.slice(p,p+fs));p+=fs;}
    var rp=[];var ins=false;
    for(var pi=0;pi<parts.length;pi++){var pa=parts[pi];if(!ins&&pa.length>=8){var ct2=String.fromCharCode(pa[4],pa[5],pa[6],pa[7]);if(ct2==="IDAT"){rp.push(iTXtChunk);ins=true;}}rp.push(pa);}
    if(!ins){var last=rp.pop();rp.push(iTXtChunk);rp.push(last);}
    var totalLen=0;for(var ri=0;ri<rp.length;ri++)totalLen+=rp[ri].length;
    var result=new Uint8Array(totalLen);var offset=0;for(var ri2=0;ri2<rp.length;ri2++){result.set(rp[ri2],offset);offset+=rp[ri2].length;}
    return result.buffer;
  }

  function embedWebP(buf, meta) {
    if (typeof HipImageEmbed !== "undefined") return HipImageEmbed.embed(buf, meta).buffer;
    // Inline WebP XMP embedding (same as HipImageEmbed)
    var src=new Uint8Array(buf);var xmpStr=buildXMP(meta);var xmpBytes=strB(xmpStr);
    var xmpChunk=new Uint8Array(8+xmpBytes.length+(xmpBytes.length&1));
    xmpChunk[0]=0x58;xmpChunk[1]=0x4D;xmpChunk[2]=0x50;xmpChunk[3]=0x20;
    xmpChunk.set(u32le(xmpBytes.length),4);xmpChunk.set(xmpBytes,8);
    var rp=[src.slice(0,12)];var p=12;
    var riffSize=src[4]|(src[5]<<8)|(src[6]<<16)|(src[7]<<24);var riffEnd=Math.min(8+riffSize,src.length);
    var hasVP8X=false;
    while(p+8<=riffEnd){var fourcc=String.fromCharCode(src[p],src[p+1],src[p+2],src[p+3]);
    var size=src[p+4]|(src[p+5]<<8)|(src[p+6]<<16)|(src[p+7]<<24);var paddedSize=size+(size&1);
    if(p+8+size>riffEnd)break;
    if(fourcc==="VP8X"){hasVP8X=true;var vClone=src.slice(p,p+8+paddedSize);vClone[8]|=0x04;rp.push(vClone);}
    else if(fourcc!=="XMP ")rp.push(src.slice(p,p+8+paddedSize));
    p+=8+paddedSize;}
    rp.push(xmpChunk);
    var totalLen=0;for(var ri=0;ri<rp.length;ri++)totalLen+=rp[ri].length;
    var result=new Uint8Array(totalLen);var offset=0;for(var ri2=0;ri2<rp.length;ri2++){result.set(rp[ri2],offset);offset+=rp[ri2].length;}
    var rs=result.length-8;result[4]=rs&0xFF;result[5]=(rs>>8)&0xFF;result[6]=(rs>>16)&0xFF;result[7]=(rs>>24)&0xFF;
    return result.buffer;
  }

  // ============================================================
  // PDF EMBEDDER
  // Uses incremental update: appends new Info dictionary entries
  // and a cross-reference update to the end of the PDF.
  // ============================================================
  function embedPDF(buf, meta) {
    var src = new Uint8Array(buf);
    var cl = CLS_LABELS[meta.classification] || meta.classification;
    var pu = meta.short_url || ("https://hipprotocol.org/proof.html?hash=" + meta.content_hash);

    // Build PDF Info entries as a new indirect object
    var hipDesc = "HIP Attested: " + cl + " | Proof: " + pu;
    // Escape parentheses in strings for PDF
    var esc = function(s) { return s.replace(/\\/g,"\\\\").replace(/\(/g,"\\(").replace(/\)/g,"\\)"); };

    // Find the existing xref/trailer to get the highest object number and startxref
    var text = new TextDecoder("latin1").decode(src);
    var startxrefMatch = text.match(/startxref\s+(\d+)\s*%%EOF/g);
    var lastStartxref = 0;
    if (startxrefMatch) {
      var last = startxrefMatch[startxrefMatch.length - 1];
      var m = last.match(/startxref\s+(\d+)/);
      if (m) lastStartxref = parseInt(m[1]);
    }

    // Find highest object number from xref or obj declarations
    var maxObj = 0;
    var objMatches = text.matchAll(/(\d+)\s+\d+\s+obj/g);
    for (var om of objMatches) {
      var objNum = parseInt(om[1]);
      if (objNum > maxObj) maxObj = objNum;
    }
    var newObjNum = maxObj + 1;

    // Build the new Info dictionary object
    var newObj = newObjNum + " 0 obj\n<< /Title (" + esc(hipDesc) + ")\n";
    newObj += "   /Author (HIP Protocol)\n";
    newObj += "   /Subject (HIP Attested Content)\n";
    newObj += "   /Creator (HIP Protocol - hipprotocol.org)\n";
    newObj += "   /Producer (HIP File Embed)\n";
    newObj += "   /Keywords (HIP, " + esc(meta.classification) + ", " + esc(meta.content_hash.substring(0,16)) + ")\n";
    newObj += "   /HIPProtocol (HIP)\n";
    newObj += "   /HIPVersion (" + (meta.protocol_version || "1.2") + ")\n";
    newObj += "   /HIPContentHash (" + esc(meta.content_hash) + ")\n";
    newObj += "   /HIPCredentialID (" + esc(meta.credential_id) + ")\n";
    newObj += "   /HIPClassification (" + esc(meta.classification) + ")\n";
    newObj += "   /HIPClassificationLabel (" + esc(cl) + ")\n";
    newObj += "   /HIPAttestedAt (" + esc(meta.attested_at) + ")\n";
    newObj += "   /HIPSignature (" + esc(meta.signature) + ")\n";
    newObj += "   /HIPProofURL (" + esc(pu) + ")\n";
    newObj += ">>\nendobj\n\n";

    // Build incremental xref + trailer
    var newObjOffset = src.length;
    var xref = "xref\n" + newObjNum + " 1\n";
    var offsetStr = newObjOffset.toString().padStart(10, "0");
    xref += offsetStr + " 00000 n \n";
    xref += "trailer\n<< /Info " + newObjNum + " 0 R /Prev " + lastStartxref + " >>\n";
    xref += "startxref\n" + (newObjOffset + new TextEncoder().encode(newObj).length) + "\n%%EOF\n";

    var appendBytes = strB(newObj + xref);
    var result = new Uint8Array(src.length + appendBytes.length);
    result.set(src, 0);
    result.set(appendBytes, src.length);
    return result.buffer;
  }

  // ============================================================
  // OFFICE OOXML EMBEDDER (DOCX/XLSX/PPTX)
  // Adds/updates docProps/custom.xml with HIP proof properties.
  // Requires async for CompressionStream.
  // ============================================================
  async function embedOOXML(buf, meta) {
    var bytes = new Uint8Array(buf);
    var hipJSON = buildHipJSON(meta);
    var cl = CLS_LABELS[meta.classification] || meta.classification;
    var pu = meta.short_url || ("https://hipprotocol.org/proof.html?hash=" + meta.content_hash);

    // Build custom.xml content
    var customXML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
    customXML += '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="HIP:Protocol"><vt:lpwstr>HIP</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="3" name="HIP:Version"><vt:lpwstr>' + (meta.protocol_version||"1.2") + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="4" name="HIP:ContentHash"><vt:lpwstr>' + meta.content_hash + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="5" name="HIP:CredentialID"><vt:lpwstr>' + meta.credential_id + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="6" name="HIP:Classification"><vt:lpwstr>' + meta.classification + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="7" name="HIP:ClassificationLabel"><vt:lpwstr>' + cl + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="8" name="HIP:AttestedAt"><vt:lpwstr>' + meta.attested_at + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="9" name="HIP:Signature"><vt:lpwstr>' + meta.signature + '</vt:lpwstr></property>\n';
    customXML += '  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="10" name="HIP:ProofURL"><vt:lpwstr>' + pu + '</vt:lpwstr></property>\n';
    customXML += '</Properties>';

    // Use a simplified approach: append a new local file entry for docProps/custom.xml
    // at store (no compression) level to the ZIP, then rebuild the central directory.
    // This avoids needing to decompress/recompress existing entries.

    // Parse existing ZIP structure
    var dv = new DataView(buf);
    var eocdPos = -1;
    for (var i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
      if (bytes[i]===0x50 && bytes[i+1]===0x4B && bytes[i+2]===0x05 && bytes[i+3]===0x06) { eocdPos = i; break; }
    }
    if (eocdPos < 0) throw new Error("Not a valid ZIP file");

    var cdOffset = dv.getUint32(eocdPos + 16, true);
    var cdSize = dv.getUint32(eocdPos + 12, true);
    var numEntries = dv.getUint16(eocdPos + 10, true);

    // Read central directory entries, skipping existing docProps/custom.xml
    var cdEntries = [];
    var pos = cdOffset;
    for (var e = 0; e < numEntries && pos + 46 <= bytes.length; e++) {
      var fnLen = dv.getUint16(pos + 28, true);
      var extraLen = dv.getUint16(pos + 30, true);
      var commentLen = dv.getUint16(pos + 32, true);
      var entrySize = 46 + fnLen + extraLen + commentLen;
      var fname = new TextDecoder().decode(bytes.subarray(pos + 46, pos + 46 + fnLen));
      if (fname !== "docProps/custom.xml") {
        cdEntries.push({ data: bytes.slice(pos, pos + entrySize), name: fname });
      }
      pos += entrySize;
    }

    // Build new local file entry for docProps/custom.xml (stored, not compressed)
    var customBytes = strB(customXML);
    var customFname = strB("docProps/custom.xml");

    // CRC32 of the uncompressed data
    var customCRC = crc32(customBytes);

    // Local file header (30 bytes + filename)
    var localHeader = new Uint8Array(30 + customFname.length);
    localHeader[0]=0x50;localHeader[1]=0x4B;localHeader[2]=0x03;localHeader[3]=0x04; // signature
    localHeader[4]=0x14;localHeader[5]=0x00; // version needed (2.0)
    // bytes 6-7: flags = 0
    // bytes 8-9: compression = 0 (stored)
    // bytes 10-13: mod time/date = 0
    localHeader.set(u32le(customCRC), 14); // CRC-32
    localHeader.set(u32le(customBytes.length), 18); // compressed size
    localHeader.set(u32le(customBytes.length), 22); // uncompressed size
    localHeader[26] = customFname.length & 0xFF; localHeader[27] = (customFname.length >> 8) & 0xFF; // filename length
    // bytes 28-29: extra field length = 0
    localHeader.set(customFname, 30);

    // Central directory entry for custom.xml
    var newLocalOffset = cdOffset; // We'll place the new local file entry where the old CD was
    var cdEntry = new Uint8Array(46 + customFname.length);
    cdEntry[0]=0x50;cdEntry[1]=0x4B;cdEntry[2]=0x01;cdEntry[3]=0x02; // signature
    cdEntry[4]=0x14;cdEntry[5]=0x00; // version made by
    cdEntry[6]=0x14;cdEntry[7]=0x00; // version needed
    // bytes 8-9: flags = 0, bytes 10-11: compression = 0
    cdEntry.set(u32le(customCRC), 16); // CRC-32
    cdEntry.set(u32le(customBytes.length), 20); // compressed size
    cdEntry.set(u32le(customBytes.length), 24); // uncompressed size
    cdEntry[28] = customFname.length & 0xFF; cdEntry[29] = (customFname.length >> 8) & 0xFF;
    // bytes 30-31: extra = 0, 32-33: comment = 0, 34-35: disk = 0, 36-37: internal attr = 0
    // bytes 38-41: external attr = 0
    cdEntry.set(u32le(newLocalOffset), 42); // local header offset
    cdEntry.set(customFname, 46);

    // Assemble: original data up to old CD + new local file + new CD (existing + new entry) + EOCD
    var parts = [];
    // 1. Everything before the central directory
    parts.push(bytes.slice(0, cdOffset));
    // 2. New local file entry
    parts.push(localHeader);
    parts.push(customBytes);
    // 3. Existing CD entries (with offsets unchanged — they point to original local headers which haven't moved)
    var newCDOffset = cdOffset + localHeader.length + customBytes.length;
    for (var ci = 0; ci < cdEntries.length; ci++) {
      parts.push(cdEntries[ci].data);
    }
    // 4. New CD entry for custom.xml
    parts.push(cdEntry);
    // 5. EOCD
    var newNumEntries = cdEntries.length + 1;
    var newCDSize = 0;
    for (var cdi = 0; cdi < cdEntries.length; cdi++) newCDSize += cdEntries[cdi].data.length;
    newCDSize += cdEntry.length;

    var eocd = new Uint8Array(22);
    eocd[0]=0x50;eocd[1]=0x4B;eocd[2]=0x05;eocd[3]=0x06;
    eocd[8] = newNumEntries & 0xFF; eocd[9] = (newNumEntries >> 8) & 0xFF;
    eocd[10] = newNumEntries & 0xFF; eocd[11] = (newNumEntries >> 8) & 0xFF;
    eocd.set(u32le(newCDSize), 12);
    eocd.set(u32le(newCDOffset), 16);
    parts.push(eocd);

    var totalLen = 0; for (var pi = 0; pi < parts.length; pi++) totalLen += parts[pi].length;
    var result = new Uint8Array(totalLen); var offset = 0;
    for (var pi2 = 0; pi2 < parts.length; pi2++) { result.set(parts[pi2], offset); offset += parts[pi2].length; }
    return result.buffer;
  }

  // ============================================================
  // MP3 EMBEDDER (ID3v2 TXXX frame)
  // Adds a TXXX frame with description "HIP:Proof" and JSON value.
  // If ID3v2 header exists, inserts frame. Otherwise prepends new ID3v2 header.
  // ============================================================
  function embedMP3(buf, meta) {
    var src = new Uint8Array(buf);
    var hipJSON = buildHipJSON(meta);

    // Build TXXX frame: encoding(1) + description + NUL + value
    // Use UTF-8 encoding (0x03)
    var descBytes = strB("HIP:Proof");
    var valueBytes = strB(hipJSON);
    var frameData = new Uint8Array(1 + descBytes.length + 1 + valueBytes.length);
    frameData[0] = 0x03; // UTF-8 encoding
    frameData.set(descBytes, 1);
    frameData[1 + descBytes.length] = 0x00; // NUL separator
    frameData.set(valueBytes, 1 + descBytes.length + 1);

    // Build TXXX frame header (ID3v2.3 format: 4-byte ID + 4-byte size + 2-byte flags)
    var frameSize = frameData.length;
    var frame = new Uint8Array(10 + frameSize);
    frame[0]=0x54;frame[1]=0x58;frame[2]=0x58;frame[3]=0x58; // "TXXX"
    frame[4]=(frameSize>>>24)&0xFF;frame[5]=(frameSize>>>16)&0xFF;
    frame[6]=(frameSize>>>8)&0xFF;frame[7]=frameSize&0xFF;
    // bytes 8-9: flags = 0
    frame.set(frameData, 10);

    if (src[0]===0x49 && src[1]===0x44 && src[2]===0x33) {
      // Existing ID3v2 header — read size, insert frame before end of tag
      var existingSize = (src[6]<<21) | (src[7]<<14) | (src[8]<<7) | src[9];
      var headerEnd = 10 + existingSize;

      // Remove existing HIP:Proof TXXX frame if present
      var cleanedTag = removeID3Frame(src.subarray(10, headerEnd), "TXXX", "HIP:Proof");
      var newTagContent = new Uint8Array(cleanedTag.length + frame.length);
      newTagContent.set(cleanedTag, 0);
      newTagContent.set(frame, cleanedTag.length);

      // Build new ID3v2 header with updated size
      var newSize = newTagContent.length;
      var newHeader = new Uint8Array(10);
      newHeader[0]=0x49;newHeader[1]=0x44;newHeader[2]=0x33; // "ID3"
      newHeader[3]=src[3];newHeader[4]=src[4]; // version
      newHeader[5]=src[5]; // flags
      // Synchsafe size
      newHeader[6]=(newSize>>21)&0x7F;newHeader[7]=(newSize>>14)&0x7F;
      newHeader[8]=(newSize>>7)&0x7F;newHeader[9]=newSize&0x7F;

      var result = new Uint8Array(10 + newSize + (src.length - headerEnd));
      result.set(newHeader, 0);
      result.set(newTagContent, 10);
      result.set(src.subarray(headerEnd), 10 + newSize);
      return result.buffer;
    } else {
      // No ID3v2 header — prepend one
      var tagSize = frame.length;
      var header = new Uint8Array(10);
      header[0]=0x49;header[1]=0x44;header[2]=0x33; // "ID3"
      header[3]=0x03;header[4]=0x00; // v2.3.0
      header[5]=0x00; // flags
      header[6]=(tagSize>>21)&0x7F;header[7]=(tagSize>>14)&0x7F;
      header[8]=(tagSize>>7)&0x7F;header[9]=tagSize&0x7F;

      var result = new Uint8Array(10 + tagSize + src.length);
      result.set(header, 0);
      result.set(frame, 10);
      result.set(src, 10 + tagSize);
      return result.buffer;
    }
  }

  // Helper: remove a specific TXXX frame from ID3v2 tag data
  function removeID3Frame(tagData, frameId, description) {
    var parts = [];
    var pos = 0;
    while (pos + 10 <= tagData.length) {
      if (tagData[pos] === 0) break; // Padding
      var fid = String.fromCharCode(tagData[pos],tagData[pos+1],tagData[pos+2],tagData[pos+3]);
      var fsize = (tagData[pos+4]<<24)|(tagData[pos+5]<<16)|(tagData[pos+6]<<8)|tagData[pos+7];
      if (fsize <= 0 || pos + 10 + fsize > tagData.length) break;
      var skip = false;
      if (fid === frameId && description) {
        // Check if this TXXX has the matching description
        var dataStart = pos + 10;
        var enc = tagData[dataStart];
        var descEnd = dataStart + 1;
        while (descEnd < dataStart + fsize && tagData[descEnd] !== 0) descEnd++;
        var desc = new TextDecoder(enc === 3 ? "utf-8" : "latin1").decode(tagData.subarray(dataStart + 1, descEnd));
        if (desc === description) skip = true;
      }
      if (!skip) parts.push(tagData.slice(pos, pos + 10 + fsize));
      pos += 10 + fsize;
    }
    var totalLen = 0; for (var i = 0; i < parts.length; i++) totalLen += parts[i].length;
    var result = new Uint8Array(totalLen); var off = 0;
    for (var j = 0; j < parts.length; j++) { result.set(parts[j], off); off += parts[j].length; }
    return result;
  }

  // ============================================================
  // FLAC EMBEDDER (Vorbis Comment)
  // Adds HIP_PROOF=<json> to the Vorbis Comment block.
  // ============================================================
  function embedFLAC(buf, meta) {
    var src = new Uint8Array(buf);
    if (src[0]!==0x66||src[1]!==0x4C||src[2]!==0x61||src[3]!==0x43) return buf; // Not FLAC
    var hipJSON = buildHipJSON(meta);
    var commentStr = "HIP_PROOF=" + hipJSON;
    var commentBytes = strB(commentStr);

    // Find existing VORBIS_COMMENT block (type 4)
    var pos = 4;
    var blocks = [];
    var vcBlockIdx = -1;
    while (pos + 4 <= src.length) {
      var header = src[pos];
      var isLast = (header & 0x80) !== 0;
      var blockType = header & 0x7F;
      var blockSize = (src[pos+1]<<16)|(src[pos+2]<<8)|src[pos+3];
      blocks.push({ pos: pos, type: blockType, isLast: isLast, size: blockSize, data: src.subarray(pos+4, pos+4+blockSize) });
      if (blockType === 4) vcBlockIdx = blocks.length - 1;
      pos += 4 + blockSize;
      if (isLast) break;
    }
    var audioStart = pos;

    if (vcBlockIdx >= 0) {
      // Existing VC block — parse it, add/replace HIP_PROOF comment, rebuild
      var vcData = blocks[vcBlockIdx].data;
      var vcDV = new DataView(vcData.buffer, vcData.byteOffset, vcData.byteLength);
      var vp = 0;
      var vendorLen = vcDV.getUint32(vp, true); vp += 4;
      var vendorStr = vcData.subarray(vp, vp + vendorLen); vp += vendorLen;
      var numComments = vcDV.getUint32(vp, true); vp += 4;
      var comments = [];
      for (var ci = 0; ci < numComments && vp + 4 <= vcData.length; ci++) {
        var cLen = vcDV.getUint32(vp, true); vp += 4;
        if (vp + cLen > vcData.length) break;
        var cStr = new TextDecoder().decode(vcData.subarray(vp, vp + cLen));
        vp += cLen;
        if (!cStr.toUpperCase().startsWith("HIP_PROOF=")) {
          comments.push(strB(cStr));
        }
      }
      comments.push(commentBytes);

      // Rebuild VC block
      var newVCSize = 4 + vendorLen + 4;
      for (var k = 0; k < comments.length; k++) newVCSize += 4 + comments[k].length;
      var newVCData = new Uint8Array(newVCSize);
      var nvDV = new DataView(newVCData.buffer);
      var np = 0;
      nvDV.setUint32(np, vendorLen, true); np += 4;
      newVCData.set(vendorStr, np); np += vendorLen;
      nvDV.setUint32(np, comments.length, true); np += 4;
      for (var ki = 0; ki < comments.length; ki++) {
        nvDV.setUint32(np, comments[ki].length, true); np += 4;
        newVCData.set(comments[ki], np); np += comments[ki].length;
      }
      blocks[vcBlockIdx].data = newVCData;
      blocks[vcBlockIdx].size = newVCSize;
    } else {
      // No VC block — create one with just a vendor string and HIP comment
      var vendor = strB("HIP Protocol");
      var newVCSize = 4 + vendor.length + 4 + 4 + commentBytes.length;
      var newVCData = new Uint8Array(newVCSize);
      var nvDV = new DataView(newVCData.buffer);
      var np = 0;
      nvDV.setUint32(np, vendor.length, true); np += 4;
      newVCData.set(vendor, np); np += vendor.length;
      nvDV.setUint32(np, 1, true); np += 4;
      nvDV.setUint32(np, commentBytes.length, true); np += 4;
      newVCData.set(commentBytes, np);
      // Insert as second-to-last block (before the last block)
      var insertIdx = blocks.length > 0 ? blocks.length - 1 : 0;
      blocks.splice(insertIdx, 0, { type: 4, isLast: false, size: newVCSize, data: newVCData });
    }

    // Reassemble: fLaC + all blocks + audio data
    var parts = [src.subarray(0, 4)]; // "fLaC"
    for (var bi = 0; bi < blocks.length; bi++) {
      var b = blocks[bi];
      var bh = new Uint8Array(4);
      bh[0] = b.type | (bi === blocks.length - 1 ? 0x80 : 0x00);
      bh[1] = (b.data.length >> 16) & 0xFF;
      bh[2] = (b.data.length >> 8) & 0xFF;
      bh[3] = b.data.length & 0xFF;
      parts.push(bh);
      parts.push(b.data);
    }
    parts.push(src.subarray(audioStart));

    var totalLen = 0; for (var pi = 0; pi < parts.length; pi++) totalLen += parts[pi].length;
    var result = new Uint8Array(totalLen); var offset = 0;
    for (var pi2 = 0; pi2 < parts.length; pi2++) { result.set(parts[pi2], offset); offset += parts[pi2].length; }
    return result.buffer;
  }

  // ============================================================
  // WAV EMBEDDER (LIST/INFO chunk)
  // Adds an ICMT (Comment) entry with HIP proof JSON.
  // ============================================================
  function embedWAV(buf, meta) {
    var src = new Uint8Array(buf);
    var hipJSON = buildHipJSON(meta);
    var commentBytes = strB(hipJSON);
    var commentFCC = strB("ICMT");

    // Build a new LIST/INFO chunk containing ICMT with HIP data
    var infoEntrySize = 8 + commentBytes.length + (commentBytes.length & 1);
    var listType = strB("INFO");
    var listDataSize = 4 + infoEntrySize; // "INFO" + entry
    var listChunk = new Uint8Array(8 + listDataSize);
    listChunk[0]=0x4C;listChunk[1]=0x49;listChunk[2]=0x53;listChunk[3]=0x54; // "LIST"
    listChunk.set(u32le(listDataSize), 4);
    listChunk.set(listType, 8);
    listChunk.set(commentFCC, 12);
    listChunk.set(u32le(commentBytes.length), 16);
    listChunk.set(commentBytes, 20);

    // Append before existing LIST/INFO if present, or at end of RIFF
    var riffSize = src[4]|(src[5]<<8)|(src[6]<<16)|(src[7]<<24);
    var riffEnd = Math.min(8 + riffSize, src.length);

    // Remove existing LIST/INFO chunks that contain ICMT with HIP data
    var parts = [src.slice(0, 12)]; // RIFF header + WAVE
    var p = 12;
    while (p + 8 <= riffEnd) {
      var fourcc = String.fromCharCode(src[p],src[p+1],src[p+2],src[p+3]);
      var size = src[p+4]|(src[p+5]<<8)|(src[p+6]<<16)|(src[p+7]<<24);
      var paddedSize = size + (size & 1);
      if (p + 8 + size > riffEnd) break;
      // Keep all chunks except LIST/INFO that we'll replace
      if (fourcc === "LIST" && p + 12 <= riffEnd) {
        var lt = String.fromCharCode(src[p+8],src[p+9],src[p+10],src[p+11]);
        if (lt === "INFO") {
          // Check if it has HIP data — if so, skip it (we'll add ours)
          var chunk = new TextDecoder("latin1").decode(src.subarray(p+8, p+8+size));
          if (chunk.indexOf("HIP") >= 0) {
            p += 8 + paddedSize;
            continue;
          }
        }
      }
      parts.push(src.slice(p, p + 8 + paddedSize));
      p += 8 + paddedSize;
    }
    parts.push(listChunk);

    var totalLen = 0; for (var pi = 0; pi < parts.length; pi++) totalLen += parts[pi].length;
    var result = new Uint8Array(totalLen); var offset = 0;
    for (var pi2 = 0; pi2 < parts.length; pi2++) { result.set(parts[pi2], offset); offset += parts[pi2].length; }
    // Fix RIFF size
    var newRiffSize = result.length - 8;
    result[4]=newRiffSize&0xFF;result[5]=(newRiffSize>>8)&0xFF;result[6]=(newRiffSize>>16)&0xFF;result[7]=(newRiffSize>>24)&0xFF;
    return result.buffer;
  }

  // ============================================================
  // MP4/MOV EMBEDDER
  // Adds a custom 'HIPd' atom inside moov/udta with JSON metadata.
  // ============================================================
  function embedMP4(buf, meta) {
    var src = new Uint8Array(buf);
    var hipJSON = buildHipJSON(meta);
    var jsonBytes = strB(hipJSON);

    // Build HIPd atom: [4-byte size][HIPd][json data]
    var hipAtom = new Uint8Array(8 + jsonBytes.length);
    var atomSize = 8 + jsonBytes.length;
    hipAtom[0]=(atomSize>>>24)&0xFF;hipAtom[1]=(atomSize>>>16)&0xFF;
    hipAtom[2]=(atomSize>>>8)&0xFF;hipAtom[3]=atomSize&0xFF;
    hipAtom[4]=0x48;hipAtom[5]=0x49;hipAtom[6]=0x50;hipAtom[7]=0x64; // "HIPd"
    hipAtom.set(jsonBytes, 8);

    // Find moov atom
    var dv = new DataView(buf);
    var moovPos = -1, moovSize = 0;
    var p = 0;
    while (p + 8 <= src.length) {
      var size = dv.getUint32(p);
      var type = String.fromCharCode(src[p+4],src[p+5],src[p+6],src[p+7]);
      if (size < 8) break;
      if (type === "moov") { moovPos = p; moovSize = size; break; }
      p += size;
    }
    if (moovPos < 0) {
      // No moov — just append the atom at the end
      var result = new Uint8Array(src.length + hipAtom.length);
      result.set(src, 0);
      result.set(hipAtom, src.length);
      return result.buffer;
    }

    // Find or create udta atom inside moov
    var moovEnd = moovPos + moovSize;
    var udtaPos = -1, udtaSize = 0;
    var mp = moovPos + 8;
    while (mp + 8 <= moovEnd) {
      var mSize = dv.getUint32(mp);
      var mType = String.fromCharCode(src[mp+4],src[mp+5],src[mp+6],src[mp+7]);
      if (mSize < 8) break;
      if (mType === "udta") { udtaPos = mp; udtaSize = mSize; break; }
      mp += mSize;
    }

    // Remove existing HIPd atom if present in udta
    if (udtaPos >= 0) {
      var udtaEnd = udtaPos + udtaSize;
      var udtaParts = []; var up = udtaPos + 8;
      while (up + 8 <= udtaEnd) {
        var uSize = dv.getUint32(up);
        var uType = String.fromCharCode(src[up+4],src[up+5],src[up+6],src[up+7]);
        if (uSize < 8) break;
        if (uType !== "HIPd") udtaParts.push(src.slice(up, up + uSize));
        up += uSize;
      }
      udtaParts.push(hipAtom);

      // Rebuild udta
      var newUdtaContentSize = 0;
      for (var ui = 0; ui < udtaParts.length; ui++) newUdtaContentSize += udtaParts[ui].length;
      var newUdtaSize = 8 + newUdtaContentSize;
      var newUdta = new Uint8Array(newUdtaSize);
      newUdta[0]=(newUdtaSize>>>24)&0xFF;newUdta[1]=(newUdtaSize>>>16)&0xFF;
      newUdta[2]=(newUdtaSize>>>8)&0xFF;newUdta[3]=newUdtaSize&0xFF;
      newUdta[4]=0x75;newUdta[5]=0x64;newUdta[6]=0x74;newUdta[7]=0x61; // "udta"
      var uo = 8;
      for (var ui2 = 0; ui2 < udtaParts.length; ui2++) { newUdta.set(udtaParts[ui2], uo); uo += udtaParts[ui2].length; }

      // Rebuild moov with new udta
      var sizeDiff = newUdtaSize - udtaSize;
      var result = new Uint8Array(src.length + sizeDiff);
      result.set(src.subarray(0, udtaPos), 0);
      result.set(newUdta, udtaPos);
      result.set(src.subarray(udtaPos + udtaSize), udtaPos + newUdtaSize);
      // Fix moov size
      var newMoovSize = moovSize + sizeDiff;
      result[moovPos]=(newMoovSize>>>24)&0xFF;result[moovPos+1]=(newMoovSize>>>16)&0xFF;
      result[moovPos+2]=(newMoovSize>>>8)&0xFF;result[moovPos+3]=newMoovSize&0xFF;
      return result.buffer;
    } else {
      // No udta — create one at end of moov with HIPd inside
      var newUdtaSize = 8 + hipAtom.length;
      var newUdta = new Uint8Array(newUdtaSize);
      newUdta[0]=(newUdtaSize>>>24)&0xFF;newUdta[1]=(newUdtaSize>>>16)&0xFF;
      newUdta[2]=(newUdtaSize>>>8)&0xFF;newUdta[3]=newUdtaSize&0xFF;
      newUdta[4]=0x75;newUdta[5]=0x64;newUdta[6]=0x74;newUdta[7]=0x61; // "udta"
      newUdta.set(hipAtom, 8);

      // Insert udta at end of moov (before next top-level atom)
      var result = new Uint8Array(src.length + newUdtaSize);
      result.set(src.subarray(0, moovEnd), 0);
      result.set(newUdta, moovEnd);
      result.set(src.subarray(moovEnd), moovEnd + newUdtaSize);
      // Fix moov size
      var newMoovSize = moovSize + newUdtaSize;
      result[moovPos]=(newMoovSize>>>24)&0xFF;result[moovPos+1]=(newMoovSize>>>16)&0xFF;
      result[moovPos+2]=(newMoovSize>>>8)&0xFF;result[moovPos+3]=newMoovSize&0xFF;
      return result.buffer;
    }
  }

  // ============================================================
  // AVI EMBEDDER (LIST/INFO chunk) — same approach as WAV
  // ============================================================
  function embedAVI(buf, meta) {
    // AVI is RIFF-based like WAV, so reuse the same approach
    return embedWAV(buf, meta);
  }

  // ============================================================
  // PUBLIC API
  // ============================================================

  var EXT_MAP = {
    jpeg:"jpg", png:"png", webp:"webp", pdf:"pdf",
    ooxml:null, // determined by original extension
    mp3:"mp3", flac:"flac", wav:"wav", ogg:"ogg",
    mp4:null, avi:"avi", mkv:null
  };

  var MIME_MAP = {
    jpeg:"image/jpeg", png:"image/png", webp:"image/webp",
    pdf:"application/pdf",
    ooxml:null, // determined by original extension
    mp3:"audio/mpeg", flac:"audio/flac", wav:"audio/wav", ogg:"audio/ogg",
    mp4:null, avi:"video/x-msvideo", mkv:null
  };

  function getExt(format, origFilename) {
    if (EXT_MAP[format]) return EXT_MAP[format];
    if (origFilename) return origFilename.toLowerCase().split(".").pop();
    return "bin";
  }

  function getMime(format, origFilename) {
    if (MIME_MAP[format]) return MIME_MAP[format];
    var ext = origFilename ? origFilename.toLowerCase().split(".").pop() : "";
    var mimeByExt = {
      docx:"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      xlsx:"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      pptx:"application/vnd.openxmlformats-officedocument.presentationml.presentation",
      mp4:"video/mp4", mov:"video/quicktime", m4a:"audio/mp4", m4v:"video/mp4",
      mkv:"video/x-matroska", webm:"video/webm"
    };
    return mimeByExt[ext] || "application/octet-stream";
  }

  function makeFilename(origFilename, format) {
    if (origFilename) {
      var lastDot = origFilename.lastIndexOf(".");
      var base = lastDot > 0 ? origFilename.substring(0, lastDot) : origFilename;
      var ext = lastDot > 0 ? origFilename.substring(lastDot) : "";
      return base + "_hip" + ext;
    }
    return "attested_hip." + getExt(format, null);
  }

  // Synchronous embed — works for all formats EXCEPT ooxml
  function embed(buffer, meta, originalFilename) {
    var format = detectFormat(buffer, originalFilename);
    if (!format) return null;

    var resultBuffer;
    switch (format) {
      case "jpeg": resultBuffer = embedJPEG(buffer, meta); break;
      case "png":  resultBuffer = embedPNG(buffer, meta); break;
      case "webp": resultBuffer = embedWebP(buffer, meta); break;
      case "pdf":  resultBuffer = embedPDF(buffer, meta); break;
      case "mp3":  resultBuffer = embedMP3(buffer, meta); break;
      case "flac": resultBuffer = embedFLAC(buffer, meta); break;
      case "wav":  resultBuffer = embedWAV(buffer, meta); break;
      case "mp4":  resultBuffer = embedMP4(buffer, meta); break;
      case "avi":  resultBuffer = embedAVI(buffer, meta); break;
      case "ooxml": return null; // Requires async — use embedAsync
      case "ogg":  return null; // OGG page rewriting too complex for reliable sync embed
      case "mkv":  return null; // EBML writing too complex
      default: return null;
    }

    return {
      buffer: resultBuffer,
      filename: makeFilename(originalFilename, format),
      mimeType: getMime(format, originalFilename),
      format: format
    };
  }

  // Async embed — works for ALL supported formats including ooxml
  async function embedAsync(buffer, meta, originalFilename) {
    var format = detectFormat(buffer, originalFilename);
    if (!format) return null;

    // OGG and MKV are not supported for embedding
    if (format === "ogg" || format === "mkv" || format === "zip") return null;

    var resultBuffer;
    if (format === "ooxml") {
      resultBuffer = await embedOOXML(buffer, meta);
    } else {
      var syncResult = embed(buffer, meta, originalFilename);
      if (!syncResult) return null;
      return syncResult;
    }

    return {
      buffer: resultBuffer,
      filename: makeFilename(originalFilename, format),
      mimeType: getMime(format, originalFilename),
      format: format
    };
  }

  // Check if a file format supports HIP metadata embedding
  function isSupported(buffer, filename) {
    var fmt = detectFormat(buffer, filename);
    if (!fmt) return false;
    // These formats support embedding
    return ["jpeg","png","webp","pdf","ooxml","mp3","flac","wav","mp4","avi"].indexOf(fmt) >= 0;
  }

  return {
    embed: embed,
    embedAsync: embedAsync,
    isSupported: isSupported,
    detectFormat: detectFormat
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = HipFileEmbed;
}
