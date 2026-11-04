// S211 regression harness for credential-bootstrap gates (BLOCKS ANNOUNCE #4).
// S212: + Didit claim-secret binding (/session, /register-dedup, /trust/initialize T1,
// /upgrade-credential tier1-idv, /recover-credential tier1-reverify).
// Run: node tools/bootstrap-gates.test.mjs   (Node >= 20; mocked KV + Didit, real Ed25519)
// Optional: node tools/bootstrap-gates.test.mjs legacy/pre-S212/worker.js  (run against a snapshot)
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const tmp = join(tmpdir(), "hip-worker-under-test.mjs");
const target = process.argv[2] ? join(process.cwd(), process.argv[2]) : join(here, "..", "worker.js");
writeFileSync(tmp, readFileSync(target));
const W = (await import(pathToFileURL(tmp).href)).default;
const SECRET="testsecret";
const kv=new Map();
const KV={async get(k){return kv.has(k)?kv.get(k):null},async put(k,v){kv.set(k,String(v))},async delete(k){kv.delete(k)},async list(){return{keys:[]}}};
const env={DEDUP_KV:KV,DEDUP_SECRET:SECRET,DIDIT_API_KEY:"k",DIDIT_WORKFLOW_ID:"w",CALLBACK_URL:"https://hipverify.org/"};
// S212: stub the Didit session-create call so POST /session runs locally.
let diditN=0;globalThis.fetch=async(url,init)=>{if(String(url).includes("didit")){diditN++;return new Response(JSON.stringify({session_id:"didit-"+diditN,url:"https://verify.didit.me/x"}),{status:201,headers:{"Content-Type":"application/json"}})}throw new Error("unexpected fetch "+url)};
// Seed a claim for a hand-made session (mirrors what /session does).
async function seedClaim(sid){const sec="sec-"+sid;kv.set("claim:"+sid,await sha(enc.encode(sec)));return sec}
const ctx={waitUntil(){}};
const enc=new TextEncoder();
const hex=b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,"0")).join("");
const b64=b=>Buffer.from(new Uint8Array(b)).toString("base64");
const sha=async b=>hex(await crypto.subtle.digest("SHA-256",b));
async function key(){const kp=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);const pub=hex(await crypto.subtle.exportKey("raw",kp.publicKey));return{kp,pub,cid:await sha(Buffer.from(pub,"hex"))}}
async function sign(k,str){return b64(await crypto.subtle.sign("Ed25519",k.kp.privateKey,enc.encode(str)))}
async function hmac(k,d){const ck=await crypto.subtle.importKey("raw",enc.encode(k),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return hex(await crypto.subtle.sign("HMAC",ck,enc.encode(d)))}
async function post(path,body){const r=await W.fetch(new Request("https://x"+path,{method:"POST",headers:{"Content-Type":"application/json","Origin":"https://hipprotocol.org","CF-Connecting-IP":"1.2.3.4"},body:JSON.stringify(body)}),env,ctx);let j;try{j=await r.json()}catch{j=null}return[r.status,j]}
let pass=0,fail=0;function chk(n,c,info){if(c){pass++;console.log("PASS",n)}else{fail++;console.log("FAIL",n,JSON.stringify(info))}}
const ts=()=>new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
const tok=o=>JSON.stringify(o); // vouch_body string the client forwards

// ---- T3 init
const a=await key();
let [s,j]=await post("/trust/initialize",{credential_id:a.cid,tier:3});chk("T3 no proof -> 400",s===400,j);
const sid="t3sess-1",its=new Date().toISOString(),it=await hmac(SECRET,`${sid}:${a.pub}:${its}`);
[s,j]=await post("/trust/initialize",{credential_id:a.cid,tier:3,public_key:a.pub,issuance_token:"0".repeat(64),t3_session_id:sid,issuance_timestamp:its});chk("T3 bad token -> 403",s===403,j);
const b=await key();
[s,j]=await post("/trust/initialize",{credential_id:b.cid,tier:3,public_key:a.pub,issuance_token:it,t3_session_id:sid,issuance_timestamp:its});chk("T3 token for other key -> 403",s===403,j);
[s,j]=await post("/trust/initialize",{credential_id:a.cid,tier:3,public_key:a.pub,issuance_token:it,t3_session_id:sid,issuance_timestamp:its});chk("T3 valid -> 200",s===200&&j.tier===3,j);

// ---- T1 upgrade
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1});chk("T1 upgrade no session -> 400",s===400,j);
// S212: every session carries a claim secret; unknown session = no claim key -> 403 from the claim check.
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"nope",claim_secret:"x"});chk("T1 upgrade unknown session -> 403",s===403,j);
kv.set("session:pend",JSON.stringify({status:"In Progress"}));const secPend=await seedClaim("pend");
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"pend",claim_secret:secPend});chk("T1 upgrade unapproved -> 400",s===400,j);
kv.set("session:nodd",JSON.stringify({status:"Approved",dedup:"insufficient_data"}));const secNodd=await seedClaim("nodd");
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"nodd",claim_secret:secNodd});chk("T1 upgrade no dedupHash -> 403",s===403,j);
kv.set("dedup:H2","someoneelse");kv.set("session:dup",JSON.stringify({status:"Approved",dedup:"exists",dedupHash:"H2"}));const secDup=await seedClaim("dup");
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"dup",claim_secret:secDup});chk("T1 upgrade identity bound elsewhere -> 409",s===409,j);
kv.set("session:ok",JSON.stringify({status:"Approved",dedup:"new",dedupHash:"H1"}));const secOk=await seedClaim("ok");
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"ok"});chk("S212 T1 upgrade session_id alone (pre-S212 bearer) -> 400",s===400,j);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"ok",claim_secret:"wrong"});chk("S212 T1 upgrade wrong claim_secret -> 403",s===403,j);
chk("S212 T1 upgrade wrong secret did nothing",!kv.has("dedup:H1")&&JSON.parse(kv.get("trust:"+a.cid)).tier===3,null);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"ok",claim_secret:secOk});chk("T1 upgrade valid -> 200 TI>=400",s===200&&j.trust_index>=400,j);
chk("T1 upgrade bound dedup + consumed session",kv.get("dedup:H1")===a.cid&&JSON.parse(kv.get("session:ok")).dedup==="registered",[kv.get("dedup:H1")]);
chk("S212 T1 upgrade consumed claim key",!kv.has("claim:ok"),null);
const c0=await key();
// make c0 a T3 then try to reuse session "ok"
const it2=await hmac(SECRET,`s2:${c0.pub}:${its}`);await post("/trust/initialize",{credential_id:c0.cid,tier:3,public_key:c0.pub,issuance_token:it2,t3_session_id:"s2",issuance_timestamp:its});
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:c0.cid,new_tier:1,session_id:"ok",claim_secret:secOk});chk("T1 upgrade session reuse for other cred (claim consumed) -> 403",s===403,j);
kv.set("claim:ok",await sha(enc.encode(secOk)));
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:c0.cid,new_tier:1,session_id:"ok",claim_secret:secOk});chk("T1 upgrade session reuse for other cred -> 409",s===409,j);

// ---- T2 init (voucher a is T1, TI 400)
const r=await key();
const vt={version:"hip-vouch-token-v1",nonce:"n1",timestamp:ts(),recipientPublicKey:r.pub,voucherCredentialId:a.cid,voucherPublicKey:a.pub,voucherTier:1};
const vb=tok(vt),vs=await sign(a,vb);
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid});chk("T2 init no token -> 400",s===400,j);
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid,vouch_body:vb,vouch_signature:await sign(b,vb)});chk("T2 init forged sig -> 403",s===403,j);
const r2=await key();
[s,j]=await post("/trust/initialize",{credential_id:r2.cid,tier:2,voucher_credential_id:a.cid,vouch_body:vb,vouch_signature:vs});chk("T2 init token for other recipient -> 403",s===403,j);
const old={...vt,timestamp:new Date(Date.now()-2*86400000).toISOString()};const ob=tok(old);
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid,vouch_body:ob,vouch_signature:await sign(a,ob)});chk("T2 init expired -> 400",s===400,j);
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid,vouch_body:vb,vouch_signature:vs});chk("T2 init valid -> 200",s===200&&j.tier===2,j);
// S212 nonce tracking
chk("S212 T2 init marked nonce used",kv.has("vnonce:hip-vouch-token-v1:"+a.cid+":n1"),null);
kv.delete("trust:"+r.cid); // simulate the one-record-per-credential bound being absent
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid,vouch_body:vb,vouch_signature:vs});chk("S212 T2 init replay of used token -> 409",s===409&&/already used/.test(j.error)&&!kv.has("trust:"+r.cid),j);
const nn={...vt};delete nn.nonce;const nnb=tok(nn);
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid,vouch_body:nnb,vouch_signature:await sign(a,nnb)});chk("S212 T2 init token without nonce -> 400",s===400,j);
const vt2={...vt,nonce:"n1b"};const vb2=tok(vt2);
[s,j]=await post("/trust/initialize",{credential_id:r2.cid,tier:2,voucher_credential_id:a.cid,vouch_body:vb2,vouch_signature:vs});chk("S212 T2 init forged token with fresh nonce still 403, nonce not burned",s===403&&!kv.has("vnonce:hip-vouch-token-v1:"+a.cid+":n1b"),j);
[s,j]=await post("/trust/initialize",{credential_id:r.cid,tier:2,voucher_credential_id:a.cid,vouch_body:vb2,vouch_signature:await sign(a,vb2)});chk("S212 T2 init fresh nonce -> 200 (r restored)",s===200,j);

// ---- T2 upgrade (c0 is T3)
const ut={version:"hip-upgrade-vouch-v1",nonce:"n2",timestamp:ts(),voucherCredentialId:a.cid,voucherPublicKey:a.pub,recipientCredentialId:c0.cid,targetTier:2};
const ub=tok(ut),us=await sign(a,ub);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,voucher_public_key:a.pub,vouch_signature:us,vouch_timestamp:ut.timestamp});chk("T2 upgrade no vouch_body (old client) -> 400",s===400,j);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,vouch_body:ub,vouch_signature:await sign(c0,ub)});chk("T2 upgrade forged sig -> 403",s===403,j);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,vouch_body:ub,vouch_signature:us});chk("T2 upgrade valid -> 200",s===200&&j.new_tier===2,j);
chk("S212 T2 upgrade marked nonce used",kv.has("vnonce:hip-upgrade-vouch-v1:"+a.cid+":n2"),null);
{const rec=JSON.parse(kv.get("trust:"+c0.cid));rec.tier=3;kv.set("trust:"+c0.cid,JSON.stringify(rec));}kv.delete("vouches:"+a.cid); // reset the 3/30d cap so the nonce check (not the cap) is what rejects
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,vouch_body:ub,vouch_signature:us});chk("S212 T2 upgrade replay -> 409, tier unchanged",s===409&&JSON.parse(kv.get("trust:"+c0.cid)).tier===3,j);
{const ut2={...ut,nonce:"n2b"};const ub2=tok(ut2);[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,vouch_body:ub2,vouch_signature:await sign(a,ub2)});chk("S212 T2 upgrade fresh nonce -> 200 (c0 restored)",s===200,j);}

// ---- T2 recovery: r (T2, voucher a) -> new key n
const n=await key(),atk=await key();
const rt={version:"hip-recovery-vouch-v1",nonce:"n3",timestamp:ts(),recipientPublicKey:n.pub,oldCredentialId:r.cid,voucherCredentialId:a.cid,voucherPublicKey:a.pub,voucherTier:1};
const rb=tok(rt),rs=await sign(a,rb);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:atk.cid,voucher_credential_id:a.cid,vouch_signature:"AAAA",vouch_body:"{}"});chk("T2 recovery junk sig (pre-S211 takeover) -> rejected",s>=400&&s<500,j);
chk("victim not superseded after attack",!JSON.parse(kv.get("trust:"+r.cid)).superseded_by,null);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:atk.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("T2 recovery real token, attacker new key -> 403",s===403,j);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:n.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("T2 recovery valid -> 200",s===200&&j.success,j);
chk("S212 T2 recovery marked nonce used",kv.has("vnonce:hip-recovery-vouch-v1:"+a.cid+":n3"),null);
{const rec=JSON.parse(kv.get("trust:"+r.cid));delete rec.superseded_by;kv.set("trust:"+r.cid,JSON.stringify(rec));kv.delete("trust:"+n.cid);}
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:n.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("S212 T2 recovery replay -> 409, no migration",s===409&&!kv.has("trust:"+n.cid),j);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:n.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("T2 recovery replay -> 409",s===409,j);

// ---- existing-record early return still works with no proof (imports)
[s,j]=await post("/trust/initialize",{credential_id:a.cid,tier:3});chk("existing record early-return unchanged -> 200",s===200&&/already exists/.test(j.message),j);
// ════════ S212: Didit claim-secret binding ════════
// ---- POST /session mints and stores the hash, returns the secret only in the body
[s,j]=await post("/session",{});chk("S212 /session -> 200 with claim_secret",s===200&&/^[0-9a-f]{64}$/.test(j.claim_secret||"")&&j.session_id==="didit-1",j);
const sid1=j.session_id,sec1=j.claim_secret;
chk("S212 /session stores SHA-256(secret), not the secret",kv.get("claim:"+sid1)===await sha(enc.encode(sec1))&&kv.get("claim:"+sid1)!==sec1,null);
chk("S212 /session verification_url carries no secret",!String(j.verification_url).includes(sec1),j.verification_url);
// Webhook equivalent: Approved, dedup new
kv.set("session:"+sid1,JSON.stringify({status:"Approved",dedup:"new",dedupHash:"HD1"}));
const d=await key();
// ---- /register-dedup
[s,j]=await post("/register-dedup",{session_id:sid1,credential_id:d.cid});chk("S212 register-dedup session_id alone -> 400",s===400,j);
[s,j]=await post("/register-dedup",{session_id:sid1,credential_id:d.cid,claim_secret:sec1.slice(0,63)+(sec1.endsWith("0")?"1":"0")});chk("S212 register-dedup wrong secret -> 403",s===403&&!kv.has("dedup:HD1"),j);
[s,j]=await post("/register-dedup",{session_id:sid1,credential_id:d.cid,claim_secret:sec1});chk("S212 register-dedup valid -> 200 binds dedup",s===200&&kv.get("dedup:HD1")===d.cid,j);
chk("S212 register-dedup keeps claim for T1 init",kv.has("claim:"+sid1),null);
// ---- /trust/initialize T1
[s,j]=await post("/trust/initialize",{credential_id:d.cid,tier:1,session_id:sid1});chk("S212 T1 init session_id alone -> 400",s===400,j);
[s,j]=await post("/trust/initialize",{credential_id:d.cid,tier:1,session_id:sid1,claim_secret:"nope"});chk("S212 T1 init wrong secret -> 403, no record",s===403&&!kv.has("trust:"+d.cid),j);
[s,j]=await post("/trust/initialize",{credential_id:d.cid,tier:1,session_id:sid1,claim_secret:sec1});chk("S212 T1 init valid -> 200 tier 1",s===200&&JSON.parse(kv.get("trust:"+d.cid)).tier===1,j);
chk("S212 T1 init consumed claim",!kv.has("claim:"+sid1),null);
[s,j]=await post("/trust/initialize",{credential_id:d.cid,tier:1,session_id:sid1,claim_secret:sec1});chk("S212 T1 init existing-record early return still 200 (imports)",s===200&&/already exists/.test(j.message),j);
const e=await key();
[s,j]=await post("/trust/initialize",{credential_id:e.cid,tier:1,session_id:sid1,claim_secret:sec1});chk("S212 T1 init replay of consumed secret for new cred -> 403",s===403&&!kv.has("trust:"+e.cid),j);
// ---- /recover-credential tier1-reverify (d is T1, identity HD1)
[s,j]=await post("/session",{});const sid2=j.session_id,sec2=j.claim_secret;
kv.set("session:"+sid2,JSON.stringify({status:"Approved",dedup:"exists",existingCredentialId:d.cid,dedupHash:"HD1"}));
const nk=await key();
[s,j]=await post("/recover-credential",{recovery_type:"tier1-reverify",session_id:sid2,old_credential_id:d.cid,new_credential_id:nk.cid,recovery_nonce:"r1"});chk("S212 T1 recovery session_id alone -> 400",s===400,j);
kv.delete("recovery_idempotency:r1");
[s,j]=await post("/recover-credential",{recovery_type:"tier1-reverify",session_id:sid2,old_credential_id:d.cid,new_credential_id:nk.cid,recovery_nonce:"r2",claim_secret:"bad"});chk("S212 T1 recovery wrong secret -> 403, dedup untouched",s===403&&kv.get("dedup:HD1")===d.cid,j);
kv.delete("recovery_idempotency:r2");
[s,j]=await post("/recover-credential",{recovery_type:"tier1-reverify",session_id:sid2,old_credential_id:d.cid,new_credential_id:nk.cid,recovery_nonce:"r3",claim_secret:sec2});chk("S212 T1 recovery valid -> 200 migrated",s===200&&kv.get("dedup:HD1")===nk.cid&&JSON.parse(kv.get("trust:"+d.cid)).superseded_by===nk.cid,j);
chk("S212 T1 recovery consumed claim",!kv.has("claim:"+sid2),null);

console.log(`\n${pass} pass / ${fail} fail`);
if (fail) process.exit(1);
