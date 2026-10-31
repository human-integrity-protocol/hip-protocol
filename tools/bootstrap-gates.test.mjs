// S211 regression harness for credential-bootstrap gates (BLOCKS ANNOUNCE #4).
// Run: node tools/bootstrap-gates.test.mjs   (Node >= 20; mocked KV, real Ed25519)
// Exercises /trust/initialize (T2, T3), /upgrade-credential (tier1-idv, tier2-vouch),
// /recover-credential (tier2-revouch) against the repo worker.js.
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const tmp = join(tmpdir(), "hip-worker-under-test.mjs");
writeFileSync(tmp, readFileSync(join(here, "..", "worker.js")));
const W = (await import(pathToFileURL(tmp).href)).default;
const SECRET="testsecret";
const kv=new Map();
const KV={async get(k){return kv.has(k)?kv.get(k):null},async put(k,v){kv.set(k,String(v))},async delete(k){kv.delete(k)},async list(){return{keys:[]}}};
const env={DEDUP_KV:KV,DEDUP_SECRET:SECRET};
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
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"nope"});chk("T1 upgrade unknown session -> 403",s===403,j);
kv.set("session:pend",JSON.stringify({status:"In Progress"}));
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"pend"});chk("T1 upgrade unapproved -> 400",s===400,j);
kv.set("session:nodd",JSON.stringify({status:"Approved",dedup:"insufficient_data"}));
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"nodd"});chk("T1 upgrade no dedupHash -> 403",s===403,j);
kv.set("dedup:H2","someoneelse");kv.set("session:dup",JSON.stringify({status:"Approved",dedup:"exists",dedupHash:"H2"}));
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"dup"});chk("T1 upgrade identity bound elsewhere -> 409",s===409,j);
kv.set("session:ok",JSON.stringify({status:"Approved",dedup:"new",dedupHash:"H1"}));
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:a.cid,new_tier:1,session_id:"ok"});chk("T1 upgrade valid -> 200 TI>=400",s===200&&j.trust_index>=400,j);
chk("T1 upgrade bound dedup + consumed session",kv.get("dedup:H1")===a.cid&&JSON.parse(kv.get("session:ok")).dedup==="registered",[kv.get("dedup:H1")]);
const c0=await key();
// make c0 a T3 then try to reuse session "ok"
const it2=await hmac(SECRET,`s2:${c0.pub}:${its}`);await post("/trust/initialize",{credential_id:c0.cid,tier:3,public_key:c0.pub,issuance_token:it2,t3_session_id:"s2",issuance_timestamp:its});
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier1-idv",credential_id:c0.cid,new_tier:1,session_id:"ok"});chk("T1 upgrade session reuse for other cred -> 409",s===409,j);

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

// ---- T2 upgrade (c0 is T3)
const ut={version:"hip-upgrade-vouch-v1",nonce:"n2",timestamp:ts(),voucherCredentialId:a.cid,voucherPublicKey:a.pub,recipientCredentialId:c0.cid,targetTier:2};
const ub=tok(ut),us=await sign(a,ub);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,voucher_public_key:a.pub,vouch_signature:us,vouch_timestamp:ut.timestamp});chk("T2 upgrade no vouch_body (old client) -> 400",s===400,j);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,vouch_body:ub,vouch_signature:await sign(c0,ub)});chk("T2 upgrade forged sig -> 403",s===403,j);
[s,j]=await post("/upgrade-credential",{upgrade_type:"tier2-vouch",credential_id:c0.cid,new_tier:2,voucher_credential_id:a.cid,vouch_body:ub,vouch_signature:us});chk("T2 upgrade valid -> 200",s===200&&j.new_tier===2,j);

// ---- T2 recovery: r (T2, voucher a) -> new key n
const n=await key(),atk=await key();
const rt={version:"hip-recovery-vouch-v1",nonce:"n3",timestamp:ts(),recipientPublicKey:n.pub,oldCredentialId:r.cid,voucherCredentialId:a.cid,voucherPublicKey:a.pub,voucherTier:1};
const rb=tok(rt),rs=await sign(a,rb);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:atk.cid,voucher_credential_id:a.cid,vouch_signature:"AAAA",vouch_body:"{}"});chk("T2 recovery junk sig (pre-S211 takeover) -> rejected",s>=400&&s<500,j);
chk("victim not superseded after attack",!JSON.parse(kv.get("trust:"+r.cid)).superseded_by,null);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:atk.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("T2 recovery real token, attacker new key -> 403",s===403,j);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:n.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("T2 recovery valid -> 200",s===200&&j.success,j);
[s,j]=await post("/recover-credential",{recovery_type:"tier2-revouch",old_credential_id:r.cid,new_credential_id:n.cid,voucher_credential_id:a.cid,vouch_signature:rs,vouch_body:rb});chk("T2 recovery replay -> 409",s===409,j);

// ---- existing-record early return still works with no proof (imports)
[s,j]=await post("/trust/initialize",{credential_id:a.cid,tier:3});chk("existing record early-return unchanged -> 200",s===200&&/already exists/.test(j.message),j);
console.log(`\n${pass} pass / ${fail} fail`);
if (fail) process.exit(1);
