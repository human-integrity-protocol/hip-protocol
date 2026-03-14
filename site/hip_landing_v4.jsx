import { useState, useEffect, useRef, useCallback } from "react";

// ============================================================
// HIP — HUMAN INTEGRITY PROTOCOL · Landing + Tools v4
// ============================================================

const G = {
  txid: "d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72",
  block: "940,558",
  timestamp: "2026-03-13 13:37:57 UTC",
  genesisHash: "401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872",
  charterHash: "d3aafa629236e34c642f59dfbaa1606d7adcf930d43ba33503f654a085f99493",
  firewallHash: "a0b28876b91848938dc1b9fd0838e671b27b899ddcc8f8a521b70ec63b2dad3c",
  guardianKey: "5645059140f824e96af935a09218c0374079e62f117078965a346423109b5026",
  opReturn: "HIP|GEN|401aa25f00b700fe07c11931b07675c62b3ac680b22f024f2f214e91c07c1872",
  ipfsPayload: "bafkreicadkrf6afxad7apqizggyhm5ogfm5mnafsf4be6lzbj2i4a7ayoi",
  ipfsCharter: "bafkreigtvl5gferw4nggil2z365kcydnplopsmguhortka7wksqil6musm",
  arweavePayload: "nTCa0kDBClUjUyregW-SYnf_vYlq5FwNqLMS5U-ahNI",
  arweaveCharter: "rG0zqLOaTmeDfYUw_uN4tqcw6xPj186Yc0HfubgkP1Y",
  explorer: "https://mempool.space/tx/d025505337a2e9c5a19adfcf312843432b256fe856a7e6dff5caa4842faf1a72",
};

// ── Crypto helpers ──
const hex = (b) => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < h.length; i += 2) b[i / 2] = parseInt(h.substr(i, 2), 16); return b; };
const sha256 = async (d) => { const buf = typeof d === "string" ? new TextEncoder().encode(d) : d; return hex(await crypto.subtle.digest("SHA-256", buf)); };
const b64e = (b) => { let s = ""; const u = new Uint8Array(b); for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); };
const b64d = (s) => { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };

const canonJSON = (o) => {
  if (o === null || o === undefined) return "null";
  if (typeof o === "boolean") return o ? "true" : "false";
  if (typeof o === "number") { if (!isFinite(o)) throw new Error("!"); return Object.is(o, -0) ? "0" : String(o); }
  if (typeof o === "string") return JSON.stringify(o);
  if (Array.isArray(o)) return "[" + o.map(v => canonJSON(v)).join(",") + "]";
  return "{" + Object.keys(o).sort().filter(k => o[k] !== undefined).map(k => JSON.stringify(k) + ":" + canonJSON(o[k])).join(",") + "}";
};

// ── Scroll fade ──
function useVis(th = 0.1) {
  const r = useRef(null);
  const [v, setV] = useState(false);
  useEffect(() => {
    const el = r.current; if (!el) return;
    const o = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setV(true); o.disconnect(); } }, { threshold: th });
    o.observe(el); return () => o.disconnect();
  }, [th]);
  return [r, v];
}
function Fade({ children, delay = 0, style = {} }) {
  const [r, v] = useVis();
  return <div ref={r} style={{ ...style, opacity: v ? 1 : 0, transform: v ? "translateY(0)" : "translateY(16px)", transition: `opacity .7s ease ${delay}s, transform .7s ease ${delay}s` }}>{children}</div>;
}

// ============================================================
// MAIN
// ============================================================
export default function HIPLanding() {
  const [ns, setNs] = useState(false);
  const [toolOpen, setToolOpen] = useState(null); // 'attest' | 'verify' | null
  useEffect(() => { const h = () => setNs(window.scrollY > 50); window.addEventListener("scroll", h); return () => window.removeEventListener("scroll", h); }, []);

  return (
    <div style={S.page}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;1,300;1,400&family=DM+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500;600;700&display=swap');
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        html{scroll-behavior:smooth}body{background:#06080f}
        a{color:${go};text-decoration:none}a:hover{text-decoration:underline}
        ::selection{background:rgba(212,160,84,0.3);color:#fff}
        strong{font-weight:600;color:${t1}}em{font-style:italic}
      `}</style>

      {/* ═══ NAV ═══ */}
      <nav style={{...S.nav, background: ns ? "rgba(6,8,15,0.96)" : "transparent", borderBottomColor: ns ? bd : "transparent"}}>
        <div style={S.navIn}>
          <div style={S.navLogo}>HIP</div>
          <div style={S.navLinks}>
            <a href="#how" style={S.navLink}>How It Works</a>
            <a href="#trust" style={S.navLink}>Trust</a>
            <a href="#bundles" style={S.navLink}>Proof Bundles</a>
            <a href="#genesis" style={S.navLink}>Genesis</a>
            <a href="#verify" style={S.navLink}>Verify</a>
            <a href="#build" style={S.navLink}>Build</a>
          </div>
          <div style={S.navTools}>
            <button style={S.navToolBtn} onClick={() => setToolOpen(toolOpen === "attest" ? null : "attest")}>Try Attestation</button>
            <button style={{...S.navToolBtn,...S.navToolBtnAlt}} onClick={() => setToolOpen(toolOpen === "verify" ? null : "verify")}>Verify</button>
          </div>
        </div>
      </nav>

      {/* ═══ TOOL DRAWER ═══ */}
      {toolOpen && (
        <div style={S.drawer}>
          <div style={S.drawerInner}>
            <div style={S.drawerHead}>
              <span style={S.drawerTitle}>{toolOpen === "attest" ? "Attestation Tool (Proof of Concept)" : "Verification Tool"}</span>
              <button style={S.drawerClose} onClick={() => setToolOpen(null)}>✕</button>
            </div>
            {toolOpen === "attest" ? <AttestWizard /> : <VerifyWizard />}
          </div>
        </div>
      )}

      {/* ═══ HERO ═══ */}
      <header style={S.hero}>
        <div style={S.heroGlow} />
        <div style={S.heroC}>
          <Fade><div style={S.ey}>A Protocol for Human Signal Integrity</div></Fade>
          <Fade delay={0.1}><h1 style={S.heroT}>Human Integrity Protocol</h1></Fade>
          <Fade delay={0.2}>
            <p style={S.heroS}>A cryptographic attestation system that lets human creators prove — verifiably, permanently, and without any institution's permission — that their work is human-made.</p>
          </Fade>
          <Fade delay={0.3}>
            <div style={S.heroBtn}>
              <a href="#how" style={S.btnG}>How It Works</a>
              <button style={S.btnG} onClick={() => setToolOpen("attest")}>Try Attestation</button>
              <a href="#genesis" style={S.btnO}>Genesis Inscription</a>
            </div>
          </Fade>
        </div>
        <div style={S.heroFade} />
      </header>

      {/* ═══ MANIFESTO ═══ */}
      <section style={S.mani}>
        <div style={S.w}>
          <Fade><blockquote style={S.mQ}>"Here we begin the ledger of human signal integrity."</blockquote></Fade>
          <Fade delay={0.1}><p style={S.mT}>In an era of pervasive synthetic media, the question is no longer whether AI can produce convincing content. It can. The question is whether a human creator can prove their work is theirs — and prove it in a way that doesn't depend on any company, platform, or government staying honest, staying online, or staying interested.</p></Fade>
          <Fade delay={0.18}><p style={S.mT}>HIP is the answer. Not a service. Not an app. A protocol — open, permanent, and verifiable by anyone with a computer and an internet connection. Its authority comes from mathematics, not institutions. Its permanence comes from the Bitcoin blockchain, not a corporate database. Its value comes from the truth it records: a living human being made this.</p></Fade>
        </div>
      </section>

      {/* ═══ HOW IT WORKS ═══ */}
      <section style={S.sec} id="how">
        <div style={S.w}>
          <Fade><div style={S.ey}>How It Works</div><h2 style={S.sT}>Four steps. No accounts. No uploads.</h2></Fade>
          <div style={S.grid2x2}>
            {[
              { n: "01", t: "Prove you're human", d: "Before you can attest, HIP confirms a living human is at the keyboard. You obtain a HUMAN-PROOF credential through one of several verification methods. This credential is yours. It doesn't expose your identity. It proves you're a real person." },
              { n: "02", t: "Select your content", d: "Choose the file you want to attest. HIP computes a SHA-256 cryptographic fingerprint of the exact bytes — on your device, locally. Your file is never uploaded, transmitted, or stored. The fingerprint is all the protocol needs." },
              { n: "03", t: "Choose your classification", d: "Honestly describe how you made it. Three categories, each equally valid:" , bullets: ["CHO — Complete Human Origin: no AI generation tools involved", "HOA — Human Origin Assisted: AI helped at the margins", "HDC — Human-Directed Collaborative: human-directed, AI co-created"] },
              { n: "04", t: "Attest and anchor", d: "Your credential signature, the content fingerprint, your classification, and a liveness verification are packaged into a Proof Bundle and anchored on the Bitcoin blockchain. Permanent. Immutable. Verifiable by anyone, forever." },
            ].map((s, i) => (
              <Fade key={i} delay={i * 0.07}>
                <div style={S.stepC}>
                  <div style={S.stepN}>{s.n}</div>
                  <h3 style={S.stepT}>{s.t}</h3>
                  <p style={S.stepD}>{s.d}</p>
                  {s.bullets && <ul style={S.stepBullets}>{s.bullets.map((b, j) => <li key={j} style={S.stepBullet}>{b}</li>)}</ul>}
                </div>
              </Fade>
            ))}
          </div>

          {/* CONTENT PLEDGE */}
          <Fade delay={0.3}>
            <div style={S.pledge}>
              <div style={S.pledgeIco}>🔒</div>
              <h3 style={S.pledgeH}>Your content is yours. Always.</h3>
              <p style={S.pledgeP}>HIP <strong>never</strong> stores your creative work — not the photo, not the article, not the video, not a single byte. Your work lives wherever <em>you</em> put it. What HIP stores is a mathematical fingerprint — a short string of characters computed from your file. This fingerprint is a one-way function: it cannot be reversed to reconstruct, view, or access your original work.</p>
              <p style={S.pledgeP}>Your content never touches the blockchain. Your content never touches any server. Your content never leaves your device during attestation. The only thing that enters the protocol is the fingerprint. From that fingerprint, no one can recreate your work. Ever.</p>
              <div style={S.pledgeBadge}>Nothing uploaded. Nothing stored. Nothing shared. The math proves without revealing.</div>
            </div>
          </Fade>
        </div>
      </section>

      {/* ═══ PROVING YOU'RE HUMAN ═══ */}
      <section style={S.dkSec} id="human">
        <div style={S.w}>
          <Fade>
            <div style={S.ey}>Proving You're Human</div>
            <h2 style={S.sT}>Multiple paths. One standard. No identity exposed.</h2>
            <p style={S.sD}>HIP uses a tiered credential system called HUMAN-PROOF. There are currently three verification paths, each balancing accessibility with assurance. More will be added as the landscape evolves. Every path confirms a living human holds the credential — without ever recording who that human is on the public ledger.</p>
          </Fade>

          <div style={S.grid3}>
            {[
              { badge: "Tier 1", name: "Government ID / Institutional", text: "Verification against an authoritative external record — a government-issued ID or recognized institutional affiliation. The highest initial assurance level. Your identity is confirmed by the pathway provider but never recorded on the public ledger.", detail: "Pseudonymous. Your name is never on-chain.", weight: "Starting strength: highest" },
              { badge: "Tier 2", name: "Device Biometric", text: "Your phone or computer's hardware security confirms a live human was present — using the same biometric systems (Face ID, fingerprint) you already use daily. No biometric data is transmitted or stored.", detail: "No new apps. No new behaviors. Your existing device.", weight: "Starting strength: moderate" },
              { badge: "Tier 3", name: "Peer Vouching", text: "An existing credentialed human vouches that you're a real person. The most globally accessible path — works without special hardware or documents. The voucher stakes their reputation: if your credential is later found fraudulent, their standing is affected.", detail: "Accessible everywhere. Accountability built in.", weight: "Starting strength: accessible" },
            ].map((tier, i) => (
              <Fade key={i} delay={i * 0.08}>
                <div style={S.tierC}>
                  <div style={S.tierB}>{tier.badge}</div>
                  <div style={S.tierN}>{tier.name}</div>
                  <p style={S.tierT}>{tier.text}</p>
                  <div style={S.tierDet}>{tier.detail}</div>
                  <div style={S.tierW}>{tier.weight}</div>
                </div>
              </Fade>
            ))}
          </div>

          <Fade delay={0.28}>
            <div style={S.progBox}>
              <h3 style={S.progH}>Where you start is not where you're stuck.</h3>
              <p style={S.progP}>Every credential earns a <strong>Trust Index</strong> — a measure of the protocol's confidence in the credential, built through consistent, honest use. A Tier 3 credential used honestly for two years can reach the same maximum standing as any Tier 1 credential. The tier is a head start, not a ceiling.</p>
              <div style={S.grid3}>
                {[
                  { l: "Earn through use", d: "Every honest attestation adds to your credential's history. Device-verified attestations earn the most. The protocol rewards consistency, not volume." },
                  { l: "Upgrade anytime", d: "A Tier 3 creator can re-verify through Tier 2 (device biometric) or Tier 1 (government ID) at any time. Your behavioral history carries forward — nothing is lost." },
                  { l: "Same ceiling for everyone", d: "The maximum Trust Index is the same regardless of starting tier. HIP does not permanently discount the human who started without institutional backing." },
                ].map((p, i) => (
                  <div key={i} style={S.progItem}>
                    <div style={S.progLabel}>{p.l}</div>
                    <div style={S.progDesc}>{p.d}</div>
                  </div>
                ))}
              </div>
            </div>
          </Fade>

          <Fade delay={0.35}>
            <div style={S.liveNote}>Every attestation also requires a <strong>point-of-use liveness check</strong> — confirming a living human is present at the moment of each attestation, not just at credential issuance. Liveness status is recorded honestly in every Proof Bundle: device-verified, behavioral fallback, or unverified. Nothing is hidden.</div>
          </Fade>
        </div>
      </section>

      {/* ═══ WHAT HIP IS / IS NOT ═══ */}
      <section style={S.sec}>
        <div style={S.w}>
          <Fade><div style={S.ey}>What HIP Is Not</div><h2 style={S.sT}>Not an NFT. Not a watermark. Not a detector.</h2></Fade>
          <div style={S.grid2}>
            <Fade delay={0.06}>
              <div style={S.conC}>
                <div style={S.conH}>HIP does not</div>
                <div style={S.conL}>
                  {["Store, upload, or transmit your content — ever", "Create tokens, NFTs, or represent ownership", "Require any platform's permission or cooperation", "Cost anything to verify", "Depend on any company staying in business", "Try to detect or flag AI content", "Expose your identity on the public ledger"].map((t, i) => (
                    <div key={i} style={S.conI}><span style={S.conX}>✗</span>{t}</div>
                  ))}
                </div>
              </div>
            </Fade>
            <Fade delay={0.12}>
              <div style={{ ...S.conC, borderColor: "rgba(212,160,84,0.25)" }}>
                <div style={S.conH}>HIP does</div>
                <div style={S.conL}>
                  {["Store only a mathematical fingerprint of your content", "Create a permanent, signed attestation record", "Work with any platform, permissionlessly", "Let anyone verify, for free, forever", "Derive its authority from math, not institutions", "Let humans prove what's theirs", "Keep you pseudonymous — credential, not identity"].map((t, i) => (
                    <div key={i} style={S.conI}><span style={S.conK}>✓</span>{t}</div>
                  ))}
                </div>
              </div>
            </Fade>
          </div>
        </div>
      </section>

      {/* ═══ TRUST MODEL ═══ */}
      <section style={S.dkSec} id="trust">
        <div style={S.w}>
          <Fade><div style={S.ey}>Trust Model</div><h2 style={S.sT}>What happens when someone lies.</h2>
            <p style={S.sD}>HIP is an attestation system — creators make claims about their work, and those claims are recorded permanently. Yes, someone could lie. Here's why the protocol is designed to catch them, and what happens when it does.</p></Fade>
          <div style={S.grid2}>
            {[
              { ico: "📊", t: "Behavioral Monitoring", d: "Every credential accumulates a Trust Index through consistent, honest use. The protocol's Propagation Fingerprint system continuously analyzes attestation patterns against content signals. Anomalies trigger automated review. The math watches even when nobody else does." },
              { ico: "🔍", t: "Three Kinds of Compromise", d: "Stolen credential — pre-theft attestations protected. Fraudulent credential — every attestation flagged, voucher takes a hit. Systematic false attestation — credential permanently invalidated. Each type has defined consequences." },
              { ico: "⛓️", t: "Permanent Public Record", d: "Confirmed compromise collapses Trust Index to zero. The credential is permanently invalidated. But nothing is deleted. Every attestation stays on the ledger — now flagged. Dishonesty is inscribed permanently, right next to honest attestations." },
              { ico: "⚖️", t: "Accountability, Not Trust", d: "HIP doesn't ask you to trust anyone. Vouchers stake their standing. Credentials build value through behavior that's costly to fake. Every piece of evidence lives on a public ledger no one controls. Integrity from structure, not intentions." },
            ].map((c, i) => (
              <Fade key={i} delay={i * 0.06}>
                <div style={S.trustC}><div style={{ fontSize: 22, marginBottom: 10 }}>{c.ico}</div><h3 style={S.trustT}>{c.t}</h3><p style={S.trustD}>{c.d}</p></div>
              </Fade>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ CATEGORIES ═══ */}
      <section style={S.sec}>
        <div style={S.w}>
          <Fade><div style={S.ey}>Three Categories</div><h2 style={S.sT}>Honest about process, not judgmental about tools.</h2>
            <p style={S.sD}>HIP records the truth about how something was made. All three categories are valid attestations by real humans about real creative work.</p></Fade>
          <div style={S.grid3}>
            {[
              { b: "CHO", n: "Complete Human Origin", d: "The entire creative work was produced by the attesting human without AI generation tools. The photo you shot. The article you wrote. The song you composed." },
              { b: "HOA", n: "Human Origin Assisted", d: "Human-created work where AI tools assisted — editing, suggestions, refinement, spell-checking, color grading. The core creative work is human." },
              { b: "HDC", n: "Human-Directed Collaborative", d: "Work produced through human-directed collaboration with AI generation tools. The human provided vision, direction, and editorial judgment." },
            ].map((c, i) => (
              <Fade key={i} delay={i * 0.07}><div style={S.catC}><div style={S.catB}>{c.b}</div><div style={S.catN}>{c.n}</div><div style={S.catD}>{c.d}</div></div></Fade>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ PROOF BUNDLES ═══ */}
      <section style={S.dkSec} id="bundles">
        <div style={S.w}>
          <Fade><div style={S.ey}>Inside a Proof Bundle</div><h2 style={S.sT}>What the attestation actually contains.</h2>
            <p style={S.sD}>When you attest, HIP creates two artifacts: a <strong>Proof Bundle</strong> (the complete off-chain record, ~2-3 KB) and a <strong>Proof Anchor</strong> (a minimal on-chain summary, ~250 bytes, inscribed on Bitcoin). Here's what's inside — and what's not.</p></Fade>

          <Fade delay={0.1}>
            <div style={S.bGrid}>
              {[
                { f: "Content Fingerprint", w: "SHA-256 hash of your file", y: "References your content without storing it. One-way — cannot reconstruct your work." },
                { f: "Classification", w: "CHO, HOA, or HDC", y: "Your honest claim about how the content was created." },
                { f: "Credential Signature", w: "Ed25519 digital signature", y: "Cryptographic proof that your verified credential signed this attestation." },
                { f: "Liveness Verification", w: "Device attestation or behavioral score", y: "Proof a living human was present at the moment of attestation." },
                { f: "Timestamp", w: "ISO 8601 UTC datetime", y: "When the attestation was made — assigned by the processing node, not self-reported." },
                { f: "Editorial Statement", w: "Optional free text (≤2000 chars)", y: "Your own words about the work. Recorded but not evaluated." },
                { f: "Credential Reference", w: "Pseudonymous credential ID", y: "Links to your credential without revealing your identity." },
                { f: "Pathway Reference", w: "Verification method + tier", y: "Which method verified your humanity and its current standing." },
              ].map((f, i) => (
                <div key={i} style={S.bF}><div style={S.bFN}>{f.f}</div><div style={S.bFW}>{f.w}</div><div style={S.bFY}>{f.y}</div></div>
              ))}
            </div>
          </Fade>

          <Fade delay={0.18}>
            <div style={S.bNot}>
              <h3 style={S.bNotH}>What is NOT in a Proof Bundle</h3>
              <p style={S.bNotP}>Your content. Your name. Your biometric data. Your location. Your device identity. Nothing that could identify you, access your work, or reconstruct your creative output. The Proof Bundle is a signed mathematical claim — nothing more, nothing less.</p>
            </div>
          </Fade>

          <Fade delay={0.24}>
            <div style={S.bAnch}>
              <h3 style={S.bAnchH}>The Proof Anchor (on-chain)</h3>
              <p style={S.bAnchP}>The Proof Anchor is a minimal summary inscribed on Bitcoin — about 250 bytes. It contains the content fingerprint, credential ID, classification, timestamp, Bundle hash, and a retrieval link. This is what makes the attestation permanent. The Bundle and Anchor are linked by a cryptographic hash — tamper with one and the other won't match. The blockchain is the ground truth.</p>
            </div>
          </Fade>

          <Fade delay={0.3}>
            <div style={S.bTech}>
              <div style={S.bTechH}>Technical Details</div>
              <div style={S.bTechG}>
                {[["Format", "JSON-LD (W3C Verifiable Credentials)"], ["Serialization", "RFC 8785 Canonical JSON"], ["Hash", "SHA-256 (FIPS 180-4)"], ["Signature", "Ed25519 (RFC 8032)"], ["Bundle Size", "1.8 – 2.7 KB typical"], ["Anchor Size", "~250 bytes"], ["Schema", "WF-v1.0"], ["Spec", "WF-SPEC-v1 + CRYPTO-SPEC-v1"]].map(([k, v], i) => (
                  <div key={i} style={S.bTR}><span style={S.bTK}>{k}</span><span style={S.bTV}>{v}</span></div>
                ))}
              </div>
            </div>
          </Fade>
        </div>
      </section>

      {/* ═══ GENESIS ═══ */}
      <section style={S.sec} id="genesis">
        <div style={S.w}>
          <Fade><div style={S.ey}>Genesis Inscription</div><h2 style={S.sT}>Born on Bitcoin. Block {G.block}.</h2>
            <p style={S.sD}>On March 13, 2026, the HIP Genesis Covenant Charter was permanently inscribed on the Bitcoin blockchain. Every subsequent HIP attestation traces its lineage to this root.</p></Fade>
          <Fade delay={0.1}>
            <div style={S.gGrid}>
              {[["Genesis Transaction", G.txid, G.explorer], ["OP_RETURN Data", G.opReturn], ["Block Height", G.block, null, 1], ["Confirmed", G.timestamp, null, 1], ["Genesis Hash (SHA-256)", G.genesisHash], ["Charter Hash", G.charterHash], ["Firewall Hash", G.firewallHash], ["Guardian Key (Ed25519)", G.guardianKey]].map(([l, v, link, plain], i) => (
                <div key={i} style={S.gF}><div style={S.gL}>{l}</div>{link ? <a href={link} target="_blank" rel="noopener" style={{ ...S.gV, color: go }}>{v}</a> : <code style={{ ...S.gV, ...(plain ? {} : { fontFamily: mo, fontSize: 11 }) }}>{v}</code>}</div>
              ))}
            </div>
          </Fade>
          <Fade delay={0.18}>
            <div style={{ ...S.subH, marginTop: 32 }}>Content-Addressed Storage</div>
            <p style={{ ...S.sD, marginBottom: 14 }}>The full payload and charter are on two independent, permanent networks. Click to retrieve directly.</p>
            <div style={S.stG}>
              {[["IPFS — Payload", G.ipfsPayload, `https://gateway.pinata.cloud/ipfs/${G.ipfsPayload}`], ["IPFS — Charter", G.ipfsCharter, `https://gateway.pinata.cloud/ipfs/${G.ipfsCharter}`], ["Arweave — Payload", G.arweavePayload, `https://arweave.net/${G.arweavePayload}`], ["Arweave — Charter", G.arweaveCharter, `https://arweave.net/${G.arweaveCharter}`]].map(([l, cid, url], i) => (
                <a key={i} href={url} target="_blank" rel="noopener" style={S.stC}><div style={S.stL}>{l}</div><code style={S.stCid}>{cid}</code><div style={S.stA}>Open →</div></a>
              ))}
            </div>
          </Fade>
        </div>
      </section>

      {/* ═══ VERIFY ═══ */}
      <section style={S.dkSec} id="verify">
        <div style={S.w}>
          <Fade><div style={S.ey}>Independent Verification</div><h2 style={S.sT}>Don't trust us. Verify it yourself.</h2>
            <p style={S.sD}>Everything about HIP is independently verifiable using only public tools. No account. No API key. No special software.</p></Fade>

          <Fade delay={0.06}>
            <div style={S.vTool}>
              <div style={S.vToolH}>Start here — opens in a new tab:</div>
              <div style={S.vToolG}>
                {[["⛓", "mempool.space", G.explorer], ["🔗", "Blockstream", `https://blockstream.info/tx/${G.txid}`], ["📄", "IPFS Payload", `https://gateway.pinata.cloud/ipfs/${G.ipfsPayload}`], ["📄", "Arweave Payload", `https://arweave.net/${G.arweavePayload}`]].map(([ico, label, url], i) => (
                  <a key={i} href={url} target="_blank" rel="noopener" style={S.vTBtn}><span style={{ fontSize: 15 }}>{ico}</span><span>{label}</span></a>
                ))}
              </div>
              <div style={{ marginTop: 10 }}>
                <button style={S.vInlineBtn} onClick={() => setToolOpen("verify")}>Open Verification Tool</button>
              </div>
            </div>
          </Fade>

          <Fade delay={0.14}><div style={{ ...S.subH, marginTop: 32 }}>The 5-Step Verification</div></Fade>
          <div style={S.vSteps}>
            {[
              { n: "1", t: "Check the blockchain", d: "Look up the Genesis Transaction on any block explorer. Find the OP_RETURN output. Confirm it contains the Genesis Hash.", h: G.genesisHash },
              { n: "2", t: "Retrieve and hash the payload", d: "Download the Genesis Inscription Payload from IPFS or Arweave. Compute its SHA-256 hash. It must match the Genesis Hash.", cmd: "shasum -a 256 genesis_inscription_payload.json" },
              { n: "3", t: "Verify the Charter hash", d: "Open the payload JSON. Extract charterHash. Download the Charter. Compute its SHA-256 hash. It must match.", h: G.charterHash },
              { n: "4", t: "Verify the Firewall hash", d: "Extract Phoenix Firewall clauses PF-1 through PF-11 from the Charter. Compute SHA-256. It must match firewallHash in the payload.", h: G.firewallHash },
              { n: "5", t: "Verify the Guardian signature", d: "Using the Guardian public key, verify the Ed25519 signature over: \"Here we begin the ledger of human signal integrity.\" All five pass = Genesis confirmed valid." },
            ].map((s, i) => (
              <Fade key={i} delay={0.18 + i * 0.04}>
                <div style={S.vS}><div style={S.vN}>{s.n}</div><div style={{ flex: 1 }}><div style={S.vST}>{s.t}</div><div style={S.vSD}>{s.d}</div>{s.h && <code style={S.vH}>{s.h}</code>}{s.cmd && <code style={S.vCmd}>{s.cmd}</code>}</div></div>
              </Fade>
            ))}
          </div>
          <Fade delay={0.42}><div style={S.vNote}>Prefer your own tools? Use any Bitcoin full node, any SHA-256 implementation, any Ed25519 library. Open standards: FIPS 180-4, RFC 8032. No proprietary software required.</div></Fade>
        </div>
      </section>

      {/* ═══ BUILD ═══ */}
      <section style={S.sec} id="build">
        <div style={S.w}>
          <Fade><div style={S.ey}>Open Protocol</div><h2 style={S.sT}>Built to be built on.</h2>
            <p style={S.sD}>HIP is a protocol, not a product. Anyone can build tools that produce or consume HIP attestation artifacts. The specification is public. No license, API key, or partnership required.</p></Fade>
          <div style={S.grid3}>
            {[
              { i: "🖥️", t: "Platform Integration", d: "Any social media platform or publishing system can check content for matching attestations and display a Proofcard automatically. No partnership needed." },
              { i: "🔌", t: "Browser Extension", d: "Fingerprint any image or text you're viewing and check for a matching attestation. The creator doesn't have to do anything beyond attesting." },
              { i: "📱", t: "Creator Tools", d: "Mobile and desktop apps that make attestation as simple as sharing. A working POC already produces spec-compliant Proof Bundles." },
              { i: "🏛️", t: "Institutional Workflows", d: "Newsrooms and publishers can integrate HIP into editorial pipelines. Multi-author Attestation Chains support collaborative content." },
              { i: "🔧", t: "Verification Scripts", d: "Build standalone verification in any language — Python, JS, Rust, Go. Standard library crypto. Accept a Bundle and Anchor, confirm the chain." },
              { i: "🌐", t: "Steward Nodes", d: "Institutions can operate Steward Nodes — distributed infrastructure that hosts Proof Bundles and processes attestations." },
            ].map((c, i) => (
              <Fade key={i} delay={i * 0.05}><div style={S.bldC}><div style={{ fontSize: 22, marginBottom: 10 }}>{c.i}</div><h3 style={S.bldT}>{c.t}</h3><p style={S.bldD}>{c.d}</p></div></Fade>
            ))}
          </div>

          <Fade delay={0.32}>
            <div style={S.specBox}>
              <div style={S.specH}>8 Companion Specifications</div>
              <p style={S.specP}>Every aspect of HIP is formally specified. Builders have a complete blueprint.</p>
              <div style={S.grid2x2sm}>
                {["WF-SPEC-v1 — Proof Bundle Wire Format", "HP-SPEC-v1 — HUMAN-PROOF Credentials", "CRYPTO-SPEC-v1 — Cryptographic Primitives", "PFV-SPEC-v1 — Propagation & Verification", "PATHWAY-SPEC-v1 — Issuance Governance", "INT-SPEC-v1 — Integration Endpoints", "GI-SPEC-v1 — Genesis Inscription", "SLA-SPEC-v1 — Steward Ledger Activity"].map((s, i) => (
                  <div key={i} style={S.specI}>{s}</div>
                ))}
              </div>
              <div style={S.specAccess}>
                <div style={S.specAH}>Accessing the Specifications</div>
                <p style={S.specAP}>The full specifications, sealed Charter, and Genesis Payload are being prepared for publication to a public repository. The protocol's root of trust is already public and permanent on-chain. No license, NDA, or partnership required. Watch this space for the repository announcement.</p>
              </div>
            </div>
          </Fade>
        </div>
      </section>

      {/* ═══ COVENANT ═══ */}
      <section style={S.covSec}>
        <div style={S.w}>
          <Fade>
            <div style={S.covLine}>"Here we begin the ledger of human signal integrity."</div>
            <div style={S.covSub}>Genesis Covenant Line — signed by the Guardian Key, inscribed on Bitcoin block {G.block}</div>
          </Fade>
        </div>
      </section>

      {/* ═══ FOOTER ═══ */}
      <footer style={S.foot}>
        <div style={S.w}>
          <div style={S.footIn}>
            <div style={S.footLogo}>HIP</div>
            <div style={S.footTag}>Human Integrity Protocol</div>
            <div style={S.footLinks}>
              {[["Verify on-chain", G.explorer], ["IPFS", `https://gateway.pinata.cloud/ipfs/${G.ipfsPayload}`], ["Arweave", `https://arweave.net/${G.arweavePayload}`], ["Blockstream", `https://blockstream.info/tx/${G.txid}`]].map(([l, u], i) => (
                <span key={i}>{i > 0 && <span style={{ color: t2, margin: "0 6px" }}>·</span>}<a href={u} target="_blank" rel="noopener" style={S.footLink}>{l}</a></span>
              ))}
            </div>
            <div style={S.footMeta}>Block {G.block} · Inscribed 2026-03-13 · Ed25519 + SHA-256</div>
            <div style={S.footLegal}>HIP is a protocol, not a product. This page is informational. The on-chain inscription and content-addressed artifacts are self-verifying.</div>
          </div>
        </div>
      </footer>
    </div>
  );
}

// ============================================================
// ATTESTATION WIZARD (embedded)
// ============================================================
function AttestWizard() {
  const [step, setStep] = useState(0);
  const [cred, setCred] = useState(null);
  const [err, setErr] = useState(null);
  const [gen, setGen] = useState(false);
  const [hash, setHash] = useState(null);
  const [fname, setFname] = useState(null);
  const [ctype, setCtype] = useState(null);
  const [cls, setCls] = useState(null);
  const [editorial, setEditorial] = useState("");
  const [bundle, setBundle] = useState(null);
  const [anchor, setAnchor] = useState(null);
  const [bHash, setBHash] = useState(null);
  const [building, setBuilding] = useState(false);
  const fref = useRef(null);

  const genCred = async () => {
    setGen(true); setErr(null);
    try {
      const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
      const pub = hex(await crypto.subtle.exportKey("raw", kp.publicKey));
      const cid = await sha256(unhex(pub));
      setCred({ pub, cid, priv: kp.privateKey, pubObj: kp.publicKey });
    } catch (e) { setErr("Ed25519 requires Chrome 113+ or Edge 113+."); }
    setGen(false);
  };

  const pickFile = async (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    setFname(f.name); setCtype(f.type || "application/octet-stream");
    setHash(await sha256(new Uint8Array(await f.arrayBuffer())));
  };

  const buildBundle = async () => {
    setBuilding(true);
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const content = {
      "@context": ["https://www.w3.org/2018/credentials/v1", "https://hip.protocol/contexts/v1"],
      attestation: { attestationChain: null, editorialStatement: editorial, priorVersion: null, type: "OriginalAttestation" },
      bundleMetadata: { processingNode: "local-poc", schemaExtensions: [] },
      credentialSubject: { classification: cls, contentHash: hash, contentType: ctype, hashAlgorithm: "sha-256", id: `urn:hip:content:${hash}` },
      issuanceDate: now,
      issuer: { id: cred.cid, issuanceTier: 2, pathwayVersion: "device-biometric-v1.0-20260915", type: "HIPCredential" },
      liveness: { behavioralScore: null, deviceAttestation: { attestationToken: b64e(crypto.getRandomValues(new Uint8Array(32))), platform: "local-poc", tokenVerification: "VerificationUnavailable" }, method: "DeviceAttestation", timestamp: now },
      pathway: { class: "DeviceBiometric", pathwayState: "Active", pathwayStateTimestamp: "2026-03-13T00:00:00Z", tier: 2, versionId: "device-biometric-v1.0-20260915" },
      type: ["VerifiableCredential", "HIPAttestationBundle"],
      version: "WF-v1.0",
    };
    const canon = canonJSON(content);
    const bh = await sha256(canon);
    setBHash(bh);
    const sigBuf = await crypto.subtle.sign("Ed25519", cred.priv, new TextEncoder().encode(canon));
    const full = { ...content, id: `urn:hip:bundle:${bh}`, proof: { created: now, proofPurpose: "assertionMethod", proofValue: b64e(sigBuf), type: "Ed25519Signature2020", verificationMethod: cred.cid }, signalAnnotations: [] };
    setBundle(full);
    setAnchor({ anchorLink: `hip://${bh.substring(0, 8)}/${bh}`, bundleHash: bh, classification: cls, contentHash: hash, credentialId: cred.cid, timestamp: now, type: "HIPProofAnchor", version: "WF-v1.0" });
    setBuilding(false);
    setStep(4);
  };

  const dl = (obj, name) => { const u = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" })); const a = document.createElement("a"); a.href = u; a.download = name; a.click(); URL.revokeObjectURL(u); };

  const steps = ["Credential", "Content", "Classify", "Attest", "Done"];
  const W = S; // reuse main styles

  return (
    <div style={S.wiz}>
      <div style={S.wizSteps}>{steps.map((s, i) => <div key={i} style={{ ...S.wizStep, color: i <= step ? go : t2, opacity: i <= step ? 1 : 0.4 }}>{i < step ? "✓" : i + 1}. {s}</div>)}</div>

      {step === 0 && (<div style={S.wizBody}>
        <p style={S.wizText}>Generate an Ed25519 credential keypair. The private key stays in your browser.</p>
        {!cred && <button style={S.btnG} onClick={genCred} disabled={gen}>{gen ? "Generating..." : "Generate Credential"}</button>}
        {err && <div style={S.wizErr}>{err}</div>}
        {cred && <div style={S.wizResult}><div style={S.wizRL}>Credential ID</div><code style={S.wizRV}>{cred.cid}</code><div style={S.wizRL}>Public Key</div><code style={S.wizRV}>{cred.pub}</code></div>}
        {cred && <button style={S.btnG} onClick={() => setStep(1)}>Next →</button>}
      </div>)}

      {step === 1 && (<div style={S.wizBody}>
        <p style={S.wizText}>Select a file. The SHA-256 fingerprint is computed locally — your file never leaves this device.</p>
        <div style={S.wizDrop} onClick={() => fref.current?.click()}>
          <input ref={fref} type="file" style={{ display: "none" }} onChange={pickFile} />
          {hash ? <div><div style={{ fontWeight: 600, color: t1, marginBottom: 6 }}>{fname}</div><code style={{ fontSize: 11, color: go, wordBreak: "break-all", fontFamily: mo }}>{hash}</code></div> : <span style={{ color: t2 }}>Click to select a file</span>}
        </div>
        <div style={S.wizNav}><button style={S.btnSm} onClick={() => setStep(0)}>← Back</button>{hash && <button style={S.btnG} onClick={() => setStep(2)}>Next →</button>}</div>
      </div>)}

      {step === 2 && (<div style={S.wizBody}>
        <p style={S.wizText}>How was this content created?</p>
        {[["CompleteHumanOrigin", "CHO", "Complete Human Origin"], ["HumanOriginAssisted", "HOA", "Human Origin Assisted"], ["HumanDirectedCollaborative", "HDC", "Human-Directed Collaborative"]].map(([id, badge, label]) => (
          <button key={id} style={{ ...S.wizCls, borderColor: cls === id ? go : bd, background: cls === id ? "rgba(212,160,84,0.08)" : "transparent" }} onClick={() => setCls(id)}>
            <span style={{ fontFamily: mo, color: go, fontWeight: 600, marginRight: 10 }}>{badge}</span>{label}
          </button>
        ))}
        <div style={S.wizNav}><button style={S.btnSm} onClick={() => setStep(1)}>← Back</button>{cls && <button style={S.btnG} onClick={() => setStep(3)}>Next →</button>}</div>
      </div>)}

      {step === 3 && (<div style={S.wizBody}>
        <p style={S.wizText}>Optional editorial statement ({editorial.length}/2000 characters):</p>
        <textarea style={S.wizTxt} value={editorial} onChange={e => setEditorial(e.target.value.slice(0, 2000))} placeholder="Describe your work..." rows={3} />
        <div style={S.wizNav}><button style={S.btnSm} onClick={() => setStep(2)}>← Back</button><button style={S.btnG} onClick={buildBundle} disabled={building}>{building ? "Building..." : "Build Proof Bundle →"}</button></div>
      </div>)}

      {step === 4 && bundle && (<div style={S.wizBody}>
        <div style={S.wizResult}>
          <div style={S.wizRL}>Bundle Hash</div><code style={{ ...S.wizRV, color: go }}>{bHash}</code>
          <div style={S.wizRL}>Bundle ID</div><code style={S.wizRV}>{bundle.id}</code>
          <div style={S.wizRL}>Anchor Link</div><code style={S.wizRV}>{anchor.anchorLink}</code>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button style={S.btnDl} onClick={() => dl(bundle, "HIP_ProofBundle.json")}>↓ Proof Bundle</button>
          <button style={S.btnDl} onClick={() => dl(anchor, "HIP_ProofAnchor.json")}>↓ Proof Anchor</button>
        </div>
        <details style={S.wizDet}><summary style={S.wizDetSum}>View Bundle JSON</summary><pre style={S.wizPre}>{JSON.stringify(bundle, null, 2)}</pre></details>
        <details style={S.wizDet}><summary style={S.wizDetSum}>View Anchor JSON</summary><pre style={S.wizPre}>{JSON.stringify(anchor, null, 2)}</pre></details>
      </div>)}
    </div>
  );
}

// ============================================================
// VERIFICATION WIZARD (embedded)
// ============================================================
function VerifyWizard() {
  const [bundleText, setBundleText] = useState("");
  const [anchorText, setAnchorText] = useState("");
  const [results, setResults] = useState(null);
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true); setResults(null);
    try {
      const b = JSON.parse(bundleText);
      const a = JSON.parse(anchorText);
      const res = [];
      const { proof, id, signalAnnotations, ...content } = b;
      const canon = canonJSON(content);
      const ch = await sha256(canon);
      res.push({ l: "Bundle hash matches Anchor", p: ch === a.bundleHash, d: ch === a.bundleHash ? ch.substring(0, 20) + "..." : `Expected ${a.bundleHash?.substring(0, 16)}...` });
      res.push({ l: "Bundle ID matches hash", p: b.id === `urn:hip:bundle:${ch}`, d: b.id });
      res.push({ l: "Content hash consistent", p: b.credentialSubject?.contentHash === a.contentHash, d: a.contentHash?.substring(0, 20) + "..." });
      res.push({ l: "Credential ID consistent", p: b.issuer?.id === a.credentialId && b.proof?.verificationMethod === b.issuer?.id, d: a.credentialId?.substring(0, 20) + "..." });
      res.push({ l: "Schema version WF-v1.0", p: b.version === "WF-v1.0" && a.version === "WF-v1.0", d: `Bundle: ${b.version}, Anchor: ${a.version}` });
      res.push({ l: "Valid classification", p: ["CompleteHumanOrigin", "HumanOriginAssisted", "HumanDirectedCollaborative"].includes(b.credentialSubject?.classification), d: b.credentialSubject?.classification });
      res.push({ l: "Anchor link format", p: a.anchorLink?.startsWith("hip://"), d: a.anchorLink });
      res.push({ l: "Ed25519 signature", p: null, d: "Requires public key lookup (not available in offline POC)" });
      setResults(res);
    } catch (e) { setResults([{ l: "Parse error", p: false, d: e.message }]); }
    setRunning(false);
  };

  return (
    <div style={S.wiz}>
      <p style={S.wizText}>Paste a Proof Bundle and Proof Anchor to verify cryptographic integrity.</p>
      <div style={S.wizFG}><label style={S.wizFL}>Proof Bundle JSON</label><textarea style={S.wizTxt} value={bundleText} onChange={e => setBundleText(e.target.value)} rows={5} placeholder="Paste Bundle JSON..." /></div>
      <div style={S.wizFG}><label style={S.wizFL}>Proof Anchor JSON</label><textarea style={S.wizTxt} value={anchorText} onChange={e => setAnchorText(e.target.value)} rows={3} placeholder="Paste Anchor JSON..." /></div>
      <button style={bundleText && anchorText ? S.btnG : S.btnDis} disabled={!bundleText || !anchorText || running} onClick={run}>{running ? "Verifying..." : "Verify"}</button>
      {results && <div style={S.vRes}>{results.map((r, i) => (
        <div key={i} style={{ ...S.vR, borderLeftColor: r.p === true ? "#4ade80" : r.p === false ? "#f87171" : "#facc15" }}>
          <span style={{ fontSize: 15, width: 22, textAlign: "center", flexShrink: 0 }}>{r.p === true ? "✓" : r.p === false ? "✗" : "?"}</span>
          <div><div style={{ fontSize: 13, fontWeight: 500, color: t1 }}>{r.l}</div><code style={{ fontSize: 10, color: t2, wordBreak: "break-all", fontFamily: mo }}>{r.d}</code></div>
        </div>
      ))}</div>}
    </div>
  );
}

// ============================================================
// TOKENS & STYLES
// ============================================================
const go = "#d4a054", gg = "rgba(212,160,84,0.05)", dk = "#06080f", dkc = "#0a0e18", bd = "rgba(212,160,84,0.1)", t1 = "#e8e0d4", t2 = "#8a8174";
const serif = "'Cormorant Garamond','Georgia',serif";
const sans = "'DM Sans','Helvetica Neue','Segoe UI',sans-serif";
const mo = "'DM Mono','SF Mono',monospace";

const S = {
  page: { background: dk, color: t1, fontFamily: sans, minHeight: "100vh", overflowX: "hidden" },
  w: { maxWidth: 1080, margin: "0 auto", padding: "0 32px" },
  sec: { padding: "100px 0" },
  dkSec: { padding: "100px 0", background: dkc, borderTop: `1px solid ${bd}`, borderBottom: `1px solid ${bd}` },
  ey: { fontFamily: mo, fontSize: 11, letterSpacing: 4, textTransform: "uppercase", color: go, marginBottom: 12 },
  sT: { fontFamily: serif, fontSize: "clamp(28px,4vw,44px)", fontWeight: 300, lineHeight: 1.2, color: t1, marginBottom: 20 },
  sD: { fontSize: 16, fontWeight: 400, lineHeight: 1.75, color: t2, maxWidth: 640, marginBottom: 36 },
  subH: { fontFamily: mo, fontSize: 13, letterSpacing: 1, color: t1, marginBottom: 14 },

  // Nav
  nav: { position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, borderBottom: "1px solid", transition: "all .3s", backdropFilter: "blur(12px)" },
  navIn: { maxWidth: 1080, margin: "0 auto", padding: "12px 32px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, flexWrap: "wrap" },
  navLogo: { fontFamily: mo, fontSize: 18, fontWeight: 500, letterSpacing: 6, color: go },
  navLinks: { display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" },
  navLink: { fontFamily: mo, fontSize: 11, letterSpacing: 1, color: t2, textDecoration: "none" },
  navTools: { display: "flex", gap: 8 },
  navToolBtn: { fontFamily: mo, fontSize: 11, padding: "7px 14px", background: go, color: dk, border: "none", borderRadius: 5, cursor: "pointer", fontWeight: 600, letterSpacing: 0.5 },
  navToolBtnAlt: { background: "transparent", color: go, border: `1px solid ${go}` },

  // Drawer
  drawer: { position: "fixed", top: 0, left: 0, right: 0, bottom: 0, zIndex: 200, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(8px)", display: "flex", justifyContent: "center", alignItems: "flex-start", padding: "60px 20px 20px", overflowY: "auto" },
  drawerInner: { width: "100%", maxWidth: 640, background: "#0c1020", border: `1px solid rgba(212,160,84,0.2)`, borderRadius: 12, padding: "24px 28px", maxHeight: "calc(100vh - 80px)", overflowY: "auto" },
  drawerHead: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 },
  drawerTitle: { fontFamily: mo, fontSize: 13, letterSpacing: 1, color: go },
  drawerClose: { background: "none", border: "none", color: t2, fontSize: 18, cursor: "pointer", fontFamily: mo, padding: 4 },

  // Hero
  hero: { position: "relative", minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden", padding: "120px 32px 80px" },
  heroGlow: { position: "absolute", top: "20%", left: "50%", transform: "translate(-50%,-50%)", width: 600, height: 600, borderRadius: "50%", background: "radial-gradient(circle,rgba(212,160,84,0.06) 0%,transparent 70%)", pointerEvents: "none" },
  heroC: { position: "relative", maxWidth: 720, textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: 24 },
  heroT: { fontFamily: serif, fontSize: "clamp(42px,8vw,80px)", fontWeight: 300, lineHeight: 1.05, color: t1 },
  heroS: { fontSize: 17, fontWeight: 400, lineHeight: 1.7, color: t2, maxWidth: 520 },
  heroBtn: { display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center" },
  heroFade: { position: "absolute", bottom: 0, left: 0, right: 0, height: 120, background: `linear-gradient(transparent,${dk})`, pointerEvents: "none" },

  // Buttons
  btnG: { display: "inline-block", fontFamily: mo, fontSize: 12, letterSpacing: 0.5, padding: "12px 24px", background: go, color: dk, borderRadius: 6, fontWeight: 600, textDecoration: "none", border: "none", cursor: "pointer" },
  btnO: { display: "inline-block", fontFamily: mo, fontSize: 12, letterSpacing: 0.5, padding: "11px 24px", background: "transparent", color: go, border: `1px solid ${go}`, borderRadius: 6, fontWeight: 500, textDecoration: "none" },
  btnSm: { fontFamily: mo, fontSize: 11, padding: "8px 16px", background: "none", border: `1px solid ${bd}`, color: t2, borderRadius: 5, cursor: "pointer" },
  btnDl: { fontFamily: mo, fontSize: 11, padding: "9px 16px", background: "rgba(212,160,84,0.08)", color: go, border: `1px solid rgba(212,160,84,0.2)`, borderRadius: 5, cursor: "pointer", fontWeight: 600 },
  btnDis: { fontFamily: mo, fontSize: 12, padding: "12px 24px", background: "#1e293b", color: "#475569", borderRadius: 6, border: "none", cursor: "not-allowed" },
  vInlineBtn: { fontFamily: mo, fontSize: 12, padding: "10px 20px", background: go, color: dk, border: "none", borderRadius: 5, cursor: "pointer", fontWeight: 600, letterSpacing: 0.5 },

  // Manifesto
  mani: { padding: "80px 32px", borderBottom: `1px solid ${bd}` },
  mQ: { fontFamily: serif, fontSize: "clamp(22px,3.5vw,36px)", fontWeight: 300, fontStyle: "italic", color: go, lineHeight: 1.4, maxWidth: 680, margin: "0 auto 32px", textAlign: "center" },
  mT: { fontSize: 16, fontWeight: 400, lineHeight: 1.8, color: t2, maxWidth: 640, margin: "0 auto 18px", textAlign: "center" },

  // Grids
  grid2x2: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 14, marginBottom: 28 },
  grid3: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 14, marginBottom: 20 },
  grid2: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 16 },
  grid2x2sm: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 5, marginBottom: 18 },

  // Steps
  stepC: { padding: "24px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: gg },
  stepN: { fontFamily: mo, fontSize: 24, fontWeight: 300, color: go, opacity: 0.45, marginBottom: 8 },
  stepT: { fontSize: 18, fontWeight: 600, color: t1, marginBottom: 8 },
  stepD: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },
  stepBullets: { listStyle: "none", marginTop: 10, display: "flex", flexDirection: "column", gap: 6 },
  stepBullet: { fontSize: 13, fontWeight: 400, lineHeight: 1.5, color: t1, paddingLeft: 14, position: "relative", borderLeft: `2px solid rgba(212,160,84,0.3)` },

  // Pledge
  pledge: { maxWidth: 700, margin: "0 auto", padding: "36px 32px", border: `2px solid rgba(212,160,84,0.2)`, borderRadius: 12, background: gg, textAlign: "center" },
  pledgeIco: { fontSize: 28, marginBottom: 12 },
  pledgeH: { fontFamily: serif, fontSize: 24, fontWeight: 400, color: t1, marginBottom: 16 },
  pledgeP: { fontSize: 15, fontWeight: 400, lineHeight: 1.8, color: t2, marginBottom: 12, textAlign: "left" },
  pledgeBadge: { fontFamily: mo, fontSize: 12, letterSpacing: 0.5, color: go, marginTop: 12, padding: "10px 18px", background: "rgba(212,160,84,0.06)", borderRadius: 6, border: `1px solid rgba(212,160,84,0.15)` },

  // Tiers
  tierC: { padding: "24px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: "rgba(212,160,84,0.02)" },
  tierB: { fontFamily: mo, fontSize: 11, fontWeight: 500, letterSpacing: 3, color: go, marginBottom: 8, textTransform: "uppercase" },
  tierN: { fontSize: 17, fontWeight: 600, color: t1, marginBottom: 8 },
  tierT: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2, marginBottom: 8 },
  tierDet: { fontFamily: mo, fontSize: 11, color: go, opacity: 0.7, lineHeight: 1.5, marginBottom: 4 },
  tierW: { fontFamily: mo, fontSize: 10, color: t2, opacity: 0.6, letterSpacing: 1, textTransform: "uppercase" },

  // Progression
  progBox: { marginTop: 20, padding: "26px 26px", border: `1px solid rgba(212,160,84,0.18)`, borderRadius: 8, background: gg },
  progH: { fontFamily: serif, fontSize: 20, fontWeight: 400, color: t1, marginBottom: 12 },
  progP: { fontSize: 15, fontWeight: 400, lineHeight: 1.75, color: t2, marginBottom: 18 },
  progItem: { padding: "16px 18px", background: "rgba(255,255,255,0.02)", borderRadius: 6, border: `1px solid ${bd}` },
  progLabel: { fontFamily: mo, fontSize: 12, fontWeight: 500, color: go, marginBottom: 5, letterSpacing: 0.5 },
  progDesc: { fontSize: 13, fontWeight: 400, lineHeight: 1.65, color: t2 },
  liveNote: { marginTop: 16, padding: "16px 20px", border: `1px solid ${bd}`, borderRadius: 8, background: gg, fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },

  // Contrast
  conC: { padding: "24px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: dkc },
  conH: { fontFamily: mo, fontSize: 12, letterSpacing: 2, textTransform: "uppercase", color: t2, marginBottom: 16 },
  conL: { display: "flex", flexDirection: "column", gap: 10 },
  conI: { fontSize: 14, fontWeight: 400, lineHeight: 1.5, color: t1, display: "flex", gap: 10, alignItems: "flex-start" },
  conX: { fontFamily: mo, fontSize: 14, color: "#c0756b", flexShrink: 0, width: 18 },
  conK: { fontFamily: mo, fontSize: 14, color: go, flexShrink: 0, width: 18 },

  // Trust
  trustC: { padding: "24px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: gg },
  trustT: { fontSize: 16, fontWeight: 600, color: t1, marginBottom: 8 },
  trustD: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },

  // Categories
  catC: { padding: "24px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: gg, textAlign: "center" },
  catB: { fontFamily: mo, fontSize: 14, fontWeight: 500, letterSpacing: 4, color: go, marginBottom: 6 },
  catN: { fontSize: 17, fontWeight: 600, color: t1, marginBottom: 6 },
  catD: { fontSize: 14, fontWeight: 400, lineHeight: 1.65, color: t2 },

  // Proof Bundle
  bGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 1, background: bd, borderRadius: 8, overflow: "hidden", marginBottom: 18 },
  bF: { padding: "16px 18px", background: dkc },
  bFN: { fontFamily: mo, fontSize: 11, fontWeight: 500, letterSpacing: 0.5, color: go, marginBottom: 3 },
  bFW: { fontSize: 14, fontWeight: 500, color: t1, marginBottom: 3 },
  bFY: { fontSize: 13, fontWeight: 400, lineHeight: 1.6, color: t2 },
  bNot: { padding: "22px 24px", border: `2px solid rgba(212,160,84,0.2)`, borderRadius: 8, background: gg, marginBottom: 18 },
  bNotH: { fontFamily: serif, fontSize: 18, fontWeight: 400, color: t1, marginBottom: 8 },
  bNotP: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },
  bAnch: { padding: "22px 24px", border: `1px solid ${bd}`, borderRadius: 8, background: "rgba(255,255,255,0.015)", marginBottom: 18 },
  bAnchH: { fontFamily: mo, fontSize: 13, letterSpacing: 0.5, color: t1, marginBottom: 8 },
  bAnchP: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2, marginBottom: 8 },
  bTech: { padding: "18px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: dkc },
  bTechH: { fontFamily: mo, fontSize: 11, letterSpacing: 2, textTransform: "uppercase", color: t2, marginBottom: 10 },
  bTechG: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 4 },
  bTR: { display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" },
  bTK: { fontFamily: mo, fontSize: 11, color: t2 },
  bTV: { fontFamily: mo, fontSize: 11, color: t1 },

  // Genesis
  gGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 1, background: bd, borderRadius: 8, overflow: "hidden", margin: "20px 0" },
  gF: { padding: "14px 18px", background: dkc },
  gL: { fontFamily: mo, fontSize: 10, letterSpacing: 2, textTransform: "uppercase", color: t2, marginBottom: 4 },
  gV: { fontFamily: mo, fontSize: 11, color: t1, wordBreak: "break-all", lineHeight: 1.5, display: "block" },
  stG: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: 10 },
  stC: { display: "block", padding: "14px 18px", border: `1px solid ${bd}`, borderRadius: 6, background: gg, textDecoration: "none" },
  stL: { fontFamily: mo, fontSize: 10, letterSpacing: 2, textTransform: "uppercase", color: t2, marginBottom: 4 },
  stCid: { fontFamily: mo, fontSize: 10, color: go, wordBreak: "break-all", lineHeight: 1.5, display: "block", marginBottom: 4 },
  stA: { fontFamily: mo, fontSize: 11, color: t1, opacity: 0.6 },

  // Verify
  vTool: { padding: "20px 22px", border: `1px solid rgba(212,160,84,0.2)`, borderRadius: 8, background: gg, marginBottom: 8 },
  vToolH: { fontFamily: mo, fontSize: 12, color: t2, marginBottom: 10 },
  vToolG: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 },
  vTBtn: { display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", border: `1px solid ${bd}`, borderRadius: 6, background: dkc, fontFamily: mo, fontSize: 11, color: t1, textDecoration: "none" },
  vSteps: { display: "flex", flexDirection: "column", gap: 2 },
  vS: { display: "flex", gap: 14, padding: "16px 20px", background: dkc, borderLeft: `2px solid ${go}`, alignItems: "flex-start" },
  vN: { fontFamily: mo, fontSize: 20, fontWeight: 300, color: go, opacity: 0.4, flexShrink: 0, width: 28, textAlign: "center" },
  vST: { fontSize: 16, fontWeight: 600, color: t1, marginBottom: 4 },
  vSD: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },
  vH: { display: "block", fontFamily: mo, fontSize: 10, color: go, opacity: 0.7, wordBreak: "break-all", lineHeight: 1.5, marginTop: 3 },
  vCmd: { display: "block", fontFamily: mo, fontSize: 11, color: t1, background: "rgba(255,255,255,0.03)", padding: "5px 9px", borderRadius: 4, marginTop: 3 },
  vNote: { marginTop: 18, padding: "14px 18px", border: `1px solid ${bd}`, borderRadius: 6, fontFamily: mo, fontSize: 12, color: t2, lineHeight: 1.6, background: gg },
  vRes: { display: "flex", flexDirection: "column", gap: 6, marginTop: 14 },
  vR: { display: "flex", gap: 10, alignItems: "flex-start", padding: "10px 14px", background: dkc, borderRadius: 6, borderLeft: "3px solid" },

  // Build
  bldC: { padding: "24px 22px", border: `1px solid ${bd}`, borderRadius: 8, background: gg },
  bldT: { fontSize: 16, fontWeight: 600, color: t1, marginBottom: 6 },
  bldD: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },
  specBox: { padding: "26px 24px", border: `1px solid rgba(212,160,84,0.2)`, borderRadius: 8, background: gg },
  specH: { fontFamily: mo, fontSize: 14, letterSpacing: 0.5, color: t1, marginBottom: 8 },
  specP: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2, marginBottom: 16 },
  specI: { fontFamily: mo, fontSize: 11, color: t2, padding: "7px 11px", background: "rgba(255,255,255,0.02)", borderRadius: 4 },
  specAccess: { padding: "16px 20px", border: `1px solid ${bd}`, borderRadius: 6, background: "rgba(255,255,255,0.01)", marginTop: 14 },
  specAH: { fontFamily: mo, fontSize: 12, letterSpacing: 0.5, color: go, marginBottom: 6 },
  specAP: { fontSize: 14, fontWeight: 400, lineHeight: 1.7, color: t2 },

  // Covenant
  covSec: { padding: "110px 32px", textAlign: "center", background: "radial-gradient(ellipse at center,rgba(212,160,84,0.04) 0%,transparent 70%)" },
  covLine: { fontFamily: serif, fontSize: "clamp(22px,4.5vw,44px)", fontWeight: 300, fontStyle: "italic", color: go, lineHeight: 1.3, marginBottom: 18 },
  covSub: { fontFamily: mo, fontSize: 11, letterSpacing: 1, color: t2, lineHeight: 1.6 },

  // Footer
  foot: { padding: "50px 0 36px", borderTop: `1px solid ${bd}` },
  footIn: { display: "flex", flexDirection: "column", alignItems: "center", gap: 10, textAlign: "center" },
  footLogo: { fontFamily: mo, fontSize: 20, fontWeight: 500, letterSpacing: 8, color: go },
  footTag: { fontFamily: mo, fontSize: 11, letterSpacing: 2, color: t2 },
  footLinks: { display: "flex", gap: 2, flexWrap: "wrap", justifyContent: "center", alignItems: "center" },
  footLink: { fontFamily: mo, fontSize: 11, color: go },
  footMeta: { fontFamily: mo, fontSize: 10, color: t2, opacity: 0.6 },
  footLegal: { fontSize: 12, fontWeight: 400, color: "rgba(138,129,116,0.4)", maxWidth: 500, lineHeight: 1.6 },

  // Wizard shared
  wiz: { display: "flex", flexDirection: "column", gap: 14 },
  wizSteps: { display: "flex", gap: 16, flexWrap: "wrap", fontFamily: mo, fontSize: 11 },
  wizStep: { letterSpacing: 0.5 },
  wizBody: { display: "flex", flexDirection: "column", gap: 12 },
  wizText: { fontSize: 14, fontWeight: 400, color: t2, lineHeight: 1.6 },
  wizErr: { fontSize: 12, color: "#fca5a5", padding: "8px 12px", background: "rgba(239,68,68,0.08)", borderRadius: 5, fontFamily: mo },
  wizResult: { padding: "14px 16px", background: "rgba(255,255,255,0.02)", borderRadius: 6, border: `1px solid ${bd}`, display: "flex", flexDirection: "column", gap: 8 },
  wizRL: { fontFamily: mo, fontSize: 10, letterSpacing: 1.5, textTransform: "uppercase", color: t2 },
  wizRV: { fontFamily: mo, fontSize: 11, color: t1, wordBreak: "break-all", lineHeight: 1.5 },
  wizDrop: { border: `2px dashed ${bd}`, borderRadius: 8, padding: "28px 20px", textAlign: "center", cursor: "pointer", fontSize: 14 },
  wizCls: { display: "block", width: "100%", textAlign: "left", padding: "12px 16px", border: `1px solid ${bd}`, borderRadius: 6, background: "transparent", color: t1, fontSize: 14, fontFamily: sans, cursor: "pointer", transition: "border-color .2s" },
  wizTxt: { width: "100%", background: "rgba(255,255,255,0.02)", border: `1px solid ${bd}`, borderRadius: 6, padding: "10px 14px", color: t1, fontSize: 13, fontFamily: sans, resize: "vertical", lineHeight: 1.6 },
  wizNav: { display: "flex", justifyContent: "space-between", alignItems: "center" },
  wizDet: { border: `1px solid ${bd}`, borderRadius: 6, overflow: "hidden" },
  wizDetSum: { padding: "10px 14px", fontSize: 12, color: t2, cursor: "pointer", background: dkc, fontFamily: mo },
  wizPre: { padding: 14, margin: 0, fontSize: 10, lineHeight: 1.5, color: t2, background: "#060a14", overflowX: "auto", maxHeight: 250, fontFamily: mo },
  wizFG: { display: "flex", flexDirection: "column", gap: 4 },
  wizFL: { fontFamily: mo, fontSize: 11, letterSpacing: 1, textTransform: "uppercase", color: t2 },
};
