# Insight Mail

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mail AI — Incident Response Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #070a10;
  --panel: #0d121b;
  --panel-light: #111927;
  --line: rgba(148,163,184,.14);
  --line-bright: rgba(148,163,184,.25);
  --text: #e8edf5;
  --muted: #7c8798;
  --muted-2: #526073;
  --red: #ff5265;
  --orange: #ffb454;
  --green: #32e6a9;
  --blue: #48c8f0;
  --purple: #9484ff;
  --shadow: 0 24px 70px rgba(0,0,0,.28);
}
* { box-sizing: border-box; -webkit-font-smoothing: antialiased; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  background:
    radial-gradient(circle at 91% 3%, rgba(255,82,101,.16), transparent 25rem),
    radial-gradient(circle at 0% 90%, rgba(72,200,240,.11), transparent 25rem),
    var(--bg);
  font-family: Inter, sans-serif;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  z-index: -1;
  opacity: .5;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(148,163,184,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148,163,184,.045) 1px, transparent 1px);
  background-size: 44px 44px;
  mask-image: linear-gradient(to bottom, black, transparent 90%);
}
button, textarea { font: inherit; }
button { cursor: pointer; }
a { color: inherit; text-decoration: none; }
.display { font-family: "Space Grotesk", sans-serif; }
.mono { font-family: "JetBrains Mono", monospace; }
.shell { width: min(1240px, calc(100% - 36px)); margin: auto; padding: 30px 0 36px; }
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: 14px; }
.logo {
  position: relative;
  display: grid;
  place-items: center;
  width: 48px;
  height: 48px;
  border: 1px solid var(--line-bright);
  border-radius: 16px;
  background: linear-gradient(135deg, #1a2637, #0c1018);
  box-shadow: 0 10px 30px rgba(72,200,240,.13);
}
.logo::after {
  content: "";
  position: absolute;
  width: 9px;
  height: 9px;
  top: -3px;
  right: -3px;
  border: 2px solid var(--bg);
  border-radius: 50%;
  background: var(--red);
}
.logo svg { width: 26px; }
.brand-name { font-size: 23px; letter-spacing: -.06em; }
.brand-name span { color: var(--blue); }
.eyebrow {
  margin: 6px 0 0;
  color: var(--muted);
  font: 10px "JetBrains Mono", monospace;
  letter-spacing: .24em;
  text-transform: uppercase;
}
.header-actions { display: flex; align-items: center; gap: 10px; }
.nav-pill, .status {
  padding: 11px 15px;
  border: 1px solid var(--line-bright);
  border-radius: 999px;
  color: var(--muted);
  font: 10px "JetBrains Mono", monospace;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.nav-pill:hover { color: var(--text); border-color: rgba(72,200,240,.45); }
.status {
  display: flex;
  align-items: center;
  gap: 8px;
  border-color: rgba(50,230,169,.28);
  background: rgba(50,230,169,.07);
  color: var(--green);
}
.status i { width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 14px var(--green); }
.hero {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 30px;
  padding: 38px 0 30px;
}
.hero h1 {
  max-width: 720px;
  margin: 0;
  font-size: clamp(2.1rem, 5vw, 4.1rem);
  line-height: .98;
  letter-spacing: -.065em;
}
.hero h1 em { color: var(--orange); font-style: normal; }
.hero p { max-width: 470px; margin: 0 0 4px; color: var(--muted); line-height: 1.7; font-size: 14px; }
.case-id { color: var(--blue); font-family: "JetBrains Mono", monospace; }
.sync { color: var(--muted-2); font: 10px "JetBrains Mono", monospace; letter-spacing: .15em; white-space: nowrap; }
.sync strong { color: var(--green); font-weight: 500; }
.grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 18px;
}
.card {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 24px;
  background: linear-gradient(150deg, rgba(255,255,255,.045), rgba(255,255,255,.012));
  box-shadow: var(--shadow);
  backdrop-filter: blur(15px);
}
.card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 15px; }
.card h2 { margin: 0; font: 600 19px "Space Grotesk", sans-serif; letter-spacing: -.035em; }
.card-label { margin: 5px 0 0; color: var(--muted); font: 10px "JetBrains Mono", monospace; letter-spacing: .16em; text-transform: uppercase; }
.input-card { grid-column: span 7; padding: 25px; }
.score-card { grid-column: span 5; padding: 25px; background: linear-gradient(160deg, #141d2c, #0d121b); }
.score-card::before { content: ""; position: absolute; top: 0; left: 12%; right: 12%; height: 1px; background: linear-gradient(90deg, transparent, var(--red), transparent); }
.icon-box {
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  border: 1px solid rgba(148,132,255,.3);
  border-radius: 12px;
  background: rgba(148,132,255,.12);
}
textarea {
  display: block;
  width: 100%;
  min-height: 220px;
  margin-top: 22px;
  padding: 17px;
  resize: vertical;
  border: 1px solid var(--line-bright);
  border-radius: 17px;
  outline: 0;
  color: #bdc8d8;
  background: rgba(3,6,11,.7);
  font: 13px/1.75 "JetBrains Mono", monospace;
}
textarea:focus { border-color: rgba(72,200,240,.6); box-shadow: 0 0 0 4px rgba(72,200,240,.08); }
.input-tools { display: flex; gap: 12px; margin-top: 14px; }
.upload {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 13px;
  min-height: 72px;
  padding: 13px 15px;
  border: 1px dashed rgba(72,200,240,.45);
  border-radius: 17px;
  color: var(--text);
  background: linear-gradient(145deg, rgba(72,200,240,.1), rgba(148,132,255,.04));
  text-align: left;
}
.upload:hover { border-color: var(--blue); transform: translateY(-1px); }
.upload-icon {
  display: grid;
  place-items: center;
  width: 42px;
  height: 42px;
  flex: 0 0 42px;
  border-radius: 13px;
  color: var(--bg);
  background: linear-gradient(135deg, var(--blue), var(--purple));
}
.upload strong { display: block; font: 13px "Space Grotesk"; }
.upload small { display: block; margin-top: 4px; color: var(--muted); font: 10px "JetBrains Mono"; }
input[type=file] { display: none; }
.primary, .download {
  border: 0;
  border-radius: 17px;
  padding: 0 22px;
  color: #071016;
  font: 600 13px "Space Grotesk";
  background: linear-gradient(135deg, var(--green), var(--blue));
  box-shadow: 0 15px 32px rgba(50,230,169,.2);
  transition: transform .2s, filter .2s;
}
.primary:hover, .download:hover { transform: translateY(-2px); filter: brightness(1.08); }
.file-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 15px; }
.file-chip, .tag {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 11px;
  border: 1px solid var(--line-bright);
  border-radius: 10px;
  color: var(--muted);
  font: 10px "JetBrains Mono";
}
.file-chip i { width: 6px; height: 6px; border-radius: 50%; background: var(--orange); }
.remove { margin-left: 3px; padding: 0; border: 0; color: var(--muted-2); background: none; }
.remove:hover { color: var(--red); }
.score-top { display: flex; align-items: flex-start; justify-content: space-between; }
.severity {
  padding: 7px 10px;
  border: 1px solid rgba(255,82,101,.4);
  border-radius: 999px;
  color: var(--red);
  background: rgba(255,82,101,.08);
  font: 10px "JetBrains Mono";
  text-transform: uppercase;
}
.gauge-wrap { position: relative; width: min(255px, 80%); margin: 16px auto 8px; }
.gauge-wrap svg { display: block; width: 100%; }
.gauge-track { fill: none; stroke: rgba(148,163,184,.12); stroke-width: 14; }
.gauge-value {
  fill: none;
  stroke: url(#gauge);
  stroke-width: 14;
  stroke-linecap: round;
  stroke-dasharray: 603.2;
  stroke-dashoffset: 603.2;
  transform: rotate(-90deg);
  transform-origin: 120px 120px;
  filter: drop-shadow(0 0 11px rgba(255,82,101,.55));
  transition: stroke-dashoffset 1.6s cubic-bezier(.2,.8,.2,1);
}
.gauge-number { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
.gauge-number strong { font: 600 55px/1 "Space Grotesk"; letter-spacing: -.08em; }
.gauge-number strong span { color: var(--muted); font-size: 22px; letter-spacing: 0; }
.gauge-number small { margin-top: 9px; color: var(--muted); font: 10px "JetBrains Mono"; letter-spacing: .18em; text-transform: uppercase; }
.metrics { display: grid; grid-template-columns: repeat(3,1fr); gap: 9px; }
.metric { padding: 13px; border: 1px solid var(--line); border-radius: 15px; background: rgba(255,255,255,.025); }
.metric:hover { border-color: var(--line-bright); transform: translateY(-2px); }
.metric span { display: block; color: var(--muted); font: 9px "JetBrains Mono"; letter-spacing: .13em; text-transform: uppercase; }
.metric strong { display: block; margin-top: 7px; font: 22px "Space Grotesk"; }
.map-card { grid-column: span 7; padding-bottom: 20px; }
.map-head { padding: 23px 25px 17px; }
.map-status { color: var(--blue); font: 10px "JetBrains Mono"; }
.map-box { position: relative; margin: 0 20px; overflow: hidden; border: 1px solid var(--line); border-radius: 18px; background: radial-gradient(circle at 50% 10%, #152033, #080b11 70%); }
#map { display: block; width: 100%; min-height: 360px; }
.map-readout {
  position: absolute;
  right: 12px;
  bottom: 12px;
  left: 12px;
  padding: 14px;
  border: 1px solid var(--line-bright);
  border-radius: 15px;
  background: rgba(8,11,17,.82);
  backdrop-filter: blur(12px);
}
.readout-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 15px; }
.readout-tag { color: var(--red); font: 9px "JetBrains Mono"; letter-spacing: .15em; text-transform: uppercase; }
.readout-title { margin: 5px 0 4px; font: 15px "Space Grotesk"; }
.readout-copy { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.55; }
.risk { padding: 6px 8px; border: 1px solid rgba(255,82,101,.4); border-radius: 8px; color: var(--red); font: 9px "JetBrains Mono"; white-space: nowrap; }
.ai-column { grid-column: span 5; display: grid; gap: 18px; align-content: start; }
.ai-card, .export-card { padding: 25px; }
.ai-card::after { content: ""; position: absolute; top: -100px; right: -80px; width: 260px; height: 260px; border-radius: 50%; background: radial-gradient(circle, rgba(148,132,255,.2), transparent 68%); pointer-events: none; }
.ai-title { display: flex; align-items: center; gap: 12px; padding-bottom: 17px; border-bottom: 1px solid var(--line); }
.ai-badge { display: grid; place-items: center; width: 38px; height: 38px; border-radius: 12px; color: var(--bg); background: linear-gradient(135deg, var(--purple), var(--blue)); }
.ai-copy { margin: 19px 0; color: #cbd5e1; font-size: 14px; line-height: 1.8; }
.signal {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  width: 100%;
  margin-top: 9px;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 13px;
  color: #b9c3d1;
  background: rgba(255,255,255,.025);
  text-align: left;
  font-size: 11px;
}
.signal:hover { border-color: var(--line-bright); background: rgba(255,255,255,.05); }
.signal b { padding: 5px 7px; border-radius: 6px; color: var(--red); background: rgba(255,82,101,.1); font: 9px "JetBrains Mono"; white-space: nowrap; }
.export-card { background: linear-gradient(140deg, rgba(255,180,84,.07), rgba(255,82,101,.03)); }
.export-card p { margin: 7px 0 20px; color: var(--muted); font: 10px/1.7 "JetBrains Mono"; }
.download { width: 100%; min-height: 52px; background: linear-gradient(135deg, #ffd86d, #ff7359, var(--red)); box-shadow: 0 15px 32px rgba(255,82,101,.2); }
.export-meta { display: flex; flex-wrap: wrap; gap: 12px 18px; margin-top: 16px; color: var(--muted-2); font: 9px "JetBrains Mono"; }
.export-meta strong { color: var(--green); font-weight: 400; }
footer { display: flex; justify-content: space-between; gap: 20px; margin-top: 25px; padding-top: 19px; border-top: 1px solid var(--line); color: var(--muted-2); font: 9px "JetBrains Mono"; letter-spacing: .12em; text-transform: uppercase; }
.route { stroke-dasharray: 7 8; animation: dash 1.4s linear infinite; }
@keyframes dash { to { stroke-dashoffset: -30; } }
.pulse { transform-box: fill-box; transform-origin: center; animation: pulse 2.3s ease-out infinite; }
@keyframes pulse { 0% { transform: scale(.4); opacity: .9 } 80%,100% { transform: scale(2.2); opacity: 0 } }
.node { cursor: pointer; outline: none; }
.node .core { transform-box: fill-box; transform-origin: center; transition: transform .25s; }
.node:hover .core, .node.active .core { transform: scale(1.3); }
@media (max-width: 900px) {
  .input-card, .score-card, .map-card, .ai-column { grid-column: span 12; }
  .hero { align-items: flex-start; flex-direction: column; }
}
@media (max-width: 620px) {
  .shell { width: min(100% - 24px, 1240px); padding-top: 18px; }
  .header-actions .nav-pill { display: none; }
  .header { align-items: flex-start; }
  .hero { padding-top: 29px; }
  .input-card, .score-card, .ai-card, .export-card { padding: 18px; }
  .input-tools { flex-direction: column; }
  .primary { min-height: 53px; }
  .map-head { padding: 18px 18px 14px; }
  .map-box { margin: 0 12px; }
  #map { min-height: 420px; }
  .metrics { gap: 6px; }
  .metric { padding: 10px; }
  .metric strong { font-size: 18px; }
  footer { flex-direction: column; line-height: 1.6; }
}






    


      


        
          
          
        
      


      


        

Mail AI


        

Email incident response · engine v4.2


      


    


    


      Cases · 128
      Watchlist
      

 Sensor live


    



  


    


      

Quarantine the incoming mail.
Trace it to the origin.


      

Paste headers or raw MIME, upload the source artifact, and Mail AI renders threat score, hop chain, and intent in seconds. Case #MA-90341 is active.


    


    

Last sync · 00:00:00 UTC



  
    


      


        


          


            
              
              
            
          


          


            

Intake · Raw email artifact


            

MIME · Headers · Signature verified


          


        


        Queue 01 / 02
      



      


        From: svc.billing@auth0-secure.io</b></span>
        <span class="file-chip" style="color:var(--red);border-color:rgba(255,82,101,.4)">SPF · fail</span>
        <span class="file-chip" style="color:var(--orange);border-color:rgba(255,180,84,.4)">DKIM · mismatch</span>
        <span class="file-chip">DKIM · visible</span>
      </div>

      <textarea id="mime" aria-label="Raw email content" spellcheck="false">From: svc.billing@auth0-secure.io
To: finance@northwind.corp
Subject: Wire transfer — Q3 audit reconciliation (URGENT)
Content-Type: multipart/mixed; boundary="x92"
MIME-Version: 1.0
X-MailAI-Engine: engaged

Body: Please review attached invoice_9042_final.exe —
payment redirection terms have changed. Sign & return within 24h.

      


        
          
            
              
            
          
          Drop attachment or browseinvoice_9042_final.exe · 812 KB · sandboxed
        
        
        Run analysis  →
      


      


         invoice_9042_final.exe ×
         payload.iso · EMU detected
      


    

    


      


        


          

Threat score


          

ML ensemble · 11 models · p=0.992


        


        Critical
      


      


        
          
            
              
              
              
            
          
          
          
        
        

0%Malicious intent


      


      


        Spoof0.97
        Payload0.93
        Social0.88
      


    



    


      


        


          

Origin trace · hop chain


          

Select a node to inspect the relay


        


        3 relays · 68 ms RTT
      


      


        
          
            
          
          
            
            
            
            
            
            
          
          
            GRID 51.5N · 0.12W
            NODE VIEW / THERMAL OVERLAY
            THREATFEED · LIVE
          
          
          
          
            
          
          
            
            
            185.220.101.4
          
          
            
            
            45.148.10.92
          
          
            
            
            203.0.113.7 · YOU
          
        
        


          


            


              

Stage 01 · Origin compromise


              

185.220.101.4 — bulletproof host


              

ASN 48351 · No reverse DNS · TOR exit rotation · first seen 04:12 with spoofed auth0-secure.io envelope.


            


            RISK 0.99
          


        


      


    



    


      


        


          


            
              
              
            
          


          


            

Trace AI · Narrative summary


            

Reasoning visible · cited evidence


          


          Live
        


        

Likely BEC → payload hybrid. Envelope spoofs a trusted IdP billing service; the .exe attachment carries an EMU macro that opens a reverse-shell over HTTPS. The route avoids VPN egress, which rules out a compromised internal relay. Recommend quarantine + block 185.220.101.0/24 at edge.


        SPF / DKIM / DMARC alignmentFAIL · FAIL · REJECT
        Attachment detonation · sandboxEMU · RANSOM-NOTE
        Infrastructure reputation · WHOIS / VTTOR · 14d
      



      


        

Forensic export


        

PCAP · Header dump · YARA + MITRE ATT&CK mapping · signed SHA-256


        Download Forensic PDF
        


          MA-90341-forensic.pdf2.4 MBGenerated just nowTamper-evident · hash C4:9A…F1:02
        


      


    


  

  


    Mail AI Security Lab · SOC-2 Type II · Data residency EU-Central
    Heuristic ensemble: RF · GNN · LLM-cite · 11/11 nominal@northwind.corp",
    body: "Corporate NAT edge · DKIM verified on transport only · mailbox rule auto-forward added at 09:38.",
    risk: "CONTAIN",
    color: "#48c8f0"
  }
];

const nodes = document.querySelectorAll(".node");
function selectNode(index) {
  const data = nodeData[index];
  document.getElementById("readoutTag").textContent = data.tag;
  document.getElementById("readoutTag").style.color = data.color;
  document.getElementById("readoutTitle").textContent = data.title;
  document.getElementById("readoutCopy").textContent = data.body;
  document.getElementById("risk").textContent = data.risk;
  document.getElementById("risk").style.color = data.color;
  document.getElementById("risk").style.borderColor = data.color + "88";
  nodes.forEach((node, i) => node.classList.toggle("active", i === index));
}
nodes.forEach((node, index) => {
  node.addEventListener("click", () => selectNode(index));
  node.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectNode(index);
    }
  });
});

document.getElementById("downloadButton").addEventListener("click", function () {
  const original = this.textContent;
  this.textContent = "Compiling evidence pack…";
  this.disabled = true;
  setTimeout(() => {
    const report = [
      "MAIL AI FORENSIC INCIDENT REPORT — MA-90341",
      "================================================",
      "",
      "Threat Score: 87% (CRITICAL)",
      "SPF: FAIL | DKIM: MISMATCH | DMARC: REJECT",
      "Attachment: invoice_9042_final.exe (EMU sandbox detonation)",
      "",
      "IP TRACE",
      "01 185.220.101.4 — bulletproof host — RISK 0.99",
      "02 45.148.10.92 — Frankfurt relay — RISK 0.81",
      "03 203.0.113.7 — corporate NAT edge — CONTAIN",
      "",
      "AI RECOMMENDATION",
      "Quarantine message and block 185.220.101.0/24 at the edge.",
      "",
      "SHA-256: C4:9A:11:7B:F0:02",
      "Generated by Mail AI Incident Response Engine v4.2"
    ].join("\n");
    const blob = new Blob([report], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "MA-90341-forensic.pdf";
    link.click();
    URL.revokeObjectURL(url);
    this.textContent = "Report downloaded";
    setTimeout(() => {
      this.textContent = original;
      this.disabled = false;
    }, 1800);
  }, 850);
});
</script>
</body>
</html>


Use this exact HTML/React layout code from my design. Do not change the visual design or colors. Just make the Threat Score dial, authentication badges, map container, and AI summary dynamic based on user input, and add two quick-fill demo buttons ('Load Safe Sample' and 'Load Phishing Sample').

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/23d6ece6-54ea-4dc7-9c3f-69f25d902fdd).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
