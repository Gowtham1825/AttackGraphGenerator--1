"""Vercel entry point for the Attack Graph Generator dashboard."""

from http.server import BaseHTTPRequestHandler
import json
import os

from api.scan import run_scan
from utils.web_history import load_scan_history, save_scan_history


class handler(BaseHTTPRequestHandler):
    """Serve the standalone dashboard without requiring a frontend build step."""

    def do_GET(self):
        if self.path == "/api/history":
            self._send_json(200, {"history": load_scan_history()})
            return
        if self.path != "/":
            self._send_json(404, {"error": "Route not found."})
            return

        page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#07111f">
  <title>Attack Graph Generator</title>
  <style>
    :root { --ink:#e9f2ff; --muted:#92a6c0; --surface:#101e31; --line:rgba(163,190,222,.15); --cyan:#41d7ff; --green:#55e6a5; --amber:#ffc857; --red:#ff6b7a; }
    * { box-sizing:border-box; } body { margin:0; min-width:320px; color:var(--ink); background:#07111f; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    body:before { content:""; position:fixed; inset:0; z-index:-1; background:radial-gradient(circle at 15% 0%,#12385a 0,transparent 34%),radial-gradient(circle at 90% 25%,#182d55 0,transparent 28%),#07111f; }
    .shell { width:min(1180px,calc(100% - 40px)); margin:auto; } header { display:flex; align-items:center; justify-content:space-between; gap:20px; padding:26px 0; border-bottom:1px solid var(--line); }
    .brand { display:flex; align-items:center; gap:12px; font-weight:750; letter-spacing:-.02em; }.shield { display:grid; place-items:center; width:38px; height:38px; border:1px solid rgba(65,215,255,.55); border-radius:12px; background:rgba(65,215,255,.09); color:var(--cyan); font-size:20px; }
    .status { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:.86rem; }.dot {width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green);}
    main { padding:56px 0 48px; }.eyebrow { margin:0 0 13px; color:var(--cyan); font-size:.78rem; font-weight:700; letter-spacing:.13em; text-transform:uppercase; } h1 { max-width:760px; margin:0; font-size:clamp(2.25rem,6vw,4.4rem); line-height:1.02; letter-spacing:-.055em; }
    .lead { max-width:650px; margin:20px 0 32px; color:var(--muted); font-size:1.08rem; line-height:1.65; }.panel { background:linear-gradient(145deg,rgba(22,42,66,.9),rgba(13,27,45,.88)); border:1px solid var(--line); box-shadow:0 24px 65px rgba(0,0,0,.2); border-radius:18px; }
    .scan-panel { padding:22px; }.scan-label { display:block; margin-bottom:10px; font-size:.9rem; font-weight:650; }.form-row { display:flex; gap:12px; }.input-wrap { position:relative; flex:1; }.input-wrap span {position:absolute;left:15px;top:14px;color:var(--cyan)}
    input { width:100%; border:1px solid rgba(173,204,238,.22); border-radius:11px; padding:14px 15px 14px 42px; color:var(--ink); background:#091829; font:inherit; outline:none; } input:focus { border-color:var(--cyan); box-shadow:0 0 0 3px rgba(65,215,255,.12); }
    button { border:0; border-radius:11px; padding:0 20px; min-height:48px; color:#00131c; background:var(--cyan); font:700 .94rem inherit; cursor:pointer; transition:transform .2s,box-shadow .2s; } button:hover {transform:translateY(-1px);box-shadow:0 9px 22px rgba(65,215,255,.25)} button:disabled {cursor:wait;opacity:.7;transform:none;}
    .hint { margin:13px 0 0; color:var(--muted); font-size:.8rem; }.hint b { color:#b9cbe0; }#message { min-height:24px; margin:16px 2px 0; color:var(--muted); font-size:.9rem; }.error {color:#ff9da6!important}.success {color:var(--green)!important}
    #results { display:none; margin-top:34px; }.summary { display:grid; grid-template-columns:repeat(4,1fr); gap:13px; margin-bottom:17px; }.metric { padding:18px; }.metric small {color:var(--muted);font-size:.78rem}.metric strong {display:block;margin-top:7px;font-size:1.8rem;letter-spacing:-.04em}.critical strong{color:var(--red)}.warning strong{color:var(--amber)}.good strong{color:var(--green)}
    .grid { display:grid; grid-template-columns:1.3fr .9fr; gap:17px; }.section {padding:22px}.section h2 {margin:0 0 6px;font-size:1.08rem}.section p {margin:0;color:var(--muted);font-size:.86rem}.graph {position:relative;height:278px;margin-top:14px;overflow:hidden;border-radius:12px;background:#091829;border:1px solid var(--line)}.graph:before{content:"";position:absolute;inset:0;background-image:linear-gradient(rgba(121,162,199,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(121,162,199,.07) 1px,transparent 1px);background-size:28px 28px}.node{position:absolute;z-index:1;display:grid;place-items:center;width:94px;min-height:48px;padding:7px;border:1px solid var(--line);border-radius:10px;background:#10233a;color:#dbeaff;font-size:.73rem;font-weight:650;text-align:center}.node.host{left:8%;top:42%;border-color:rgba(65,215,255,.7);color:var(--cyan)}.node.port{left:39%;top:20%}.node.service{left:39%;bottom:17%}.node.risk{right:8%;top:42%;border-color:rgba(255,107,122,.7);color:#ff9da6}.edge{position:absolute;z-index:0;height:1px;background:linear-gradient(90deg,var(--cyan),rgba(255,107,122,.8));transform-origin:left}.e1{left:26%;top:49%;width:17%;transform:rotate(-24deg)}.e2{left:26%;top:50%;width:17%;transform:rotate(24deg)}.e3{left:53%;top:49%;width:30%;}
    .finding {display:flex;gap:12px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--line)}.finding:last-child{border:0}.tag{padding:4px 7px;border-radius:5px;background:rgba(255,107,122,.12);color:#ff9da6;font-size:.68rem;font-weight:750;letter-spacing:.05em}.tag.medium{background:rgba(255,200,87,.12);color:var(--amber)}.finding h3{margin:1px 0 5px;font-size:.9rem}.finding p{line-height:1.45}.footer {display:flex;justify-content:space-between;gap:20px;padding:22px 0 34px;color:#7086a2;font-size:.8rem;border-top:1px solid var(--line)}
    .history-toggle{min-height:38px;padding:0 14px;background:transparent;border:1px solid rgba(65,215,255,.45);color:var(--cyan)}.history-toggle:hover{box-shadow:none}.history{display:none;margin-top:34px}.history-header{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:14px}.history-header h2{margin:0;font-size:1.15rem}.history-list{display:grid;gap:10px}.history-item{width:100%;min-height:0;padding:16px;text-align:left;color:var(--ink);background:#091829;border:1px solid var(--line);border-radius:12px}.history-item:hover{border-color:rgba(65,215,255,.55)}.history-item strong,.history-item span{display:block}.history-item span{margin-top:5px;color:var(--muted);font-size:.82rem}.history-empty{color:var(--muted);padding:8px 0}.history-details{display:none;margin-top:17px}.service-list{margin:10px 0 0;padding-left:18px;color:var(--muted);font-size:.86rem}.service-list li{margin:6px 0}
    @media(max-width:700px){.shell{width:min(100% - 28px,1180px)}header{padding:17px 0}.status{display:none}main{padding:38px 0}.form-row{flex-direction:column}button{width:100%}.summary{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.footer{flex-direction:column}.graph{height:240px}.node{width:78px;font-size:.65rem}.node.host{left:4%}.node.port,.node.service{left:35%}.node.risk{right:4%}}
  </style>
</head>
<body><div class="shell"><header><div class="brand"><div class="shield">⌬</div>Attack Graph Generator</div><div class="status"><span class="dot"></span>Workspace ready</div><button id="historyButton" class="history-toggle" type="button">Scan history</button></header><main>
  <p class="eyebrow">Attack surface mapping</p><h1>Turn network exposure into clear security priorities.</h1><p class="lead">Build an easy-to-read view of hosts, exposed services and potential attack paths for your authorised environment.</p>
  <section class="panel scan-panel" aria-labelledby="scan-label"><label class="scan-label" id="scan-label" for="network">Target network</label><div class="form-row"><div class="input-wrap"><span>⌕</span><input id="network" type="text" autocomplete="off" placeholder="Example: 192.168.1.0/24" aria-describedby="scan-help"></div><button id="scanButton" type="button">Generate overview</button></div><p class="hint" id="scan-help"><b>Authorised use only.</b> Enter an IPv4 address or CIDR range that you own or are permitted to assess.</p><div id="message" role="status" aria-live="polite"></div></section>
  <section id="results" aria-live="polite"><div class="summary"><div class="panel metric"><small>Hosts in scope</small><strong id="hostCount">00</strong></div><div class="panel metric good"><small>Services mapped</small><strong id="serviceCount">00</strong></div><div class="panel metric warning"><small>Needs review</small><strong id="findingCount">00</strong></div><div class="panel metric critical"><small>High-priority paths</small><strong id="pathCount">00</strong></div></div><div class="grid"><section class="panel section"><h2>Attack-path preview</h2><p id="graphCaption">Live relationship map appears after a completed scan.</p><div class="graph"><i class="edge e1"></i><i class="edge e2"></i><i class="edge e3"></i><div class="node host" id="hostNode">Target host</div><div class="node port" id="portNode">Open port</div><div class="node service" id="serviceNode">Service</div><div class="node risk" id="riskNode">No findings</div></div></section><section class="panel section"><h2>Review queue</h2><p id="queueCaption">Prioritised from the completed scan.</p><div id="findingList"></div></section></div></section>
  <section id="history" class="history" aria-live="polite"><div class="history-header"><div><p class="eyebrow">Saved results</p><h2>Scan history</h2></div><button id="refreshHistory" class="history-toggle" type="button">Refresh</button></div><div id="historyList" class="history-list"></div><section id="historyDetails" class="panel section history-details"></section></section>
  </main><footer class="footer"><span>Attack Graph Generator · Security assessment workspace</span><span>Local mode scans private or loopback targets on selected common TCP ports.</span></footer></div>
  <script>
    const input=document.getElementById('network'),button=document.getElementById('scanButton'),message=document.getElementById('message'),results=document.getElementById('results'),historyButton=document.getElementById('historyButton'),historySection=document.getElementById('history'),historyList=document.getElementById('historyList'),historyDetails=document.getElementById('historyDetails'),refreshHistory=document.getElementById('refreshHistory');
    const targetPattern=/^(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\/(?:[0-9]|[12]\\d|3[0-2]))?$/;
    function showMessage(text,type){message.textContent=text;message.className=type||'';}
    function escapeHtml(value){const node=document.createElement('span');node.textContent=value;return node.innerHTML;}
    function renderResults(data){const service=data.services[0];document.getElementById('hostCount').textContent=String(data.hosts_in_scope).padStart(2,'0');document.getElementById('serviceCount').textContent=String(data.services.length).padStart(2,'0');document.getElementById('findingCount').textContent=String(data.findings.length).padStart(2,'0');document.getElementById('pathCount').textContent=String(data.priority_paths).padStart(2,'0');document.getElementById('hostNode').textContent=data.target;document.getElementById('portNode').innerHTML=service?'Port '+service.port:'No open<br>common ports';document.getElementById('serviceNode').textContent=service?service.service:'No service';document.getElementById('riskNode').textContent=data.findings.length?'Review '+data.findings.length+' finding(s)':'No findings';document.getElementById('graphCaption').textContent='Live scan result for '+data.target+'. '+data.hosts_with_services+' host(s) responded on the checked ports.';const list=document.getElementById('findingList');document.getElementById('queueCaption').textContent=data.findings.length?'Prioritised from the completed scan.':'No exposure findings from the checked ports.';list.innerHTML=data.findings.length?data.findings.map(f=>'<div class="finding"><span class="tag '+(f.severity==='MEDIUM'?'medium':'')+'">'+escapeHtml(f.severity)+'</span><div><h3>'+escapeHtml(f.title)+' · '+escapeHtml(f.host)+':'+escapeHtml(f.port)+'</h3><p>'+escapeHtml(f.reason)+'</p></div></div>').join(''):'<div class="finding"><div><h3>No findings to review</h3><p>None of the checked services produced an exposure finding.</p></div></div>';results.style.display='block';results.scrollIntoView({behavior:'smooth',block:'start'});}
    function serviceSummary(services){return services.length?services.map(service=>'<li>'+escapeHtml(service.host||'Target')+' · '+escapeHtml(String(service.port))+' / '+escapeHtml(service.service||'Unknown')+'</li>').join(''):'<li>No supported TCP services responded.</li>';}
    function showHistoryEntry(item){historyDetails.innerHTML='<h2>Saved result — '+escapeHtml(item.target)+'</h2><p>'+escapeHtml(item.scanned_at)+' · '+escapeHtml(String(item.hosts_with_services||0))+' host(s) with services · '+escapeHtml(String(item.findings.length))+' finding(s)</p><h3>Detected services</h3><ul class="service-list">'+serviceSummary(item.services)+'</ul>';historyDetails.style.display='block';historyDetails.scrollIntoView({behavior:'smooth',block:'nearest'});}
    function renderHistory(items){historyList.innerHTML='';historyDetails.style.display='none';if(!items.length){historyList.innerHTML='<p class="history-empty">No scans have been saved yet.</p>';return;}items.forEach(item=>{const entry=document.createElement('button');entry.className='history-item';entry.type='button';entry.innerHTML='<strong>'+escapeHtml(item.target)+'</strong><span>'+escapeHtml(item.scanned_at)+' · '+escapeHtml(String(item.services.length))+' service(s) · '+escapeHtml(String(item.findings.length))+' finding(s)</span>';entry.addEventListener('click',()=>showHistoryEntry(item));historyList.appendChild(entry);});}
    async function loadHistory(){refreshHistory.disabled=true;try{const response=await fetch('/api/history');const data=await response.json();if(!response.ok)throw new Error(data.error||'History could not be loaded.');renderHistory(data.history||[]);}catch(error){historyList.innerHTML='<p class="history-empty">'+escapeHtml(error.message)+'</p>';}finally{refreshHistory.disabled=false;}}
    async function generateOverview(){const target=input.value.trim();if(!targetPattern.test(target)){showMessage('Enter a valid IPv4 address or CIDR range, for example 192.168.1.0/24.','error');input.focus();return;}button.disabled=true;button.textContent='Scanning…';showMessage('Scanning authorised private target on common TCP ports…');try{const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});const data=await response.json();if(!response.ok)throw new Error(data.error||'Scan failed.');renderResults(data);showMessage('Live scan complete. '+data.services.length+' open service(s) mapped.','success');}catch(error){showMessage(error.message,'error');}finally{button.disabled=false;button.textContent='Generate overview';}}
    button.addEventListener('click',generateOverview);input.addEventListener('keydown',event=>{if(event.key==='Enter')generateOverview();});historyButton.addEventListener('click',()=>{const opening=historySection.style.display!=='block';historySection.style.display=opening?'block':'none';historyButton.textContent=opening?'Hide history':'Scan history';if(opening){loadHistory();historySection.scrollIntoView({behavior:'smooth',block:'start'});}});refreshHistory.addEventListener('click',loadHistory);
  </script></body></html>"""
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Run a limited local scan for the dashboard; Vercel remains UI-only."""
        if self.path != "/api/scan":
            self._send_json(404, {"error": "Route not found."})
            return
        if os.environ.get("VERCEL"):
            self._send_json(501, {"error": "Live scans are available only in the local desktop preview."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            target = str(payload.get("target", "")).strip()
            scan_result = run_scan(target)
            save_scan_history(scan_result)
            self._send_json(200, scan_result)
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json(400, {"error": str(error)})
        except Exception:
            self._send_json(500, {"error": "The scan could not be completed. Try a smaller authorised range."})

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
