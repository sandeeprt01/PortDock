import asyncio
import html
import json
import os
import re
import socket
import ssl
import subprocess
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse
from aiohttp import ClientSession, ClientTimeout, WSMsgType, web
from multidict import CIMultiDict
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROUTES_FILE = os.path.join(BASE_DIR, "routes.json")
MKCERT_FILE = os.path.join(BASE_DIR, "mkcert.exe")
CERT_DIR = os.path.join(BASE_DIR, "certificates")
os.makedirs(CERT_DIR, exist_ok=True)
DASHBOARD_HOST = "portdock.localhost"
HTTP_PORT = 80
HTTPS_PORT = 443
REQUEST_LOGS = deque(maxlen=50)
SSL_CONTEXTS = {}
ACTIVE_WEBSOCKETS = 0
def normalize_target(target):
    if isinstance(target, int):
        return f"http://127.0.0.1:{target}"
    target = str(target).strip()
    if target.isdigit():
        return f"http://127.0.0.1:{target}"
    return target
def load_routes():
    if not os.path.exists(ROUTES_FILE):
        return {}
    try:
        with open(ROUTES_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        return {
            domain: normalize_target(target)
            for domain, target in data.items()
        }
    except Exception:
        return {}
def save_routes(routes):
    with open(ROUTES_FILE, "w", encoding="utf-8") as file:
        json.dump(routes, file, indent=4)
def validate_target_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return None
        if not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.hostname.lower() == DASHBOARD_HOST:
            return None
        if (
            parsed.hostname in ["localhost", "127.0.0.1"]
            and parsed.port in [80, 443]
        ):
            return None
        return url.rstrip("/")
    except ValueError:
        return None
def clean_service_name(name):
    name = name.strip().lower()
    if not re.fullmatch(r"[a-z0-9-]+", name):
        return None
    return name
def is_local_target(target):
    try:
        host = urlparse(target).hostname
        return host in ["localhost", "127.0.0.1"]
    except Exception:
        return False
def local_target_running(target):
    try:
        parsed = urlparse(target)
        host = parsed.hostname
        if host == "localhost":
            host = "127.0.0.1"
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False
def port_is_used(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.3)
    result = sock.connect_ex(("127.0.0.1", port))
    sock.close()
    return result == 0
def build_backend_url(target, request):
    target = target.rstrip("/") + "/"
    path = request.rel_url.path.lstrip("/")
    backend = urljoin(target, path)
    if request.rel_url.query_string:
        backend += "?" + request.rel_url.query_string
    return backend
def target_origin(target):
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        default_port = (
            parsed.scheme == "http"
            and parsed.port == 80
        ) or (
            parsed.scheme == "https"
            and parsed.port == 443
        )
        if not default_port:
            origin += f":{parsed.port}"
    return origin
def get_hostname(request):
    return request.host.split(":")[0].lower()
def certificate_paths(domain):
    safe_name = re.sub(
        r"[^a-zA-Z0-9_-]",
        "_",
        domain
    )
    cert_file = os.path.join(
        CERT_DIR,
        safe_name + ".crt"
    )
    key_file = os.path.join(
        CERT_DIR,
        safe_name + ".key"
    )
    return cert_file, key_file
def generate_certificate(domain):
    cert_file, key_file = certificate_paths(domain)
    if (
        os.path.exists(cert_file)
        and os.path.exists(key_file)
    ):
        return cert_file, key_file
    print(f"[TLS] Creating certificate for {domain}")
    subprocess.run(
        [
            MKCERT_FILE,
            "-cert-file",
            cert_file,
            "-key-file",
            key_file,
            domain
        ],
        cwd=BASE_DIR,
        check=True
    )
    return cert_file, key_file
def create_domain_ssl_context(domain):
    cert_file, key_file = generate_certificate(domain)
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )
    context.load_cert_chain(
        cert_file,
        key_file
    )
    SSL_CONTEXTS[domain] = context
    return context
def create_main_ssl_context():
    routes = load_routes()
    create_domain_ssl_context(DASHBOARD_HOST)
    for domain in routes:
        try:
            create_domain_ssl_context(domain)
        except Exception as error:
            print(
                f"[TLS ERROR] {domain}: {error}"
            )
    main_context = SSL_CONTEXTS[
        DASHBOARD_HOST
    ]
    def sni_callback(
        ssl_socket,
        server_name,
        initial_context
    ):
        if not server_name:
            return
        domain = server_name.lower()
        if domain in SSL_CONTEXTS:
            ssl_socket.context = SSL_CONTEXTS[
                domain
            ]
    main_context.set_servername_callback(
        sni_callback
    )
    return main_context
def log_request(
    method,
    host,
    target,
    request_type,
    status="FORWARDED"
):
    REQUEST_LOGS.appendleft(
        {
            "time": datetime.now().strftime(
                "%H:%M:%S"
            ),
            "method": method,
            "host": host,
            "target": target,
            "type": request_type,
            "status": status
        }
    )
def build_dashboard(message=""):
    routes = load_routes()
    service_rows = ""
    local_running = 0
    remote_targets = 0
    for domain, target in routes.items():
        local = is_local_target(target)
        if local:
            running = local_target_running(target)
            if running:
                local_running += 1
            target_type = "LOCAL"
            status = (
                "RUNNING"
                if running
                else "OFFLINE"
            )
            status_class = (
                "green"
                if running
                else "red"
            )
        else:
            remote_targets += 1
            target_type = "REMOTE"
            status = "REMOTE"
            status_class = "blue"
        escaped_domain = html.escape(domain)
        escaped_target = html.escape(target)
        service_rows += f"""
        <tr>
            <td>
                <strong>{escaped_domain}</strong>
            </td>
            <td>
                <a
                    href="https://{escaped_domain}"
                    target="_blank"
                >
                    https://{escaped_domain}
                </a>
            </td>
            <td>
                {escaped_target}
            </td>
            <td>
                <span class="badge">
                    {target_type}
                </span>
            </td>
            <td>
                <span class="badge {status_class}">
                    {status}
                </span>
            </td>
            <td>
                <span class="badge green">
                    HTTPS
                </span>
            </td>
            <td>
                <form
                    method="POST"
                    action="/__portdock__/remove/{escaped_domain}"
                >
                    <button class="remove">
                        Remove
                    </button>
                </form>
            </td>
        </tr>
        """
    if not service_rows:
        service_rows = """
        <tr>
            <td colspan="7">
                No services registered yet.
            </td>
        </tr>
        """
    message_html = ""
    if message:
        message_html = f"""
        <div class="message">
            {html.escape(message)}
        </div>
        """
    return f"""
<!DOCTYPE html>
<html>
<head>
<title>PortDock Dashboard</title>
<meta charset="UTF-8">
<style>
* {{
    box-sizing: border-box;
}}
body {{
    margin: 0;
    font-family: Arial, sans-serif;
    background: #0b0f19;
    color: #e8eaf0;
}}
.container {{
    width: 94%;
    max-width: 1400px;
    margin: 35px auto;
}}
h1 {{
    margin-bottom: 5px;
    font-size: 34px;
}}
.subtitle {{
    color: #8e98ad;
    margin-bottom: 30px;
}}
.cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 25px;
}}
.card {{
    background: #141a28;
    border: 1px solid #242d40;
    border-radius: 12px;
    padding: 20px;
}}
.card-title {{
    color: #8e98ad;
    font-size: 13px;
    margin-bottom: 10px;
}}
.card-value {{
    font-size: 27px;
    font-weight: bold;
}}
.section {{
    background: #141a28;
    border: 1px solid #242d40;
    border-radius: 12px;
    padding: 22px;
    margin-bottom: 22px;
}}
.flow {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 16px;
    flex-wrap: wrap;
    padding: 25px;
}}
.flow-box {{
    background: #0e1420;
    border: 1px solid #303b50;
    padding: 17px 20px;
    border-radius: 10px;
    text-align: center;
    min-width: 180px;
}}
.arrow {{
    font-size: 25px;
}}
input {{
    background: #0e1420;
    border: 1px solid #303b50;
    color: white;
    padding: 12px;
    border-radius: 7px;
    width: 280px;
    margin-right: 8px;
}}
button {{
    padding: 12px 18px;
    border: none;
    border-radius: 7px;
    cursor: pointer;
    background: #5267ff;
    color: white;
    font-weight: bold;
}}
button:hover {{
    opacity: 0.9;
}}
.remove {{
    background: #a83d49;
    padding: 8px 12px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}
th {{
    text-align: left;
    color: #8e98ad;
    font-size: 12px;
    border-bottom: 1px solid #30384a;
    padding: 12px;
}}
td {{
    border-bottom: 1px solid #222a39;
    padding: 12px;
    font-size: 14px;
}}
a {{
    color: #8ca4ff;
    text-decoration: none;
}}
.badge {{
    background: #30384b;
    border-radius: 20px;
    padding: 5px 9px;
    font-size: 11px;
    font-weight: bold;
}}
.green {{
    background: #174e37;
    color: #7ce4ae;
}}
.red {{
    background: #58272c;
    color: #ff9ca4;
}}
.blue {{
    background: #1d365a;
    color: #92bfff;
}}
.orange {{
    background: #59421e;
    color: #ffd27c;
}}
.message {{
    background: #173d30;
    border: 1px solid #2f7257;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 20px;
}}
.tech {{
    font-family: Consolas, monospace;
    color: #a9f0c3;
}}
small {{
    color: #8e98ad;
}}
.more-container {{
    text-align: center;
    margin-top: 18px;
}}
#readMoreButton {{
    display: none;
    background: #30384b;
}}
@media(max-width: 900px) {{
    .cards {{
        grid-template-columns: 1fr 1fr;
    }}
}}
</style>
</head>
<body>
<div class="container">
<h1>⚓ PortDock</h1>
<div class="subtitle">
Local Reverse Proxy & Developer Traffic Router
</div>
{message_html}
<div class="cards">
<div class="card">
<div class="card-title">
REGISTERED SERVICES
</div>
<div class="card-value">
{len(routes)}
</div>
</div>
<div class="card">
<div class="card-title">
LOCAL RUNNING
</div>
<div class="card-value">
{local_running}
</div>
</div>
<div class="card">
<div class="card-title">
REMOTE TARGETS
</div>
<div class="card-value">
{remote_targets}
</div>
</div>
<div class="card">
<div class="card-title">
ACTIVE WEBSOCKETS
</div>
<div
    class="card-value"
    id="wsCount"
>
{ACTIVE_WEBSOCKETS}
</div>
</div>
</div>
<div class="section">
<h2>
Live Reverse Proxy Flow
</h2>
<div class="flow">
<div class="flow-box">
<strong>
Browser
</strong>
<br><br>
<span
    class="tech"
    id="flowHost"
>
https://name.localhost
</span>
</div>
<div class="arrow">
→
</div>
<div class="flow-box">
<strong>
PortDock
</strong>
<br><br>
<span class="tech">
HTTPS :443
</span>
<br>
<small>
TLS + Routing + Proxy
</small>
</div>
<div class="arrow">
→
</div>
<div class="flow-box">
<strong>
Backend
</strong>
<br><br>
<span
    class="tech"
    id="flowTarget"
>
Waiting for traffic...
</span>
</div>
</div>
<div style="text-align:center">
<span class="badge green">
TLS ACTIVE
</span>
<span class="badge blue">
HTTP PROXY
</span>
<span class="badge orange">
WEBSOCKET PROXY
</span>
<span class="badge">
SNI ENABLED
</span>
</div>
</div>
<div class="section">
<h2>
Add Target
</h2>
<form
    method="POST"
    action="/__portdock__/add"
>
<input
    name="name"
    placeholder="Service name (game)"
    required
>
<input
    name="url"
    placeholder="http://localhost:8501"
    required
>
<button>
Add Target
</button>
</form>
</div>
<div class="section">
<h2>
Registered Services
</h2>
<table>
<thead>
<tr>
<th>Name</th>
<th>PortDock URL</th>
<th>Backend Target</th>
<th>Type</th>
<th>Status</th>
<th>TLS</th>
<th>Action</th>
</tr>
</thead>
<tbody>
{service_rows}
</tbody>
</table>
</div>
<div class="section">
<h2>
Recent Proxy Requests
</h2>
<small>
This proves traffic is passing through PortDock before reaching the backend.
</small>
<table>
<thead>
<tr>
<th>Time</th>
<th>Method</th>
<th>Hostname</th>
<th>Backend</th>
<th>Traffic</th>
<th>Status</th>
</tr>
</thead>
<tbody id="requestRows">
<tr>
<td colspan="6">
Waiting for requests...
</td>
</tr>
</tbody>
</table>
<div class="more-container">
<button
    id="readMoreButton"
    onclick="toggleLogs()"
>
Show more
</button>
</div>
</div>
</div>
<script>
let allLogs = [];
let showAll = false;
function renderLogs() {{
    const rows =
        document.getElementById(
            "requestRows"
        );
    const button =
        document.getElementById(
            "readMoreButton"
        );
    if (allLogs.length === 0) {{
        rows.innerHTML = `
        <tr>
            <td colspan="6">
                Waiting for requests...
            </td>
        </tr>
        `;
        button.style.display =
            "none";
        return;
    }}
    const visibleLogs =
        showAll
        ? allLogs
        : allLogs.slice(0, 5);
    let output = "";
    for (const log of visibleLogs) {{
        const trafficClass =
            log.type === "WEBSOCKET"
            ? "orange"
            : "blue";
        const statusClass =
            log.status === "ERROR"
            ? "red"
            : "green";
        output += `
        <tr>
            <td>
                ${{log.time}}
            </td>
            <td>
                ${{log.method}}
            </td>
            <td>
                ${{log.host}}
            </td>
            <td class="tech">
                ${{log.target}}
            </td>
            <td>
                <span
                    class="badge ${{trafficClass}}"
                >
                    ${{log.type}}
                </span>
            </td>
            <td>
                <span
                    class="badge ${{statusClass}}"
                >
                    ${{log.status}}
                </span>
            </td>
        </tr>
        `;
    }}
    rows.innerHTML = output;
    if (allLogs.length > 5) {{
        button.style.display =
            "inline-block";
        if (showAll) {{
            button.textContent =
                "Show less";
        }} else {{
            button.textContent =
                "Show more (" +
                (allLogs.length - 5) +
                ")";
        }}
    }} else {{
        button.style.display =
            "none";
    }}
}}
function toggleLogs() {{
    showAll = !showAll;
    renderLogs();
}}
async function updateStatus() {{
    try {{
        const response =
            await fetch(
                "/__portdock__/status"
            );
        const data =
            await response.json();
        document.getElementById(
            "wsCount"
        ).textContent =
            data.active_websockets;
        allLogs = data.logs;
        renderLogs();
        if (data.logs.length > 0) {{
            const latest =
                data.logs[0];
            document.getElementById(
                "flowHost"
            ).textContent =
                "https://" +
                latest.host;
            document.getElementById(
                "flowTarget"
            ).textContent =
                latest.target;
        }}
    }}
    catch(error) {{
        console.log(
            "Status update failed"
        );
    }}
}}
updateStatus();
setInterval(
    updateStatus,
    1000
);
</script>
</body>
</html>
"""
async def dashboard_handler(request):
    return web.Response(
        text=build_dashboard(),
        content_type="text/html"
    )
async def status_handler(request):
    return web.json_response(
        {
            "active_websockets":
                ACTIVE_WEBSOCKETS,
            "logs":
                list(REQUEST_LOGS)
        }
    )
async def add_service(request):
    if get_hostname(request) != DASHBOARD_HOST:
        return web.Response(
            status=403,
            text="Forbidden"
        )
    form = await request.post()
    name = clean_service_name(
        form.get("name", "")
    )
    target = validate_target_url(
        form.get("url", "")
    )
    if not name:
        return web.Response(
            text=build_dashboard(
                "Invalid service name."
            ),
            content_type="text/html"
        )
    if not target:
        return web.Response(
            text=build_dashboard(
                "Invalid target URL."
            ),
            content_type="text/html"
        )
    domain = f"{name}.localhost"
    routes = load_routes()
    routes[domain] = target
    save_routes(routes)
    try:
        create_domain_ssl_context(
            domain
        )
    except Exception as error:
        return web.Response(
            text=build_dashboard(
                f"Route saved but TLS failed: {error}"
            ),
            content_type="text/html"
        )
    return web.Response(
        text=build_dashboard(
            f"{domain} → {target} added successfully."
        ),
        content_type="text/html"
    )
async def remove_service(request):
    if get_hostname(request) != DASHBOARD_HOST:
        return web.Response(
            status=403,
            text="Forbidden"
        )
    domain = request.match_info[
        "name"
    ]
    routes = load_routes()
    routes.pop(
        domain,
        None
    )
    save_routes(routes)
    # Remove all old proxy requests
    # belonging to this service.
    remaining_logs = [
        log
        for log in REQUEST_LOGS
        if log.get("host") != domain
    ]
    REQUEST_LOGS.clear()
    REQUEST_LOGS.extend(
        remaining_logs
    )
    return web.Response(
        text=build_dashboard(
            f"{domain} removed."
        ),
        content_type="text/html"
    )
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}
def make_upstream_headers(
    request,
    target
):
    headers = CIMultiDict()
    skip_headers = (
        HOP_BY_HOP_HEADERS
        | {
            "host",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
        }
    )
    for key, value in request.headers.items():
        if key.lower() in skip_headers:
            continue
        headers.add(
            key,
            value
        )
    headers[
        "X-Forwarded-Host"
    ] = request.host
    headers[
        "X-Forwarded-Proto"
    ] = "https"
    headers[
        "X-Forwarded-Port"
    ] = "443"
    if request.remote:
        headers[
            "X-Forwarded-For"
        ] = request.remote
    origin = target_origin(
        target
    )
    if "Origin" in headers:
        headers["Origin"] = origin
    if "Referer" in headers:
        headers["Referer"] = (
            origin + "/"
        )
    return headers
def rewrite_cookie(cookie):
    parts = cookie.split(";")
    cleaned = []
    for part in parts:
        if (
            part.strip()
            .lower()
            .startswith("domain=")
        ):
            continue
        cleaned.append(part)
    return ";".join(cleaned)
def rewrite_location(
    location,
    target,
    proxy_host
):
    origin = target_origin(
        target
    )
    if location.startswith(
        origin
    ):
        return location.replace(
            origin,
            f"https://{proxy_host}",
            1
        )
    return location
async def proxy_http(
    request,
    target
):
    session = request.app[
        "session"
    ]
    host = get_hostname(
        request
    )
    backend_url = build_backend_url(
        target,
        request
    )
    log_request(
        request.method,
        host,
        backend_url,
        "HTTP"
    )
    print(
        f"[HTTP] {host} -> {backend_url}"
    )
    try:
        body = await request.read()
        headers = make_upstream_headers(
            request,
            target
        )
        async with session.request(
            method=request.method,
            url=backend_url,
            headers=headers,
            data=body,
            allow_redirects=False
        ) as response:
            response_body = (
                await response.read()
            )
            response_headers = (
                CIMultiDict()
            )
            for (
                key,
                value
            ) in response.headers.items():
                key_lower = (
                    key.lower()
                )
                if (
                    key_lower
                    in HOP_BY_HOP_HEADERS
                ):
                    continue
                if (
                    key_lower
                    == "set-cookie"
                ):
                    continue
                if (
                    key_lower
                    == "location"
                ):
                    value = rewrite_location(
                        value,
                        target,
                        host
                    )
                response_headers.add(
                    key,
                    value
                )
            proxy_response = web.Response(
                status=response.status,
                body=response_body,
                headers=response_headers
            )
            for cookie in response.headers.getall(
                "Set-Cookie",
                []
            ):
                proxy_response.headers.add(
                    "Set-Cookie",
                    rewrite_cookie(
                        cookie
                    )
                )
            return proxy_response
    except Exception as error:
        print(
            f"[HTTP ERROR] {error}"
        )
        log_request(
            request.method,
            host,
            backend_url,
            "HTTP",
            "ERROR"
        )
        return web.Response(
            status=502,
            text=(
                "PortDock could not "
                "reach the target."
            )
        )
async def proxy_websocket(
    request,
    target
):
    global ACTIVE_WEBSOCKETS
    session = request.app[
        "session"
    ]
    host = get_hostname(
        request
    )
    backend_url = build_backend_url(
        target,
        request
    )
    if backend_url.startswith(
        "https://"
    ):
        backend_ws_url = (
            "wss://"
            + backend_url[8:]
        )
    else:
        backend_ws_url = (
            "ws://"
            + backend_url[7:]
        )
    requested_protocols = []
    protocol_header = (
        request.headers.get(
            "Sec-WebSocket-Protocol"
        )
    )
    if protocol_header:
        requested_protocols = [
            protocol.strip()
            for protocol
            in protocol_header.split(",")
            if protocol.strip()
        ]
    headers = make_upstream_headers(
        request,
        target
    )
    log_request(
        "WS",
        host,
        backend_ws_url,
        "WEBSOCKET",
        "CONNECTED"
    )
    print(
        f"[WS] Browser -> {host}"
    )
    print(
        f"[WS] Backend -> {backend_ws_url}"
    )
    try:
        async with session.ws_connect(
            backend_ws_url,
            headers=headers,
            protocols=requested_protocols,
            heartbeat=30
        ) as backend_ws:
            browser_protocols = []
            if backend_ws.protocol:
                browser_protocols = [
                    backend_ws.protocol
                ]
            elif requested_protocols:
                browser_protocols = (
                    requested_protocols
                )
            browser_ws = (
                web.WebSocketResponse(
                    protocols=browser_protocols,
                    heartbeat=30
                )
            )
            await browser_ws.prepare(
                request
            )
            ACTIVE_WEBSOCKETS += 1
            print(
                f"[WS] CONNECTED: "
                f"{host} <-> "
                f"{backend_ws_url}"
            )
            async def browser_to_backend():
                async for msg in browser_ws:
                    if msg.type == WSMsgType.TEXT:
                        await backend_ws.send_str(
                            msg.data
                        )
                    elif msg.type == WSMsgType.BINARY:
                        await backend_ws.send_bytes(
                            msg.data
                        )
                    elif msg.type == WSMsgType.PING:
                        await backend_ws.ping(
                            msg.data
                        )
                    elif msg.type == WSMsgType.PONG:
                        await backend_ws.pong(
                            msg.data
                        )
            async def backend_to_browser():
                async for msg in backend_ws:
                    if msg.type == WSMsgType.TEXT:
                        await browser_ws.send_str(
                            msg.data
                        )
                    elif msg.type == WSMsgType.BINARY:
                        await browser_ws.send_bytes(
                            msg.data
                        )
                    elif msg.type == WSMsgType.PING:
                        await browser_ws.ping(
                            msg.data
                        )
                    elif msg.type == WSMsgType.PONG:
                        await browser_ws.pong(
                            msg.data
                        )
            task1 = asyncio.create_task(
                browser_to_backend()
            )
            task2 = asyncio.create_task(
                backend_to_browser()
            )
            done, pending = (
                await asyncio.wait(
                    [task1, task2],
                    return_when=
                    asyncio.FIRST_COMPLETED
                )
            )
            for task in pending:
                task.cancel()
            await browser_ws.close()
            return browser_ws
    except Exception as error:
        print(
            f"[WS ERROR] {error}"
        )
        log_request(
            "WS",
            host,
            backend_ws_url,
            "WEBSOCKET",
            "ERROR"
        )
        return web.Response(
            status=502,
            text=(
                "PortDock WebSocket "
                "connection failed."
            )
        )
    finally:
        if ACTIVE_WEBSOCKETS > 0:
            ACTIVE_WEBSOCKETS -= 1
async def main_handler(request):
    host = get_hostname(
        request
    )
    print(
        f"[REQUEST] "
        f"{request.method} "
        f"{host}"
        f"{request.rel_url}"
    )
    if host == DASHBOARD_HOST:
        return await dashboard_handler(
            request
        )
    routes = load_routes()
    if host not in routes:
        return web.Response(
            status=404,
            text=f"""
            <html>
            <body style="
                font-family:Arial;
                background:#0b0f19;
                color:white;
                padding:40px;
            ">
            <h2>
                PortDock Route Not Found
            </h2>
            <p>
                No route exists for:
            </p>
            <strong>
                {html.escape(host)}
            </strong>
            </body>
            </html>
            """,
            content_type="text/html"
        )
    target = routes[
        host
    ]
    if (
        is_local_target(target)
        and not local_target_running(target)
    ):
        return web.Response(
            status=503,
            text=f"""
            <html>
            <body style="
                font-family:Arial;
                background:#0b0f19;
                color:white;
                padding:40px;
            ">
            <h2>
                Backend Offline
            </h2>
            <p>
                PortDock found the route:
            </p>
            <p>
            <strong>
                {html.escape(host)}
            </strong>
            →
            <strong>
                {html.escape(target)}
            </strong>
            </p>
            <p>
                Start the backend service and refresh.
            </p>
            </body>
            </html>
            """,
            content_type="text/html"
        )
    upgrade = (
        request.headers
        .get(
            "Upgrade",
            ""
        )
        .lower()
    )
    if upgrade == "websocket":
        return await proxy_websocket(
            request,
            target
        )
    return await proxy_http(
        request,
        target
    )
async def redirect_handler(request):
    host = request.host.split(
        ":"
    )[0]
    location = (
        f"https://{host}"
        f"{request.rel_url}"
    )
    raise web.HTTPMovedPermanently(
        location=location
    )
async def create_https_app():
    app = web.Application(
        client_max_size=
        100 * 1024 * 1024
    )
    timeout = ClientTimeout(
        total=None,
        connect=20,
        sock_connect=20,
        sock_read=None
    )
    app["session"] = ClientSession(
        timeout=timeout,
        auto_decompress=False
    )
    async def cleanup(app):
        await app[
            "session"
        ].close()
    app.on_cleanup.append(
        cleanup
    )
    app.router.add_post(
        "/__portdock__/add",
        add_service
    )
    app.router.add_post(
        "/__portdock__/remove/{name}",
        remove_service
    )
    app.router.add_get(
        "/__portdock__/status",
        status_handler
    )
    app.router.add_route(
        "*",
        "/{path:.*}",
        main_handler
    )
    return app
async def create_http_app():
    app = web.Application()
    app.router.add_route(
        "*",
        "/{path:.*}",
        redirect_handler
    )
    return app
async def start_portdock():
    print()
    print("=" * 55)
    print("PORTDOCK")
    print("Local Reverse Proxy")
    print("=" * 55)
    if not os.path.exists(
        MKCERT_FILE
    ):
        print()
        print(
            "ERROR: mkcert.exe was not found."
        )
        return
    if port_is_used(
        HTTP_PORT
    ):
        print()
        print(
            "ERROR: Port 80 is already used."
        )
        return
    if port_is_used(
        HTTPS_PORT
    ):
        print()
        print(
            "ERROR: Port 443 is already used."
        )
        return
    print()
    print(
        "[TLS] Loading certificates..."
    )
    ssl_context = (
        create_main_ssl_context()
    )
    https_app = (
        await create_https_app()
    )
    http_app = (
        await create_http_app()
    )
    https_runner = web.AppRunner(
        https_app
    )
    http_runner = web.AppRunner(
        http_app
    )
    await https_runner.setup()
    await http_runner.setup()
    https_site = web.TCPSite(
        https_runner,
        "127.0.0.1",
        HTTPS_PORT,
        ssl_context=ssl_context
    )
    http_site = web.TCPSite(
        http_runner,
        "127.0.0.1",
        HTTP_PORT
    )
    await https_site.start()
    await http_site.start()
    print()
    print(
        "PortDock is running!"
    )
    print()
    print(
        "Dashboard:"
    )
    print(
        "https://portdock.localhost"
    )
    print()
    print(
        "HTTP  : 127.0.0.1:80"
    )
    print(
        "HTTPS : 127.0.0.1:443"
    )
    print()
    routes = load_routes()
    if routes:
        print(
            "Registered routes:"
        )
        for domain, target in routes.items():
            print(
                f"  https://{domain}"
                f" -> {target}"
            )
    else:
        print(
            "No routes registered yet."
        )
    print()
    print(
        "Press Ctrl+C to stop."
    )
    try:
        while True:
            await asyncio.sleep(
                3600
            )
    finally:
        await https_runner.cleanup()
        await http_runner.cleanup()
if __name__ == "__main__":
    try:
        asyncio.run(
            start_portdock()
        )
    except KeyboardInterrupt:
        print()
        print(
            "PortDock stopped."
        )
