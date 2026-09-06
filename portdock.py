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
from urllib.parse import urlparse, urljoin
from aiohttp import (
    ClientSession,
    ClientTimeout,
    WSMsgType,
    web,
)
from multidict import CIMultiDict
# ============================================================
# CONFIG
# ============================================================
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)
ROUTES_FILE = os.path.join(
    BASE_DIR,
    "routes.json"
)
MKCERT_FILE = os.path.join(
    BASE_DIR,
    "mkcert.exe"
)
CERT_DIR = os.path.join(
    BASE_DIR,
    "certificates"
)
os.makedirs(
    CERT_DIR,
    exist_ok=True
)
DASHBOARD_HOST = "portdock.localhost"
HTTP_PORT = 80
HTTPS_PORT = 443
REQUEST_LOGS = deque(
    maxlen=50
)
SSL_CONTEXTS = {}
# ============================================================
# ROUTES
# ============================================================
def normalize_target(target):
    if isinstance(target, int):
        return f"http://127.0.0.1:{target}"
    target = str(target).strip()
    # Support old routes.json values like "8501"
    if target.isdigit():
        return f"http://127.0.0.1:{target}"
    return target
def load_routes():
    try:
        with open(
            ROUTES_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)
        routes = {}
        for domain, target in data.items():
            routes[
                domain.strip().lower()
            ] = normalize_target(
                target
            )
        return routes
    except FileNotFoundError:
        return {}
    except Exception as error:
        print(
            "[ROUTES ERROR]",
            error
        )
        return {}
def save_routes(routes):
    with open(
        ROUTES_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            routes,
            file,
            indent=4
        )
# ============================================================
# TARGET VALIDATION
# ============================================================
def validate_target_url(url):
    url = url.strip()
    if not url.startswith(
        (
            "http://",
            "https://"
        )
    ):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        if parsed.scheme not in [
            "http",
            "https"
        ]:
            return None
        if not parsed.hostname:
            return None
        # Don't allow usernames/passwords
        # embedded inside URLs.
        if (
            parsed.username is not None
            or
            parsed.password is not None
        ):
            return None
        # Prevent users from routing PortDock
        # back into itself and creating a loop.
        if parsed.hostname.lower() in [
            "portdock.localhost"
        ]:
            return None
        if parsed.port in [
            80,
            443
        ] and parsed.hostname in [
            "localhost",
            "127.0.0.1"
        ]:
            return None
        return url.rstrip("/")
    except ValueError:
        return None
# ============================================================
# SERVICE NAME
# ============================================================
def clean_service_name(name):
    name = (
        str(name)
        .lower()
        .strip()
    )
    if not re.fullmatch(
        r"[a-z0-9-]+",
        name
    ):
        return None
    return name
# ============================================================
# LOCAL / REMOTE HELPERS
# ============================================================
def is_local_target(target):
    try:
        parsed = urlparse(target)
        return parsed.hostname in [
            "localhost",
            "127.0.0.1"
        ]
    except Exception:
        return False
def local_target_running(target):
    try:
        parsed = urlparse(target)
        if parsed.hostname not in [
            "localhost",
            "127.0.0.1"
        ]:
            return True
        if parsed.port is None:
            return False
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        sock.settimeout(0.25)
        result = sock.connect_ex(
            (
                "127.0.0.1",
                parsed.port
            )
        )
        sock.close()
        return result == 0
    except Exception:
        return False
def port_is_used(port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )
    sock.settimeout(0.25)
    result = sock.connect_ex(
        (
            "127.0.0.1",
            port
        )
    )
    sock.close()
    return result == 0
# ============================================================
# BUILD BACKEND URL
# ============================================================
def build_backend_url(
    target,
    request
):
    target = target.rstrip("/") + "/"
    relative = request.rel_url.path.lstrip("/")
    backend = urljoin(
        target,
        relative
    )
    if request.rel_url.query_string:
        backend += (
            "?"
            +
            request.rel_url.query_string
        )
    return backend
def target_origin(target):
    parsed = urlparse(target)
    origin = (
        f"{parsed.scheme}://"
        f"{parsed.hostname}"
    )
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
# ============================================================
# TLS CERTIFICATE MANAGEMENT
# ============================================================
def certificate_paths(domain):
    safe_name = re.sub(
        r"[^a-zA-Z0-9_-]",
        "_",
        domain
    )
    return (
        os.path.join(
            CERT_DIR,
            safe_name + ".crt"
        ),
        os.path.join(
            CERT_DIR,
            safe_name + ".key"
        )
    )
def generate_certificate(domain):
    cert_file, key_file = (
        certificate_paths(domain)
    )
    if (
        os.path.exists(cert_file)
        and
        os.path.exists(key_file)
    ):
        return cert_file, key_file
    if not os.path.exists(
        MKCERT_FILE
    ):
        print(
            "ERROR: mkcert.exe not found."
        )
        return None, None
    print(
        f"[TLS] Creating certificate "
        f"for {domain}"
    )
    try:
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
        print(
            f"[TLS] Ready: {domain}"
        )
        return cert_file, key_file
    except Exception as error:
        print(
            "[TLS ERROR]",
            error
        )
        return None, None
def create_domain_ssl_context(domain):
    cert_file, key_file = (
        generate_certificate(domain)
    )
    if not cert_file:
        return None
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )
    context.load_cert_chain(
        certfile=cert_file,
        keyfile=key_file
    )
    SSL_CONTEXTS[
        domain
    ] = context
    return context
def create_main_ssl_context():
    context = create_domain_ssl_context(
        DASHBOARD_HOST
    )
    if context is None:
        raise RuntimeError(
            "Could not prepare dashboard TLS."
        )
    routes = load_routes()
    for domain in routes:
        create_domain_ssl_context(
            domain
        )
    def sni_callback(
        ssl_socket,
        server_name,
        initial_context
    ):
        if not server_name:
            return
        domain = (
            server_name
            .lower()
            .strip()
        )
        domain_context = (
            SSL_CONTEXTS.get(
                domain
            )
        )
        if domain_context:
            ssl_socket.context = (
                domain_context
            )
    context.set_servername_callback(
        sni_callback
    )
    return context
# ============================================================
# HOSTNAME
# ============================================================
def get_hostname(request):
    return (
        request.host
        .split(":")[0]
        .lower()
        .strip()
    )
# ============================================================
# DASHBOARD
# ============================================================
def build_dashboard(
    message=None,
    message_type="success"
):
    routes = load_routes()
    service_rows = ""
    local_running = 0
    remote_count = 0
    for domain, target in routes.items():
        name = domain.replace(
            ".localhost",
            ""
        )
        if is_local_target(target):
            running = (
                local_target_running(
                    target
                )
            )
            if running:
                local_running += 1
                status = (
                    '<span class="running">'
                    'RUNNING'
                    '</span>'
                )
            else:
                status = (
                    '<span class="offline">'
                    'OFFLINE'
                    '</span>'
                )
            target_type = "LOCAL"
        else:
            remote_count += 1
            status = (
                '<span class="remote">'
                'REMOTE'
                '</span>'
            )
            target_type = "REMOTE"
        service_rows += f"""
        <tr>
            <td>
                {html.escape(name)}
            </td>
            <td>
                <a
                    href="https://{html.escape(domain)}"
                    target="_blank"
                    class="link"
                >
                    https://{html.escape(domain)}
                </a>
            </td>
            <td class="backend">
                {html.escape(target)}
            </td>
            <td>
                {target_type}
            </td>
            <td>
                {status}
            </td>
            <td>
                <div class="actions">
                    <a
                        class="open"
                        href="https://{html.escape(domain)}"
                        target="_blank"
                    >
                        Open
                    </a>
                    <form
                        method="POST"
                        action="/__portdock__/remove/{html.escape(name)}"
                    >
                        <button
                            class="remove"
                        >
                            Remove
                        </button>
                    </form>
                </div>
            </td>
        </tr>
        """
    if not service_rows:
        service_rows = """
        <tr>
            <td
                colspan="6"
                class="empty"
            >
                No services registered.
            </td>
        </tr>
        """
    log_rows = ""
    for log in reversed(
        REQUEST_LOGS
    ):
        log_rows += f"""
        <tr>
            <td>
                {html.escape(log["time"])}
            </td>
            <td>
                {html.escape(log["method"])}
            </td>
            <td>
                {html.escape(log["host"])}
            </td>
            <td>
                {html.escape(log["target"])}
            </td>
            <td>
                {html.escape(log["type"])}
            </td>
        </tr>
        """
    if not log_rows:
        log_rows = """
        <tr>
            <td
                colspan="5"
                class="empty"
            >
                No proxy requests yet.
            </td>
        </tr>
        """
    message_html = ""
    if message:
        message_html = f"""
        <div
            class="message {message_type}"
        >
            {html.escape(message)}
        </div>
        """
    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>
<title>
PortDock Dashboard
</title>
<style>
* {{
    box-sizing: border-box;
}}
body {{
    margin: 0;
    background: #090c11;
    color: white;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
}}
.container {{
    width: 94%;
    max-width: 1250px;
    margin: auto;
    padding: 40px 0;
}}
h1 {{
    margin: 0;
    font-size: 38px;
}}
.subtitle {{
    color: #9da8ba;
    margin-top: 10px;
}}
.badge {{
    display: inline-block;
    margin-top: 15px;
    padding: 9px 14px;
    background: #103c28;
    color: #5ce39d;
    border-radius: 8px;
    font-weight: bold;
}}
.stats {{
    display: grid;
    grid-template-columns:
        repeat(3, 1fr);
    gap: 18px;
    margin-top: 30px;
}}
.card {{
    background: #151922;
    border:
        1px solid #2a303a;
    border-radius: 14px;
    padding: 22px;
    margin-top: 22px;
}}
.stat-title {{
    color: #9ea8b8;
}}
.stat-number {{
    font-size: 32px;
    font-weight: bold;
    margin-top: 8px;
}}
.form-grid {{
    display: grid;
    grid-template-columns:
        1fr 2fr auto;
    gap: 14px;
    align-items: end;
}}
label {{
    display: block;
    margin-bottom: 8px;
}}
input {{
    width: 100%;
    padding: 13px;
    border-radius: 8px;
    border:
        1px solid #363d4b;
    background: #0c1016;
    color: white;
}}
button {{
    border: 0;
    border-radius: 8px;
    cursor: pointer;
    font-weight: bold;
}}
.add {{
    padding: 14px 20px;
    background: white;
    color: black;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}
th,
td {{
    padding: 14px 10px;
    border-bottom:
        1px solid #2a303a;
    text-align: left;
}}
th {{
    color: #9ea8b8;
}}
.backend {{
    font-family: monospace;
    max-width: 360px;
    overflow-wrap: anywhere;
}}
.link {{
    color: #82adff;
    text-decoration: none;
}}
.running {{
    color: #59df9a;
    font-weight: bold;
}}
.offline {{
    color: #ff7a7a;
    font-weight: bold;
}}
.remote {{
    color: #82adff;
    font-weight: bold;
}}
.actions {{
    display: flex;
    gap: 8px;
}}
.open {{
    padding: 9px 13px;
    background: #252b36;
    color: white;
    text-decoration: none;
    border-radius: 8px;
}}
.remove {{
    padding: 9px 13px;
    background: #421d1d;
    color: #ff8c8c;
}}
.message {{
    padding: 15px;
    border-radius: 9px;
    margin-top: 20px;
}}
.success {{
    background: #103c28;
    color: #60e6a2;
}}
.error {{
    background: #481c1c;
    color: #ff8c8c;
}}
.muted {{
    color: #9ea8b8;
}}
.empty {{
    text-align: center;
    color: #919bac;
}}
@media (
    max-width: 800px
) {{
    .stats {{
        grid-template-columns: 1fr;
    }}
    .form-grid {{
        grid-template-columns: 1fr;
    }}
}}
</style>
</head>
<body>
<div class="container">
<h1>
PortDock Dashboard
</h1>
<div class="subtitle">
Route local apps and remote websites
through clean HTTPS .localhost domains.
</div>
<div class="badge">
🔒 HTTPS + HTTP + WebSocket + Remote Targets
</div>
{message_html}
<div class="stats">
<div class="card">
<div class="stat-title">
Registered Services
</div>
<div class="stat-number">
{len(routes)}
</div>
</div>
<div class="card">
<div class="stat-title">
Local Running
</div>
<div class="stat-number">
{local_running}
</div>
</div>
<div class="card">
<div class="stat-title">
Remote Targets
</div>
<div class="stat-number">
{remote_count}
</div>
</div>
</div>
<div class="card">
<h2>
Add Target
</h2>
<form
    method="POST"
    action="/__portdock__/add"
>
<div class="form-grid">
<div>
<label>
Service Name
</label>
<input
    name="name"
    placeholder="demo"
    required
>
</div>
<div>
<label>
Target URL
</label>
<input
    name="url"
    placeholder="https://example.com"
    required
>
</div>
<button
    class="add"
>
Add Target
</button>
</div>
</form>
<p class="muted">
Local example:
http://localhost:8501
</p>
<p class="muted">
Remote example:
https://example.com
</p>
<p class="muted">
Both become:
https://name.localhost
</p>
</div>
<div class="card">
<h2>
Services
</h2>
<table>
<thead>
<tr>
<th>Name</th>
<th>PortDock URL</th>
<th>Target</th>
<th>Type</th>
<th>Status</th>
<th>Actions</th>
</tr>
</thead>
<tbody>
{service_rows}
</tbody>
</table>
</div>
<div class="card">
<h2>
Recent Proxy Requests
</h2>
<table>
<thead>
<tr>
<th>Time</th>
<th>Method</th>
<th>Host</th>
<th>Target</th>
<th>Type</th>
</tr>
</thead>
<tbody>
{log_rows}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""
# ============================================================
# DASHBOARD HANDLERS
# ============================================================
async def dashboard_handler(request):
    return web.Response(
        text=build_dashboard(),
        content_type="text/html"
    )
async def add_service(request):
    if get_hostname(
        request
    ) != DASHBOARD_HOST:
        raise web.HTTPNotFound()
    form = await request.post()
    name = clean_service_name(
        form.get(
            "name",
            ""
        )
    )
    target = validate_target_url(
        str(
            form.get(
                "url",
                ""
            )
        )
    )
    if not name:
        return web.Response(
            text=build_dashboard(
                "Invalid service name.",
                "error"
            ),
            content_type="text/html"
        )
    if not target:
        return web.Response(
            text=build_dashboard(
                "Enter a valid HTTP or HTTPS URL.",
                "error"
            ),
            content_type="text/html"
        )
    domain = (
        f"{name}.localhost"
    )
    routes = load_routes()
    routes[
        domain
    ] = target
    save_routes(
        routes
    )
    context = (
        create_domain_ssl_context(
            domain
        )
    )
    if context is None:
        return web.Response(
            text=build_dashboard(
                "Route saved, but TLS "
                "certificate generation failed.",
                "error"
            ),
            content_type="text/html"
        )
    print()
    print(
        f"[ROUTE] {domain}"
        f" -> {target}"
    )
    return web.Response(
        text=build_dashboard(
            f"{domain} now routes to {target}",
            "success"
        ),
        content_type="text/html"
    )
async def remove_service(request):
    if get_hostname(
        request
    ) != DASHBOARD_HOST:
        raise web.HTTPNotFound()
    name = clean_service_name(
        request.match_info[
            "name"
        ]
    )
    if not name:
        raise web.HTTPBadRequest()
    domain = (
        f"{name}.localhost"
    )
    routes = load_routes()
    routes.pop(
        domain,
        None
    )
    save_routes(
        routes
    )
    raise web.HTTPFound(
        location=(
            "https://portdock.localhost/"
        )
    )
# ============================================================
# PROXY HEADERS
# ============================================================
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
    target,
    websocket=False
):
    headers = {}
    for key, value in (
        request.headers.items()
    ):
        lower = key.lower()
        if lower in HOP_BY_HOP_HEADERS:
            continue
        if lower == "host":
            continue
        if (
            websocket
            and lower.startswith(
                "sec-websocket-"
            )
        ):
            continue
        headers[
            key
        ] = value
    host = get_hostname(
        request
    )
    headers[
        "X-Forwarded-Host"
    ] = host
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
    # Rewrite browser Origin so
    # remote/local backend sees its
    # own origin instead of .localhost.
    if "Origin" in headers:
        headers[
            "Origin"
        ] = target_origin(
            target
        )
    if "Referer" in headers:
        headers[
            "Referer"
        ] = (
            target_origin(target)
            + "/"
        )
    return headers
# ============================================================
# COOKIE REWRITE
# ============================================================
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
        cleaned.append(
            part
        )
    return ";".join(
        cleaned
    )
# ============================================================
# REDIRECT REWRITE
# ============================================================
def rewrite_location(
    location,
    target,
    host
):
    origin = target_origin(
        target
    )
    if location.startswith(
        origin
    ):
        return location.replace(
            origin,
            f"https://{host}",
            1
        )
    return location
# ============================================================
# HTTP PROXY
# ============================================================
async def proxy_http(
    request,
    target,
    session
):
    host = get_hostname(
        request
    )
    backend_url = (
        build_backend_url(
            target,
            request
        )
    )
    REQUEST_LOGS.append(
        {
            "time":
                datetime.now()
                .strftime("%H:%M:%S"),
            "method":
                request.method,
            "host":
                host,
            "target":
                target,
            "type":
                "HTTP"
        }
    )
    headers = (
        make_upstream_headers(
            request,
            target
        )
    )
    try:
        body = await request.read()
        async with session.request(
            method=request.method,
            url=backend_url,
            headers=headers,
            data=body,
            allow_redirects=False
        ) as backend_response:
            response_body = (
                await backend_response.read()
            )
            response_headers = (
                CIMultiDict()
            )
            for key, value in (
                backend_response
                .headers
                .items()
            ):
                lower = key.lower()
                if lower in (
                    HOP_BY_HOP_HEADERS
                ):
                    continue
                if lower == "set-cookie":
                    continue
                if lower == "location":
                    value = (
                        rewrite_location(
                            value,
                            target,
                            host
                        )
                    )
                response_headers.add(
                    key,
                    value
                )
            # Preserve multiple cookies
            # while removing remote Domain=.
            for cookie in (
                backend_response
                .headers
                .getall(
                    "Set-Cookie",
                    []
                )
            ):
                response_headers.add(
                    "Set-Cookie",
                    rewrite_cookie(
                        cookie
                    )
                )
            return web.Response(
                body=response_body,
                status=(
                    backend_response.status
                ),
                headers=response_headers
            )
    except Exception as error:
        print(
            "[HTTP ERROR]",
            backend_url,
            error
        )
        return web.Response(
            status=502,
            text=(
                "PortDock could not "
                "reach the target."
            )
        )
# ============================================================
# WEBSOCKET PROXY
# ============================================================
async def proxy_websocket(
    request,
    target,
    session
):
    host = get_hostname(
        request
    )
    backend_url = build_backend_url(
        target,
        request
    )
    parsed = urlparse(
        backend_url
    )
    if parsed.scheme == "https":
        backend_ws_url = (
            "wss://"
            + backend_url[
                len("https://"):
            ]
        )
    else:
        backend_ws_url = (
            "ws://"
            + backend_url[
                len("http://"):
            ]
        )
    REQUEST_LOGS.append(
        {
            "time":
                datetime.now()
                .strftime("%H:%M:%S"),
            "method":
                "WS",
            "host":
                host,
            "target":
                target,
            "type":
                "WebSocket"
        }
    )
    protocol_header = (
        request.headers.get(
            "Sec-WebSocket-Protocol",
            ""
        )
    )
    protocols = [
        item.strip()
        for item
        in protocol_header.split(",")
        if item.strip()
    ]
    headers = (
        make_upstream_headers(
            request,
            target,
            websocket=True
        )
    )
    print(
        f"[WS] {host}"
        f" -> {backend_ws_url}"
    )
    try:
        upstream_ws = (
            await session.ws_connect(
                backend_ws_url,
                headers=headers,
                protocols=protocols,
                heartbeat=30
            )
        )
    except Exception as error:
        print(
            "[WS ERROR]",
            error
        )
        return web.Response(
            status=502,
            text=(
                "Could not connect "
                "to target WebSocket."
            )
        )
    browser_protocols = []
    if upstream_ws.protocol:
        browser_protocols = [
            upstream_ws.protocol
        ]
    elif protocols:
        browser_protocols = (
            protocols
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
    print(
        f"[WS] CONNECTED "
        f"{host}"
    )
    async def browser_to_target():
        try:
            async for message in (
                browser_ws
            ):
                if (
                    message.type
                    == WSMsgType.TEXT
                ):
                    await upstream_ws.send_str(
                        message.data
                    )
                elif (
                    message.type
                    == WSMsgType.BINARY
                ):
                    await upstream_ws.send_bytes(
                        message.data
                    )
                elif (
                    message.type
                    == WSMsgType.PING
                ):
                    await upstream_ws.ping(
                        message.data
                    )
                elif (
                    message.type
                    == WSMsgType.PONG
                ):
                    await upstream_ws.pong(
                        message.data
                    )
                else:
                    break
        except Exception:
            pass
    async def target_to_browser():
        try:
            async for message in (
                upstream_ws
            ):
                if (
                    message.type
                    == WSMsgType.TEXT
                ):
                    await browser_ws.send_str(
                        message.data
                    )
                elif (
                    message.type
                    == WSMsgType.BINARY
                ):
                    await browser_ws.send_bytes(
                        message.data
                    )
                elif (
                    message.type
                    == WSMsgType.PING
                ):
                    await browser_ws.ping(
                        message.data
                    )
                elif (
                    message.type
                    == WSMsgType.PONG
                ):
                    await browser_ws.pong(
                        message.data
                    )
                else:
                    break
        except Exception:
            pass
    tasks = [
        asyncio.create_task(
            browser_to_target()
        ),
        asyncio.create_task(
            target_to_browser()
        )
    ]
    done, pending = (
        await asyncio.wait(
            tasks,
            return_when=(
                asyncio.FIRST_COMPLETED
            )
        )
    )
    for task in pending:
        task.cancel()
    if not upstream_ws.closed:
        await upstream_ws.close()
    if not browser_ws.closed:
        await browser_ws.close()
    return browser_ws
# ============================================================
# MAIN ROUTING
# ============================================================
async def main_handler(request):
    host = get_hostname(
        request
    )
    print(
        f"[REQUEST] {request.method} "
        f"{host}{request.rel_url}"
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
<body
style="
background:#090c11;
color:white;
font-family:Arial;
padding:40px;
"
>
<h1>
Unknown PortDock Service
</h1>
<p>
{html.escape(host)}
is not registered.
</p>
<a
href="https://portdock.localhost/"
style="color:#82adff"
>
Open Dashboard
</a>
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
        and
        not local_target_running(
            target
        )
    ):
        return web.Response(
            status=503,
            text=f"""
<html>
<body
style="
background:#090c11;
color:white;
font-family:Arial;
padding:40px;
"
>
<h1>
Local Service Offline
</h1>
<p>
Target:
<b>
{html.escape(target)}
</b>
</p>
</body>
</html>
""",
            content_type="text/html"
        )
    session = request.app[
        "client_session"
    ]
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
            target,
            session
        )
    return await proxy_http(
        request,
        target,
        session
    )
# ============================================================
# HTTP -> HTTPS
# ============================================================
async def redirect_handler(request):
    host = get_hostname(
        request
    )
    raise web.HTTPPermanentRedirect(
        location=(
            f"https://{host}"
            f"{request.rel_url}"
        )
    )
# ============================================================
# APPLICATIONS
# ============================================================
async def create_https_app():
    app = web.Application(
        client_max_size=(
            100 * 1024 * 1024
        )
    )
    timeout = ClientTimeout(
        total=None,
        connect=20,
        sock_connect=20,
        sock_read=None
    )
    app[
        "client_session"
    ] = ClientSession(
        timeout=timeout,
        auto_decompress=False
    )
    async def cleanup(app):
        await app[
            "client_session"
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
    app.router.add_route(
        "*",
        "/{path:.*}",
        main_handler
    )
    return app
def create_http_app():
    app = web.Application()
    app.router.add_route(
        "*",
        "/{path:.*}",
        redirect_handler
    )
    return app
# ============================================================
# START
# ============================================================
async def start_portdock():
    print()
    print(
        "=========================================="
    )
    print(
        "                 PORTDOCK"
    )
    print(
        "=========================================="
    )
    print()
    if not os.path.exists(
        MKCERT_FILE
    ):
        print(
            "ERROR: mkcert.exe not found."
        )
        return
    if port_is_used(
        HTTP_PORT
    ):
        print(
            "ERROR: Port 80 is already used."
        )
        return
    if port_is_used(
        HTTPS_PORT
    ):
        print(
            "ERROR: Port 443 is already used."
        )
        return
    print(
        "Preparing HTTPS certificates..."
    )
    ssl_context = (
        create_main_ssl_context()
    )
    https_app = (
        await create_https_app()
    )
    http_app = (
        create_http_app()
    )
    https_runner = (
        web.AppRunner(
            https_app
        )
    )
    http_runner = (
        web.AppRunner(
            http_app
        )
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
        "PortDock is running."
    )
    print()
    print(
        "Dashboard:"
    )
    print(
        "https://portdock.localhost/"
    )
    print()
    print(
        "Local targets: ENABLED"
    )
    print(
        "Remote targets: ENABLED"
    )
    print(
        "HTTP proxy: ENABLED"
    )
    print(
        "WebSockets: ENABLED"
    )
    print(
        "Automatic TLS: ENABLED"
    )
    print()
    routes = load_routes()
    if routes:
        print(
            "Registered services:"
        )
        for domain, target in (
            routes.items()
        ):
            print(
                f"https://{domain}"
                f" -> {target}"
            )
    print()
    print(
        "Press CTRL+C to stop."
    )
    try:
        await asyncio.Event().wait()
    finally:
        await https_runner.cleanup()
        await http_runner.cleanup()
# ============================================================
# ENTRY
# ============================================================
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
