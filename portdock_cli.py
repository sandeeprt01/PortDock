import json
import sys
import os
import socket
import subprocess
import webbrowser

from urllib.parse import urlparse


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

ROUTES_FILE = os.path.join(
    BASE_DIR,
    "routes.json"
)

PORTDOCK_FILE = os.path.join(
    BASE_DIR,
    "portdock.py"
)


# =========================================================
# LOAD / SAVE ROUTES
# =========================================================

def load_routes():

    try:
        with open(ROUTES_FILE, "r") as file:
            return json.load(file)

    except FileNotFoundError:
        return {}

    except json.JSONDecodeError:
        print("ERROR: routes.json is invalid.")
        return {}


def save_routes(routes):

    with open(ROUTES_FILE, "w") as file:
        json.dump(
            routes,
            file,
            indent=4
        )


# =========================================================
# PORT UTILITIES
# =========================================================

def is_port_running(port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.25)

    result = sock.connect_ex(
        (
            "127.0.0.1",
            int(port)
        )
    )

    sock.close()

    return result == 0


def find_free_port():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.bind(
        (
            "127.0.0.1",
            0
        )
    )

    port = sock.getsockname()[1]

    sock.close()

    return port


# =========================================================
# EXTRACT PORT FROM URL
# =========================================================
def extract_port(url):

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

        hostname = parsed.hostname

        if hostname not in [
            "localhost",
            "127.0.0.1"
        ]:
            return None

        if parsed.port is None:
            return None

        return parsed.port

    except ValueError:

        return None

# =========================================================
# ADD SERVICE
# =========================================================

def add_service(name, url):

    routes = load_routes()

    name = name.strip().lower()

    if not name:
        print("Invalid service name.")
        return

    domain = f"{name}.localhost"

    port = extract_port(url)

    if port is None:

        print()
        print("Could not find a port in the URL.")
        print()
        print("Example:")
        print("http://localhost:5000")
        print()

        return

    routes[domain] = int(port)

    save_routes(routes)

    print()
    print("SERVICE REGISTERED")
    print()
    print(f"{domain} -> localhost:{port}")
    print(f"http://{domain}")
    print()


# =========================================================
# RUN SERVICE WITH DYNAMIC PORT
# =========================================================

def run_service(name, command_parts):

    name = name.strip().lower()

    if not name:
        print("Invalid service name.")
        return

    if not command_parts:
        print("No command provided.")
        return

    port = find_free_port()

    routes = load_routes()

    domain = f"{name}.localhost"

    routes[domain] = port

    save_routes(routes)

    env = os.environ.copy()

    env["PORT"] = str(port)

    print()
    print("==============================================")
    print("          PORTDOCK DYNAMIC SERVICE")
    print("==============================================")
    print()
    print(f"Service : {name}")
    print(f"Port    : {port}")
    print(f"Domain  : http://{domain}")
    print()
    print("Starting command:")
    print(" ".join(command_parts))
    print()

    try:

        subprocess.Popen(
            command_parts,
            env=env,
            cwd=BASE_DIR
        )

        print("Service process started.")
        print()
        print(
            f"Open: http://{domain}"
        )
        print()

    except FileNotFoundError:

        print()
        print("Could not start the command.")
        print("Check that the command is correct.")
        print()

        if domain in routes:
            del routes[domain]
            save_routes(routes)

    except Exception as error:

        print()
        print("Failed to start service:")
        print(error)
        print()

        if domain in routes:
            del routes[domain]
            save_routes(routes)


# =========================================================
# REMOVE SERVICE
# =========================================================

def remove_service(name):

    routes = load_routes()

    domain = f"{name.strip().lower()}.localhost"

    if domain not in routes:

        print()
        print("Service not found.")
        print()

        return

    del routes[domain]

    save_routes(routes)

    print()
    print(f"Removed {domain}")
    print()


# =========================================================
# LIST SERVICES
# =========================================================

def list_services():

    routes = load_routes()

    print()
    print(
        "============================================================"
    )
    print(
        "                   PORTDOCK SERVICES"
    )
    print(
        "============================================================"
    )
    print()

    if not routes:

        print("No services registered.")
        print()

        return

    for domain, port in routes.items():

        status = (
            "RUNNING"
            if is_port_running(port)
            else "OFFLINE"
        )

        print(
            f"{domain:<25}"
            f" -> localhost:{port:<7}"
            f" {status}"
        )

    print()


# =========================================================
# OPEN SERVICE
# =========================================================

def open_service(name):

    name = name.strip().lower()

    if name == "dashboard":

        url = "http://portdock.localhost"

        print()
        print(f"Opening {url}")
        print()

        webbrowser.open(url)

        return

    routes = load_routes()

    domain = f"{name}.localhost"

    if domain not in routes:

        print()
        print("Service is not registered.")
        print()

        return

    url = f"http://{domain}"

    print()
    print(f"Opening {url}")
    print()

    webbrowser.open(url)


# =========================================================
# START PORTDOCK
# =========================================================

def start_portdock():

    print()
    print(
        "=============================================="
    )
    print(
        "              STARTING PORTDOCK"
    )
    print(
        "=============================================="
    )
    print()

    if is_port_running(80):

        print("Port 80 is already in use.")
        print()
        print("PortDock may already be running.")
        print()

        return

    subprocess.run(
        [
            sys.executable,
            PORTDOCK_FILE
        ]
    )


# =========================================================
# HELP
# =========================================================

def show_help():

    print()
    print("PortDock")
    print()

    print("Commands:")
    print()

    print("  portdock start")

    print("  portdock list")

    print("  portdock add NAME URL")

    print(
        "  portdock run NAME COMMAND..."
    )

    print("  portdock remove NAME")

    print("  portdock open NAME")

    print("  portdock open dashboard")

    print()

    print("Examples:")
    print()

    print(
        "  portdock add login http://localhost:5000"
    )

    print(
        "  portdock run login python login_service.py"
    )

    print(
        "  portdock run admin python admin_service.py"
    )

    print()


# =========================================================
# COMMAND HANDLING
# =========================================================

if len(sys.argv) < 2:

    show_help()
    sys.exit()


command = sys.argv[1].lower()


if command == "start":

    start_portdock()


elif command == "list":

    list_services()


elif command == "add":

    if len(sys.argv) != 4:

        print()
        print("Usage:")
        print(
            "portdock add NAME URL"
        )
        print()

    else:

        add_service(
            sys.argv[2],
            sys.argv[3]
        )


elif command == "run":

    if len(sys.argv) < 4:

        print()
        print("Usage:")
        print(
            "portdock run NAME COMMAND..."
        )
        print()

        print("Example:")
        print(
            "portdock run login python login_service.py"
        )
        print()

    else:

        service_name = sys.argv[2]

        command_parts = sys.argv[3:]

        run_service(
            service_name,
            command_parts
        )


elif command == "remove":

    if len(sys.argv) != 3:

        print()
        print("Usage:")
        print("portdock remove NAME")
        print()

    else:

        remove_service(
            sys.argv[2]
        )


elif command == "open":

    if len(sys.argv) != 3:

        print()
        print("Usage:")
        print("portdock open NAME")
        print()

    else:

        open_service(
            sys.argv[2]
        )


elif command == "help":

    show_help()


else:

    print()
    print(
        f"Unknown command: {command}"
    )

    show_help()