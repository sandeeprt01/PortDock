# PortDock 🥶

PortDock is a high-performance local reverse proxy and control plane designed to map multiple local development servers and remote websites to clean, secure `.localhost` domains (e.g., `https://my-app.localhost`). 

It provides automatic TLS certificate generation, WebSocket support, cookie/redirect rewriting, and a modern web dashboard for real-time traffic monitoring.

---

## Features

* **Custom Local Domains:** Map any local port (e.g., `8501`, `3000`) or remote URL to a clean `*.localhost` domain.
* **Automatic TLS / HTTPS:** Uses `mkcert` to generate trusted local SSL certificates on the fly.
* **WebSocket Proxying:** Full bidirectional support for real-time applications (like Streamlit, Vite, or WebSockets).
* **Header & Cookie Rewriting:** Automatically strips hop-by-hop headers, handles multiple cookies, and rewrites redirect locations.
* **Unified Dashboard:** Monitor running services, view live request logs, and manage routes instantly through an intuitive UI.

---

## Prerequisites (Windows)

1. **Python 3.8+** installed on your Windows machine.
2. **`mkcert`** installed and set up in your project directory as `mkcert.exe` for local SSL generation.

---

## Installation & Setup

1. Clone or download the repository containing `portdock.py`.
2. Ensure `mkcert.exe` is placed in the root project folder alongside `portdock.py`.
3. Install the required Python dependencies via your terminal:
   ```bash
   pip install aiohttp multidict