# PortDock ⚙️

> **Stop wrestling with port numbers and broken local environments.** 

PortDock is an elite, high-performance local reverse proxy and control plane engineered to intercept messy, random local development ports (like `localhost:3000`, `8501`, or `5000`) and map them instantly to clean, lightning-fast, secure `.localhost` domains (e.g., `https://my-app.localhost`). 

Whether you're juggling microservices, testing OAuth flows, or debugging live web apps, PortDock gives you absolute command over your local traffic.

---

## ⚡ Why PortDock Beats the Alternatives

* **Zero Hosts-File Hell:** No more manually editing your system's `/etc/hosts` file every time you spin up a new project. PortDock handles routing dynamically.
* **Instant Production-Grade HTTPS:** Automatically generates trusted local SSL certificates via `mkcert` on the fly, meaning secure cookies, token redirects, and HTTPS webhooks will finally behave identically to production.
* **Bulletproof WebSockets:** Full, uncompromised bidirectional WebSocket support out of the box—essential for frameworks like Streamlit, Vite, and real-time dashboards.
* **Local & Remote Flexibility:** It doesn't just map local ports; it can proxy and re-route remote URLs as well, rewriting cookies and redirect headers dynamically.
* **The Command Center Dashboard:** A sleek, unified web interface running right at `https://portdock.localhost/` to monitor running/remote server liveness and stream live proxy request logs.

---

## 💻 Tech Stack & Architecture

* **Core Engine:** Built on asynchronous Python (`asyncio` + `aiohttp`) for high-concurrency performance and minimal overhead.
* **Security & TLS:** Integrated `mkcert` wrapper for local certificate authority generation.
* **Data Persistence:** Lightweight JSON routing configuration (`routes.json`).

---

## 🛠️ Prerequisites & Setup

### Windows
1. **Python 3.8+** installed on your machine.
2. **`mkcert`** installed and set up inside your project directory as `mkcert.exe` for zero-warning local SSL.

### macOS & Linux
1. **Python 3.8+** installed on your system.
2. **`mkcert`** and **`nss`** installed via your package manager:
   * **macOS:** `brew install mkcert nss`
   * **Linux (Debian/Ubuntu):** `sudo apt install libnss3-tools` then download/install `mkcert` from its official releases.
3. Initialize the local CA by running: `mkcert -install` in your terminal.

---

## 🚀 Quick Start Guide

1. Clone or open your project directory containing `portdock.py`.
2. Install the required high-performance networking dependencies:
   ```bash
   pip install aiohttp multidict
