import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "ren-default-secret-key"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"REN started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

# ---------------------- FAKE HOMEPAGE ----------------------
FAKE_HOMEPAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>John Doe | Photography</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', sans-serif;
            background: #0a0a0a;
            color: #e5e5e5;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 2rem;
        }
        .hero h1 {
            font-size: 3rem;
            font-weight: 300;
            letter-spacing: 10px;
            text-transform: uppercase;
            margin-bottom: 1rem;
        }
        .hero p {
            font-size: 1.1rem;
            color: #666;
            max-width: 500px;
            line-height: 1.8;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            width: 100%;
            max-width: 900px;
            margin-top: 2rem;
        }
        .gallery img {
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-radius: 12px;
            filter: grayscale(30%);
            transition: .3s;
        }
        .gallery img:hover {
            filter: grayscale(0);
            transform: scale(1.02);
        }
        footer {
            margin-top: 3rem;
            color: #444;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="hero">
        <h1>John Doe</h1>
        <p>Capturing moments that last forever. Based in Amsterdam, available worldwide.</p>
    </div>
    <div class="gallery">
        <img src="https://images.unsplash.com/photo-1506744038136-46273834b3fb?w=400" alt="Mountain">
        <img src="https://images.unsplash.com/photo-1469474968028-56623f02e42e?w=400" alt="Forest">
        <img src="https://images.unsplash.com/photo-1501785888041-af3ef285b470?w=400" alt="Lake">
        <img src="https://images.unsplash.com/photo-1441974231531-c6227db76b6e?w=400" alt="Sunshine">
        <img src="https://images.unsplash.com/photo-1518837695005-2083093ee35b?w=400" alt="Ocean">
        <img src="https://images.unsplash.com/photo-1472214103451-9374bd1c798e?w=400" alt="Autumn">
    </div>
    <footer>
        &copy; 2025 John Doe Photography. All rights reserved.
    </footer>
</body>
</html>
"""

@app.get("/")
async def root():
    return HTMLResponse(content=FAKE_HOMEPAGE_HTML)

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ---------------------- GLASSMORPHISM LOGIN ----------------------
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN - Sign In</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
        --glass-bg: rgba(255, 255, 255, 0.05);
        --glass-border: rgba(255, 255, 255, 0.1);
        --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        --blur-amount: 20px;
        --primary: #6366f1;
        --primary-glow: rgba(99, 102, 241, 0.3);
        --text: rgba(255, 255, 255, 0.95);
        --text-secondary: rgba(255, 255, 255, 0.6);
        --radius: 20px;
    }
    [data-theme="light"] {
        --glass-bg: rgba(255, 255, 255, 0.3);
        --glass-border: rgba(0, 0, 0, 0.08);
        --glass-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
        --text: #1e293b;
        --text-secondary: #64748b;
    }
    body {
        font-family: 'Inter', 'Vazirmatn', sans-serif;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        transition: background 0.5s;
        overflow: hidden;
        position: relative;
    }
    [data-theme="light"] body {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
    }
    .bg-shapes {
        position: fixed;
        inset: 0;
        z-index: 0;
        pointer-events: none;
    }
    .shape {
        position: absolute;
        border-radius: 50%;
        filter: blur(80px);
        opacity: 0.15;
    }
    .shape-1 { width: 400px; height: 400px; background: #6366f1; top: -10%; left: -5%; }
    .shape-2 { width: 350px; height: 350px; background: #8b5cf6; bottom: -10%; right: -5%; }
    .shape-3 { width: 250px; height: 250px; background: #a78bfa; top: 50%; left: 60%; }
    .login-card {
        position: relative;
        z-index: 10;
        width: 100%;
        max-width: 400px;
        margin: 20px;
        background: var(--glass-bg);
        backdrop-filter: blur(var(--blur-amount));
        -webkit-backdrop-filter: blur(var(--blur-amount));
        border: 1px solid var(--glass-border);
        border-radius: var(--radius);
        box-shadow: var(--glass-shadow);
        padding: 40px 30px;
        animation: fadeInUp 0.8s cubic-bezier(0.23, 1, 0.32, 1);
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .brand { text-align: center; margin-bottom: 30px; }
    .brand svg { filter: drop-shadow(0 0 15px var(--primary-glow)); }
    .brand h1 { font-size: 28px; font-weight: 800; color: var(--text); margin-top: 10px; letter-spacing: -0.5px; }
    .brand p { font-size: 13px; color: var(--text-secondary); margin-top: 4px; font-weight: 500; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .form-group input {
        width: 100%; padding: 12px 16px; background: rgba(255, 255, 255, 0.06);
        border: 1px solid var(--glass-border); border-radius: 14px;
        color: var(--text); font-size: 15px; outline: none; transition: all 0.3s;
    }
    .form-group input:focus {
        border-color: var(--primary);
        box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
        background: rgba(255, 255, 255, 0.08);
    }
    .login-btn {
        width: 100%; padding: 13px; background: var(--primary); border: none;
        border-radius: 14px; color: white; font-weight: 700; font-size: 15px;
        cursor: pointer; transition: all 0.3s; margin-top: 10px;
        position: relative; overflow: hidden;
    }
    .login-btn:hover { background: #4f46e5; transform: translateY(-2px); box-shadow: 0 10px 25px rgba(99, 102, 241, 0.4); }
    .login-btn:active { transform: translateY(0); }
    .error-msg {
        background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2);
        color: #ef4444; padding: 10px 15px; border-radius: 12px; font-size: 13px;
        margin-bottom: 20px; display: none;
    }
    .error-msg.show { display: block; animation: shake 0.4s; }
    @keyframes shake {
        0%,100% { transform: translateX(0); }
        20%,60% { transform: translateX(-5px); }
        40%,80% { transform: translateX(5px); }
    }
    .theme-toggle {
        position: absolute; top: 20px; right: 20px;
        background: var(--glass-bg); backdrop-filter: blur(10px);
        border: 1px solid var(--glass-border); border-radius: 50%;
        width: 40px; height: 40px; display: flex; align-items: center; justify-content: center;
        cursor: pointer; color: var(--text); font-size: 18px; z-index: 20; transition: 0.3s;
    }
    .theme-toggle:hover { background: rgba(255,255,255,0.1); }
</style>
</head>
<body>
    <div class="bg-shapes">
        <div class="shape shape-1"></div>
        <div class="shape shape-2"></div>
        <div class="shape shape-3"></div>
    </div>
    <div class="theme-toggle" onclick="toggleTheme()" id="theme-btn">🌙</div>
    <div class="login-card">
        <div class="brand">
            <svg width="60" height="60" viewBox="0 0 56 56" fill="none">
                <rect width="56" height="56" rx="14" fill="url(#logo-grad)"/>
                <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
                <circle cx="28" cy="18" r="3.5" fill="#fff"/>
                <circle cx="19" cy="33" r="3.5" fill="#fff"/>
                <circle cx="37" cy="33" r="3.5" fill="#fff"/>
                <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
                <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
                <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
                <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
                <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#6366f1"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs>
            </svg>
            <h1>REN</h1>
            <p>VLESS Management Panel</p>
        </div>
        <div class="error-msg" id="err-box"></div>
        <form id="login-form">
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" placeholder="Enter your password" autofocus>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
        </form>
    </div>

    <script>
        let theme = localStorage.getItem('ren_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', theme);
        document.getElementById('theme-btn').innerHTML = theme === 'dark' ? '☀️' : '🌙';

        function toggleTheme() {
            theme = theme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('ren_theme', theme);
            document.getElementById('theme-btn').innerHTML = theme === 'dark' ? '☀️' : '🌙';
        }

        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const errBox = document.getElementById('err-box');
            errBox.classList.remove('show');
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: document.getElementById('password').value })
                });
                if (!res.ok) {
                    const data = await res.json().catch(() => ({}));
                    throw new Error(data.detail || 'Login failed');
                }
                window.location.href = '/dashboard';
            } catch (err) {
                errBox.textContent = err.message;
                errBox.classList.add('show');
            }
        });
    </script>
</body>
</html>
"""

# ---------------------- GLASSMORPHISM DASHBOARD ----------------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
        --glass-bg: rgba(20, 20, 20, 0.6);
        --glass-border: rgba(255, 255, 255, 0.08);
        --blur: 15px;
        --sidebar-bg: rgba(15, 15, 15, 0.7);
        --text: rgba(255, 255, 255, 0.92);
        --text-secondary: rgba(255, 255, 255, 0.5);
        --primary: #dc2626;
        --primary-dim: rgba(220, 38, 38, 0.1);
        --green: #22c55e;
        --green-dim: rgba(34, 197, 94, 0.1);
        --red: #ef4444;
        --red-dim: rgba(239, 68, 68, 0.1);
        --yellow: #fbbf24;
        --radius: 16px;
        --shadow: 0 4px 24px rgba(0,0,0,0.3);
    }
    [data-theme="light"] {
        --glass-bg: rgba(255, 255, 255, 0.5);
        --glass-border: rgba(0, 0, 0, 0.06);
        --sidebar-bg: rgba(255, 255, 255, 0.7);
        --text: #0f172a;
        --text-secondary: #475569;
        --shadow: 0 4px 24px rgba(0,0,0,0.05);
    }
    body {
        font-family: 'Inter', 'Vazirmatn', sans-serif;
        background: radial-gradient(circle at top left, #1e293b, #0f172a);
        color: var(--text);
        display: flex;
        min-height: 100vh;
        transition: background 0.3s;
    }
    [data-theme="light"] body {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
    }

    /* Sidebar */
    .sidebar {
        width: 260px;
        background: var(--sidebar-bg);
        backdrop-filter: blur(var(--blur));
        -webkit-backdrop-filter: blur(var(--blur));
        border-right: 1px solid var(--glass-border);
        display: flex;
        flex-direction: column;
        position: fixed;
        top: 0; bottom: 0; left: 0;
        z-index: 100;
        transition: transform 0.3s ease;
    }
    .sidebar-brand { padding: 20px; border-bottom: 1px solid var(--glass-border); display: flex; align-items: center; gap: 10px; }
    .sidebar-brand h2 { font-size: 18px; font-weight: 700; }
    .nav-item {
        display: flex; align-items: center; gap: 10px;
        padding: 12px 20px; color: var(--text-secondary);
        cursor: pointer; transition: 0.2s; border: none; background: none; width: 100%; text-align: left; font-size: 14px;
    }
    .nav-item:hover, .nav-item.active { background: var(--glass-bg); color: var(--text); }
    .nav-item.active { border-left: 3px solid var(--primary); }
    .sidebar-footer { padding: 20px; border-top: 1px solid var(--glass-border); }

    /* Main */
    .main { margin-left: 260px; flex: 1; padding: 24px; }

    /* Cards */
    .card, .stat-card, .modal-content, .toast {
        background: var(--glass-bg);
        backdrop-filter: blur(var(--blur));
        -webkit-backdrop-filter: blur(var(--blur));
        border: 1px solid var(--glass-border);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
    }
    .stat-card { padding: 20px; transition: 0.3s; }
    .stat-card:hover { transform: translateY(-2px); }
    .card { padding: 20px; margin-bottom: 16px; }
    .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .card-title { font-weight: 600; font-size: 14px; }

    /* Buttons */
    .btn {
        padding: 8px 16px; border-radius: 8px; border: 1px solid var(--glass-border);
        background: var(--glass-bg); color: var(--text); cursor: pointer; font-weight: 500; transition: 0.2s;
        backdrop-filter: blur(5px);
    }
    .btn-primary { background: var(--primary); color: #fff; border: none; }
    .btn-primary:hover { filter: brightness(1.2); }
    .btn-danger { color: var(--red); border-color: rgba(239,68,68,0.3); }
    .btn-danger:hover { background: var(--red-dim); }

    /* Table */
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 12px; font-size: 11px; text-transform: uppercase; color: var(--text-secondary); border-bottom: 1px solid var(--glass-border); }
    td { padding: 12px; border-bottom: 1px solid var(--glass-border); font-size: 13px; }
    tr:hover td { background: var(--glass-bg); }

    /* Toggle, usage bars etc. */
    .toggle { width: 40px; height: 20px; border-radius: 10px; background: var(--glass-bg); position: relative; cursor: pointer; border: 1px solid var(--glass-border); }
    .toggle.on { background: var(--green); }
    .toggle::after { content: ''; position: absolute; width: 16px; height: 16px; border-radius: 50%; background: white; top: 1px; left: 1px; transition: 0.3s; }
    .toggle.on::after { left: 21px; }
    .progress-bar { height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }
    .progress-fill { height: 100%; border-radius: 3px; }

    /* Modals */
    .modal-overlay {
        position: fixed; inset: 0; background: rgba(0,0,0,0.5); backdrop-filter: blur(4px);
        display: none; align-items: center; justify-content: center; z-index: 200;
    }
    .modal-overlay.show { display: flex; }
    .modal-content { width: 90%; max-width: 500px; padding: 24px; position: relative; }
    .modal-close { position: absolute; top: 10px; right: 10px; background: none; border: none; color: var(--text); cursor: pointer; font-size: 18px; }

    /* Toast */
    .toast {
        position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
        padding: 12px 20px; z-index: 300; opacity: 0; transition: 0.3s;
    }
    .toast.show { opacity: 1; }

    /* Responsive */
    @media (max-width: 768px) {
        .sidebar { transform: translateX(-100%); }
        .sidebar.open { transform: translateX(0); }
        .main { margin-left: 0; padding-top: 60px; }
    }
    .mobile-header { display: none; position: fixed; top: 0; left: 0; right: 0; height: 50px; background: var(--sidebar-bg); backdrop-filter: blur(10px); z-index: 99; align-items: center; padding: 0 16px; }
    @media (max-width: 768px) { .mobile-header { display: flex; } }
</style>
</head>
<body>

<!-- Mobile Header -->
<div class="mobile-header">
    <button onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
    <span style="font-weight:600;">REN</span>
    <div></div>
</div>

<!-- Sidebar -->
<aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
        <svg width="24" height="24" viewBox="0 0 56 56" fill="none">
            <rect width="56" height="56" rx="14" fill="#dc2626"/>
            <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
            <circle cx="28" cy="18" r="3" fill="#fff"/>
            <circle cx="19" cy="33" r="3" fill="#fff"/>
            <circle cx="37" cy="33" r="3" fill="#fff"/>
            <line x1="28" y1="21" x2="22" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
            <line x1="28" y1="21" x2="34" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
            <line x1="22" y1="33" x2="34" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        </svg>
        <h2>REN</h2>
    </div>
    <nav>
        <button class="nav-item active" data-page="dashboard">📊 Dashboard</button>
        <button class="nav-item" data-page="inbounds">🔗 Inbounds</button>
        <button class="nav-item" data-page="traffic">📈 Traffic</button>
        <button class="nav-item" data-page="addresses">🌍 Clean IP</button>
        <button class="nav-item" data-page="domain">🌐 Domain</button>
        <button class="nav-item" data-page="security">🔒 Security</button>
    </nav>
    <div class="sidebar-footer">
        <button class="btn btn-danger" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')" style="width:100%">Logout</button>
        <div style="text-align:center; margin-top:10px; font-size:12px; color: var(--text-secondary);">v1.0</div>
    </div>
</aside>

<!-- Main Content -->
<main class="main" id="main-content">
    <!-- Pages will be loaded dynamically with vanilla JS -->
</main>

<!-- Toast -->
<div class="toast" id="toast"></div>

<!-- Generic Modal -->
<div class="modal-overlay" id="generic-modal">
    <div class="modal-content">
        <button class="modal-close" onclick="closeModal()">&times;</button>
        <div id="modal-body"></div>
    </div>
</div>

<script>
    // Global state
    let currentPage = 'dashboard';
    let lang = 'en';
    let theme = localStorage.getItem('ren_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    let allLinks = [];
    let statsData = {};
    let trafficChart = null;

    // Helper
    const $ = (s) => document.querySelector(s);
    const $$ = (s) => document.querySelectorAll(s);

    // Navigation
    $$('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            $$('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            const page = item.dataset.page;
            if (page !== currentPage) {
                currentPage = page;
                loadPage(page);
            }
            document.getElementById('sidebar').classList.remove('open');
        });
    });

    function loadPage(page) {
        const main = $('#main-content');
        switch(page) {
            case 'dashboard': renderDashboard(); break;
            case 'inbounds': renderInbounds(); break;
            case 'traffic': renderTraffic(); break;
            case 'addresses': renderAddresses(); break;
            case 'domain': renderDomain(); break;
            case 'security': renderSecurity(); break;
        }
    }

    function toast(msg, isError=false) {
        const t = $('#toast');
        t.textContent = msg;
        t.style.background = isError ? 'rgba(239,68,68,0.8)' : 'var(--glass-bg)';
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 3000);
    }

    async function api(url, options={}) {
        try {
            const res = await fetch(url, options);
            if (res.status === 401) { window.location.href = '/login'; return; }
            return res;
        } catch (e) { toast('Network error', true); }
    }

    // Dashboard
    async function loadStats() {
        const res = await api('/stats');
        if (res && res.ok) statsData = await res.json();
    }

    function renderDashboard() {
        const main = $('#main-content');
        main.innerHTML = `
            <h2 style="margin-bottom:20px;">Dashboard</h2>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px,1fr)); gap:16px;" id="stats-cards">
                <div class="stat-card"><div>Traffic</div><div class="stat-value" id="stat-traffic">--</div></div>
                <div class="stat-card"><div>Inbounds</div><div class="stat-value" id="stat-links">--</div></div>
                <div class="stat-card"><div>Uptime</div><div class="stat-value" id="stat-uptime">--</div></div>
                <div class="stat-card"><div>Domain</div><div class="stat-value" id="stat-domain">--</div></div>
            </div>
            <div class="card" style="margin-top:16px;">
                <div class="card-header"><span>Traffic Chart</span></div>
                <canvas id="trafficChart" height="200"></canvas>
            </div>
        `;
        updateStats();
        setInterval(updateStats, 10000);
    }

    async function updateStats() {
        await loadStats();
        if (!statsData) return;
        $('#stat-traffic').textContent = statsData.total_traffic_mb + ' MB';
        $('#stat-links').textContent = statsData.links_count;
        $('#stat-uptime').textContent = statsData.uptime;
        $('#stat-domain').textContent = statsData.domain;
        updateChart();
    }

    function updateChart() {
        if (!statsData.hourly_traffic) return;
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;
        const labels = [], data = [];
        Object.entries(statsData.hourly_traffic).sort().slice(-12).forEach(([h, b]) => {
            labels.push(h);
            data.push(Math.round(b/1048576));
        });
        if (trafficChart) trafficChart.destroy();
        trafficChart = new Chart(ctx, {
            type: 'bar',
            data: { labels, datasets: [{ label: 'MB', data, backgroundColor: '#dc2626' }] },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    // Inbounds
    async function loadLinks() {
        const res = await api('/api/links');
        if (res && res.ok) {
            const data = await res.json();
            allLinks = data.links || [];
        }
    }

    function renderInbounds() {
        $('#main-content').innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                <h2>Inbounds</h2>
                <button class="btn btn-primary" onclick="showAddInboundModal()">+ Add</button>
            </div>
            <div class="card">
                <table>
                    <thead><tr><th>Name</th><th>Type</th><th>Usage</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody id="links-tbody"></tbody>
                </table>
            </div>
        `;
        refreshLinksList();
    }

    async function refreshLinksList() {
        await loadLinks();
        const tbody = $('#links-tbody');
        tbody.innerHTML = allLinks.map(l => `
            <tr>
                <td>${l.label}</td>
                <td><span style="background:var(--primary-dim); padding:2px 8px; border-radius:4px;">VLESS</span></td>
                <td>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span>${(l.used_bytes/1048576).toFixed(1)} MB</span>
                        <div class="progress-bar" style="flex:1;"><div class="progress-fill" style="width:${l.limit_bytes ? Math.min(100, (l.used_bytes/l.limit_bytes)*100) : 0}%; background:${l.limit_bytes && l.used_bytes/l.limit_bytes > 0.9 ? 'var(--red)' : 'var(--primary)'}"></div></div>
                        <span>${l.limit_bytes ? (l.limit_bytes/1073741824).toFixed(1)+'GB' : 'Unlimited'}</span>
                    </div>
                </td>
                <td><span class="toggle ${l.active ? 'on' : ''}" onclick="toggleLink('${l.uuid}', this)"></span></td>
                <td>
                    <button class="btn" onclick="copyLink('${l.vless_link}')">📋</button>
                    <button class="btn" onclick="showQR('${l.vless_link}')">🔳</button>
                    <button class="btn btn-danger" onclick="deleteLink('${l.uuid}')">🗑</button>
                </td>
            </tr>
        `).join('');
    }

    async function toggleLink(uuid, el) {
        const link = allLinks.find(l => l.uuid === uuid);
        if (!link) return;
        const res = await api(`/api/links/${uuid}`, {
            method: 'PATCH',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({active: !link.active})
        });
        if (res && res.ok) {
            link.active = !link.active;
            el.classList.toggle('on');
        }
    }

    async function deleteLink(uuid) {
        if (!confirm('Delete?')) return;
        const res = await api(`/api/links/${uuid}`, {method:'DELETE'});
        if (res && res.ok) { toast('Deleted'); refreshLinksList(); }
    }

    function copyLink(link) {
        navigator.clipboard.writeText(link);
        toast('Copied');
    }

    function showQR(link) {
        const modal = $('#generic-modal');
        $('#modal-body').innerHTML = `
            <h3>QR Code</h3>
            <div style="text-align:center; padding:20px;">
                <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(link)}" alt="QR">
            </div>
        `;
        modal.classList.add('show');
    }

    function showAddInboundModal() {
        const modal = $('#generic-modal');
        $('#modal-body').innerHTML = `
            <h3>Add Inbound</h3>
            <div style="margin:10px 0;"><input id="new-label" placeholder="Name" style="width:100%; padding:8px;"></div>
            <div style="display:flex; gap:10px;"><input id="new-limit" type="number" placeholder="Limit (GB)" style="flex:1; padding:8px;"><input id="new-maxconn" type="number" placeholder="Max IPs" style="flex:1; padding:8px;"></div>
            <button class="btn btn-primary" onclick="createInbound()" style="margin-top:10px; width:100%;">Create</button>
        `;
        modal.classList.add('show');
    }

    async function createInbound() {
        const label = $('#new-label').value.trim();
        const limit = parseFloat($('#new-limit').value) || 0;
        const maxconn = parseInt($('#new-maxconn').value) || 0;
        if (!label) return toast('Name required', true);
        const res = await api('/api/links', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({label, limit_value:limit, limit_unit:'GB', max_connections:maxconn})
        });
        if (res && res.ok) {
            toast('Created');
            closeModal();
            refreshLinksList();
        }
    }

    function closeModal() {
        $('#generic-modal').classList.remove('show');
    }

    // Other pages (traffic, addresses, domain, security) simplified for brevity
    function renderTraffic() {
        $('#main-content').innerHTML = `<h2>Traffic</h2><div class="card">Total: <span id="total-traffic">--</span> MB</div>`;
        loadStats().then(() => {
            if (statsData) $('#total-traffic').textContent = statsData.total_traffic_mb;
        });
    }

    function renderAddresses() {
        $('#main-content').innerHTML = `<h2>Clean IP</h2><div id="addr-list"></div><button class="btn btn-primary" onclick="addAddress()">Add</button>`;
        loadAddresses();
    }

    async function loadAddresses() {
        const res = await api('/api/addresses');
        if (res && res.ok) {
            const data = await res.json();
            const list = $('#addr-list');
            list.innerHTML = data.addresses.map((a,i) => `<div>${a} <button onclick="deleteAddress(${i})">x</button></div>`).join('');
        }
    }

    async function addAddress() {
        const addr = prompt('Enter IP or domain:');
        if (!addr) return;
        await api('/api/addresses', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({address:addr})});
        loadAddresses();
    }

    async function deleteAddress(i) {
        await api(`/api/addresses/${i}`, {method:'DELETE'});
        loadAddresses();
    }

    function renderDomain() {
        $('#main-content').innerHTML = `
            <h2>Domain</h2>
            <div class="card">
                <p>Current: <span id="current-domain"></span></p>
                <input id="custom-domain" placeholder="yourdomain.com">
                <button onclick="saveDomain()">Save</button>
            </div>
        `;
        loadDomain();
    }

    async function loadDomain() {
        const res = await api('/api/domain');
        if (res && res.ok) {
            const data = await res.json();
            $('#current-domain').textContent = data.domain || getDomain();
        }
    }

    async function saveDomain() {
        const domain = $('#custom-domain').value.trim();
        await api('/api/domain', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({domain})});
        loadDomain();
    }

    function getDomain() {
        return location.host;
    }

    function renderSecurity() {
        $('#main-content').innerHTML = `
            <h2>Security</h2>
            <div class="card">
                <input id="cur-pw" type="password" placeholder="Current password"><br>
                <input id="new-pw" type="password" placeholder="New password"><br>
                <button onclick="changePassword()">Change</button>
            </div>
        `;
    }

    async function changePassword() {
        const cur = $('#cur-pw').value, nw = $('#new-pw').value;
        const res = await api('/api/change-password', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({current_password:cur, new_password:nw})
        });
        if (res && res.ok) toast('Password changed');
        else toast('Error', true);
    }

    // Initial load
    loadPage('dashboard');
</script>
</body>
</html>
"""

# ---------------------- API ENDPOINTS (unchanged) ----------------------
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "expiry": expiry, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"REN-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0), "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data), "created_at": data["created_at"], "current_connections": count_connections_for_link(uid), "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"REN-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# REN Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"REN-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"REN-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])

