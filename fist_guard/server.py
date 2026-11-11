# © 2026 Олег / GONKA LAB. Все права защищены.
"""Локальный веб-интерфейс демо-версии. Слушает только 127.0.0.1.

Защита: проверка заголовка Host (против DNS rebinding) и токен сессии в каждом запросе к API.
"""
from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .report import UI_DIR, to_html
from .scanner import ScanError, scan

HOST = "127.0.0.1"
MAX_BODY = 10_000


def make_handler(token: str, port: int, start_path: str = ""):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    page = (UI_DIR / "index.html").read_text("utf-8").replace("__FIST_TOKEN__", token)
    page = page.replace("__FIST_START_PATH__",
                        json.dumps(start_path, ensure_ascii=False)[1:-1].replace("</", "<\\/"))
    last: dict = {}

    class Handler(BaseHTTPRequestHandler):
        server_version = "FISTGuard"

        def log_message(self, *args):
            pass

        def _send(self, code, body: bytes, ctype: str, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _host_ok(self):
            return self.headers.get("Host", "") in allowed_hosts

        def _token_ok(self, query_token: str = ""):
            got = self.headers.get("X-FIST-Token", "") or query_token
            return secrets.compare_digest(got, token)

        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "forbidden host"})
            if self.path in ("/", "/index.html"):
                return self._send(200, page.encode(), "text/html; charset=utf-8")
            if self.path.startswith("/api/export/html"):
                qt = self.path.split("?t=")[-1] if "?t=" in self.path else ""
                if not self._token_ok(qt):
                    return self._json(403, {"error": "bad token"})
                if "result" not in last:
                    return self._json(404, {"error": "нет результата"})
                return self._send(200, to_html(last["result"]).encode(), "text/html; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="fist-guard-report.html"'})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok() or not self._token_ok():
                return self._json(403, {"error": "forbidden"})
            if self.path != "/api/scan":
                return self._json(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._json(413, {"error": "too large"})
            try:
                path = str(json.loads(self.rfile.read(n) or b"{}").get("path", "")).strip()
            except (ValueError, AttributeError):
                return self._json(400, {"error": "Неверный запрос"})
            if not path:
                return self._json(400, {"error": "Укажите путь к папке"})
            try:
                res = scan(path)
            except ScanError as e:
                return self._json(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": f"Ошибка проверки: {type(e).__name__}"})
            last["result"] = res
            return self._json(200, res.to_dict())

    return Handler


def create_server(port: int = 8765, start_path: str = ""):
    token = secrets.token_urlsafe(24)
    return ThreadingHTTPServer((HOST, port), make_handler(token, port, start_path)), token


def serve(port: int = 8765, open_browser: bool = True, start_path: str = "") -> None:
    if start_path:
        start_path = str(Path(start_path).expanduser().resolve())
    httpd, _ = create_server(port, start_path)
    url = f"http://127.0.0.1:{port}/"
    print(f"FIST Guard (демо-версия) открыт: {url}\nРаботает только на этом компьютере. Остановить: Ctrl+C")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        httpd.server_close()
