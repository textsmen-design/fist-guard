"""Локальный веб-интерфейс: работает, но защищён от чужих страниц."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from fist_guard.server import create_server


@pytest.fixture
def server():
    httpd, token = create_server(port=0)
    port = httpd.server_address[1]
    # пересоздаём с реальным портом, чтобы проверка Host совпадала
    httpd.server_close()
    httpd, token = create_server(port=port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", token, port
    httpd.shutdown()
    httpd.server_close()


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # без системного прокси


def req(url, data=None, headers=None, method=None):
    r = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                               headers=headers or {}, method=method)
    try:
        with _OPENER.open(r, timeout=20) as resp:
            return resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def test_binds_only_localhost(server):
    base, _, _ = server
    assert base.startswith("http://127.0.0.1:")


def test_index_page(server):
    base, token, _ = server
    code, body, headers = req(base + "/")
    assert code == 200 and "FIST Guard" in body and token in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_scan_requires_token(server, demo_dir):
    base, _, _ = server
    code, _, _ = req(base + "/api/scan", {"path": str(demo_dir)}, {"Content-Type": "application/json"})
    assert code == 403


def test_foreign_host_rejected(server, demo_dir):
    base, token, _ = server
    code, _, _ = req(base + "/api/scan", {"path": str(demo_dir)},
                     {"X-FIST-Token": token, "Host": "evil.example:80"})
    assert code == 403


def test_scan_ok_and_export(server, demo_dir):
    base, token, _ = server
    code, body, _ = req(base + "/api/scan", {"path": str(demo_dir)}, {"X-FIST-Token": token})
    assert code == 200
    data = json.loads(body)
    assert data["verdict"] == "RED"
    code, html, headers = req(base + "/api/export/html?t=" + token)
    assert code == 200 and "FIST Guard" in html and "attachment" in headers["Content-Disposition"]


def test_export_requires_token(server):
    base, _, _ = server
    assert req(base + "/api/export/html")[0] == 403


def test_scan_bad_path(server, tmp_path):
    base, token, _ = server
    code, body, _ = req(base + "/api/scan", {"path": str(tmp_path / "nope")}, {"X-FIST-Token": token})
    assert code == 400 and "не найдена" in json.loads(body)["error"]
