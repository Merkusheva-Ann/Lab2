"""
Запускать ПОСЛЕ применения патчей.
pip install pytest flask
"""
import json
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:5000"


def post(path, payload):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_sqli_bypass_blocked():
    status, body = post("/login", {"username": "admin' -- ", "password": "x"})
    assert status == 401 and not body.get("ok")


def test_sqli_union_blocked():
    inj = "x' UNION SELECT id, username, password FROM users -- "
    status, body = post("/login", {"username": inj, "password": "x"})
    assert status == 401


def test_bruteforce_is_limited():
    codes = []
    for _ in range(10):
        status, _b = post("/login", {"username": "nobody", "password": "bad"})
        codes.append(status)
    assert 429 in codes, f"Нет rate limit: {codes}"


def test_legit_login_still_works():
    status, body = post("/login",
                        {"username": "admin", "password": "S3cr3tAdm1n!"})
    assert status == 200 and body["ok"]
