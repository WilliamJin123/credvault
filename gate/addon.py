# credvault key gate: mitmproxy addon. Swaps a sentinel for its real key on the key's hosts only.
# fd 3 in: the map (JSON, read once). fd 4 out: one JSON line per sentinel seen. Values never go out.
import json
import os
import re

from mitmproxy import http

SENTINEL = re.compile(r"wsk_[a-z2-7]{28}")
BODY_MAX = 1 << 20

with os.fdopen(3, "r") as f:
    _MAP = json.load(f)
PORTS = {int(p): r for p, r in _MAP["ports"].items()}
KEYS = _MAP["keys"]  # sentinel -> {role, name, value, hosts}
_events = os.fdopen(4, "w", buffering=1)


def _host_ok(host: str, hosts: list) -> bool:
    for h in hosts:
        if h == host or (h.startswith("*.") and host.endswith(h[1:])):
            return True
    return False


def _emit(**e) -> None:
    try:
        _events.write(json.dumps(e) + "\n")
    except (BrokenPipeError, ValueError):
        pass


def _deny(flow: http.HTTPFlow, why: str) -> None:
    flow.response = http.Response.make(403, f"credvault gate: {why}\n".encode(), {"content-type": "text/plain"})


def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    role = PORTS.get(flow.client_conn.sockname[1]) if flow.client_conn.sockname else None
    host = req.pretty_host.lower()
    path = req.path.split("?", 1)[0]

    found = set()
    for _, v in req.headers.items(multi=True):
        found.update(SENTINEL.findall(v))
    for _, v in req.query.items(multi=True):
        found.update(SENTINEL.findall(v))
    body = None
    if req.raw_content and len(req.raw_content) <= BODY_MAX:
        try:
            body = req.get_text(strict=False)
        except ValueError:
            body = None
        if body:
            found.update(SENTINEL.findall(body))
    if not found:
        return

    for s in found:
        k = KEYS.get(s)
        why = None
        if k is None:
            why = "unknown sentinel"
        elif k["role"] != role:
            why = "key not for this role"
        elif not _host_ok(host, k["hosts"]):
            why = "key not for this host"
        if why:
            _emit(t="deny", name=(k or {}).get("name"), key_role=(k or {}).get("role"), role=role, host=host, path=path, why=why)
            _deny(flow, why)
            return

    for s in found:
        k = KEYS[s]
        for name, v in list(req.headers.items(multi=True)):
            if s in v:
                req.headers.set_all(name, [x.replace(s, k["value"]) for x in req.headers.get_all(name)])
        for name in list(req.query.keys()):
            vals = req.query.get_all(name)
            if any(s in x for x in vals):
                req.query.set_all(name, [x.replace(s, k["value"]) for x in vals])
        if body and s in body:
            body = body.replace(s, k["value"])
            req.set_text(body)
        _emit(t="use", name=k["name"], key_role=k["role"], role=role, host=host, path=path)
