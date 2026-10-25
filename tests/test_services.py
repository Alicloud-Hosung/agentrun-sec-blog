"""Local tests for the hook service and ticket MCP server.

Usage: python3 tests/test_services.py   (starts both services on localhost)
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PKG = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def call(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})},
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def clean_env():
    """Inherited env without hook/server settings, so tests do not depend on your shell or .env."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("HOOK_", "MCP_AUTH_"))}


def start(script, port, env):
    e = dict(clean_env(), PORT=str(port), FC_SERVER_PORT=str(port), **env)
    p = subprocess.Popen([sys.executable, "-I", script], env=e,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
            break
        except urllib.error.HTTPError:
            break  # 401 means it is up
        except Exception:
            time.sleep(0.1)
    return p


UPTOK = "tok-7f3a9c"  # distinctive, so "token not leaked" checks cannot match by accident
b64 = lambda o: base64.b64encode(json.dumps(o).encode()).decode()
unb64 = lambda s: json.loads(base64.b64decode(s).decode())
TOOLS = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [
    {"name": "list_tickets"}, {"name": "get_ticket"}, {"name": "delete_ticket"}]}}


def pre(name, args, role="user", extra=None):
    body = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": args}}
    return {"event": "PRE_CALL_TOOL", "toolname": "ticketdesk",
            "request": {"headers": {"X-User-Role": role, **(extra or {})}, "body": b64(body)}}


procs = []
try:
    # ---------- 1. hook, defaults (as measured: no secret)
    procs.append(start(f"{PKG}/hook_service/hook.py", 18101, {}))
    H = "http://127.0.0.1:18101"
    s, o = call(H + "/hook", {"event": "POST_LIST_TOOLS", "request": {"headers": {"X-User-Role": "user"}},
                              "response": {"body": b64(TOOLS)}})
    names = [t["name"] for t in unb64(o["response"]["body"])["result"]["tools"]]
    check("list: user loses delete_ticket", names == ["list_tickets", "get_ticket"])
    s, o = call(H + "/hook", {"event": "POST_LIST_TOOLS", "request": {"headers": {"X-User-Role": "admin"}},
                              "response": {"body": b64(TOOLS)}})
    check("list: admin unchanged", o == {})
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"}))
    check("pre: user cross-customer T-1002 blocked 403",
          o.get("response", {}).get("status_code") == 403 and
          "Globex" in unb64(o["response"]["body"])["error"]["message"])
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}))
    check("pre: user own ticket T-1004 passes", o == {})
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1004"}))
    check("pre: user delete blocked", o.get("response", {}).get("status_code") == 403)
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1002"}, role="admin"))
    check("pre: admin delete passes", o == {})
    s, o = call(H + "/hook", pre("list_tickets", {"customer": "Initech LLC"}))
    check("pre: user list other customer blocked", o.get("response", {}).get("status_code") == 403)
    bad = {"event": "PRE_CALL_TOOL", "request": {"headers": {"X-User-Role": "user"},
           "body": b64({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": "oops"})}}
    s, o = call(H + "/hook", bad)
    check("pre: malformed params -> fail-closed 403", o.get("response", {}).get("status_code") == 403)
    res = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text",
           "text": "Contact on file: phone +82-10-5555-0101, alt +1-555-0100, "
                   "email jane.doe@acme-example.com."}]}}
    s, o = call(H + "/hook", {"event": "POST_CALL_TOOL", "request": {"headers": {"X-User-Role": "user"}},
                              "response": {"body": b64(res)}})
    out = unb64(o["response"]["body"])["result"]
    txt = out["content"][0]["text"]
    check("post: phone/email masked + audit_id",
          "[PHONE-MASKED]" in txt and "[EMAIL-MASKED]" in txt and "5555" not in txt
          and "0100" not in txt and "jane.doe" not in txt and out.get("audit_id"))
    plain = "Ticket T-1002 was opened on 2026-10-20 and updated 2026-10-21."
    s, o = call(H + "/hook", {"event": "POST_CALL_TOOL", "request": {"headers": {"X-User-Role": "user"}},
                              "response": {"body": b64({"jsonrpc": "2.0", "id": 4, "result": {
                                  "content": [{"type": "text", "text": plain}]}})}})
    check("post: ticket IDs and dates are not masked",
          unb64(o["response"]["body"])["result"]["content"][0]["text"] == plain)
    s, o = call(H + "/hook", {"event": "POST_LIST_TOOLS", "request": {"headers": {}},
                              "response": {"body": b64(TOOLS)}})
    names = [t["name"] for t in unb64(o["response"]["body"])["result"]["tools"]]
    check("list: no role header -> treated as general user", "delete_ticket" not in names)
    s, o = call(H + "/hook", {"event": "PRE_CALL_TOOL", "request": {"headers": {}, "body": b64(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
         "params": {"name": "get_ticket", "arguments": {"ticket_id": "T-1002"}}})}})
    check("pre: no role header -> treated as general user (blocked)",
          o.get("response", {}).get("status_code") == 403)
    s, o = call(H + "/hooklogs")
    check("hooklogs open without secret (default)", s == 200)
    procs[-1].terminate()

    # ---------- 2. hook with shared secret
    procs.append(start(f"{PKG}/hook_service/hook.py", 18102, {"HOOK_SHARED_SECRET": "s3cret"}))
    H = "http://127.0.0.1:18102"
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1004"}))
    check("secret: missing -> 401", s == 401)
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1004"}, extra={"X-Hook-Secret": "s3cret"}))
    check("secret: in payload headers -> processed (403 deny)", s == 200 and o["response"]["status_code"] == 403)
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1004"}), headers={"X-Hook-Secret": "s3cret"})
    check("secret: in HTTP header -> processed", s == 200 and o["response"]["status_code"] == 403)
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}, extra={"X-Hook-Secret": "wrong"}))
    check("secret: wrong -> 401", s == 401)
    s, o = call(H + "/hooklogs")
    check("secret: hooklogs without secret -> 401", s == 401)
    procs[-1].terminate()

    # ---------- 3. ticket server, default and with token
    procs.append(start(f"{PKG}/mcp_server/server.py", 18103, {}))
    M = "http://127.0.0.1:18103"
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    check("server default: tools/list works", s == 200 and len(o["result"]["tools"]) == 3)
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "delete_ticket", "arguments": {"ticket_id": "T-1002"}}})
    check("server default: direct delete works (the bypass)", s == 200 and "deleted" in json.dumps(o))
    procs[-1].terminate()
    procs.append(start(f"{PKG}/mcp_server/server.py", 18104, {"MCP_AUTH_TOKEN": "tok"}))
    M = "http://127.0.0.1:18104"
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "delete_ticket", "arguments": {"ticket_id": "T-1002"}}})
    check("server token: direct delete without token -> 401", s == 401)
    s, o = call(M + "/logs")
    check("server token: /logs without token -> 401", s == 401)
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
                headers={"Authorization": "Bearer tok"})
    check("server token: with token works", s == 200 and len(o["result"]["tools"]) == 3)
    procs[-1].terminate()

    # ---------- 4. hook token injection (HOOK_UPSTREAM_TOKEN)
    e = dict(clean_env(), PORT="18105", FC_SERVER_PORT="18105", HOOK_UPSTREAM_TOKEN=UPTOK)
    r = subprocess.run([sys.executable, "-I", f"{PKG}/hook_service/hook.py"], env=e,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=10)
    check("inject: refuses to start without HOOK_SHARED_SECRET",
          r.returncode != 0 and "requires HOOK_SHARED_SECRET" in r.stderr)
    procs.append(start(f"{PKG}/hook_service/hook.py", 18106,
                       {"HOOK_SHARED_SECRET": "s3cret", "HOOK_UPSTREAM_TOKEN": UPTOK}))
    H = "http://127.0.0.1:18106"
    S = {"X-Hook-Secret": "s3cret"}
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}, extra=S))
    check("inject: allowed call gets Authorization header",
          o == {"request": {"headers": {"Authorization": f"Bearer {UPTOK}"}}})
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"}, extra=S))
    check("inject: blocked call gets 403 and no token",
          o.get("response", {}).get("status_code") == 403 and "request" not in o
          and UPTOK not in json.dumps(o))
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1004"}, extra=S))
    check("inject: user delete blocked, no token", o.get("response", {}).get("status_code") == 403
          and "request" not in o)
    s, o = call(H + "/hook", pre("delete_ticket", {"ticket_id": "T-1002"}, role="admin", extra=S))
    check("inject: admin delete gets token",
          o.get("request", {}).get("headers", {}).get("Authorization") == f"Bearer {UPTOK}")
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}))
    check("inject: hook without secret -> 401 (token not handed out)", s == 401 and UPTOK not in json.dumps(o))
    procs[-1].terminate()

    # ---------- 5. ticket server, MCP_AUTH_SCOPE=tools/call
    procs.append(start(f"{PKG}/mcp_server/server.py", 18107,
                       {"MCP_AUTH_TOKEN": UPTOK, "MCP_AUTH_SCOPE": "tools/call"}))
    M = "http://127.0.0.1:18107"
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    check("scope: initialize open", s == 200 and "result" in o)
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    check("scope: tools/list open", s == 200 and len(o["result"]["tools"]) == 3)
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                             "params": {"name": "delete_ticket", "arguments": {"ticket_id": "T-1002"}}})
    check("scope: direct tools/call without token -> 401", s == 401)
    s, o = call(M + "/mcp", {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": "get_ticket", "arguments": {"ticket_id": "T-1004"}}},
                headers={"Authorization": f"Bearer {UPTOK}"})
    check("scope: tools/call with injected token works", s == 200 and "T-1004" in json.dumps(o))
    s, o = call(M + "/logs")
    check("scope: /logs still needs token", s == 401)
    s, o = call(M + "/reset", {})
    check("scope: /reset still needs token", s == 401)
    procs[-1].terminate()

    # ---------- 6. hook + server together on the real dataset
    procs.append(start(f"{PKG}/mcp_server/server.py", 18108, {}))
    procs.append(start(f"{PKG}/hook_service/hook.py", 18109, {}))
    M, H = "http://127.0.0.1:18108", "http://127.0.0.1:18109"

    def get_ticket(tid):
        return call(M + "/mcp", {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                 "params": {"name": "get_ticket", "arguments": {"ticket_id": tid}}})[1]

    # every phone and email the server can return must come out of Post-Call Tool masked
    contacts, leaked = 0, []
    for n in range(1001, 1031):
        res = get_ticket(f"T-{n}")
        rec = json.loads(res["result"]["content"][0]["text"])
        secrets = [v for v in (rec.get("phone"), rec.get("email")) if v]
        contacts += len(secrets)
        s, o = call(H + "/hook", {"event": "POST_CALL_TOOL", "request": {"headers": {"X-User-Role": "user"}},
                                  "response": {"body": b64(res)}})
        text = json.dumps(unb64(o["response"]["body"]))
        leaked += [v for v in secrets if v in text]
    check(f"mask: every phone and email in the dataset is masked ({contacts} found)",
          contacts > 0 and not leaked)

    # odd ticket ID spellings: either the hook blocks, or the server finds nothing
    odd = ["t-1002", " T-1002", "T-1002 ", "T-01002", "T-1002\n", "T‑1002", "T-1002x", "T-1002,T-1004"]
    bad = []
    for tid in odd:
        s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": tid}))
        if o == {}:  # hook let it through, so check what the server actually returns
            txt = json.dumps(get_ticket(tid))
            if "Globex" in txt or "Initech" in txt:
                bad.append(tid)
    check("pre + server: odd ticket IDs never return another customer's ticket", not bad)
    procs[-1].terminate()
    procs[-2].terminate()

    # ---------- 7. per-user mode: one shared tool, scope from a signed session ID
    SS = "sess-secret"

    def sid(user, nonce="0123456789abcdef0123456789abcdef", secret=SS):
        mac = hmac.new(secret.encode(), f"{user}-{nonce}".encode(),
                       hashlib.sha256).hexdigest()[:32]
        return f"{user}-{nonce}-{mac}"

    def bag(s):  # how AgentRun hands the session ID to the hook
        return {"Baggage": f"gen_ai.session.id={s},other=1"}

    def blocked(o):
        return o.get("response", {}).get("status_code") == 403

    procs.append(start(f"{PKG}/hook_service/hook.py", 18110,
                       {"HOOK_SESSION_SECRET": SS,
                        "HOOK_USER_SCOPES": json.dumps({"alice": "Acme Corp", "bob": "Globex Inc"})}))
    H = "http://127.0.0.1:18110"
    s, o1 = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}, extra=bag(sid("alice"))))
    s, o2 = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"}, extra=bag(sid("alice"))))
    check("user: alice reads Acme, not Globex", o1 == {} and blocked(o2))
    s, o1 = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"}, extra=bag(sid("bob"))))
    s, o2 = call(H + "/hook", pre("list_tickets", {"customer": "Acme Corp"}, extra=bag(sid("bob"))))
    check("user: bob reads Globex, not Acme (same tool)", o1 == {} and blocked(o2))
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}))
    check("user: no session -> blocked", blocked(o))
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"},
                                 extra=bag("bob-0123456789abcdef0123456789abcdef-" + "0" * 32)))
    check("user: forged signature -> blocked", blocked(o))
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"},
                                 extra=bag(sid("bob", secret="not-the-secret"))))
    check("user: signed with another secret -> blocked", blocked(o))
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"}, extra=bag(sid("mallory"))))
    check("user: valid signature but unknown user -> blocked", blocked(o))
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "t-1004"}, extra=bag(sid("alice"))))
    check("user: unknown ticket owner -> blocked", blocked(o))
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1004"},
                                 extra={"X-AgentRun-Session-Id": sid("alice")}))
    check("user: X-AgentRun-Session-Id header also accepted", o == {})
    s, o = call(H + "/hook", pre("get_ticket", {"ticket_id": "T-1002"}, role="admin",
                                 extra=bag(sid("alice"))))
    check("user: scope follows the user, not the role header", blocked(o))
finally:
    for p in procs:
        p.terminate()

print(f"\n{sum(ok for _, ok in results)}/{len(results)} passed")
sys.exit(0 if all(ok for _, ok in results) else 1)
