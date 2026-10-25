#!/usr/bin/env python3
"""App-side example for per-user mode: issue a signed session ID for a signed-in
user and call the agent with it.

Run this on your app server only. It holds the agent API key and the session
secret. End users never see either, and never set X-AgentRun-Session-Id
themselves: your app authenticates the user first, then picks the session.

Session ID format (must match hook_service/hook.py):
    <user>-<nonce>-<mac>, mac = HMAC-SHA256(secret, "<user>-<nonce>")[:32 hex]
The nonce is random, so session IDs cannot be guessed. Keep them private:
a leaked session ID can be replayed by anyone who also holds the agent API key.

Env: AGENT_URL_USER, AGENT_API_KEY, AGENT_MODEL, HOOK_SESSION_SECRET
Usage: python3 scripts/session_gateway.py alice "Show me ticket T-1004."
"""
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import urllib.request

USER_RE_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789")


def sign_session(user, nonce, secret):
    mac = hmac.new(secret.encode(), f"{user}-{nonce}".encode(),
                   hashlib.sha256).hexdigest()[:32]
    return f"{user}-{nonce}-{mac}"


def issue_session(user, secret):
    """New random session for an authenticated user. Users are [a-z0-9]{1,32}."""
    if not user or len(user) > 32 or set(user) - USER_RE_CHARS:
        raise ValueError("user id must be 1-32 chars of a-z and 0-9")
    if not secret:
        raise ValueError("HOOK_SESSION_SECRET is not set")
    return sign_session(user, secrets.token_hex(16), secret)


def ask_agent(agent_url, api_key, model, session_id, prompt, timeout=120):
    """One chat turn in the given session. Returns the reply text."""
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    hdr = {"Content-Type": "application/json", "X-AgentRun-Session-Id": session_id}
    if api_key:
        hdr["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(agent_url.rstrip("/") + "/chat/completions",
                                 data=body, headers=hdr)
    with urllib.request.urlopen(req, timeout=timeout,
                                context=ssl.create_default_context()) as r:
        resp = json.loads(r.read().decode())
    try:
        return resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(resp)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    user, prompt = sys.argv[1], sys.argv[2]
    sid = issue_session(user, os.environ.get("HOOK_SESSION_SECRET", ""))
    print(ask_agent(os.environ["AGENT_URL_USER"], os.environ.get("AGENT_API_KEY", ""),
                    os.environ.get("AGENT_MODEL", "qwen3.8-max"), sid, prompt))
