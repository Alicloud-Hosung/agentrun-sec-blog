#!/usr/bin/env python3
"""Deploy the fake ticket MCP server + hook service to Function Compute (FC 3.0).

Reads credentials ONLY from repo-local .env (gitignored). Creates or updates two
custom-runtime web functions in ap-southeast-1 with an anonymous HTTP trigger and
prints their public URLs (needed for AgentRun MCP remote connection + hook config).

The trigger is anonymous at the FC level, so anyone who learns the ticket server
URL can call its tools directly, bypassing the hooks. To close that path, set in
.env: HOOK_SHARED_SECRET, HOOK_UPSTREAM_TOKEN and MCP_AUTH_TOKEN (same value as
HOOK_UPSTREAM_TOKEN) with MCP_AUTH_SCOPE=tools/call. See README "Security notes".

Usage: bash scripts/build_zips.sh && python3 scripts/deploy_fc.py
"""
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for line in open(os.path.join(ROOT, ".env")):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

AK = os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"]
SK = os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"]
UID = os.environ["ALIBABA_CLOUD_UID"]
REGION = os.environ.get("REGION", "ap-southeast-1")

from alibabacloud_fc20230330 import models as m
from alibabacloud_fc20230330.client import Client
from alibabacloud_tea_openapi import models as om

cfg = om.Config(access_key_id=AK, access_key_secret=SK,
                endpoint=f"{UID}.{REGION}.fc.aliyuncs.com",
                read_timeout=60000, connect_timeout=30000)
cli = Client(cfg)

def _opt(*keys):
    return {k: os.environ[k] for k in keys if os.environ.get(k)}


FUNCS = [
    {"name": "sec-ticket-mcp", "zip": "dist/ticket-mcp.zip",
     "cmd": ["python3", "server.py"], "env": _opt("MCP_AUTH_TOKEN", "MCP_AUTH_SCOPE")},
    {"name": "sec-hook-svc", "zip": "dist/hook-service.zip",
     "cmd": ["python3", "hook.py"],
     "env": {"HOOK_LIST_FILTER": "on", "HOOK_PRE_BLOCK": "on",
             "HOOK_POST_MASK": "on", "HOOK_FAIL_CLOSED": "on",
             **_opt("HOOK_SHARED_SECRET", "HOOK_UPSTREAM_TOKEN",
                    "HOOK_SESSION_SECRET", "HOOK_USER_SCOPES")}},
]


def b64zip(rel):
    with open(os.path.join(ROOT, rel), "rb") as f:
        return base64.b64encode(f.read()).decode()


def ensure(fn):
    code = m.InputCodeLocation(zip_file=b64zip(fn["zip"]))
    crc = m.CustomRuntimeConfig(command=fn["cmd"], port=9000)
    common = dict(runtime="custom.debian10", handler="index.handler",
                  memory_size=512, cpu=0.35, disk_size=512, timeout=120,
                  # one instance serves up to 20 requests at once, so a sequential
                  # eval stays on a single instance and its in-memory log stays whole
                  instance_concurrency=20,
                  code=code, custom_runtime_config=crc,
                  environment_variables=fn["env"],
                  description="AgentRun security hands-on (fake data only)")
    try:
        cli.get_function(fn["name"], m.GetFunctionRequest())
        cli.update_function(fn["name"], m.UpdateFunctionRequest(
            body=m.UpdateFunctionInput(**common)))
        print(f"[update] {fn['name']}")
    except Exception as e:
        if "FunctionNotFound" in str(e) or "404" in str(e):
            cli.create_function(m.CreateFunctionRequest(
                body=m.CreateFunctionInput(function_name=fn["name"], **common)))
            print(f"[create] {fn['name']}")
        else:
            raise
    # ensure anonymous http trigger (update existing to anonymous, else create)
    anon = json.dumps({"authType": "anonymous",
                       "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                       "disableURLInternet": False})
    try:
        tr = cli.list_triggers(fn["name"], m.ListTriggersRequest())
        names = [t.trigger_name for t in (tr.body.triggers or [])]
        http = [t for t in (tr.body.triggers or []) if t.trigger_type == "http"]
        if http:
            cli.update_trigger(fn["name"], http[0].trigger_name,
                               m.UpdateTriggerRequest(
                                   body=m.UpdateTriggerInput(
                                       trigger_config=anon)))
            print(f"[trigger-anon] {fn['name']}/{http[0].trigger_name}")
        else:
            cli.create_trigger(fn["name"], m.CreateTriggerRequest(
                body=m.CreateTriggerInput(
                    trigger_name="httpAnon", trigger_type="http",
                    trigger_config=anon)))
            print(f"[trigger-create] {fn['name']}")
    except Exception as e:
        print(f"[trigger-warn] {fn['name']}: {e}")
    print(f"URL https://{fn['name']}.{UID}.{REGION}.fcapp.run/")


for fn in FUNCS:
    ensure(fn)
print("deploy done")
