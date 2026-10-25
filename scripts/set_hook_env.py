#!/usr/bin/env python3
"""Switch the hook service defense layers for a given measurement layer.

Usage: python3 scripts/set_hook_env.py L0|L1|L2|L3|L4
  L0/L1 : all hooks off   (L1 differs only by agent system prompt)
  L2    : POST_LIST_TOOLS on
  L3    : + PRE_CALL_TOOL on
  L4    : + POST_CALL_TOOL on
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for line in open(os.path.join(ROOT, ".env")):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

layer = (sys.argv[1] if len(sys.argv) > 1 else "L4").upper()
MATRIX = {
    "L0": ("off", "off", "off"),
    "L1": ("off", "off", "off"),
    "L2": ("on", "off", "off"),
    "L3": ("on", "on", "off"),
    "L4": ("on", "on", "on"),
}
lst, pre, post = MATRIX[layer]

from alibabacloud_fc20230330 import models as m
from alibabacloud_fc20230330.client import Client
from alibabacloud_tea_openapi import models as om

UID = os.environ["ALIBABA_CLOUD_UID"]
R = os.environ.get("REGION", "ap-southeast-1")
cfg = om.Config(access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
                access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
                endpoint=f"{UID}.{R}.fc.aliyuncs.com",
                read_timeout=60000, connect_timeout=30000)
cli = Client(cfg)
import time as _t
for attempt in range(5):
    try:
        # merge with the current env so secrets such as HOOK_SHARED_SECRET survive
        cur = cli.get_function("sec-hook-svc", m.GetFunctionRequest())
        env = dict(cur.body.environment_variables or {})
        env.update({"HOOK_LIST_FILTER": lst, "HOOK_PRE_BLOCK": pre,
                    "HOOK_POST_MASK": post})
        cli.update_function("sec-hook-svc", m.UpdateFunctionRequest(
            body=m.UpdateFunctionInput(environment_variables=env)))
        break
    except Exception as e:
        if attempt == 4:
            raise
        print("retry", attempt, str(e)[:80])
        _t.sleep(10)
print(f"hook env set for {layer}: list={lst} pre={pre} post={post}")
