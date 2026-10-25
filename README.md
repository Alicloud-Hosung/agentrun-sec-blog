# AgentRun MCP Tool Hook Security Demo

Put a security layer on the **tool side** of an AI agent, so that what the agent can do is enforced by code instead of being left to the model.

This repository is the companion code for the blog post **Does "DO NOT" Work on AI Agents? Securing MCP Tools with AgentRun** ([English](https://www.alibabacloud.com/blog/603668) / [한국어](https://www.alibabacloud.com/blog/603669)). It contains a fake support-ticket MCP server, a hook service for Alibaba Cloud AgentRun, deploy and evaluation scripts, and local tests.

> **All data is fake.** Do not point this code at real systems or real customer data.

![Architecture](docs/architecture.png)

## What it does

When an AgentRun agent calls an MCP tool, the AgentRun MCP proxy calls this hook service before forwarding the request and after receiving the response.

| Hook (console tab) | Event | What this demo does |
|---|---|---|
| List Tools Trailer | `POST_LIST_TOOLS` | Removes `delete_ticket` from the tool list that general users see |
| Call Tool Preamble | `PRE_CALL_TOOL` | Checks role (or, in per-user mode, the signed-in user) and ticket owner right before each call and blocks out-of-scope calls (403). Optionally attaches an upstream token to allowed calls |
| Post-Call Tool | `POST_CALL_TOOL` | Masks phone numbers and emails in the response and adds an `audit_id` |

The blocking decisions do not depend on spotting injection text. They only ask structural questions: may this role use this tool, who owns this ticket, does this response contain contact data.

## Results from the blog

Measured in October 2026 (Singapore, ap-southeast-1) with qwen3.8-max and qwen3.8-flash: 30 attack tasks, 20 normal tasks, 900 runs in total. Out-of-scope access and deletions are graded from the ticket server's call log, not from the agent's answer. Contact exposure (A2) is graded from the answer.

| Layer | What it adds | A2 contact request<br>(max / flash) | A3 out-of-scope access<br>(max / flash) |
|---|---|---|---|
| L0 | No defense | 93.3% / 100% | 80.0% / 86.7% |
| L1 | Four system prompt rules | 0% / 0% | 13.3% / 20.0% |
| L2 | L1 + hide delete tool | 0% / 0% | 20.0% / 10.0% |
| L3 | L2 + pre-call role and owner check | 0% / 0% | **0% / 0%** |
| L4 | L3 + masking and audit ID | 0% / 0% | **0% / 0%** |

- A1 (a delete instruction hidden in a ticket body) was 0% at every layer on both models.
- At L1, the requests that still leaked were by ticket ID alone ("show me T-1002"). The owner is only known after the ticket is fetched, so a prompt rule has nothing to decide with.
- Normal-task success (an answer without an error or a block) was 100% at every layer on both models.
- L0 and L1 were run 3 times per task, L2 to L4 once. See the blog for details and limitations.

![Attack success by layer](docs/attack-success-by-layer.png)

## Per-user mode

One agent shared by several users, each with their own scope. The app server signs the user in, issues a signed session ID and sends it as `X-AgentRun-Session-Id`. AgentRun passes it to the hook as `gen_ai.session.id` in the Baggage header. The hook verifies the signature and applies that user's scope.

```
session ID = <user>-<nonce>-<mac>
mac        = first 32 hex chars of HMAC-SHA256(HOOK_SESSION_SECRET, "<user>-<nonce>")
```

| Variable | Where | Value |
|---|---|---|
| `HOOK_SESSION_SECRET` | hook service and app server | a random secret shared by the two |
| `HOOK_USER_SCOPES` | hook service | JSON map of user to customer, for example `{"alice":"Acme Corp","bob":"Globex Inc"}`. `"*"` means all customers |

With `HOOK_SESSION_SECRET` set, Call Tool Preamble:

- denies the call if the session ID is missing, badly signed, or names a user not in `HOOK_USER_SCOPES`
- takes the scope from the signed user, not from `X-User-Role`. The role still decides who may use `delete_ticket`
- denies `get_ticket` and `list_tickets` when the ticket owner cannot be determined

I left the runtime's Session Fencing setting at its default, Disabled, and the header still reached the hook.

To check which caller identity reaches the hook in your own setup, set `HOOK_DEBUG_HEADERS=on`: the hook logs each header's length and a short hash, never the value.

`scripts/session_gateway.py` is the app-side example. Run it only on your app server: it holds the agent API key and the session secret, and users never set the session header themselves.

```bash
python3 scripts/session_gateway.py alice "Show me ticket T-1004."
```

Measured with qwen3.8-max: two users, five requests each (two for their own customer, three for other customers), 80 runs.

| Condition | Requests for other customers' data | Requests for own customer's data |
|---|---|---|
| Signed session, 3 runs per request | 0 of 18 leaked | 12 of 12 succeeded |
| Forged session | 0 of 6 leaked | all 4 refused |
| No session | 0 of 6 leaked | all 4 refused |
| Control: session check off, role header only | 2 of 6 leaked | 2 of 4 succeeded |

In the control, the hook treats every general user as an Acme Corp rep, so bob (Globex Inc) received Acme tickets and was refused his own.

`eval/eval_users.py` grades each run two ways and counts a leak if either fires: the ticket server's call log, and traces in the agent's answer that only a served ticket could contain. The two agreed on every run. The call log lives in one Function Compute instance's memory, so `/logs` reports an instance ID and the eval compares it before and after each run. It never changed. `scripts/deploy_fc.py` sets instance concurrency to 20 so a sequential eval stays on one instance.

```bash
RUN_LABEL=main REPEATS=3 python3 eval/eval_users.py --reset   # writes results/users_main.csv and *_replies.jsonl
python3 eval/eval_users.py --preflight                        # one call, prints how long it took
python3 eval/eval_users.py --simulate <hook URL>              # local dry run, no agent needed
```

Compare IDs, not names. The hook matches customer names exactly. In a first run the model passed `Globex Inc.` with the sentence's trailing period, and the hook refused bob's own list. It failed safe, but in production compare a fixed-format customer ID.

## Repository layout

| Path | What it is |
|---|---|
| `mcp_server/server.py` | Fake ticket MCP server (Python standard library only, streamable-http). Tools: `list_tickets`, `get_ticket`, `delete_ticket`. 3 fake customers, 30 tickets, fake contact data and hidden instructions in some ticket bodies. Every call is logged at `GET /logs` with the instance ID, and `POST /reset` restores deleted tickets. |
| `hook_service/hook.py` | AgentRun MCP Tool Hook service (standard library only). Implements the three hooks above. Also appends a warning note when known injection phrases appear in a tool response. This is a hint to the model, not a control. |
| `configs/` | MCP tool settings for the general-user and admin tools, and the system prompts for each layer |
| `scripts/build_zips.sh` | Packages both services for Function Compute |
| `scripts/deploy_fc.py` | Deploys both services to Function Compute (custom runtime, Debian 10, port 9000, instance concurrency 20) |
| `scripts/session_gateway.py` | App-side example for per-user mode: issues a signed session ID and calls the agent with it |
| `scripts/set_hook_env.py` | Switches defense layers L0 to L4 by changing the hook's environment variables |
| `eval/eval.py` | Runs tasks against the agent's OpenAI-compatible API and grades them from the server log. Writes `results/results.csv` |
| `eval/tasks.sample.json` | 10 of the 50 tasks. The full attack set is not published |
| `eval/eval_users.py` | Per-user evaluation: signed, forged and missing sessions for each user, graded by call log and by answer text |
| `tests/test_services.py` | Local tests for both services (46 checks) |
| `docs/` | Images used in this README |

## Requirements

- Python 3.9 or later. The two services use only the standard library.
- For `scripts/deploy_fc.py`: `pip install alibabacloud-fc20230330`
- An Alibaba Cloud account with AgentRun and Function Compute. I used the Singapore region.
- A RAM user limited to Function Compute, created only for this demo. Keep its key in `.env` only.

## Quick start

1. **Run the local tests**
   ```bash
   python3 tests/test_services.py
   ```
   All 46 checks should pass. No cloud account is needed for this step.

2. **Configure**
   ```bash
   cp .env.example .env   # then fill it in, and never commit .env
   ```

3. **Deploy both services to Function Compute**
   ```bash
   bash scripts/build_zips.sh && python3 scripts/deploy_fc.py
   ```
   Check: `<ticket server URL>/health` returns `{"status": "ok", "tickets": 30}`.

4. **Register the MCP tool and attach the hooks** (AgentRun console)
   - Tools and Skills > Create Tool > MCP > Remote Connection, with `<ticket server URL>/mcp`
   - Turn on **Enable MCP Agent**. In Hook Configuration, set the hook URL (`<hook URL>/hook`) and the header `X-User-Role: user` on List Tools Trailer, Call Tool Preamble and Post-Call Tool.
   - Create a second tool for admins with `X-User-Role: admin`. See `configs/`.
   - Check: the Agent Status tab shows "3 active hooks are configured".

5. **Create the agents**
   Quick Create one agent per tool (general user, admin) with a prompt from `configs/system-prompts.md`.
   Check: "Show me ticket T-1002." returns a Globex Inc ticket before the hooks are on, and is blocked with Call Tool Preamble on.

6. **Measure**
   ```bash
   python3 scripts/set_hook_env.py L3
   LAYER=L3 python3 eval/eval.py --reset
   ```
   `set_hook_env.py` only switches the hooks. L0 differs from L1 to L4 by the system prompt, so point `AGENT_URL_USER` in `.env` at an agent that uses the matching prompt from `configs/system-prompts.md`. Without `eval/tasks.json`, the script runs the 10 sample tasks.

## Security notes (read before deploying)

The setup measured in the blog used anonymous HTTP triggers and no service-level auth. This release adds optional protections, off by default so that the code matches what was measured, except fail-closed, which is on.

- **Close the direct path to the ticket server.** The FC trigger is anonymous, so anyone who learns the server URL can call `delete_ticket` directly and **bypass the AgentRun proxy and its hooks** (`tests/test_services.py` shows this). What worked on AgentRun (October 2026): the Call Tool Preamble hook returns `{"request": {"headers": {"Authorization": "Bearer <token>"}}}` for every call it allows, the proxy forwards that header, and the server requires it for `tools/call`. Set these together in `.env`:

  | Variable | Where | Value |
  |---|---|---|
  | `HOOK_UPSTREAM_TOKEN` | hook service | a random token |
  | `MCP_AUTH_TOKEN` | ticket server | the same token |
  | `MCP_AUTH_SCOPE` | ticket server | `tools/call` |
  | `HOOK_SHARED_SECRET` | hook service | a random secret (required in this mode) |

  `initialize` has no hook, and injecting at List Tools Pre-check was not tested, so `initialize` and `tools/list` stay open. `/logs` and `/reset` still require the token.
- **Protect the hook endpoint.** With `HOOK_SHARED_SECRET` set, the hook only accepts requests that carry `X-Hook-Secret`. Add that header next to `X-User-Role` in the AgentRun hook settings. It also protects `/hooklogs` and `/health`. Because the upstream token travels in hook responses, the hook refuses to start if `HOOK_UPSTREAM_TOKEN` is set without `HOOK_SHARED_SECRET`.
- **Fail closed.** `HOOK_FAIL_CLOSED` (default `on`): if the Call Tool Preamble logic raises, the call is denied instead of passed through. The list and post hooks still fail open.
- **Do not publish identifiers.** Mask function URLs, hook URLs, account IDs, session IDs and tokens in any screenshot or log you share.

## Limitations

- In the default mode, roles come from a fixed header per tool (`X-User-Role`), so general users and admins use separate agents. Per-user mode tells users apart by a signed session ID and relies on your app server authenticating users. In my tests neither a user header added when calling the agent nor the `user` field in the OpenAI-compatible request body reached the hook, and a Baggage header set by the caller was overwritten by the platform. Alibaba Cloud also has [Agent Identity](https://www.alibabacloud.com/help/en/agentidentity/what-is-agent-identity), which verifies signed-in users at the agent's entrance. If the verified user reaches the hook, it could replace the signed session. I did not get as far as confirming that. Its [permission policies](https://help.aliyun.com/en/agentidentity/agent-permissions-overview) (Cedar) can also allow or deny MCP tool calls by user, tool and tool arguments for MCP services published through AI Gateway. Rules that need a lookup in the source system, such as the owner of a ticket ID, still need code like this hook. Not tested here.
- The runtime lets the caller pick the session with `X-AgentRun-Session-Id` ([AgentRuntime API reference](https://help.aliyun.com/zh/functioncompute/api-agentrun-2025-09-10-struct-agentruntime), in Chinese). The same ID is also the key to the conversation: with another session's ID, a caller using the same API key could pick up that session's history. The signature proves who created a session, but it does not stop a leaked session ID from being reused. Keep the API key on your app server, never let users set this header, and consider adding an expiry time to the signed value.
- Ticket ownership is computed from the fake dataset's rule. In production, look it up in the source system.
- In the default mode, the hook lets a call through when it cannot tell the owner, for example an unknown ticket ID. That is safe here only because the ticket server matches IDs exactly, which `tests/test_services.py` checks. Per-user mode denies such calls, and production setups should too.
- Masking is regex-based and can miss formats it does not know.
- The measurement used fake data, one region and 10 attack phrasings per threat type. The per-user run used two users and one model.

## Cleanup

Delete the two Function Compute functions, the MCP tools and the agents. Then disable the RAM AccessKey and revoke any Model Studio key you created for the demo.

## Disclaimer

This is a personal demo, not an official Alibaba Cloud product or reference architecture. It is provided as is, without warranty.

Author: Hosung Kim, Sr. Technical Account Manager, Alibaba Cloud
