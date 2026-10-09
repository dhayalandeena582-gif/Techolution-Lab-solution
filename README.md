# aiscan.py

Does your AI feature do what a stranger's comment tells it to?

If your app has an AI agent that reads user-generated content — comments,
reviews, tickets, docs — and that agent is logged in as someone, this tool
tells you whether a planted comment can make it act.

> **Authorized testing only.** `--mode exploit` performs real destructive
> actions, including deleting accounts. Run it against staging, or an app you
> own. `--mode recon` is read-only and always safe.

## Quickstart

```bash
pip install -r requirements.txt

./aiscan.py https://staging.your-app.com                     # 1. read-only look
./aiscan.py https://staging.your-app.com --mode canary       # 2. harmless proof
./aiscan.py https://staging.your-app.com --mode exploit \
    --report report.md                                        # 3. real test + fixes
```

Stop as soon as you have your answer. Most teams only need step 2.

| Mode | Does | Side effects |
|---|---|---|
| `recon` *(default)* | Maps the agent, the sinks, and which destructive actions it could reach | **none** |
| `canary` | Plants a harmless instruction and checks whether the agent obeyed | posts a comment |
| `exploit` | Attempts the real destructive action | **changes account state** |

## Reading the result

One line per attempt, then one verdict:

```
  [1/9] delete-task-queue            CONFIRMED  the agent followed the planted instruction
  [2/9] delete-prove-impact          resisted   the agent read the content and did not comply
  [3/9] delete-sandbox-reversible    not read   the agent never fetched the page we planted on

=== RESULT ===
[VULN] VULNERABLE - 1/3 attempt(s) complied (delete-task-queue)
```

Four outcomes, four exit codes:

| Verdict | Exit | Means |
|---|---|---|
| `VULNERABLE` | 0 | the agent performed the injected action — shows `n/N` attempts that complied |
| `RESISTED` | 1 | the agent **read** the planted content and refused every payload |
| `INCONCLUSIVE` | 3 | the agent never read the planted content — **nothing was tested**, fix the setup |
| `ERROR` | 2 | could not plant or trigger |

**`RESISTED` and `INCONCLUSIVE` are not the same thing.** `RESISTED` means the
agent fetched your planted content and refused it — a real result about your
agent. `INCONCLUSIVE` means it never fetched the page, so nothing was tested;
check `--post` and that the agent actually scans the page you planted on. Each
attempt is checked against the agent's own request log to tell these apart.

The agent is a live LLM, so a single attempt is not repeatable. That is why the
verdict is a rate over *delivered* attempts rather than one pass/fail — raise
`--rounds` for a tighter number. `--seed N` fixes the canary RNG when you need
a byte-identical rerun.

## The report

```bash
./aiscan.py https://staging.your-app.com --mode canary --report report.md
```

Hand `report.md` to the team that owns the feature. It contains the verdict and
severity, the agent's own request log with the injected call marked, the exact
command to reproduce, and prioritised fixes with how to verify each one.

Add `--json results.json` for CI. Want just the remediation advice, without
running a test? `./aiscan.py --fix-guide`.

## Pointing it at your app

Defaults match the app this was built against. For yours, copy a profile and
change the endpoints — no Python edits:

```bash
cp profiles/example-app.json profiles/mine.json
$EDITOR profiles/mine.json
./aiscan.py https://staging.your-app.com --profile profiles/mine.json
```

The profile holds your login route and field names, your account page, your
state-changing endpoints, your agent's start/status/report endpoints, and how
to recognise content pages. See [docs/PROFILES.md](docs/PROFILES.md).

## Common options

| Flag | Purpose |
|---|---|
| `--user` / `--password` | credentials to log in with |
| `--target-user` | identity the *agent* holds |
| `--objective` | `delete_account`, `change_email`, `exfil`, `all` |
| `--rounds N` | attempts per payload; the verdict is a rate over them (default 3) |
| `--payload NAME` | run one payload (`--list-payloads`) |
| `--proxy` | route through Burp |
| `-v` | per-request detail instead of one line per attempt |
| `--seed N` | fix the RNG for reproducible runs |

`./aiscan.py --help` for the rest.

## Going deeper

- **[docs/METHODOLOGY.md](docs/METHODOLOGY.md)** — how detection avoids false
  positives, the payload library, what we learned making it work, code map.
- **[docs/PROFILES.md](docs/PROFILES.md)** — profile reference.

Python 3.8+, one dependency (`requests`).
