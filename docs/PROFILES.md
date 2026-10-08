# Profiles

A profile is the only thing you change to point `aiscan.py` at a different
application. It is JSON, merged over the built-in defaults, so **include only
the keys that differ**.

```bash
cp profiles/example-app.json profiles/mine.json
$EDITOR profiles/mine.json
./aiscan.py https://staging.your-app.com --profile profiles/mine.json
```

## Reference

| Key | Meaning | Default |
|---|---|---|
| `name` | label shown in output and reports | `default` |
| `login.path` | where credentials are POSTed | `/login` |
| `login.username_field` | form field name | `username` |
| `login.password_field` | form field name | `password` |
| `account_path` | page listing the user's own account controls | `/my-account` |
| `actions.delete_account` | account-deletion endpoint | `/my-account/delete` |
| `actions.change_email` | email-change endpoint | `/my-account/change-email` |
| `agent.start` | POSTed with the page id to launch the agent | `/api/audit/start` |
| `agent.status` | returns `{status, currentTurn, maxTurns}` | `/api/audit/status` |
| `agent.report` | page publishing what the agent did | `/scanresults` |
| `success_marker` | string in the homepage HTML once the objective is achieved; `null` if none | `is-solved` |
| `sink_keywords` | substrings matched against form action URLs to find user-content forms | `["comment","review","feedback","message"]` |
| `content_patterns` | regexes matching links to pages carrying user content | post/product patterns |

## Notes

**`actions` keys are objective names.** `actions.delete_account` is what
`--objective delete_account` targets. The oracle for that objective looks for a
POST to this exact path, and payload text mentioning the default path is
rewritten to yours automatically.

**`success_marker: null`** is fine. Most real apps have no "solved" banner.
Detection then relies entirely on the agent's tool-call log, which is the
stronger signal anyway.

**`agent.report` is the critical one.** Detection works because the agent
publishes the requests it made. If your agent does not expose a per-run
tool-call log, point `agent.report` at whatever transcript it does produce — and
consider exposing one, since it is both how this gets detected and how you would
audit a real incident.

**If your agent has no HTTP control plane**, `agent.start`/`status` will not
apply. Trigger the agent yourself and use `--mode recon` for the surface map;
the plant-and-judge loop needs a programmatic trigger.

## Checking a profile

```bash
./aiscan.py https://staging.your-app.com --profile profiles/mine.json --mode recon
```

Recon is read-only. If it finds your sinks, your agent API and your destructive
actions, the profile is right.
