# Demo 01 — Basic triage

You suspect one of your accounts is showing up in dumps. BREACHWATCH aggregates
three **local** sources you already have on disk and produces a single,
risk-scored triage report — no network, no API keys.

## Sources in this demo

- `hibp_catalog.json` — a slice of the public HIBP breach catalog (metadata only).
- `hibp_accounts.json` — which of *your* emails appeared in which breaches
  (this membership normally comes from the paid HIBP API; here it is a local map).
- `dehashed.json` — a DeHashed-style entries dump.
- `stealer_log.txt` — raw infostealer credential lines (`URL:LOGIN:PASS`).
- `config.json` — ties your identities to the source files above.

## Run it

```bash
python -m breachwatch triage demos/01-basic/config.json
python -m breachwatch triage demos/01-basic/config.json --format json
python -m breachwatch triage demos/01-basic/config.json --min-severity high
```

## What to expect

- The plaintext password from the stealer log for `chris@example.com` scores
  **critical** and drives an URGENT rotate-password action.
- A stale, hashed-only HIBP hit scores lower.
- Duplicate hits across sources are deduped (highest score wins).
- Use `--fail-on high` in cron/CI to get a non-zero exit when something serious
  shows up.
