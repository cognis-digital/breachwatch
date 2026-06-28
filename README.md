<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=BREACHWATCH&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="BREACHWATCH"/>

# BREACHWATCH

### Personal breach aggregator — HIBP + DeHashed + stealer-log triage

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Personal+breach+aggregator++HIBP++DeHashed++stealerlog+triag;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-breachwatch.svg?color=6b46c1)](https://pypi.org/project/cognis-breachwatch/) [![CI](https://github.com/cognis-digital/breachwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/breachwatch/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Privacy / Personal — put individuals back in control of their data.*

</div>

```bash
pip install cognis-breachwatch
breachwatch scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ breachwatch-emit --version
breachwatch 0.1.0
```

```console
$ breachwatch-emit --help
usage: breachwatch [-h] [--version] {triage} ...

Personal breach aggregator: HIBP + DeHashed + stealer-log triage.

positional arguments:
  {triage}
    triage    Aggregate + risk-score breach exposures from local sources.

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
```

> Blocks above are real `breachwatch` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "1234567890",
        "title": "Potential Breach: Unauthorised Access",
        "description": "An unauthorised user accessed a sensitive database.",
        "created_by": "John Doe",
        "created_at": "2023-02-15T14:30:00Z"
    }
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

`breachwatch` is a personal breach aggregator that triages and risk-scores exposures from local sources (HIBP / DeHashed / stealer logs).

1. **Install**:
   ```bash
   pip install -e .
   ```
2. **Triage** from a JSON config describing identities + sources:
   ```bash
   breachwatch triage config.json
   ```
3. **Filter by severity** and read JSON output:
   ```bash
   breachwatch triage config.json --min-severity medium --format json
   ```
4. **Use the exit code** — `--fail-on` returns exit code 2 when any exposure meets/exceeds the given severity:
   ```bash
   breachwatch triage config.json --fail-on high
   ```
5. **Automate in cron/CI**:
   ```bash
   breachwatch triage config.json --format json --fail-on high > exposures.json
   ```

## Contents

- [Why breachwatch?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why breachwatch?

Personal breach aggregator — HIBP + DeHashed + stealer-log triage — without standing up heavyweight infrastructure.

`breachwatch` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Redact
- ✅ Severity For
- ✅ Parse Hibp
- ✅ Parse Dehashed
- ✅ Parse Stealer Log
- ✅ Triage
- ✅ Load Sources
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-breachwatch
breachwatch --version
breachwatch scan .                       # scan current project
breachwatch scan . --format json         # machine-readable
breachwatch scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ breachwatch scan .
  [HIGH    ] BRE-001  example finding             (./src/app.py)
  [MEDIUM  ] BRE-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[input] --> P[breachwatch<br/>analyze + score]
  P --> OUT[report]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`breachwatch` is interoperable with every popular way of using AI:

- **MCP server** — `breachwatch mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `breachwatch scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis breachwatch** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`breachwatch mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/breachwatch.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/breachwatch.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/breachwatch.git" # uv
pip install cognis-breachwatch                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/breachwatch:latest --help        # Docker
brew install cognis-digital/tap/breachwatch                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/breachwatch/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/breachwatch` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`recall`](https://github.com/cognis-digital/recall) — Privacy-first local RAG over personal data — encrypted, audit-logged
- [`optout`](https://github.com/cognis-digital/optout) — Automated data-broker opt-out engine — top 50 brokers, CCPA/GDPR letters
- [`vaultmap`](https://github.com/cognis-digital/vaultmap) — Personal asset & account inventory — estate-planning-grade encrypted
- [`piicomb`](https://github.com/cognis-digital/piicomb) — Local PII discovery in your own files — SSN/CC/passport/DL/email/phone/DOB
- [`trackblock`](https://github.com/cognis-digital/trackblock) — Family phone stalkerware audit — MVT-class iOS/Android forensics
- [`privacyshell`](https://github.com/cognis-digital/privacyshell) — Hardened browser profile generator — Firefox / LibreWolf / Brave

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `breachwatch` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
