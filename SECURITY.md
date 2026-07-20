# Security Policy

## Project status: Alpha

AI Code Auditor is **experimental alpha software**. It is a heuristic,
deterministic scanner intended to *assist* human review of AI-generated code.
It is **not** a certified security tool and must **not** be relied on as the
sole safeguard for sensitive, regulated, or safety-critical systems. Absence
of findings is never proof that code is safe (the tool itself reports
"executed", not "passed", for exactly this reason).

What the tool does locally and deliberately does **not** do:

- Scans run entirely on your machine; reports are written to a local
  directory you choose and are never uploaded by the tool.
- Reports may contain **source snippets** from the scanned repository —
  treat generated `report.json` / `report.md` with the same confidentiality
  as the code itself.
- In online mode the tool queries the *public* registries (PyPI, npm, Maven
  Central, NuGet) about package *names* only. `--offline` disables all
  network access. Private registries are never contacted.
- Outgoing report text passes a redaction layer (auth headers, tokens,
  password-shaped values), but redaction is heuristic — review reports
  before sharing them.

## Supported versions

Only the latest alpha release receives fixes. There are no backports.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- Use GitHub's **"Report a vulnerability"** (Security Advisories) on this
  repository: `Security` tab → `Advisories` → `Report a vulnerability`.
- Do **not** open a public issue for an unpatched vulnerability, and do not
  include real secrets or private code in any report.

You can expect an acknowledgement within 7 days. Since this is a solo alpha
project, fix timelines are best-effort; coordinated disclosure is
appreciated.
