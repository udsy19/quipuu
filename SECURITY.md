# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through
[GitHub Security Advisories](https://github.com/udsy19/seawall/security/advisories/new).
You should get an acknowledgement within 72 hours and an assessment within 7 days.

## Scope — what counts as a vulnerability here

seawall is a security tool that runs against untrusted source trees, so its own threat model
matters. The following are in scope:

- **Any violation of the four trust invariants.** These are contractual:
  - **P1** — no LLM or model call at runtime; detection is fully deterministic.
  - **P2** — no outbound network unless `--allow-network` names the host.
  - **P3** — every finding resolves to a real `file:line` literal.
  - **P4** — the scanned project's code is never executed.
  A reproducible breach of any of these is a security bug, not a feature request.
- **Code execution triggered by scanning a hostile input** — a crafted source file, certificate,
  or dependency manifest that causes seawall to execute code, escape the target directory,
  or write outside its declared output paths.
- **Denial of service from untrusted input** — a parser that hangs or exhausts memory on a crafted
  file. seawall is expected to run in CI against arbitrary repositories.
- **Leakage of scanned source** into any outbound request.

## Not in scope

- **False positives and false negatives in detection.** These are correctness bugs — please file
  them as normal issues, with the file and line, so they can be measured against the audit corpus.
  They are tracked openly; see `PRECISION_AUDIT_V3.md`.
- Vulnerabilities in the *scanned* project. That is the tool working correctly.
- Missing hardening in a dependency with no demonstrated exploit path through seawall.

## Disclosure

Coordinated disclosure. We will agree a date with you, credit you unless you ask otherwise, and
publish an advisory with the fix. If a report is declined as out of scope, you will get the reason
in writing and remain free to disclose.
