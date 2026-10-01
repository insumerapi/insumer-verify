# Security Policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/insumerapi/insumer-verify/security/advisories/new)**

That opens an advisory visible only to you and the maintainers. If you cannot use GitHub, email support@insumermodel.com.

Please do not open a public issue for a suspected vulnerability. If you already have, that is not a problem; it will be handled the same way.

## Scope

This policy covers both packages built from this repository: `insumer-verify` on npm (the TypeScript source under `src/`) and `insumer-verify` on PyPI (the Python source under `python/`). A finding in one is checked against the other before the advisory is published, since they implement the same checks.

## What to expect

Your report will be acknowledged. Beyond that, no response time is promised.

If a report is confirmed, a GitHub Security Advisory is published and you are credited as the reporter unless you ask otherwise. Tell us the name or handle you would like used.

## What is useful in a report

The affected version, the code path or endpoint involved, and what an attacker gains. A proof of concept helps but is not required.
