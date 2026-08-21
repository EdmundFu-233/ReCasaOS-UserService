# Security Policy

## Current support status

Only the latest `main` branch receives ReCasaOS security work. No current
ReCasaOS User Service release is declared ready for direct public-Internet
exposure. Upstream CasaOS tags are not security-supported by this fork unless a
ReCasaOS release explicitly says otherwise.

## Private vulnerability reports

Use GitHub's private vulnerability reporting form:

<https://github.com/EdmundFu-233/ReCasaOS-UserService/security/advisories/new>

Include affected versions or commits, impact, reproduction prerequisites, and
a minimal proof of concept when safe. Do not open a public issue for an
unpatched exploitable vulnerability.

Never include real passwords, access tokens, cookies, private keys, database
contents, `.env` files, or unredacted user data. Replace secrets with inert
placeholders and rotate any credential that was exposed during testing.

Public hardening work is tracked in
[issue #1](https://github.com/EdmundFu-233/ReCasaOS-UserService/issues/1), but
that issue is not a substitute for a private report.

## Safe testing

Test only systems and accounts you own or are authorized to assess. Prefer an
isolated disposable environment. Avoid denial of service, persistence, data
destruction, public exposure, or access to other users' data.
