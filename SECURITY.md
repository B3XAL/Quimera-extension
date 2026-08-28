# Security policy

Report vulnerabilities through GitHub private security advisories, not public issues. Include the
affected version, reproduction, impact and mitigation; never attach real customer credentials.
The latest release on `main` is supported.

Quimera runs only after explicit host authorization. An empty host scope captures nothing unless
the user explicitly grants the optional all-websites permission, which enables collection on every
regular HTTP(S) page. The Burp bridge rejects processing outside Burp Target Scope. The
optional Burp bridge is disabled by default, uses loopback only and requires the random token shown
by the Burp extension. Captured values are capped before analysis/transfer. Target Scope synchronization is token-
authenticated, bounded, and never grants browser permission without a user gesture. The project contains
no telemetry, ads, remote code or remotely hosted executable logic.
