# Privacy policy

Quimera accesses cookies and, only on sites the user explicitly authorizes, website content needed
to inspect authentication state: local/session storage and limited runtime authentication signals.
It uses this information solely to display, edit and analyze that state for authorized security
testing. Data stays on the user's device. There is no account, telemetry, analytics, advertising,
sale, profiling or transfer to the developer or third parties.

The optional Burp bridge is off by default. If the user enables and pairs it, selected snapshots
are sent only to the Quimera Burp extension on `127.0.0.1`; they do not leave the computer.
If Target Scope synchronization is enabled, the extension polls the authenticated local bridge for
bounded host candidates observed in Burp scope. New hosts remain pending until the user approves
the browser permission prompt unless global website access has been granted. With that optional
permission, the extension collects on every regular HTTP(S) page; Quimera Burp ignores received
snapshots outside Burp Target Scope. Removed synchronized hosts do not delete manual entries.
Options and recent findings are stored in browser extension storage. Users can clear them by
removing extension data or uninstalling the extension and can revoke site access in browser
settings at any time.

## Limited Use

Quimera's use of the data described above is limited to providing and improving the disclosed
security-testing functionality of the extension. Specifically:

- Data is not sold, rented or otherwise transferred to third parties.
- Data is not used or transferred for serving advertising, including retargeting, personalized or
  interest-based advertising.
- Data is not used or transferred to determine creditworthiness or for lending purposes.
- Data is not used to build a profile of the user beyond what is required for the disclosed
  functionality (inspecting and managing browser-side authentication state during authorized
  testing on the sites the user selects).
- No human reads user data collected by the extension, except as necessary for security purposes
  (for example, investigating abuse or a security incident), to comply with applicable law, or
  with the user's affirmative consent.

This statement is intended to match the store privacy disclosures. If behavior changes, update the
code, this policy and every store questionnaire together before release.
