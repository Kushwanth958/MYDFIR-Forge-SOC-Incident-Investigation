# SOC Incident Investigation — RDP Persistence and Endpoint Compromise

A hands-on investigation in the **MYDFIR Forge SOC lab** using Microsoft Defender XDR and KQL. I started with an RDP alert, found hidden local administrator accounts and scheduled-task persistence, then reviewed a separate high-severity incident on the same device involving Defender tampering and suspected data exfiltration.

**Host:** `mts-contractorpc1`  
**Cases:** 1290 (Medium) and 1296 / Incident 2565 (High)  
**Dates reviewed:** October 6–15, 2026

## Findings

- Oct 7: three local admin accounts were created and hidden; a password-reset task was set to run every ten minutes.
- Oct 11–13: the newly created accounts appeared in successful authentication events.
- Oct 10: Defender reported tampering attempts, `VNLIKE247.exe` execution, and suspected data transfer. A matching outbound connection to `149.154.166.110:443` was confirmed.
- Device isolation was skipped in the automated response records. The investigation supports escalation, **not a claim of completed remediation**.

The cases involve the same host, but I couldn't prove they were operated by the same attacker.

## Files

- [Investigation report](INVESTIGATION_REPORT.md) — findings, timeline, screenshots, indicators, and IR handoff
- [KQL hunting queries](queries/investigation.kql) — searches used during the investigation and screenshot collection
- [Learning notes](LEARNING_NOTES.md) — pivots that worked, dead ends, and what I'd do differently

This is a simulated SOC exercise. The screenshots are original. I used narrower searches to retrieve evidence **after** discovering the events, not as a substitute for the initial investigation.