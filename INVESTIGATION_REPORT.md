# SOC Investigation Report — RDP Persistence and Endpoint Compromise

**Environment:** MYDFIR Forge SOC lab / Microsoft Defender XDR  
**Cases:** 1290 (Medium, RDP alert) and 1296 / Incident 2565 (High, compromised device)  
**Device:** `mts-contractorpc1`  
**Period:** October 6–15, 2026; times below are CDT (UTC−5)  
**Disposition:** Investigated and ready for IR handoff. Full remediation is not verified.

## Summary

**The host is compromised.** The logs show three new administrator accounts, hidden account entries, and a scheduled password-reset task. Two of those accounts were used again days later.

A separate high-severity case on the same host involved Defender tampering, `VNLIKE247.exe`, and a Defender alert for suspected data exfiltration. I assessed Case 1296 as **True Positive — Multi-Staged Attack** and would escalate both cases to IR. Business impact is unknown in this lab.

## Timeline

| When (CDT) | What happened | Evidence |
| --- | --- | --- |
| Oct 6, 3:29 PM | `administrator` RDP success from `2.147.252.234` | Starting alert / `DeviceLogonEvents` |
| Oct 6, 3:34 PM | `explorer.exe → cmd.exe → net.exe`, running `net user` | [Fig. 1](evidence/01-oct06-account-discovery.png) |
| Oct 7, 12:40 PM | Administrator RDP session; matching Unlock event linked to `116.118.45.151` | [Fig. 2](evidence/02-oct07-rdp-correlation.png) |
| Oct 7, 12:47 PM | `system16`, `system32`, `system64` created and added to Administrators; registry hiding and recurring task configured | [Fig. 3](evidence/03-oct07-account-creation.png), [Fig. 4](evidence/04-oct07-persistence-activity.png), [Fig. 5](evidence/05-oct07-scheduled-task.png) |
| Oct 8, 1:00 AM | Another administrator RDP login; source `116.98.254.228` | `DeviceLogonEvents` |
| Oct 10, morning | Defender tampering, `dControl.exe`, and `VNLIKE247.exe` execution | [Fig. 8](evidence/08-defender-tampering.png), [Fig. 9](evidence/09-vnlike-execution.png) |
| Oct 10, 5:56 AM | Defender reported staging/transfer; matching TCP connection to `149.154.166.110:443` | [Fig. 11](evidence/11-telegram-ip-connection.png), [Fig. 12](evidence/12-defender-exfil-event.png) |
| Oct 11–13 | Successful logons involving `system32` and `system16` | [Fig. 6](evidence/06-oct11-13-account-reuse.png) |
| Oct 15 | Automated uncontain of `WDAGUtilityAccounts` marked Completed | [Fig. 13](evidence/13-response-actions.png) |

## What I found

### RDP activity and persistence

I started with the Oct 6 RDP alert and checked the successful login against `DeviceLogonEvents`. My first process query only covered four minutes. That was too short: when I widened it, I found `net user` account enumeration around 3:34 PM [Fig. 1](evidence/01-oct06-account-discovery.png).

The Oct 7 session was more revealing. Its `RemoteInteractive` record had no `RemoteIP`, but an `Unlock` event with the same Logon ID (`72229258`) had `116.118.45.151` [Fig. 2](evidence/02-oct07-rdp-correlation.png). My first attempt to link processes by Logon ID did not return useful results. Pivoting on `ProcessRemoteSessionIP` worked.

From that session, process logs showed commands creating `system16`, `system32`, and `system64`, adding them to the local Administrators group, and hiding them with `Winlogon\SpecialAccounts\UserList` registry entries [Fig. 3](evidence/03-oct07-account-creation.png), [Fig. 4](evidence/04-oct07-persistence-activity.png). A task named `ResetUserPasswords` ran `C:\Scripts\ResetPasswords.cmd` every ten minutes with highest privileges. I found repeated script-related execution after task creation [Fig. 5](evidence/05-oct07-scheduled-task.png).

I then checked whether those accounts were actually used. `system32` logged on successfully on Oct 11, including a `RemoteInteractive` session; `system16` and `system32` had successful **Network** logons on Oct 13 [Fig. 6](evidence/06-oct11-13-account-reuse.png). I checked other devices too, but found no evidence of access to a second internal host. The Oct 13 successes were Network logons, not RDP.

### Defender tampering and suspicious execution

During host scoping, I found a separate High-severity compromised-device case with 17 alerts [Fig. 7](evidence/07-case1296-overview.png). The Oct 10 alert story included `dControl.exe` (DefenderControl), attempts to turn off antivirus, Defender registry/service changes, and PowerShell activity [Fig. 8](evidence/08-defender-tampering.png). This is evidence of attempted defense evasion.

`VNLIKE247.exe` executed around 5:52 AM under `wdagutilityaccounts`, launched by `explorer.exe` [Fig. 9](evidence/09-vnlike-execution.png). Its SHA256 was:

`7392942a2151c61d587d8aa557f30cad09bf2cb528e420f855f2fd84f4fa5072`

### Network activity and suspected transfer

The broad network search for `VNLIKE247.exe` produced **703 IP/port groupings**, not 703 distinct IPs [Fig. 10](evidence/10-vnlike-network-summary.png). I then checked the destination from Defender's exfiltration event. `DeviceNetworkEvents` confirmed `VNLIKE247.exe` made a successful TCP connection to `149.154.166.110:443` [Fig. 11](evidence/11-telegram-ip-connection.png).

The device timeline reported `SuspiciousProcessDataExfiltration` at 5:56:25 AM, with staging under `C:\Users\WDAGUtilityAccounts\Desktop\vnlike` [Fig. 12](evidence/12-defender-exfil-event.png). IP-registration research associated the destination with Telegram infrastructure. Defender flagged a transfer, but I never found out what was sent, how much, or to whom.

The logs spell this name three ways (`wdagutilityaccounts`, `WDAGUtilityAccounts`, and `WDAGUtilityAccount`), so I kept each as recorded. Staging files under what looks like a normally non-interactive Windows utility account is unusual and worth checking.

I also checked Rclone and WinRAR. The observed Rclone command downloaded an archive **from Google Drive to the device**, not the other way around. Some `vnlike` files appeared before that download. I left the two events separate rather than force a connection.

**Case relationship:** Both cases involve the same host, and `116.98.254.228` appears in the Oct 8 RDP evidence and as an entity in Case 1296. I found no direct evidence that the same person ran both attacks.

## Response status

These were **automated Defender actions**, not changes I made [Fig. 13](evidence/13-response-actions.png):

| Action | Status |
| --- | --- |
| Contain `WDAGUtilityAccounts` (Oct 10) | Completed |
| Disable `WDAGUtilityAccounts` (Oct 10) | Skipped |
| Isolate `mts-contractorpc1` (twice, Oct 10) | Skipped |
| Uncontain `WDAGUtilityAccounts` (Oct 15) | Completed |

### IR handoff

1. **IR / endpoint team:** Verify and, if authorized, isolate the host; check Defender health.
2. **Identity / IR:** Review and disable unauthorized local admin accounts; rotate affected credentials and revoke sessions.
3. **DFIR:** Preserve the binaries, task, script, registry changes, logs, and related network evidence.
4. **IT / IR:** Remove persistence, restore protections, and rebuild if needed; verify recovery.
5. **Threat hunting / system owner:** Check other hosts and establish whether sensitive data was exposed.

## Main indicators

| Indicator | What it was |
| --- | --- |
| `mts-contractorpc1` | Endpoint in both cases |
| `system16`, `system32`, `system64` | New privileged local accounts |
| `ResetUserPasswords`; `C:\Scripts\ResetPasswords.cmd` | Scheduled-task persistence |
| `Winlogon\SpecialAccounts\UserList` | Registry-based account hiding |
| `2.147.252.234`; `116.118.45.151`; `116.98.254.228` | RDP-related source IPs |
| `41.82.206.14`; `154.121.45.209`; `194.31.72.239` | Later authentication source IPs |
| `dControl.exe` | Defender tampering tool detection; no verified hash |
| `VNLIKE247.exe` — SHA256 above | Executed suspicious binary |
| `149.154.166.110:443` | Connection seen at the time of the Defender exfil alert |

**ATT&CK:** T1021.001 (RDP), T1087.001 (account discovery), T1136.001 (local account), T1053.005 (scheduled task), T1564 (hiding), T1562.001 (impair defenses), T1074.001 (staging), T1041 (suspected exfiltration).

## Open questions and handoff status

This was a lab investigation. I still do not know whether the original administrator access was authorized, whether both cases involved the same operator, exactly what data left the device, or the business impact. Containment and recovery were not confirmed. The Incident ID associated with Case 1290 also needs to be checked in the portal.

**Outcome:** Case 1290 documents malicious account persistence. Case 1296 supports **True Positive / Multi-Staged Attack**. My investigation is ready for handoff; Incident 2565 should stay In Progress until the response team verifies recovery.

[Original screenshot index](EVIDENCE_INDEX.md) · [Hunting queries](queries/investigation.kql) · [Investigation lessons](LEARNING_NOTES.md)