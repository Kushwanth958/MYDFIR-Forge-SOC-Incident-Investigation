# Investigation Notes

This page records how I worked through the MYDFIR Forge lab. The main findings and screenshots belong in [INVESTIGATION_REPORT.md](INVESTIGATION_REPORT.md).

## What changed during the investigation

I started with an RDP alert on `mts-contractorpc1`. My first process query covered only about four minutes after the initial login. That was too narrow. When I widened the window, I found `cmd.exe` and `net user` activity that I had missed.

For the October 7 administrator session, matching process activity by Logon ID did not return the records I expected. Pivoting with `ProcessRemoteSessionIP` worked and exposed commands to create local users, add them to the Administrators group, hide them through the registry, and establish a recurring scheduled task.

I then searched later logon events for the new accounts rather than assuming that creating them proved continued access. The subsequent logons on October 11 and 13 showed that the accounts were used.

## Scope and judgement

Case 1296 involved the same device and additional tampering and exfiltration detections. I documented it separately because a shared device doesn't prove a single attacker controlled both cases.

The `rclone.exe` command I reviewed copied an archive from a Google Drive remote to the device; I did not label that command an upload. The `VNLIKE247.exe` network connection and Defender transfer alert support suspected exfiltration, but the specific files transferred were not recovered.

I also checked the automated response records. Device isolation was skipped, and later user uncontainment was completed. I did not perform or verify remediation in the lab.

## What I'd check next

- Validate the authorization of the RDP access with the system owner.
- Compare authentication and host telemetry to investigate the relationship between the cases.
- Obtain file-content or network evidence to establish what data, if any, was transferred.
- Verify containment and credential rotation before marking the high-severity incident resolved.
