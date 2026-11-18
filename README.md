# Cloud-Based SIEM Detection Lab

A hands-on security monitoring project built on Microsoft Azure. I deployed an internet-facing Linux VM, piped its authentication logs into Microsoft Sentinel (Azure's SIEM), simulated a brute-force SSH attack against it with Hydra, and wrote a custom detection rule that automatically flags the attack and opens a security incident.

## Architecture

```
Attacker (Hydra, or real internet scanners)
        |
        v
  SSH attempts on port 22
        |
        v
Ubuntu VM (Azure) -- rsyslog writes auth events
        |
        v
Azure Monitor Agent (AMA) -- reads auth/authpriv logs
        |
        v
Log Analytics Workspace -- Syslog table
        |
        v
Microsoft Sentinel -- KQL queries + custom analytics rule
        |
        v
Incident: "SSH Brute Force Detection"
```

## Skills Demonstrated

- Cloud infrastructure deployment (Azure VMs, networking, resource groups)
- Linux system administration (Ubuntu, SSH, rsyslog, user/auth management)
- SIEM configuration (Microsoft Sentinel, Log Analytics workspaces)
- Log pipeline engineering (Azure Monitor Agent, data collection rules)
- KQL (Kusto Query Language) for log analysis and detection engineering
- Offensive security tooling (Hydra) for controlled attack simulation
- Security incident triage and verification

## What I Built

**Target environment:** An Ubuntu 24.04 LTS VM in Azure, exposed to the internet on port 22, acting as a lightweight honeypot.

**SIEM pipeline:** Microsoft Sentinel workspace receiving the VM's authentication logs via the Azure Monitor Agent, using a data collection rule scoped to the `auth` and `authpriv` syslog facilities at `LOG_INFO` level.

**Attack simulation:** Used Hydra (via WSL) to run a brute-force attack against a decoy account (`decoyuser`) with a deliberately weak password, both to generate failed-login telemetry and to confirm the pipeline captures a successful compromise, not just noise.

**Detection rule:** A custom Sentinel analytics rule that scans the `Syslog` table every 5 minutes and fires an alert whenever 5 or more failed SSH logins arrive from a single source IP within a 5-minute window. Tagged against the MITRE ATT&CK tactics *Credential Access* and *Initial Access*.

```kql
Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password" or SyslogMessage has "Invalid user"
| parse SyslogMessage with * "from " SourceIP " port" *
| summarize FailedAttempts = count() by SourceIP, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Result:** The rule correctly detected the simulated attack and generated a real Sentinel incident ("SSH Brute Force Detection," Medium severity).

## An Unplanned Finding

Within hours of exposing port 22 to the internet, the VM was already receiving brute-force attempts from real, unrelated source IPs scanning for open SSH servers, independent of anything I ran myself. I verified this by comparing the source IPs in the logs against my own public IP, confirming that a public cloud honeypot picks up organic attack traffic almost immediately. This also meant my detection rule had to work generically (by failure pattern, not by a specific test account) in order to catch both my simulated attack and this real background traffic.

## Screenshots

**Hydra successfully brute-forcing the decoy account**, showing failed attempts followed by an accepted password and an opened session:

![Hydra brute-force success](screenshots/hydra-decoy-success.png)

**Sentinel automatically detecting the attack and opening an incident:**

![Sentinel incident](screenshots/sentinel-incident.png)

**Real, unprompted scanning traffic from the open internet**, captured within hours of deployment:

![Background scanning traffic](screenshots/bot-scanning-traffic.png)

## Tools Used

Microsoft Azure (Virtual Machines, Resource Groups), Microsoft Sentinel, Log Analytics, Azure Monitor Agent, KQL, Ubuntu Linux, rsyslog, Hydra, WSL

## Notes

This was a short, scoped project focused on Phase 1 of a larger lab plan (environment setup, log pipeline, attack simulation, and detection engineering). It stops before the dashboard/GeoIP visualization phase.
