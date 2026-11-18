
# Active Directory Detection Lab

### Building, Monitoring, and Investigating Security Events in a Windows Active Directory Environment

A hands-on cybersecurity lab designed to simulate common security events in a Windows Active Directory environment and investigate them using the Wazuh SIEM.

The project focuses on Windows security auditing, endpoint telemetry collection, detection validation, and SOC-style security investigations.

Three controlled security scenarios were completed:

1. **Brute-Force Authentication Detection** — Identifying repeated failed authentication attempts through Windows Security logs and Wazuh event correlation.
2. **PowerShell Process Discovery Detection** — Identifying discovery activity through PowerShell Script Block Logging and Wazuh detection rules.
3. **Active Directory Account and Group Modification** — Monitoring account status changes and security group membership modifications.

Each investigation includes the simulated activity, relevant Windows Event IDs, Wazuh detection rules, investigation findings, and an analyst assessment.

> **Project scope:** All activity was performed in an isolated VMware lab using authorized test accounts. Detection results were validated against deliberately generated events. No real-world systems were targeted.

---

## Project Objectives

The primary objective was to build a functional security monitoring environment and practice the responsibilities of an entry-level SOC analyst.

Specific objectives included:

- Deploying and administering a Windows Active Directory domain.
- Configuring Windows Advanced Audit Policy through Group Policy.
- Centralizing Windows security telemetry using Wazuh.
- Installing and configuring Sysmon for endpoint process and network monitoring.
- Enabling PowerShell Script Block Logging for command-level visibility.
- Simulating security-relevant behavior in a controlled environment.
- Identifying relevant Windows Event IDs and Wazuh detection rules.
- Analyzing security alerts and distinguishing suspicious behavior from confirmed malicious activity.
- Mapping relevant detections to the MITRE ATT&CK framework.
- Documenting investigations using a structured SOC-style reporting format.

---

## Lab Architecture

The lab was built using VMware Workstation and an isolated host-only network.

### Network Diagram

```text
                 Physical Host
                VMware Workstation
                       |
              VMnet2 — Host-Only
               192.168.100.0/24
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
  +------------+ +------------+ +-------------+
  |    DC01    | |    WS01    | |   SIEM01    |
  |            | |            | |             |
  | Windows    | | Windows 11 | | Ubuntu      |
  | Server 2022| |            | | Server 24.04|
  |            | | Wazuh Agent| |             |
  | AD DS / DNS| | Sysmon     | | Wazuh SIEM   |
  | Wazuh Agent| | PowerShell | | Manager      |
  |            | | Logging    | | Dashboard    |
  +------------+ +------------+ +-------------+
        |              |              |
  192.168.100.10 192.168.100.20 192.168.100.30
        |              |
        +------+-------+
               |
           lab.test
```

SIEM01 also used a separate VMware NAT adapter for internet connectivity during setup. The Windows lab systems communicated over the host-only network.

### Virtual Machines

| Machine | Operating System | IP Address | Purpose |
|---|---|---|---|
| DC01 | Windows Server 2022 | `192.168.100.10` | Active Directory Domain Services, DNS, Windows Security auditing |
| WS01 | Windows 11 | `192.168.100.20` | Domain-joined workstation, endpoint monitoring, simulated activity |
| SIEM01 | Ubuntu Server 24.04 | `192.168.100.30` | Centralized Wazuh SIEM |

**Domain:** `lab.test`

### Additional Environment

A Kali Linux virtual machine was also prepared for a future external-origin authentication simulation.

Kali was connected to the isolated lab network, but the planned compromised-account scenario was not completed. It is not included among the validated investigations.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| VMware Workstation | Virtualization and isolated lab networking |
| Windows Server 2022 | Domain controller and Windows security auditing |
| Active Directory Domain Services | Domain authentication, users, computers, and security groups |
| Group Policy | Centralized security auditing and PowerShell logging configuration |
| Windows 11 | Domain-joined workstation for endpoint activity simulations |
| Ubuntu Server 24.04 | Wazuh server operating system |
| Wazuh 4.14.10 | Security event collection, correlation, and alert analysis |
| Microsoft Sysmon 15.22 | Process creation and network connection telemetry |
| Windows Event Viewer | Local security event investigation |
| Windows PowerShell | Administrative operations and controlled simulations |
| MITRE ATT&CK | Security technique classification and detection mapping |

---

## Security Monitoring Configuration

### 1. Active Directory Security Auditing

A dedicated Group Policy Object was created and linked to the Domain Controllers organizational unit:

`SOC-Lab-DC-Security-Auditing`

The following audit categories were enabled:

**Account Logon**

- Audit Credential Validation — Success and Failure
- Audit Kerberos Authentication Service — Success and Failure
- Audit Kerberos Service Ticket Operations — Success and Failure

**Account Management**

- Audit User Account Management — Success and Failure
- Audit Security Group Management — Success and Failure
- Audit Computer Account Management — Success and Failure

These policies enabled the collection of security events associated with authentication failures, account modifications, and security group membership changes.

The effective configuration was verified on DC01 using:

```powershell
auditpol /get /category:"Account Logon"
auditpol /get /category:"Account Management"
```

### 2. Sysmon Endpoint Monitoring

Microsoft Sysmon was installed on WS01 to provide additional visibility beyond standard Windows Security logs.

The configuration enabled:

| Sysmon Event ID | Description |
|---|---|
| 1 | Process Creation |
| 3 | Network Connection |

Process creation events provided information including executable paths, command-line arguments, parent processes, and user context.

Network connection events provided source and destination addresses, ports, protocols, and associated processes.

Sysmon telemetry was collected from:

`Microsoft-Windows-Sysmon/Operational`

A Wazuh agent configuration block was added:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Successful event collection was verified through Sysmon-based Wazuh alerts.

### 3. PowerShell Script Block Logging

A separate GPO was created and linked to the Workstations organizational unit:

`SOC-Lab-Workstation-PowerShell-Logging`

The following policy was enabled:

`Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`

Group Policy application was verified using:

```powershell
gpresult /scope computer /r
```

PowerShell Script Block Logging generated Windows Event ID **4104**, allowing executed PowerShell code to be examined.

Wazuh was configured to collect these events:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4104]</query>
</localfile>
```

This provided visibility into PowerShell commands executed within an existing session, beyond the executable launch information available through Sysmon.

---

## Completed Security Investigations

### Investigation 01 — Brute-Force Authentication Detection

**MITRE ATT&CK:** T1110 — Brute Force

**Detection:** Wazuh Rule 60204 — Multiple Windows Logon Failures

**Alert Severity:** Level 10

Multiple incorrect passwords were entered for the domain account `LAB\jcarter` on WS01.

Windows recorded authentication failures on the workstation and domain controller.

Relevant events included:

| Event | Description |
|---|---|
| 4625 | Failed Windows logon |
| 4771 | Kerberos pre-authentication failure |
| Wazuh 60122 | Individual Windows logon failure |
| Wazuh 60104 | Windows audit failure |
| Wazuh 60204 | Multiple Windows logon failures |

Wazuh's built-in correlation rule successfully identified the repeated authentication failures and generated a Level 10 alert.

**Result:** Successful detection of a controlled brute-force authentication pattern.

[Read Investigation 01](investigations/investigation-01-brute-force-detection.md)

---

### Investigation 02 — PowerShell Process Discovery Detection

**MITRE ATT&CK:** T1057 — Process Discovery

**Detection:** Wazuh Rule 91815 — PowerShell executing process discovery

**Alert Severity:** Level 4

A controlled PowerShell discovery command was executed on WS01:

```powershell
Get-Process | Out-Null; Get-Service | Out-Null; Get-LocalUser
```

The command enumerated running processes, Windows services, and local user accounts without modifying the system.

PowerShell Script Block Logging recorded the complete command as Windows Event ID 4104.

Wazuh collected the event, matched the process-discovery behavior, and generated a Level 4 alert.

The complete command was visible in the Wazuh field:

`data.win.eventdata.scriptBlockText`

**Result:** Successful detection of PowerShell process-discovery behavior.

[Read Investigation 02](investigations/investigation-02-powershell-process-discovery.md)

---

### Investigation 03 — Active Directory Account and Security Group Modification

**MITRE ATT&CK:** T1098 — Account Manipulation

**Detection Sources:** Windows Security auditing and Wazuh account-management rules

Two administrative security scenarios were performed on DC01.

**Scenario A — Account Status Changes**

The domain account `LAB\rpatel` was temporarily disabled and then re-enabled.

Windows Security events confirmed the changes, and Wazuh identified the affected account and administrator responsible.

**Scenario B — Security Group Modifications**

A dedicated security-enabled global group named `SOC-Lab-Privileged-Test` was created.

The account `rpatel` was temporarily added to the group and subsequently removed.

The group was used only for testing and was not assigned administrative privileges.

Relevant detection results:

| Windows Event ID | Activity | Wazuh Rule | Level |
|---|---|---|---|
| 4725 | User account disabled | 60111 | 8 |
| 4722 | User account enabled | 60109 | 8 |
| 4738 | User account changed | 60110 | 8 |
| 4727 | Security-enabled global group created | 60140 | 5 |
| 4728 | Group member added | 60141 | 5 |
| 4729 | Group member removed | 60142 | 5 |

All five primary test events were successfully detected in Wazuh.

The test account was restored to its original enabled state, and the test group's membership was verified as empty.

**Result:** Successful monitoring of Active Directory account changes and security group modifications.

[Read Investigation 03](investigations/investigation-03-active-directory-account-management.md)

---

## Detection Summary

| Investigation | Primary Telemetry | Wazuh Rule(s) | Result |
|---|---|---|---|
| Brute-Force Authentication | Windows 4625, 4771 | 60204 | Successful |
| PowerShell Process Discovery | PowerShell 4104 | 91815 | Successful |
| AD Account Changes | Windows 4722, 4725, 4738 | 60109, 60111, 60110 | Successful |
| Security Group Changes | Windows 4727, 4728, 4729 | 60140, 60141, 60142 | Successful |

All detections were validated using built-in Wazuh rules. No custom detection rules were developed as part of these investigations.

---

## SOC Investigation Methodology

Each investigation followed a structured process:

1. **Define the scenario** — Identify the security-relevant behavior to simulate.
2. **Establish a baseline** — Verify the relevant account, system, or logging configuration.
3. **Generate controlled activity** — Execute authorized actions within the lab.
4. **Identify security events** — Locate the corresponding Windows Event IDs and Wazuh alerts.
5. **Analyze event details** — Review timestamps, accounts, processes, command lines, source addresses, and affected objects.
6. **Validate the detection** — Confirm that the alert corresponds to the deliberately executed activity.
7. **Determine disposition** — Distinguish correctly detected behavior from evidence of actual compromise.
8. **Document findings** — Record the evidence, detection results, and analyst assessment.

### Investigation Classification

All three investigations involved intentional and authorized simulations.

The observed alerts were classified as **true positive detections of test activity**, not confirmed malicious incidents.

This distinction is important because suspicious behavior alone does not establish attacker intent or successful compromise.

---

## Project Findings

The lab demonstrated several important security monitoring principles.

### Visibility Depends on Audit Configuration

Windows security events must be enabled and collected before they can support effective investigation.

Configuring Advanced Audit Policy through Group Policy provided the authentication and account-management telemetry needed for the investigations.

### Sysmon Provides Additional Endpoint Context

Sysmon exposed process execution details and network connection information that are not always available from standard authentication logs.

### PowerShell Logging Improves Command Visibility

PowerShell Script Block Logging recorded executed script content, allowing Wazuh to identify discovery-related commands within PowerShell sessions.

### Event Collection and Alert Generation Are Different

A Windows event can be successfully generated and forwarded without necessarily producing a visible Wazuh alert.

Wazuh's detection rules determine whether an event matches conditions that warrant an alert.

### Alerts Require Context

Several legitimate administrative activities generated security alerts.

The investigations reinforced the need to examine the underlying event fields, establish authorization, and correlate related activity before determining whether an incident is malicious.

---

## Challenges and Lessons Learned

### Sysmon Configuration Behavior

An initial Sysmon configuration did not produce the expected process-creation events.

The event filtering configuration was corrected, and Event IDs 1 and 3 were subsequently verified in both Windows Event Viewer and Wazuh.

### Windows Event Log Permissions

Accessing the Sysmon Operational event log initially produced an Access Denied error.

Opening Event Viewer with administrative privileges resolved the issue.

### Understanding Wazuh Detection Logic

Not every ordinary Windows or PowerShell event generated an alert.

Detection validation required identifying the correct Wazuh rules and confirming that the underlying event matched the simulated activity.

### Active Directory Group Policy Scope

Dedicated GPOs were used for domain controller security auditing and workstation PowerShell logging.

The resulting settings were verified using `auditpol`, `gpupdate`, and `gpresult`.

---

## Future Improvements

Potential enhancements include:

- Completing a Kali Linux-origin authentication investigation.
- Simulating password spraying across multiple test accounts.
- Investigating Kerberos-related attack techniques in the isolated lab.
- Developing custom Wazuh correlation and detection rules.
- Creating additional PowerShell behavioral detections.
- Adding more advanced Sysmon configuration and event filtering.
- Creating a separate Splunk-based threat-hunting investigation.
- Expanding incident-response workflows to include containment verification and recovery.

These are proposed improvements and were not part of the completed detection results.

---

## Skills Demonstrated

- Security Information and Event Management (SIEM)
- Wazuh deployment and administration
- Windows Server and Active Directory
- Group Policy configuration
- Windows Advanced Audit Policy
- Windows Security Event Log analysis
- Sysmon endpoint monitoring
- PowerShell Script Block Logging
- Security alert triage
- Detection rule validation
- Authentication monitoring
- Account and security group auditing
- MITRE ATT&CK mapping
- Security investigation documentation
- VMware virtualization and isolated lab networking

---

## Disclaimer

This project was conducted entirely within an isolated, self-managed virtual lab.

All accounts, systems, and security events were created or controlled for educational purposes.

The simulated activities were authorized and did not involve real-world targets.

The purpose of this project was to practice defensive security monitoring, detection validation, and incident investigation.

---

## Author

Cybersecurity student and IT professional pursuing an entry-level Security Operations Center (SOC) Analyst position.

This project was developed to demonstrate practical security monitoring, Active Directory administration, event analysis, and investigation skills.
