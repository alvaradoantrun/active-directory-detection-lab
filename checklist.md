I’m building a small Active Directory lab to practice investigating Windows sign-ins and process activity in Wazuh. I’ll use four lab cases to test my detections against normal activity and document how I reached each verdict.

## Lab setup

- [x] Added a `.gitignore` for local scratch files before my first commit.
- [ ] Created a VMware host-only network for my three lab VMs.
- [ ] Created `WAZUH01` on Ubuntu with 4 vCPUs, 8 GB of RAM, and 50 GB of disk space.
- [ ] Installed Wazuh and signed in to the dashboard.
- [ ] Set up Active Directory and DNS on `DC01`.
- [ ] Created lab users and a test service account.
- [ ] Pointed `WIN11-01` at the lab DNS server and joined it to the domain.
- [ ] Enrolled both Windows VMs and confirmed they show up as active agents in Wazuh.
- [ ] Saved my network diagram and VM settings in `docs/`.

## Windows logs

- [ ] Enabled success and failure auditing for Windows sign-ins.
- [ ] Verified a successful sign-in (`4624`) and a failed sign-in (`4625`) in Wazuh.
- [ ] Enabled Kerberos authentication and service-ticket auditing on `DC01`.
- [ ] Verified Kerberos events from `DC01`, including a service-ticket request (`4769`).
- [ ] Installed Sysmon on the workstation and verified a process creation event (`1`) in Wazuh.
- [ ] Enabled PowerShell script block logging and verified a script block event (`4104`) in Wazuh.
- [ ] Recorded my audit settings and took VM snapshots after verifying the logs.

## Case investigations

- [ ] Created one folder per case under `evidence/` and set up a private scratch folder for raw exports.

### Password spraying

- [ ] Identified failures across several accounts from one source in my lab data.
- [ ] Checked for a related successful sign-in and recorded what the evidence supported.

### Brute force

- [ ] Traced repeated sign-in failures against one account.
- [ ] Compared the pattern with the spray and with an ordinary mistyped password.

### Kerberoasting

- [ ] Identified the account, source, and service in my sample `4769` events.
- [ ] Compared the suspicious ticket requests with normal service activity.

### Suspicious PowerShell

- [ ] Used Sysmon to identify the process that launched PowerShell.
- [ ] Used the script block log to determine what ran.

### Evidence for all four cases

- [ ] Saved the key Windows event and its matching Wazuh alert or search result for each case, with the timestamp, time zone, host, and query.

## Detection testing

- [ ] Checked which cases triggered Wazuh’s built-in rules.
- [ ] Wrote custom rules for at least two cases and saved the XML in `rules/`.
- [ ] Logged the expected and actual outcomes for both normal and suspicious activity in `tests/`.
- [ ] Retested my rules after tuning and recorded what fired, what was missed, and how the alert counts changed.

## Reports and publishing

- [ ] Wrote four short case reports in `reports/` with a timeline, evidence, verdict, confidence, and next action.
- [ ] Reviewed my staged files for secrets and personal details before publishing.
- [ ] Added a short findings summary and links to my reports, rules, test results, and sanitized evidence.
