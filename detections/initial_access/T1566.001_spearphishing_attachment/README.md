# T1566.001 — Spearphishing Attachment: Suspicious Child Process from Mail Client

| Field | Value |
|---|---|
| **Tactic** | Initial Access |
| **Technique** | T1566.001 — Phishing: Spearphishing Attachment |
| **Severity** | High |
| **Confidence** | Medium |
| **Status** | Production |
| **SIEM** | Splunk |
| **Data Sources** | Sysmon (Event ID 1) |

## What this detects

Malicious attachments — Office macros, PDFs with embedded scripts, ISO files, or shortcut (LNK) files — typically achieve code execution by spawning a child process from the mail client. This rule fires when Outlook or Thunderbird launches a scripting engine or LOLBAS binary that has no legitimate reason to originate from email.

Covered child processes: `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `msiexec.exe`, `certutil.exe`

## Data source requirements

- **Sysmon** deployed with a config that captures `ProcessCreate` (Event ID 1), including `CommandLine` and `ParentImage` fields
- Log forwarded to Splunk under `index=endpoint`, sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

## Tuning notes

**Low FP environment (recommended starting point):** Run as-is for 48 hours and review the `commandlines` field. Suppression suggestions are in `rule.yml`.

**Higher FP environments:** Add a lookup against known-good signed hashes or restrict to specific high-value user groups (executives, finance, HR) before broadening scope.

## Response

1. Isolate host — do not wait for sandbox analysis before containing if severity=high
2. Pull full process tree from Sysmon (Event IDs 1, 3, 11) for the host/timeframe
3. Check `commandlines` field for network callbacks (`IEX`, `DownloadString`, `curl`, `wget`)
4. Pull the email from the mail server logs to identify sender and attachment hash
5. Search for the attachment hash across all endpoints (Sysmon Event ID 11 — FileCreate)

## References

- [MITRE ATT&CK T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [Red Canary Threat Detection Report — Phishing](https://redcanary.com/threat-detection-report/techniques/phishing/)
