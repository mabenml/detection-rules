# Detection Rules

A portfolio of production-tested Splunk correlation searches, sanitized for public sharing.
Each detection includes MITRE ATT&CK mapping, data source requirements, and operational
tuning notes drawn from real-world deployment experience.

> **Note:** Index names, lookup references, field aliases, and environment-specific thresholds
> have been generalized. Detections should be adapted to your data model and tested before
> production deployment.

## Structure

Rules are organized by MITRE ATT&CK tactic. Each detection lives in its own directory
containing a machine-readable `rule.yml` and a human-readable `README.md`.

## Data Source Assumptions

Unless otherwise noted, detections assume:
- **Endpoint telemetry:** Sysmon v13+ with a standard configuration
- **Field naming:** Splunk CIM-compliant field names
- **Log sources:** Normalized to a common `endpoint` index

## Detection index

| ID | Title | Tactic | Severity | Status |
|---|---|---|---|---|
| [T1566.001](detections/initial_access/T1566.001_spearphishing_attachment/) | Suspicious Email Attachment Execution via Outlook | Initial Access | High | Production |

## Enrichment searches

| Name | Title | Status |
|---|---|---|
| [CreateADComputers](detections/enrichment/CreateADComputers/) | AD Computer Object Asset Enrichment | Production |

## Structure

```
detections/
└── <tactic>/
    └── TXXXX.YYY_short_name/
        ├── rule.yml    # YAML envelope with inline SPL
        └── README.md   # Data sources, tuning notes, response steps
templates/
└── rule_template.yml   # Blank template for new rules
```

## Usage

Rules are written for Splunk. Paste the `detection.spl` block directly into a new saved search or correlation alert. Adjust `index=` and suppression suggestions from `tuning.suppression_suggestions` to match your environment before promoting to production.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the folder naming convention and sanitization checklist.
