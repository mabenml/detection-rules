# detection-rules
Sanitized Splunk correlation searches mapped to MITRE ATT&CK, with tuning notes and data source documentation.

Each rule ships as a YAML envelope with inline SPL, a human-readable `README.md` covering data source requirements and response steps, and explicit tuning/false-positive guidance.

## Detection index

| ID | Title | Tactic | Severity | Status |
|---|---|---|---|---|
| [T1566.001](detections/initial_access/T1566.001_spearphishing_attachment/) | Suspicious Email Attachment Execution via Outlook | Initial Access | High | Production |

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
