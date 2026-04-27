# Contributing

## Adding a new detection

1. Copy `templates/rule_template.yml` into the correct tactic folder under `detections/`
2. Name the folder `TXXXX.YYY_short_descriptive_name` (lowercase, underscores)
3. Generate a UUID for the `id` field — any UUID v4 generator works
4. Fill in both `rule.yml` and `README.md` before marking status `production`

## Folder naming

Tactic folders follow MITRE ATT&CK tactic names:

```
initial_access / execution / persistence / privilege_escalation /
defense_evasion / credential_access / discovery / lateral_movement /
collection / exfiltration / command_and_control / impact
```

## Rule status lifecycle

| Status | Meaning |
|---|---|
| `draft` | Written but not yet tested in a live environment |
| `test` | Running in test/dev; tuning in progress |
| `production` | Validated, tuned, and running in production |

## Sanitization checklist

Before committing:

- [ ] No real hostnames, usernames, or IP addresses in SPL or tuning notes
- [ ] No internal index names that reveal environment topology
- [ ] Sandbox report URLs replaced with public references where possible
- [ ] UUIDs are freshly generated (not reused from another rule)
