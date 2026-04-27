# AD Computer Object Asset Enrichment (CreateADComputers)

| Field | Value |
|---|---|
| **Type** | Enrichment |
| **Status** | Production |
| **SIEM** | Splunk |
| **App Dependencies** | SA-LDAPSearch, Splunk Enterprise Security |
| **Schedule** | Daily at 04:00 (`0 4 * * *`) |
| **Outputs** | `AD_Computers.csv`, `HostMacIPWithAssetID` |

## What this does

Two-phase scheduled search that builds the Splunk ES Asset & Identity Framework lookup from Active Directory computer objects.

**Phase 1 — AD Extraction → `AD_Computers.csv`:** Queries AD for all machine accounts, infers OS and business unit from OU path, joins MAC/IP from the existing `HostMacIP.csv` lookup, and writes a normalized asset record per host.

**Phase 2 — Merge → `HostMacIPWithAssetID`:** Appends `HostMacIP.csv` directly (covering unmanaged hosts and network devices not in AD), merges the two schemas, deduplicates, applies cardinality filtering, resolves PCI domain classification, and writes the final lookup consumed by ES correlation searches.

## App / add-on dependencies

| Add-on | Purpose |
|---|---|
| Splunk Supporting Add-on for Active Directory (SA-LDAPSearch) | Provides the `ldapsearch` command |
| Splunk Enterprise Security | Implied by `outputlookup` targets and asset field schema (`pci_domain`, `asset_tag`) |

## Required inputs

| Source | Fields Used |
|---|---|
| LDAP / Active Directory (via `ldapsearch`) | `name`, `operatingSystem`, `operatingSystemVersion`, `description`, `DNSHostName`, `dn` |
| `HostMacIP.csv` | `Hostname`, `MACAddress`, `IPAddress`, `FQDN` |

## Generated outputs

| Lookup | Consumers |
|---|---|
| `AD_Computers.csv` | Asset inventory, identity correlation |
| `HostMacIPWithAssetID` | ES Asset & Identity Framework (`asset_lookup_by_str`, `asset_lookup_by_cidr`), downstream correlation searches |

## Phase 1 walkthrough

**1. LDAP query**
Pulls all computer objects using `SAMAccountType=805306369` (the well-known constant for machine accounts). Returns raw LDAP attributes including the full distinguished name (`dn`).

**2. OU extraction**
`rex field=dn "OU=(?<OUs>.*?)\," max_match=0` — extracts all OU components as a multivalue field, capturing every level of the hierarchy for downstream `mvfilter` lookups.

**3. Operating system inference**
Where `operatingSystem` is missing from the LDAP record, falls back to matching OU path components against a known OS list. Handles machines where the AD attribute is unpopulated.

**4. Business unit assignment**
Derives `bunit` by matching OU components against a known list of BU OU names. No direct AD attribute — entirely OU-path-driven.

**5. Priority and compliance fields**
`priority` is derived from `category` (`Servers` → High, else Low). Note: `category` is null at this point in the search, so all records will resolve to Low unless `category` is pre-seeded by a lookup join upstream. `should_update` and `requires_av` are statically set to `true`; `is_expected` and `should_timesync` are explicitly nulled for Phase 2 to resolve.

**6. MAC/IP join**
Joins `HostMacIP.csv` on hostname to bring in network identity data. Multiple IPs are pipe-delimited for CSV compatibility.

**7. Field normalization and output**
Renames to ES asset schema field names (`nt_host`, `dns`) before writing `AD_Computers.csv`.

## Phase 2 walkthrough

**8. Append raw network lookup**
`inputlookup append=t HostMacIP.csv` brings in machines with network presence but no AD record — unmanaged hosts, network devices, printers.

**9. Identity field coalescing**
Normalizes field names across the two source schemas. `HostMacIP.csv` uses `Hostname`/`FQDN`/`IPAddress`/`MACAddress`; the AD results use `nt_host`/`dns`/`ip`/`mac`.

**10. Deduplication and cardinality filtering**
`stats values(*) as * by nt_host` merges all records per hostname. The `mvcount < 20` filters on IP and MAC drop hosts with implausibly large cardinality — typically DHCP infrastructure, load balancers, or dirty data that would pollute asset correlation.

**11. Multivalue → pipe-delimited string**
ES asset lookups expect pipe-delimited strings for multi-value network identifiers, not native Splunk multivalue fields.

**12. Compliance field defaults**
`fillnull value="false"` ensures records sourced only from `HostMacIP.csv` get explicit `false` values rather than null, preventing downstream `isnull()` logic from misfiring.

**13. PCI domain and category enrichment**
- If `category == "cardholder"` and not already tagged `pci` → appends `pci` to the category multivalue field
- `pci_domain` is constructed from existing values: `pci`/`wireless`/`dmz` → adds `trust`; `cardholder` → adds both `trust` and `cardholder`; defaults to `untrust` if still null after all logic
- `asset_tag` is a composite multivalue built from boolean compliance flags (`should_timesync`, `should_update`, `is_expected`) plus `category` and `bunit` — used by ES tag-based correlation logic

**14. Final output**
Writes `HostMacIPWithAssetID` in the field schema expected by `asset_lookup_by_str` and `asset_lookup_by_cidr`.

## Field schema

| Field | Source | Notes |
|---|---|---|
| `nt_host` | AD `name` / `HostMacIP.csv` Hostname | Primary join key |
| `dns` | AD `DNSHostName` / `HostMacIP.csv` FQDN | Coalesced across schemas |
| `ip` | `HostMacIP.csv` IPAddress | Pipe-delimited multivalue |
| `mac` | `HostMacIP.csv` MACAddress | Pipe-delimited multivalue |
| `bunit` | Derived from AD OU path | No direct AD attribute used |
| `operatingSystem` | AD attribute or OU-inferred fallback | |
| `priority` | Derived from `category` | Effectively always Low unless category pre-populated |
| `pci_domain` | Derived from `category` / existing `pci_domain` | Defaults to `untrust` |
| `category` | External — not populated by this search directly | Must be pre-seeded upstream |
| `asset_tag` | Computed composite | Drives tag-based ES correlation |
| `requires_av` | Statically `true` | |
| `should_update` | Statically `true` | |
| `is_expected` | Null in Phase 1, `false` default in Phase 2 | |
| `should_timesync` | Null in Phase 1, `false` default in Phase 2 | |

## Tuning notes

**Cardinality thresholds:** The `mvcount < 20` filters are conservative. If your environment has legitimate multi-homed hosts (e.g., hypervisors, servers with many VIPs), raise the threshold or add host-specific exclusions before the filter.

**Category gap:** `category` is not populated by this search — `priority` will always resolve to Low until category is pre-seeded by a separate lookup join running before this search. If server/workstation classification matters for downstream rules, resolve this dependency first.

**PCI domain logic:** The PCI enrichment eval is stateful — it reads and writes `pci_domain` in the same eval chain. If `pci_domain` is already populated from a prior run or upstream lookup, the logic appends to it rather than overwriting. Verify on first run that `pci_domain` values are not accumulating across runs.
