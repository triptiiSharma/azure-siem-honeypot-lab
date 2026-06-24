# Observations & Analysis

## Lab Environment

| Parameter | Value |
|-----------|-------|
| VM Name | CORP-NET-EAST-1 |
| OS | Windows 10 Enterprise |
| Region | East US 2 (Zone 1) |
| Public IP | 20.109.34.67 |
| VM Created | 6/22/2026, 6:55 AM UTC |
| NSG Rule | DANGER_AllowAnyCustomAnyInbound (all ports, all protocols, priority 100) |
| Firewall | Disabled — Domain, Private, and Public profiles |
| Log Workspace | LOG-Analytics-SOC-Lab-0000 (East US 2) |
| Observation Window | ~24 hours |

<br>

## Attack Volume

| Metric | Value |
|--------|-------|
| Total security events (Event Viewer) | 7,260 |
| Failed logins — Event ID 4625 (Event Viewer) | 5,445 |
| Failed logins — Event ID 4625 (Sentinel, 3-day window) | 5,404 |
| Geo-enriched log rows | 7,868 |
| Failed logins as % of total events | ~75% |

The marginal difference between Event Viewer (5,445) and Sentinel (5,404) counts reflects the 3-day time range applied to the Sentinel query versus the local log's full retention — not a data loss issue. The geo-enriched row count (7,868) exceeds the raw 4625 count because `ipv4_lookup()` can return multiple geographic rows per IP when a source IP maps to overlapping CIDR ranges in the watchlist.

<br>

## Geographic Attribution

Attack traffic was distributed across multiple regions simultaneously, which is a strong indicator of **botnet infrastructure** rather than a single actor:

| Origin | Volume |
|--------|--------|
| Patna, India | ~2,460 |
| United States (various) | ~2,460 |
| Auckland, New Zealand | ~1,310 |
| Ulsan, South Korea | 691 |
| Makati City, Philippines | 450 |
| Crowley, United States | 226 |
| Milton Keynes, United Kingdom | 139 |
| Burlington, Canada | 48 |
| Hyderabad, India | 36 |
| Other | 36 |

**Total unique countries:** 9+ across 4 continents (Asia, North America, Oceania, Europe).

A single human actor cannot simultaneously generate thousands of requests per hour from India, the US, New Zealand, and South Korea. The concurrent multi-region activity confirms **distributed, automated tooling** — likely compromised hosts or commercial VPS infrastructure being used as attack proxies.

<br>

## Username Targeting Analysis

Usernames observed in geo-enriched log output (from `sentinel-logs.png` and `geo-enriched-logs.png`):

`REMOTE`, `ADMINISTRATOR`, `XEON`, `HOME`, `SCAN`, `SCANNER`, `\1`

**Pattern interpretation:**

- **ADMINISTRATOR** — the default built-in Windows admin account. Its presence at the top of every attacker's wordlist is expected; successful compromise of this account grants full, unrestricted system access.
- **REMOTE / SCAN / SCANNER** — generic service-oriented usernames, commonly created by network device vendors (NAS boxes, printers, IP cameras). Attackers include these because many organizations use vendor default credentials on internet-facing devices.
- **XEON / HOME** — non-standard names that appear in common credential dumps and public wordlists derived from real breach data. Their presence indicates the attacker tool is using a broad dictionary, not just a small static list.
- **\1** — a numeric username entry, likely a wordlist artifact or a probe targeting Active Directory SID enumeration (SID 500 = built-in Administrator).

The breadth of usernames across a short time window, combined with the multi-region source distribution, is consistent with a **credential stuffing framework** operating on pre-built wordlists — not a targeted attack against this specific VM.

<br>

## Behavioral Analysis

### Speed of attack onset
The VM was created on **6/22/2026 at 6:55 AM UTC**. Event Viewer and Sentinel logs show attack activity beginning on **6/23/2026 at 9:01 AM UTC** — within approximately 26 hours of provisioning, and likely much sooner given log forwarding latency. Internet-facing RDP (TCP 3389) is continuously scanned by automated tooling; no deliberate advertisement of this host was required.

### Attack cadence
Multiple failed logins from the same source IP within seconds of each other (e.g., REMOTE at 9:01:44, ADMINISTRATOR at 9:01:43, XEON at 9:01:43, HOME at 9:01:38 from overlapping IPs) indicate **high-frequency automated tooling** cycling through credentials at machine speed, not human-paced manual attempts.

### Infrastructure diversity as a defence-evasion technique
By distributing requests across hosts in India, the US, NZ, South Korea, and the Philippines, attackers avoid triggering single-source IP-based rate limits or geo-blocking rules. This is a known tactic to evade simple threshold-based detection in SIEMs — which is precisely why **behavioral analytics** (failed login rate per account, not per IP) is more effective than IP blocklists alone.

<br>

## Defensive Implications

| Observation | Defensive Control |
|-------------|------------------|
| RDP exposed on default port (3389) | Change RDP port or disable public RDP; use Azure Bastion or Just-In-Time VM access |
| Default `ADMINISTRATOR` account targeted heavily | Rename or disable the built-in Administrator account; enforce account lockout policy |
| Attacks from 9+ countries simultaneously | Geo-blocking is insufficient — use MFA and conditional access policies instead |
| High-frequency credential cycling | Implement account lockout (e.g., 5 failed attempts → 30-minute lockout) |
| No alerting during attack window | Configure Sentinel analytics rules with brute-force detection thresholds to generate incidents automatically |
