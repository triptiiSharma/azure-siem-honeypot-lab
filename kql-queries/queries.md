# KQL Queries

All queries were executed in Microsoft Sentinel (Log Analytics Workspace: `LOG-Analytics-SOC-Lab-0000`) against the `SecurityEvent` table ingested via the "Windows Security Events via AMA" data connector.

<br>

## 1. Filter Failed Login Attempts (Event ID 4625)

```kql
SecurityEvent
| where EventID == 4625
```

**Purpose:** Baseline filter to isolate failed logon events from all Windows Security Event noise.

**Event ID 4625** is generated whenever an account fails to authenticate on a Windows system. In the context of this lab, every 4625 event represents one attempt by an external actor to authenticate via RDP using an invalid credential combination.

**Result:** 5,404 events returned over the last 3-day window — representing ~75% of all ingested security events.

<br>

## 2. Geo-Enriched Failed Logins

```kql
let GeoIPDB_FULL = _GetWatchlist("GEOIP");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Account, Computer, IpAddress, cityname, countryname, longitude, latitude
```

**Purpose:** Joins failed login events with the GeoIP watchlist to resolve attacker IP addresses into geographic locations (city, country, coordinates).

**How it works:**
- `_GetWatchlist("GEOIP")` loads the 54,000-row IP-range-to-location mapping into a variable.
- `evaluate ipv4_lookup()` performs a CIDR-aware join between each attacker's IP and the watchlist network ranges — more accurate than exact-match lookups since IP blocks are allocated in ranges, not individual addresses.
- `project` selects only the columns needed for visualization and analysis, discarding irrelevant fields.

**Result:** 7,868 enriched rows with full geographic attribution — used as the data source for the Sentinel Workbook attack map.

<br>

## 3. Single-IP Deep Dive

```kql
let GeoIPDB_FULL = _GetWatchlist("GEOIP");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<target_IP>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Account, Computer, IpAddress, cityname, countryname, longitude, latitude
```

**Purpose:** Scopes the enriched query to a single source IP for targeted investigation — useful when a particular IP shows unusual volume or targets unusual usernames, warranting deeper inspection.

Replace `<target_IP>` with the specific IP address to investigate (e.g., `203.215.181.30` for the Crowley, US source observed in this lab).

<br>

## Notes on KQL Syntax Used

| Operator | Function |
|----------|----------|
| `where` | Row-level filter (equivalent to SQL `WHERE`) |
| `order by` | Sorts results; `desc` = most recent first |
| `evaluate ipv4_lookup()` | CIDR-aware IP-to-range join against a reference table |
| `project` | Column selection — reduces output to specified fields only |
| `let` | Assigns a named variable for reuse within the query |
| `_GetWatchlist()` | Loads a Sentinel Watchlist as an in-query table |
