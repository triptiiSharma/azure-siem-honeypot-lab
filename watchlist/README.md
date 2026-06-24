# GeoIP Watchlist

## Source
```
https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/misc/geoip-summarized.csv
```

## What it is
A CSV file containing approximately **54,000 rows**, each mapping an IP network range (CIDR block) to a geographic location — including country name, city name, latitude, and longitude.

Imported into Microsoft Sentinel as a **Watchlist** with alias `GEOIP`.

## How it's used in this lab
The watchlist is loaded in KQL using `_GetWatchlist("GEOIP")` and joined against raw attacker IPs via `evaluate ipv4_lookup()`. This performs a **CIDR-aware** match — meaning an attacker IP like `203.215.181.30` correctly resolves to the network range that contains it, rather than requiring an exact IP match.

The enriched output adds `cityname`, `countryname`, `latitude`, and `longitude` columns to each failed login event, enabling geographic visualization in the Sentinel Workbook.

## Why it's not stored in this repo
The CSV is ~54,000 rows and changes infrequently. Use the source URL above to download it directly and import it into your own Sentinel instance via: **Microsoft Sentinel → Watchlists → + New**.

Set the **SearchKey** column to `network` (the CIDR range field) to enable `ipv4_lookup()` to function correctly.

## Production equivalent
In an enterprise environment, this static CSV would be replaced by a dynamically updated threat intelligence feed — such as Microsoft Defender Threat Intelligence (MDTI), MISP, or a commercial TI provider — refreshed on a scheduled basis via Logic Apps or the Sentinel TI connector.
