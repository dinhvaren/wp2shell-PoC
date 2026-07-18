#!/bin/bash
# WordPress setup script - runs inside the container
# Usage: setup-wp.sh

set -e

URL="${1:-http://localhost}"
TITLE="${2:-WordPress}"
ADMIN_USER="${3:-admin}"
ADMIN_PASS="${4:-wp2shell-local-lab}"
ADMIN_EMAIL="${5:-admin@localhost.local}"

echo "Installing WordPress at ${URL}..."
wp core install \
    --url="${URL}" \
    --title="${TITLE}" \
    --admin_user="${ADMIN_USER}" \
    --admin_password="${ADMIN_PASS}" \
    --admin_email="${ADMIN_EMAIL}" \
    --skip-email \
    --allow-root

# Create test posts
wp post create \
    --post_type=post \
    --post_title="Test Post 1" \
    --post_content="Test content for wp2shell lab." \
    --post_status=publish \
    --post_author=1 \
    --allow-root

wp post create \
    --post_type=post \
    --post_title="Test Post 2" \
    --post_content="Another test post." \
    --post_status=publish \
    --post_author=1 \
    --allow-root

echo "WordPress installed successfully at ${URL}"
