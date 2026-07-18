<?php
/**
 * WordPress Configuration for wp2shell VULNERABLE instance (7.0.1)
 * DO NOT USE IN PRODUCTION - Local Docker lab only
 */

// ============================================================
// Database
// ============================================================
define( 'DB_NAME',     getenv_docker( 'WORDPRESS_DB_NAME', 'wordpress' ) );
define( 'DB_USER',     getenv_docker( 'WORDPRESS_DB_USER', 'wordpress' ) );
define( 'DB_PASSWORD', getenv_docker( 'WORDPRESS_DB_PASSWORD', 'wp2shell_local_only' ) );
define( 'DB_HOST',     getenv_docker( 'WORDPRESS_DB_HOST', 'mysql-vulnerable' ) );
define( 'DB_CHARSET',  'utf8' );
define( 'DB_COLLATE',  '' );
$table_prefix = getenv_docker( 'WORDPRESS_TABLE_PREFIX', 'wp_' );

// ============================================================
// Authentication Unique Keys and Salts (deterministic for local lab)
// ============================================================
define( 'AUTH_KEY',         'wp2shell-vuln-auth-key-local-lab-only-2026' );
define( 'SECURE_AUTH_KEY',  'wp2shell-vuln-secure-auth-key-local-lab-only' );
define( 'LOGGED_IN_KEY',    'wp2shell-vuln-logged-in-key-local-lab-only' );
define( 'NONCE_KEY',        'wp2shell-vuln-nonce-key-local-lab-only-2026' );
define( 'AUTH_SALT',        'wp2shell-vuln-auth-salt-local-lab-only-2026' );
define( 'SECURE_AUTH_SALT', 'wp2shell-vuln-secure-auth-salt-local-lab-only' );
define( 'LOGGED_IN_SALT',   'wp2shell-vuln-logged-in-salt-local-lab-only' );
define( 'NONCE_SALT',       'wp2shell-vuln-nonce-salt-local-lab-only-2026' );

// ============================================================
// Debug & Development
// ============================================================
define( 'WP_DEBUG',              true );
define( 'WP_DEBUG_LOG',          true );
define( 'WP_DEBUG_DISPLAY',      false );
define( 'SCRIPT_DEBUG',          true );
define( 'SAVEQUERIES',           true );
define( 'WP_AUTO_UPDATE_CORE',   false );
define( 'DISABLE_WP_CRON',       true );

// ============================================================
// Site URLs
// ============================================================
define( 'WP_HOME',    'http://127.0.0.1:8081' );
define( 'WP_SITEURL', 'http://127.0.0.1:8081' );

// ============================================================
// Helper: get environment variable with fallback
// ============================================================
function getenv_docker( $env, $default ) {
	$value = getenv( $env );
	if ( false !== $value ) {
		return $value;
	}
	return $default;
}

// ============================================================
// Bootstrap WordPress
// ============================================================
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __FILE__ ) . '/' );
}

require_once ABSPATH . 'wp-settings.php';
