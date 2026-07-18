# Patch Diff Analysis — 7.0.1 → 7.0.2

## Files Changed

```
src/wp-includes/class-wp-query.php           ★ SQLi fix
src/wp-includes/rest-api.php                  ★ Re-entrancy guard
src/wp-includes/rest-api/class-wp-rest-server.php  ★ Route confusion fix
src/wp-admin/about.php                        (version bump)
src/wp-includes/version.php                   (version bump)
composer.json / package.json                  (version bump)
```

## Fix 1: Array Alignment (class-wp-rest-server.php)

```diff
  foreach ( $requests as $single_request ) {
      if ( is_wp_error( $single_request ) ) {
          $has_error    = true;
+         $matches[]    = $single_request;   // ← KEY FIX
          $validation[] = $single_request;
          continue;
      }
```

When a request fails parsing, both `$matches[]` and `$validation[]` now get the `WP_Error`. Arrays stay aligned. Dispatch loop uses correct `$matches[$i]` for every request.

## Fix 2: Re-entrancy Guards

### serve_request()
```diff
  public function serve_request( $path = null ) {
+     if ( $this->is_dispatching() ) {
+         return false;
+     }
```

### rest_api_loaded()
```diff
  function rest_api_loaded() {
+     if ( isset( $GLOBALS['wp_rest_server'] )
+         && $GLOBALS['wp_rest_server'] instanceof WP_REST_Server
+         && $GLOBALS['wp_rest_server']->is_dispatching()
+     ) {
+         return;
+     }
```

Prevents a fresh REST dispatch cycle from starting while another is already in flight — blocks recursive batch exploits.

## Fix 3: WP_Query Sanitization (class-wp-query.php)

```diff
  if ( ! empty( $query_vars['author__not_in'] ) ) {
-     if ( is_array( $query_vars['author__not_in'] ) ) {
-         $query_vars['author__not_in'] = array_unique(
-             array_map( 'absint', $query_vars['author__not_in'] )
-         );
-         sort( $query_vars['author__not_in'] );
+     $author__not_in_id_list = wp_parse_id_list( $query_vars['author__not_in'] );
+     if ( count( $author__not_in_id_list ) > 0 ) {
+         sort( $author__not_in_id_list );
+         $where .= sprintf(
+             " AND {$wpdb->posts}.post_author NOT IN (%s) ",
+             implode( ',', $author__not_in_id_list )
+         );
+         $query_vars['author__not_in'] = $author__not_in_id_list;
      }
-     $author__not_in = implode( ',', (array) $query_vars['author__not_in'] );
-     $where .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
  }
```

**Old:** `is_array()` gate skipped for strings → `(array)` cast → raw string in SQL.

**New:** `wp_parse_id_list()` handles all input types uniformly → always returns `int[]` → safe.

## All Version Pairs

| Pair | Both Fixes |
|------|-----------|
| 7.0.1 → 7.0.2 | ✅ |
| 6.9.4 → 6.9.5 | ✅ (identical patches) |
| 6.8.5 → 6.8.6 | ✅ SQLi fix + guards (6.8 has no batch endpoint but guards added defensively) |

## Commit Hashes

| Tag | Commit |
|-----|--------|
| 7.0.1 (vuln) | `ca02900921` |
| 7.0.2 (fixed) | `855551c447` |
| 6.9.4 (vuln) | `074792ef21` |
| 6.9.5 (fixed) | `22cfe2318f` |
| 6.8.5 (vuln) | `a1b6ae4c8e` |
| 6.8.6 (fixed) | `c4ee97a868` |
