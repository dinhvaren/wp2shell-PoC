# Root Cause Analysis — wp2shell

## CVE-2026-63030: REST Batch Route Confusion

### Location
`src/wp-includes/rest-api/class-wp-rest-server.php` — `serve_batch_request_v1()`

### Bug

When a batch sub-request fails `wp_parse_url()` (e.g. path `"///"`), a `WP_Error` is pushed to `$validation[]` but **not** to `$matches[]`:

```php
// Vulnerable (7.0.1)
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        $has_error    = true;
        $validation[] = $single_request;  // appended
        continue;                          // $matches[] NOT appended — BUG
    }
    $match     = $this->match_request_to_handler( $single_request );
    $matches[] = $match;
    // ... validation ...
}
```

This causes index misalignment. With 3 requests `[WP_Error, req_A, req_B]`:

| Loop $i | `$validation[]` | `$matches[]` |
|---------|----------------|-------------|
| 0 (WP_Error) | index 0 | **skipped** |
| 1 (req_A) | index 1 | index 0 |
| 2 (req_B) | index 2 | index 1 |

In the dispatch loop, `$matches[$i]` is used with `$i` from `$requests`, but `$matches` has fewer elements:

```php
foreach ( $requests as $i => $single_request ) {
    $match = $matches[ $i ];  // $i=1 → $matches[1] = req_B's handler!
```

**Result:** req_A executes with req_B's callback.

### Fix (7.0.2)

```php
if ( is_wp_error( $single_request ) ) {
    $has_error    = true;
    $matches[]    = $single_request;  // NOW both arrays stay aligned
    $validation[] = $single_request;
    continue;
}
```

Plus re-entrancy guards in `serve_request()` and `rest_api_loaded()` checking `$this->is_dispatching()`.

---

## CVE-2026-60137: WP_Query SQL Injection

### Location
`src/wp-includes/class-wp-query.php`

### Bug

`author__not_in` is only sanitized when it is an **array**. Scalar strings bypass the guard:

```php
// Vulnerable (7.0.1)
if ( ! empty( $q['author__not_in'] ) ) {
    if ( is_array( $q['author__not_in'] ) ) {
        // absint() each element — only runs for arrays
        $q['author__not_in'] = array_unique( array_map( 'absint', $q['author__not_in'] ) );
    }
    // (array) wraps string → single-element array → implode returns raw string
    $author__not_in = implode( ',', (array) $q['author__not_in'] );
    $where .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
}
```

**Payload:** `author__not_in = "0) AND SLEEP(5)-- -"`

- `is_array("0) AND SLEEP(5)-- -")` → false, sanitize skipped
- `(array)"0) AND SLEEP(5)-- -"` → `["0) AND SLEEP(5)-- -"]`
- `implode(',', ...)` → `"0) AND SLEEP(5)-- -"` (raw, unsanitized)
- Result SQL: `... AND post_author NOT IN (0) AND SLEEP(5)-- -)`

### Fix (7.0.2)

```php
$author__not_in_id_list = wp_parse_id_list( $q['author__not_in'] );
if ( count( $author__not_in_id_list ) > 0 ) {
    sort( $author__not_in_id_list );
    $where .= sprintf(
        " AND {$wpdb->posts}.post_author NOT IN (%s) ",
        implode( ',', $author__not_in_id_list )
    );
    $q['author__not_in'] = $author__not_in_id_list;
}
```

`wp_parse_id_list()` converts any input (scalar, array, CSV) → `int[]`. All values are guaranteed integers before reaching SQL.

---

## Why They Must Be Chained

| Alone | Impact |
|-------|--------|
| Route confusion only | Wrong handler dispatch, but REST schema validation rejects strings for `author_exclude` |
| SQLi only | `author_exclude` validated as `array<int>` by REST schema → string rejected at API layer |

| Chained | Impact |
|---------|--------|
| Confusion bypasses schema validation (validated against wrong route) → string reaches `WP_Query::author__not_in` → **SQL injection** |
