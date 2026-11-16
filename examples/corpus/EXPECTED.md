# Test corpus — expected findings

Each row encodes a labelled fixture. Run `python -m tests.corpus.run` to
check the current engine output against the expected labels.

## flask_vulnerable/app.py (adapter: flask)

| Endpoint | Expected | Reason |
|---|---|---|
| `user_details(user_id)` | 🔴 **FINDING** | `User.query.get(user_id)` directly from URL param; no auth, no ownership |
| `my_profile()` | ✅ CLEAN | `@login_required` + uses `current_user` only |
| `delete_user(user_id)` | ✅ CLEAN | `@login_required` + explicit role check |
| `get_post(post_id)` | 🟡 KNOWN FP | intentionally public; adapter can't distinguish without manual |
| `edit_post(post_id)` | 🔴 **FINDING** | `@login_required` is authn not authz; no ownership on edit |

Expected true-positive rate: 2/2 (user_details, edit_post).
Expected known FP: 1 (get_post — public by design, requires per-adapter exception).

## Future corpora

- `django_vulnerable/` — Zulip-authz-model style
- `fastapi_vulnerable/` — Depends()-based gates vs missing
- `go_net_http_vulnerable/` — SQL injection + open redirect

Total corpus target: 10+ fixtures, ≥80% catch rate on expected FINDINGs,
≤20% FP rate on expected CLEANs.
