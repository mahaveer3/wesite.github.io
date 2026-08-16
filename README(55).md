# SQL Injection in WHERE clause — `category` parameter

**Finding ID:** WSALAB-SQLI-001 | **Status:** validated | **Lab:** SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

## Summary

The `category` query parameter on `/filter` is concatenated into a SQL `WHERE` clause without parameterization. An attacker can alter the query's semantics with a single quote, comment syntax, and boolean logic to retrieve rows the query was intended to hide (unreleased products). In a full-scope engagement the same primitive extends to UNION-based extraction of arbitrary table data.

## Affected Asset

- **Host:** `https://0a5200d603fc38c8806cd57100880028.web-security-academy.net`
- **Endpoint:** `/filter`
- **Parameter:** `category` (GET)

## Preconditions

- None — the endpoint is unauthenticated. Any visitor can exploit it.
- Authorized lab target (PortSwigger Web Security Academy).

## Steps to Reproduce

1. Baseline: `GET /filter?category=Gifts` → **200**, 3 products.
2. Syntax mutation: `GET /filter?category=Gifts'` → **500** (broken SQL — proves input reaches query construction).
3. Comment restore: `GET /filter?category=Gifts'--` → **200**, query valid again.
4. Boundary violation: `GET /filter?category=' OR 1=1--` → **200**, **20 products** including hidden/unreleased rows.

## Expected Result

`category=Gifts` returns only the products matching the Gifts category; `OR 1=1` is inert data, not SQL.

## Actual Result

`category=' OR 1=1--` returns the full product catalog (20 rows vs 3 baseline), including products not listed in any category filter — e.g. *Giant Pillow Thing*, *The Trapster*, *Eggtastic*, *Safety First* — i.e. data the WHERE clause was designed to suppress.

## Security Impact

**Confidentiality loss.** An unauthenticated attacker retrieves records hidden from the public catalog. At scale (same flawed pattern in a real app), an attacker could combine this with UNION queries to extract arbitrary database contents (users, credentials, PII).

## Evidence

| Artifact | Content |
|---|---|
| `evidence_baseline_Gifts.html` | Baseline: `category=Gifts`, 200, 3 products |
| `evidence_mutation_quote_500.html` | `category=Gifts'`, 500 — DB-layer causality |
| `evidence_comment_restore.html` | `category=Gifts'--`, 200 — comment syntax valid |
| `evidence_OR_1_1_all_products.html` | `category=' OR 1=1--`, 200, 20 products |
| `evidence_repro1.html` / `evidence_repro2.html` | Two repeats, identical 200/20 — reproducible |
| `evidence_control_nonexistent.html` | `category=NonexistentXYZ`, 200 empty — not a generic error |

## False-Positive Checks (passed)

- **WAF block?** No — trigger returns a real application page with the product list, not a block/challenge page.
- **Generic app error?** No — a nonexistent category returns a clean 200 empty list; only SQL-syntax-mutating input produces the 500. The differential (empty input 200 → quote 500 → comment 200 → OR 1=1 more rows) proves database-layer causality.

## Validation

- Reproducible: 2/2 repeats returned identical 200 / 20-product responses.
- Security boundary violated: rows outside the requested category (hidden/unreleased) are returned.
- False-positive checks passed.
- Independent confirmation: PortSwigger lab marked **Solved**.

## Remediation Direction

Use parameterized queries / prepared statements for the `category` filter. Never concatenate user-controlled input into SQL. Apply least-privilege DB roles so that even a query-injection primitive cannot reach sensitive tables.

## Limitations

- Lab environment; impact demonstrated read-only with 8 total requests. No UNION-based data extraction was performed (out of scope for the lab objective).
