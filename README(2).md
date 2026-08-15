# Bug Bounty Hunter's Web Application Security Playbook

> A practical, modern methodology for finding, validating, chaining, and reporting web application vulnerabilities against **authorized bug-bounty targets**.
>
> **Current reference model: OWASP Top 10:2025.** This guide also pulls in the OWASP API Security Top 10, OWASP ASVS 5.0, the OWASP Web Security Testing Guide, and current web-security research. The goal is not to memorize a payload list; it is to understand trust boundaries, state transitions, parser differences, authorization decisions, and business invariants well enough to discover bugs that scanners miss.

---

## Table of Contents

- [1. Scope and Rules](#1-scope-and-rules)
- [2. Current OWASP Top 10:2025](#2-current-owasp-top-102025)
- [3. How to Think Like a Bug Bounty Hunter](#3-how-to-think-like-a-bug-bounty-hunter)
- [3.1. The Bug Bounty Operating Loop](#31-the-bug-bounty-operating-loop)
- [3.2. Gold-Standard Vulnerability Analysis Format](#32-gold-standard-vulnerability-analysis-format)
- [4. Modern Web Attack Surface](#4-modern-web-attack-surface)
- [5. Reconnaissance and Attack-Surface Mapping](#5-reconnaissance-and-attack-surface-mapping)
- [6. A01:2025 Broken Access Control](#6-a012025-broken-access-control)
- [7. A02:2025 Security Misconfiguration](#7-a022025-security-misconfiguration)
- [8. A03:2025 Software Supply Chain Failures](#8-a032025-software-supply-chain-failures)
- [9. A04:2025 Cryptographic Failures](#9-a042025-cryptographic-failures)
- [10. A05:2025 Injection](#10-a052025-injection)
- [11. A06:2025 Insecure Design](#11-a062025-insecure-design)
- [12. A07:2025 Authentication Failures](#12-a072025-authentication-failures)
- [13. A08:2025 Software or Data Integrity Failures](#13-a082025-software-or-data-integrity-failures)
- [14. A09:2025 Security Logging and Alerting Failures](#14-a092025-security-logging-and-alerting-failures)
- [15. A10:2025 Mishandling of Exceptional Conditions](#15-a102025-mishandling-of-exceptional-conditions)
- [16. Cross-Cutting Modern Techniques](#16-cross-cutting-modern-techniques)
- [16.5. 2025–2026 Research Priorities](#165-20252026-research-priorities)
- [17. API Security](#17-api-security)
- [18. OAuth / OIDC / SSO Testing](#18-oauth--oidc--sso-testing)
- [19. GraphQL Testing](#19-graphql-testing)
- [20. WebSocket Testing](#20-websocket-testing)
- [21. HTTP Desync and Request Smuggling](#21-http-desync-and-request-smuggling)
- [22. Web Cache Poisoning and Cache Deception](#22-web-cache-poisoning-and-cache-deception)
- [23. Race Conditions and TOCTOU](#23-race-conditions-and-toctou)
- [24. SSRF and Cloud Metadata](#24-ssrf-and-cloud-metadata)
- [25. Client-Side and Browser Attack Surface](#25-client-side-and-browser-attack-surface)
- [26. Common Bug-Bounty Chains](#26-common-bug-bounty-chains)
- [27. Tooling and Automation](#27-tooling-and-automation)
- [28. Validation and False-Positive Control](#28-validation-and-false-positive-control)
- [29. Impact, Severity, and Reports](#29-impact-severity-and-reports)
- [30. Practical Checklists](#30-practical-checklists)
- [31. Learning Path](#31-learning-path)
- [32. Research Corpus: POCs, Write-Ups, Disclosures, and Case Studies](#32-research-corpus-pocs-write-ups-disclosures-and-case-studies)
- [33. True-Positive Validation and Detailed POC Engineering](#33-true-positive-validation-and-detailed-poc-engineering)
- [34. Primary References](#34-primary-references)

---

# 1. Scope and Rules

This playbook assumes you are testing systems where you have explicit authorization, such as an in-scope bug-bounty asset, your own application, a lab, or a written penetration-test scope.

### Non-negotiable rules

1. Read the program policy before sending active traffic.
2. Treat production data as real data even when it is technically accessible.
3. Never destroy, modify, delete, encrypt, or mass-download data just to prove impact.
4. Do not test denial-of-service, mail bombing, account locking, payment abuse, or destructive race conditions unless the program explicitly authorizes that testing.
5. Use the minimum number of requests needed to demonstrate the issue.
6. Prefer two test accounts you control for authorization testing.
7. Prefer canary/OAST infrastructure you control for blind SSRF or XXE validation.
8. Stop once you have enough evidence to demonstrate impact.
9. Keep timestamps, request/response pairs, and exact reproduction steps.
10. Report the root cause and security impact, not merely the interesting response.

### Core principle

A bug bounty is not a contest to collect weird responses. A valid finding normally needs this chain:

```text
Attacker-controlled input
        ↓
Unexpected trust-boundary crossing / security-control failure
        ↓
Observable security property violation
        ↓
Concrete impact
        ↓
Reproducible evidence
```

A `200 OK`, an error stack trace, an exposed header, or a permissive CORS header is not automatically a vulnerability.

---

# 2. Current OWASP Top 10:2025

OWASP's current web application Top 10 is the 2025 edition. The categories are:

| Rank | Category | Hunter's high-value focus |
|---|---|---|
| A01 | Broken Access Control | IDOR/BOLA, privilege escalation, forced browsing, CORS, tenant isolation |
| A02 | Security Misconfiguration | Debug surfaces, exposed admin/debug endpoints, cloud/storage mistakes, parser configuration, unsafe defaults |
| A03 | Software Supply Chain Failures | Dependency provenance, CI/CD, build systems, package compromise, workflow trust |
| A04 | Cryptographic Failures | Weak secrets, bad key handling, token protection, downgrade/misuse, predictable randomness |
| A05 | Injection | SQL/NoSQL/OS/template/LDAP/XPath/HTML/command injection, parser confusion |
| A06 | Insecure Design | Missing business invariants, abuse cases, workflow bypass, unsafe trust assumptions |
| A07 | Authentication Failures | Account enumeration, reset flaws, MFA/session issues, credential abuse, OAuth/OIDC weaknesses |
| A08 | Software or Data Integrity Failures | Unsafe deserialization, untrusted artifacts, update integrity, dynamic loading, tampered data |
| A09 | Security Logging & Alerting Failures | Security events not recorded/detected, log forgery, blind spots, alert bypass |
| A10 | Mishandling of Exceptional Conditions | Fail-open states, error-path auth bypasses, race conditions, inconsistent rollback, parser/error-state bugs |

OWASP states that two categories are new in 2025 and that the taxonomy was reorganized around root causes. A03 and A10 therefore deserve special attention when comparing modern research with older 2021-era checklists.

### 2021 → 2025 migration mindset

Do not stop testing a class because its old OWASP label disappeared.

Examples:

- **XXE** still matters; it is largely discussed under misconfiguration/injection-related weaknesses depending on root cause.
- **SSRF** still matters and can appear under access-control or injection/design problems depending on the exact flaw.
- **XSS** remains injection even though it is no longer a standalone Top 10 item.
- **CSRF** remains relevant wherever a state-changing operation lacks a robust origin/authentication binding.
- **Insecure deserialization** remains highly relevant and is explicitly represented in A08.
- **Security misconfiguration** moved to A02 and is broader than headers alone.

Use the OWASP category to communicate the root cause. Use CWE and the program's taxonomy to communicate the precise weakness.

---

# 3. How to Think Like a Bug Bounty Hunter

## 3.1 The five questions

For every endpoint, ask:

1. **Who can call it?**
2. **What can they control?**
3. **What trust boundary does the data cross?**
4. **What security decision is made from that data?**
5. **What invariant should never be violated?**

The fifth question is where many high-quality findings come from.

Examples:

- A user may edit **their own** invoice, never another customer's invoice.
- A password reset token may be valid only for **one** account, one purpose, and one bounded lifetime.
- A discount may reduce a price but never make the final amount negative.
- A deleted object must not remain accessible through an old identifier.
- A tenant identifier supplied by the client must never override the tenant derived from the authenticated session.
- A server-side fetch feature must not become a primitive for reaching internal control planes.

## 3.2 Model applications as state machines

Many modern vulnerabilities are state problems rather than string problems.

```text
Unauthenticated
      ↓ login
Authenticated user
      ↓ role change / tenant change
Privileged state
      ↓ sensitive action
Committed business state
```

At each transition, test whether the server actually verifies the expected preconditions.

Common questions:

- Can step 3 be called without step 1?
- Can step 2 be repeated?
- Can step 2 be replayed after logout?
- Can a value from step 1 be swapped into step 3?
- Can two requests cross in time?
- Does a failed request leave partial state behind?
- Does a cached response preserve state that should be private?

## 3.3 Think in differential tests

The most reliable manual method is to change **one security-relevant variable at a time**.

Examples:

```text
User A → object 1001 → 200
User B → object 1001 → 403

User A → object 1002 → 200
```

The interesting observation is not the absolute response; it is the difference caused by changing identity, role, tenant, object, method, origin, or state.

---


## 3.1. The Bug Bounty Operating Loop

Do not treat bug hunting as a flat checklist of vulnerability names. The strongest workflow is a closed loop that turns reconnaissance into hypotheses, hypotheses into validated findings, and validated findings into reproducible reports.

```text
Recon
  ↓
Attack Surface Map
  ↓
Hypothesis Generation
  ↓
Manual Testing
  ↓
Automation
  ↓
Candidate Findings
  ↓
Differential Testing
  ↓
True / False Positive Decision
  ↓
Impact Validation
  ↓
Minimal Safe POC
  ↓
Chaining
  ↓
Demonstrable Business Impact
  ↓
Evidence Package
  ↓
Reproducible Report
  ↓
Retest
  ↓
Regression Confirmation
  ↺
New hypotheses from what you learned
```

### Stage 1 — Recon → Attack Surface Map

The objective is not “find as many subdomains as possible.” The objective is to understand **where the application's trust boundaries, identities, data flows, and business operations live**.

Map at minimum:

```text
Assets
├── Domains / subdomains
├── Web applications
├── APIs
├── Mobile backends
├── GraphQL
├── WebSockets
├── OAuth / OIDC / SSO
├── File upload / download
├── Admin surfaces
├── Partner / integration APIs
├── Webhooks
├── CDN / cache layers
├── Object storage
└── Supporting infrastructure
```

For every high-value surface, record:

| Field | Example |
|---|---|
| Host | `app.example.com` |
| Function | Account management |
| Auth state | Anonymous / user / admin |
| Input types | JSON, query, path, headers, files |
| Sensitive objects | invoices, users, API keys |
| Trust boundary | browser → API → service |
| Interesting controls | RBAC, tenant checks, rate limits |
| Candidate hypotheses | BOLA, race, parser differential |
| Evidence | Request/response references |

The output of reconnaissance should therefore be an **attack-surface map**, not a raw list of URLs.

### Stage 2 — Hypothesis Generation → Manual Testing

For each mapped component, ask a concrete question.

Bad hypothesis:

```text
“Maybe this has IDOR.”
```

Better:

```text
“The invoice API appears to authorize using the invoice ID alone.
Does a normal user from tenant B receive tenant A's invoice when the
object identifier is changed?”
```

A useful hypothesis specifies:

```text
Attacker capability
+ security boundary
+ manipulated condition
+ expected control
+ observable outcome
```

Manual testing comes before heavy automation when the bug depends on business logic, state, sequencing, role relationships, or parser behavior.

### Stage 3 — Automation → Candidate Findings

Automation should reduce repetitive work, not replace reasoning.

Good automation targets:

- endpoint and parameter discovery
- technology fingerprinting
- passive JavaScript analysis
- known-pattern detection
- parameter mining
- HTTP method enumeration
- content discovery
- basic differential comparisons
- repeated, rate-limited checks
- organizing evidence

The output should be a **candidate queue**:

```text
Candidate
├── What triggered it?
├── Asset
├── Endpoint
├── Input
├── Hypothesis
├── Evidence
├── Confidence
└── Next manual test
```

A scanner alert is never equivalent to a confirmed vulnerability.

### Stage 4 — Differential Testing → True / False Positive

Differential testing is one of the highest-value validation techniques in web security.

Change exactly one relevant variable and compare outcomes.

Examples:

```text
User A vs User B
Authenticated vs anonymous
Authorized object vs unauthorized object
Valid ID vs neighboring ID
Normal header vs manipulated header
Normal parser input vs ambiguous parser input
Before state transition vs after state transition
One request vs concurrent requests
Cached vs uncached request
GET vs POST / PATCH / DELETE
```

Compare more than status codes:

```text
Status
Body
Sensitive fields
Headers
Set-Cookie
Redirect target
Cache headers
Response timing
Side effects
Server-side state
Out-of-band callbacks
```

The goal is to answer:

> **What security-relevant property changed, and was the manipulated condition actually responsible for that change?**

### Stage 5 — Impact Validation → Minimal Safe PoC

Once the security boundary is proven, demonstrate the **minimum impact needed to remove ambiguity**.

Prefer:

```text
read-only proof > destructive proof
researcher-owned account > real victim
canary data > real sensitive dataset
one affected object > bulk extraction
controlled callback > internal service probing
```

Do not inflate impact by doing unnecessary damage.

### Stage 6 — Chaining → Demonstrable Business Impact

Chaining is not “adding bugs together.” A useful chain demonstrates that one weakness materially increases the consequences of another.

```text
Weak authorization
      ↓
Sensitive object access
      ↓
Export functionality
      ↓
Cross-tenant disclosure
```

Or:

```text
Stored XSS
   ↓
Privileged user context
   ↓
CSRF-like state-changing action
   ↓
Account takeover
```

A chain should make the business consequence clearer than the individual findings did alone.

### Stage 7 — Evidence → Reproducible Report

Evidence should allow another security researcher or triager to reproduce the issue without reverse-engineering your narrative.

Capture:

```text
Scope
Account / role
Preconditions
Baseline request
Trigger request
Response evidence
Expected behavior
Observed behavior
Security boundary violated
Impact
Reproduction rate
Relevant timestamps
Safe proof of consequence
```

Never substitute a screenshot for the underlying request/response evidence when raw evidence is available.

### Stage 8 — Retest → Regression Confirmation

A mature workflow continues after remediation.

Retest the same security property using:

```text
Original exploit condition
Original negative control
Adjacent method / endpoint where relevant
Original authorization boundary
Original state transition
```

A good retest answers:

```text
Fixed completely?
Fixed only at the UI layer?
Fixed one endpoint but not siblings?
Fixed reads but not writes?
Fixed one role but not another?
Fixed the symptom but not the root cause?
```

The goal is **regression confirmation**, not merely seeing a different status code.

---

## 3.2. Gold-Standard Vulnerability Analysis Format

Every vulnerability class in this playbook should be analyzed using the same structure. This makes the guide operational rather than a collection of disconnected payload lists.

> **What to look for → Where to look → Test methodology → Expected vulnerable behavior → False positives → Safe PoC → Impact → Chaining opportunities → Evidence → Report wording**

### 1. What to look for

Define the underlying security failure, not the payload.

Examples:

```text
IDOR/BOLA
→ Object is referenced by attacker-controlled identifier without
  server-side ownership authorization.

Request smuggling
→ Different HTTP components parse the same message boundary differently.

Race condition
→ A security-sensitive state transition is not atomic.
```

### 2. Where to look

Identify the highest-probability surfaces.

```text
Object IDs
Admin endpoints
Bulk operations
Exports
File processing
Webhooks
OAuth callbacks
Password recovery
Background jobs
Caching layers
Parser boundaries
Multi-step transactions
```

### 3. Test methodology

Describe the test as an experiment.

```text
Baseline
→ manipulate one variable
→ compare with control
→ repeat
→ test adjacent paths
→ confirm server-side effect
```

Where useful, specify a matrix:

| Dimension | Control | Variant |
|---|---|---|
| Identity | User A | User B |
| Object | Own object | Other user's object |
| Role | Standard | Admin |
| Method | GET | PATCH |
| State | Before action | After action |
| Timing | Sequential | Concurrent |
| Cache | Miss | Hit |
| Parser | Unambiguous | Ambiguous |

### 4. Expected vulnerable behavior

State exactly what would constitute a security failure.

Examples:

```text
Expected: 403 or equivalent object-level denial.
Vulnerable: attacker receives another principal's protected object.
```

or:

```text
Expected: all intermediaries agree on the request boundary.
Vulnerable: front-end and back-end disagree and process attacker-controlled
bytes as different requests.
```

### 5. False positives

Document what can look vulnerable without actually creating a security issue.

Common examples:

- a public object that is intentionally public
- client-side-only role information
- a decoded but correctly verified JWT
- reflection without executable context
- a CORS header without sensitive credentialed data exposure
- a `200 OK` error wrapper that does not grant access
- a sequential identifier without missing authorization
- a server-side request that only reaches an expected public resource
- inconsistent responses caused by normal caching or rate limiting

### 6. Safe PoC

Use the smallest reliable demonstration.

```text
Input
→ security boundary
→ observable violation
→ minimum consequence
```

The POC should be safe to run repeatedly and should preferably use accounts, records, domains, callback URLs, or data controlled by the researcher.

### 7. Impact

Translate the technical primitive into a security consequence.

```text
Confidentiality
Integrity
Availability
Authentication
Authorization
Account takeover
Cross-tenant isolation
Financial manipulation
Sensitive-data exposure
Security-control bypass
```

Do not claim impact that the evidence does not support.

### 8. Chaining opportunities

Identify realistic next steps that could increase severity.

Examples:

```text
BOLA → export → PII disclosure
Stored XSS → privileged session → account action
SSRF → internal service → credential exposure
Weak authorization → API-key creation → account compromise
Cache issue → sensitive response storage → cross-user disclosure
```

A chain is a hypothesis until every link is demonstrated or logically necessary and evidenced.

### 9. Evidence

Keep an evidence hierarchy:

```text
Level 1 — hypothesis
Level 2 — suspicious response
Level 3 — repeatable behavior
Level 4 — confirmed security-boundary violation
Level 5 — demonstrated impact
Level 6 — demonstrated chain / business consequence
```

Only report the strongest level that is actually supported.

### 10. Report wording

Use this basic structure:

```markdown
## Summary
<one paragraph describing the security issue>

## Affected Asset
<host / endpoint / feature>

## Preconditions
<account, role, state>

## Steps to Reproduce
1. <baseline step>
2. <controlled modification>
3. <trigger>
4. <observation>

## Expected Result
<secure behavior>

## Actual Result
<observed vulnerable behavior>

## Security Impact
<concrete attacker capability>

## Evidence
<request / response / callback / state evidence>

## Remediation Direction
<root-cause-oriented fix>
```

### Gold-standard rule

For every vulnerability class, do **not** stop at:

```text
“Here is a payload.”
```

The real objective is:

```text
“What security property was supposed to hold,
what experiment showed it failed,
what evidence proves the failure,
and what impact can an authorized attacker demonstrate safely?”
```


# 4. Modern Web Attack Surface

Modern applications are rarely a single web server. Model the full request path:

```text
Browser / mobile app
       ↓
CDN / WAF / bot defense
       ↓
Load balancer / reverse proxy
       ↓
Web server / API gateway
       ↓
Application / microservice
       ↓
Queue / worker
       ↓
Database / cache / object storage
       ↓
Third-party SaaS / webhook / cloud control plane
```

Every boundary is a possible parser or trust mismatch.

### High-value surfaces

- REST APIs
- GraphQL endpoints
- WebSockets / SSE
- OAuth/OIDC callbacks
- SAML endpoints
- Password-reset flows
- Invitation flows
- File uploads and document processors
- PDF/image/video conversion
- Webhooks
- URL preview / fetch / import functions
- Search and filtering
- Export/report generation
- Admin consoles
- Multi-tenant APIs
- Background jobs
- CI/CD integrations
- Marketplace/plugin systems
- “Connect your GitHub/GitLab/Jira/etc.” integrations
- CDN/cache layers
- Server-side rendered frontend frameworks
- Service workers and browser storage

---

# 5. Reconnaissance and Attack-Surface Mapping

Recon is useful only when it produces a map that changes your testing decisions.

## 5.1 Passive discovery

Collect only what the program permits.

Useful sources:

- Certificate transparency
- DNS records
- Public DNS history
- Search engines
- Public documentation
- Public Git repositories
- Package registries
- JavaScript bundles
- Mobile app traffic/documentation
- Public cloud asset references
- Security headers and server fingerprints

Example tool workflow:

```bash
subfinder -d example.com -silent -o subs.txt
httpx -l subs.txt -silent -status-code -title -tech-detect -o live.txt
```

For production programs, keep rate limits conservative and respect scope. Asset discovery is not permission to attack every hostname you find; confirm that each asset is explicitly in scope.

## 5.2 Build a route inventory

For each host, record:

| Field | Example |
|---|---|
| Host | api.example.com |
| Endpoint | `/v2/projects/{id}` |
| Method | `GET`, `PATCH` |
| Auth | Bearer / cookie / none |
| Role | user / manager / admin |
| Object | project |
| Identifier | UUID / integer / slug |
| Sensitive action | read / update / delete / invite |
| Interesting input | redirect, URL, file, template, filter |
| Backend clue | REST, GraphQL, WebSocket |
| Caching | CDN / private / unknown |
| Notes | tenant-sensitive |

This table becomes the foundation for access-control and business-logic testing.

## 5.3 JavaScript is a roadmap, not evidence

Review front-end bundles for:

- API routes
- hidden features
- admin routes
- feature flags
- GraphQL operations
- WebSocket URLs
- OAuth client IDs
- scopes
- cloud storage URLs
- undocumented parameters
- debug endpoints
- environment names
- source-map references

A client-side secret is not automatically a server-side secret. Public identifiers such as OAuth client IDs can be intentionally public. Validate whether the discovered value actually grants unauthorized capability.

---

# 6. A01:2025 Broken Access Control

OWASP A01 remains #1 in the 2025 list. Its examples include IDOR, missing method-level controls, privilege escalation, JWT/cookie metadata manipulation, CORS-related authorization failures, and forced browsing.

## 6.1 What you are really testing

You are testing a proposition like:

```text
Can subject S perform action A on resource R in state T?
```

The server should derive the authorization decision from trusted identity and policy—not from a user-editable identifier, UI control, hidden field, or client-side role value.

## 6.2 IDOR / BOLA methodology

Create two accounts you control.

```text
Account A → object A
Account B → object B
```

Then test:

```text
A reads A   → expected 200
A reads B   → expected 403/404
A modifies B → expected 403/404
A deletes B  → expected 403/404
B repeats     → expected isolation
```

Do not stop at `GET`. Test all relevant methods:

```text
GET    /api/projects/123
PATCH  /api/projects/123
PUT    /api/projects/123
DELETE /api/projects/123
POST   /api/projects/123/members
```

The classic error is testing only object lookup. The highest impact often comes from a write endpoint that forgot the same ownership check.

## 6.3 Identifier transformations

Test whether authorization survives harmless identifier transformations:

- integer ↔ string representation
- UUID casing if accepted
- alternate resource aliases
- duplicate parameters
- nested resource paths
- query vs JSON body identifiers
- path parameter vs body parameter disagreement

Be careful with destructive methods. Establish the authorization failure using a read-only operation first.

## 6.4 Horizontal privilege escalation

Ask whether one ordinary account can cross a peer boundary:

```text
user A → user B's profile
tenant A → tenant B's invoice
team A → team B's project
customer A → customer B's export
```

## 6.5 Vertical privilege escalation

Use a lower-privileged account and discover privileged operations through the UI or documented functionality. Then test direct invocation.

Typical areas:

- role changes
- user deletion
- API key creation
- organization settings
- billing changes
- invitation management
- audit-log export
- SSO configuration
- webhook configuration
- integrations

Do not claim privilege escalation just because an endpoint exists. Demonstrate that the low-privileged identity actually performs an action it should not be able to perform.

## 6.6 Method confusion

A common mistake is protecting `GET` while forgetting `POST`, `PATCH`, or `DELETE`.

Build a method matrix:

| Endpoint | A anonymous | A user | A admin | B user |
|---|---:|---:|---:|---:|
| GET object | | | | |
| POST action | | | | |
| PATCH object | | | | |
| DELETE object | | | | |

Populate it deliberately rather than relying on intuition.

## 6.7 CORS as an access-control issue

Look for:

```http
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
```

The existence of CORS is not the issue. The question is whether an attacker-controlled origin can read sensitive authenticated responses.

Validate with a controlled origin and a non-destructive read of data that the victim is authorized to view.

## 6.8 JWT and authorization metadata

Check whether the server correctly validates:

- signature
- issuer
- audience
- expiration
- not-before
- intended scope
- token type
- tenant/subject relationship

Do not report a decoded JWT as vulnerable. JWTs are designed to be decodable. The bug exists when the server **trusts attacker-modifiable claims without appropriate verification**.

## 6.9 High-value A01 chains

```text
BOLA → sensitive export → PII disclosure
BOLA → invoice modification → financial impact
Role bypass → API key creation → account takeover
CORS → credentialed API read → data disclosure
Forced browsing → admin action → privilege escalation
JWT validation flaw → privileged session → account takeover
```

## 6.10 False positives

Not vulnerabilities by themselves:

- sequential IDs
- accessible API documentation
- hidden admin links in JavaScript
- `403` changing to `404`
- a public object that is intentionally public
- a client-side role label
- readable JWT claims with no trust violation

---

# 7. A02:2025 Security Misconfiguration

Misconfiguration is broad and often overlooked because each individual issue can appear harmless.

## 7.1 High-value targets

- Debug mode
- Development endpoints
- Actuator / management endpoints
- Directory listing
- Backup files
- Source maps
- Debug logs
- Stack traces
- Default credentials
- Unprotected metrics
- Internal documentation
- Exposed cloud storage
- Unsafe CORS
- Missing security headers where they materially matter
- Overly permissive cookie attributes
- Host-header trust
- Proxy trust settings
- Unsafe parser configuration
- XXE-capable XML processing
- Admin interfaces accidentally exposed

## 7.2 Information-disclosure ladder

Treat findings by sensitivity:

```text
Version banner
   ↓
Framework/version + environment detail
   ↓
Internal path / source map
   ↓
Configuration / stack trace / service topology
   ↓
Credentials / tokens / private keys
   ↓
Direct access to protected data
```

A version string is weak evidence. A leaked secret that works against an in-scope privileged system is a materially different finding.

## 7.3 Error-message testing

Compare valid and invalid requests. Deliberately trigger benign errors:

- missing parameter
- wrong content type
- invalid JSON
- out-of-range numeric value
- unsupported method
- oversized but program-safe input
- invalid object identifier

Look for:

- SQL statements
- filesystem paths
- internal hostnames
- cloud resource IDs
- stack traces
- secret material
- service credentials
- framework internals

## 7.4 Host-header and proxy trust

Check whether the application uses request host information in:

- password-reset links
- absolute redirects
- canonical URLs
- CORS
- cookie domain decisions
- email links
- generated HTML

The issue is not simply reflection of `Host`; it is using untrusted host data in a security-sensitive decision.

## 7.5 Cloud configuration

Look for application-controlled references to:

- object storage
- signed URLs
- temporary credentials
- server-side fetches
- internal DNS names
- metadata endpoints
- container dashboards
- build/deployment services

Never probe resources outside authorization just because you discovered an internal name.

---

# 8. A03:2025 Software Supply Chain Failures

A03 is one of the most important changes in 2025. It treats weaknesses in the software supply chain as a first-class application-security risk.

## 8.1 What to inspect in a bug bounty

- `package.json`, lockfiles, manifests
- dependency versions
- CDN-hosted third-party JavaScript
- build scripts
- GitHub/GitLab/Bitbucket workflows
- CI service integrations
- container images
- plugin systems
- package publishing workflows
- dependency update bots
- artifact registries
- release pipelines
- build-time scripts that consume untrusted input

## 8.2 Dependency confusion logic

The key question is:

```text
Does a trusted build process resolve a dependency from a location
or namespace that an attacker can influence?
```

Do not publish a package with a real target name or intentionally weaponize a namespace against someone else's build unless the program explicitly authorizes such a test.

For safe research, reproduce the condition in a lab:

```text
Internal dependency name
        ↓
Public registry collision
        ↓
Resolver selection
        ↓
Unexpected package consumed
```

## 8.3 CI/CD trust boundaries

Look for workflows that consume attacker-controlled data:

```text
Issue title
PR title/body
commit message
branch name
artifact metadata
filename
release tag
```

Then trace whether that data reaches:

- shell commands
- build scripts
- package installation
- deployment parameters
- AI agents
- secrets-accessing steps
- artifact publishing

The central question is not “can I inject a string?” but “does untrusted content cross into a privileged build context?”

## 8.4 AI-assisted CI/CD

Modern pipelines increasingly use automated agents. A new supply-chain testing angle is **untrusted repository content influencing privileged agent behavior**.

Test only within explicitly authorized CI environments and with harmless canaries. Model:

```text
Untrusted PR text
      ↓
AI/automation instruction context
      ↓
Privileged tool call
      ↓
Secret or repository operation
```

A prompt-injection finding becomes serious when it crosses a privilege boundary and causes an unauthorized action—not merely because the model can be made to say something unexpected.

---

# 9. A04:2025 Cryptographic Failures

This category is about failing to protect sensitive data or keys correctly, not simply “using encryption that I don't like.”

## 9.1 What to test

### Transport

- HTTPS correctly enforced
- sensitive endpoints not available over plaintext
- no insecure mixed content for security-sensitive flows
- correct certificate validation by clients
- safe redirect behavior
- no sensitive data leaked through URL/query strings

### Passwords

Look for evidence of:

- plaintext storage
- reversible encryption
- weak hashing
- missing salt
- static or predictable reset secrets

A black-box tester normally cannot prove password storage quality without a controlled account, documented behavior, source access, or a meaningful side channel.

### Tokens and secrets

Inspect:

- reset tokens
- invite tokens
- API keys
- session identifiers
- signed URLs
- verification links
- unsubscribe tokens

Test whether tokens are:

- guessable
- reusable after consumption
- valid for the wrong account
- valid after password reset
- valid after logout where they should be revoked
- leaked through referer or logs
- scoped too broadly

## 9.2 Randomness testing

Do not judge randomness from a handful of values.

Look for structural evidence:

```text
timestamp + user ID
counter + timestamp
short numeric token
predictable UUID construction
repeated token after reset
```

Where you have a controlled test account, collect enough samples to determine whether a token contains predictable structure. Do not brute-force real users' credentials or tokens.

## 9.3 Cryptographic downgrade and algorithm confusion

Relevant examples include:

- accepting weaker protocol modes
- confusing HMAC/public-key token algorithms
- using the wrong key for a token type
- failing to enforce key separation
- accepting unsigned or improperly signed data

For JWT, validate server behavior rather than relying on decoder behavior.

---

# 10. A05:2025 Injection

OWASP 2025 keeps injection at A05. The category covers a large family of input-to-interpreter failures, including SQL injection and XSS.

The universal pattern is:

```text
Attacker input
      ↓
Parser / interpreter boundary
      ↓
Input becomes syntax or instructions
      ↓
Unexpected behavior
```

## 10.1 Build an injection map

For every input, ask what consumes it:

| Input | Potential sink |
|---|---|
| search | SQL / template / regex |
| filename | filesystem / shell / image processor |
| URL | HTTP client / parser |
| XML | XML parser |
| JSON field | object binder / command / template |
| Markdown | HTML renderer |
| template name | template engine |
| filter | SQL / NoSQL / expression engine |
| header | proxy / application / cache |
| cookie | authorization / parser |

## 10.2 SQL injection methodology

Use a differential sequence rather than immediately jumping to automated exploitation.

1. Identify a parameter reaching a database-backed operation.
2. Establish a baseline response.
3. Introduce syntax-changing input.
4. Compare response status, body length, database error behavior, timing, and application state.
5. Confirm the behavior with a minimally invasive proof.
6. Only then use automation in the authorized scope.

For a lab or explicitly authorized target, tools such as `sqlmap` can help confirm a candidate. Avoid dumping entire production databases just because the tool can.

## 10.3 NoSQL injection

Test whether user-controlled JSON changes query operators or structures.

Potential signals:

```json
{"username":{"$ne":null}}
```

or unexpected type confusion between:

```json
{"role":"user"}
```

and structured objects.

A type change is not sufficient evidence; confirm that the authorization or query semantics actually changed.

## 10.4 Command injection

Look for parameters that reach process execution, such as:

- diagnostics
- image conversion
- document conversion
- archive handling
- DNS/network tools
- backup utilities
- custom script runners

Use a safe canary first. A blind command-execution claim should have a controlled OAST-style callback or another non-destructive proof when the program permits it.

## 10.5 Server-side template injection

Identify template contexts from features such as:

- custom emails
- notification templates
- page themes
- report templates
- document generation
- workflow expressions

Differentiate between ordinary string interpolation and actual server-side code/template evaluation.

## 10.6 XSS

Always identify the sink and context:

- HTML body
- attribute
- JavaScript string
- URL context
- CSS context
- DOM sink
- SVG
- template rendering

A generic payload that works in one context may fail in another.

Test reflected, stored, and DOM-based flows.

For stored XSS, use a harmless proof such as a controlled callback or visible marker. Do not use credential-stealing payloads against real users.

## 10.7 Parser differential injection

Modern applications often use multiple parsers:

```text
WAF parser
  ≠
reverse proxy parser
  ≠
application parser
  ≠
database/parser library
```

Look for discrepancies in:

- duplicate parameters
- duplicate JSON keys
- Unicode normalization
- URL decoding
- path normalization
- content-type parsing
- multipart boundaries
- XML tolerance
- newline handling
- duplicate headers
- semicolon/parameter parsing

The interesting condition is when the security-control layer interprets the request differently from the security-sensitive component.

---

# 11. A06:2025 Insecure Design

This is where business-logic hunting lives.

A secure implementation cannot save an insecure rule.

## 11.1 Identify business invariants

Examples:

```text
A coupon can be used once.
A user cannot approve their own request.
An invitation can only be accepted once.
A refund cannot exceed the captured amount.
A trial cannot be restarted indefinitely.
A user cannot transfer ownership without authorization.
A password reset should not be usable for another account.
A deleted organization cannot still receive privileged requests.
```

Turn each invariant into a test.

## 11.2 Workflow bypass

Map the complete flow:

```text
Create → Verify → Approve → Execute → Commit
```

Then test:

- direct execution before approval
- replay of an earlier step
- duplicated steps
- skipped steps
- reordered steps
- stale tokens
- conflicting parameters between steps
- changing identity/tenant between steps

## 11.3 Multi-tenant isolation

A tenant boundary is a security boundary.

Compare:

```text
Host tenant
JWT tenant claim
Cookie
URL path
JSON body tenantId
GraphQL argument
Database-derived tenant
```

If the same concept is accepted from multiple places, test whether conflicting values lead to inconsistent authorization.

## 11.4 Sensitive business flows

The API Security Top 10 explicitly highlights unrestricted access to sensitive business flows. High-value examples include:

- account creation
- coupon redemption
- ticket purchase
- password reset
- referral bonuses
- vote/reaction systems
- reservation holds
- inventory allocation
- bulk invite flows
- promotional credits

A vulnerability may exist even when there is no classic injection or access-control bypass.

---

# 12. A07:2025 Authentication Failures

Authentication is broader than login.

## 12.1 Attack surface

Test:

- registration
- login
- logout
- password reset
- email change
- MFA enrollment
- MFA reset
- recovery codes
- device trust
- session creation
- SSO
- API token issuance
- OAuth callback
- account linking
- invitation acceptance

## 12.2 Account enumeration

Compare responses for:

```text
valid user + wrong password
invalid user + wrong password
valid email + reset
invalid email + reset
valid phone + OTP
invalid phone + OTP
```

Compare:

- status code
- body length
- error text
- headers
- timing
- redirect location
- rate-limit state

Enumeration alone may have limited severity. It becomes stronger when combined with credential attacks, reset flaws, targeted phishing, or sensitive account discovery.

## 12.3 Rate limiting

Do not treat “no 429” as proof of no rate limiting.

Test the actual security property:

- can authentication attempts continue indefinitely?
- is throttling per IP only?
- can an attacker rotate IPs without friction?
- is the limit per account, device, credential, or challenge?
- does the limit create an account-lockout DoS?

Use your own accounts and low request volumes.

## 12.4 Password reset testing

For a controlled account, check:

1. Is the token bound to the correct account?
2. Is it single-use?
3. Does it expire?
4. Does using it invalidate prior reset links?
5. Is it invalidated after password change?
6. Does changing email/password affect existing sessions appropriately?
7. Can a token be replayed across accounts?
8. Is the reset URL derived from untrusted host information?
9. Can the token leak through a referrer or third-party resource?

## 12.5 Session management

Check whether sessions:

- rotate after login
- are invalidated after logout
- are invalidated after sensitive credential changes where expected
- expire correctly
- use secure cookie attributes
- are protected from fixation
- are properly scoped by host/path

## 12.6 MFA logic

High-value mistakes:

- MFA enforced in UI but not at API level
- recovery flow weaker than primary authentication
- trusted-device bypass
- OTP reuse
- OTP not bound to user/session/action
- backup-code reuse
- enrollment without recent authentication
- changing email/phone without reauthentication

## 12.7 OAuth/OIDC

Test authorization-code flows, redirect handling, client identity, state/nonce, PKCE, token audience and account-linking logic.

See the dedicated OAuth section below.

---

# 13. A08:2025 Software or Data Integrity Failures

A08 focuses on failing to maintain the trust and integrity of software or data artifacts.

## 13.1 Key distinctions

### A03: Supply chain

Question:

```text
How can untrusted software enter the build/dependency/release process?
```

### A08: Integrity

Question:

```text
Why does the application trust an artifact or data object
without adequately verifying its integrity/provenance?
```

The categories overlap in real systems; use the root cause.

## 13.2 Unsafe deserialization

Look for serialized data in:

- cookies
- session blobs
- hidden fields
- API payloads
- import/export features
- job queues
- cached objects
- framework-specific formats

First establish whether the server actually deserializes attacker-controlled data. Then determine whether the format permits type/object manipulation.

Do not jump straight to RCE gadget chains on production targets. A safe validation may be enough to show that the application accepts attacker-controlled object state and reaches a security-sensitive code path.

## 13.3 Dynamic loading

Watch for:

- plugins
- themes
- user-uploaded modules
- remote scripts
- webhook processors
- custom functions
- package installers
- “import configuration” features

The central question is whether untrusted content becomes executable or privileged content.

## 13.4 Update integrity

Look for update processes that:

- download artifacts over insecure channels
- do not authenticate origin
- do not verify signatures
- use predictable update URLs
- trust mutable locations
- execute archives without strong validation

Testing this against third-party infrastructure requires explicit authorization. For bounty work, prioritize the application's own trust decision and a controlled proof.

---

# 14. A09:2025 Security Logging and Alerting Failures

A09 is often misunderstood as “there is no SIEM.” That is too shallow.

You are testing whether security-relevant behavior is observable and actionable.

## 14.1 Security events worth examining

- login failures
- privilege changes
- password resets
- MFA changes
- API key creation
- role changes
- access-control failures
- suspicious bulk reads
- high-risk administrative actions
- token replay indicators
- unexpected source/origin changes

## 14.2 Practical bug-bounty angles

Potential findings include:

- sensitive security events missing entirely from audit logs
- audit logs writable by ordinary users
- audit logs that can be tampered with
- log injection that changes interpretation
- security controls that fail silently
- alerts that are trivially bypassed

Do not demand that every endpoint emit an alert. The meaningful question is whether a security-critical control or event becomes effectively invisible.

## 14.3 Log injection

Test whether attacker-controlled strings can inject new log records or misleading fields.

Use harmless markers rather than fake administrative instructions.

The impact is strongest when logs are consumed by automated systems, analysts, or security tooling and the injected content changes their interpretation.

---

# 15. A10:2025 Mishandling of Exceptional Conditions

A10 is new in the 2025 model and is extremely useful for modern hunting.

OWASP explicitly includes fail-open behavior, improper error handling, state corruption, resource issues, and timing/race-related failures in this category.

## 15.1 The key question

What happens when something goes wrong **halfway through a security-sensitive operation**?

Examples:

```text
Authorize → debit → crash → no rollback

Validate → save → error → partial privilege

Check permission → object fetch → timeout → fallback to allow

Token lookup → cache miss → fallback path → unintended access
```

## 15.2 Error-path access-control testing

Take an authorized request and induce a controlled failure in a non-destructive field.

Compare:

```text
normal request → expected denial
error-path request → ?
```

High-value signals:

- 500 response containing sensitive data
- fallback to anonymous/default account
- skipped authorization check
- cached error containing another user's data
- state mutation despite failed transaction

## 15.3 Fail-open testing

Systems often have fallback code such as:

```text
if security_check fails:
    continue
```

or:

```text
if policy unavailable:
    allow request
```

From black-box testing, you infer this through controlled dependency/state changes.

## 15.4 Race conditions

Race conditions are a natural A10 hunting area.

Look for:

- one-time coupons
- password reset consumption
- email verification
- invite acceptance
- credits
- transfers
- account creation
- rate-limit counters
- file upload processing
- permission changes

The invariant is usually:

```text
N valid operations
      →
exactly N state changes
```

If concurrent requests create more state changes than the business rule permits, you have evidence of a race condition.

---

# 16. Cross-Cutting Modern Techniques

The OWASP Top 10 is a taxonomy, not the full bug bounty playbook. High-value modern research cuts across multiple categories.

## 16.1 Parser differentials

Whenever a request passes through multiple components, compare how each component could parse:

- URLs
- headers
- JSON
- XML
- multipart
- paths
- query strings
- encodings
- Unicode
- duplicate keys

The bug appears when one component enforces a security rule on interpretation A while another uses interpretation B.

## 16.2 Canonicalization

Test transformations such as:

```text
raw → percent-decoded
raw → double-decoded
UTF-8 → Unicode normalized
path → dot-segment normalized
backslash → slash normalized
host → lowercase / IDNA normalized
```

A path filter may reject one representation but the backend may normalize it into another path.

## 16.3 Duplicate parameters

Probe safely with duplicate keys:

```text
?id=100&id=200
```

or equivalent JSON/body structures.

Different frameworks may implement:

```text
first wins
last wins
array
concatenation
```

A security issue exists when a filter validates one value and a security-sensitive sink uses another.

## 16.4 Unicode and normalization

Modern research continues to find security bugs where:

```text
validator interpretation
        ≠
application interpretation
```

Pay attention to usernames, filenames, hostnames, URLs, identifiers, and allowlists.

## 16.5 Response splitting / CRLF

Where an endpoint copies attacker-controlled data into headers, test whether control characters can alter the response structure.

Validate conservatively. A reflected string in a header is not automatically response splitting.

---

# 16.5. 2025–2026 Research Priorities

The current research landscape shows a clear move away from single-parser, single-endpoint bugs toward **cross-component inconsistencies and exploit chains**. Recent web-security research has highlighted several themes worth deliberately adding to your hunting workflow.

## Parser differentials are getting more important

Look for interpretation mismatches between:

```text
browser
  ↓
CDN / WAF
  ↓
reverse proxy
  ↓
framework
  ↓
application code
```

Important examples include HTTP parsing, URL parsing, JSON duplicate keys, Unicode normalization, path normalization, and header handling. The useful question is always:

```text
What did security layer A validate?
What did security-sensitive layer B actually process?
```

## Request desync is broader than classic CL.TE

Current research includes browser-powered desynchronization, CL.0-style behavior, HTTP/2 translation problems, early-response gadgets, connection reuse, and other parser/timing primitives. Treat HTTP desync as an **architecture problem**, not merely a three-row CL.TE/TE.CL checklist.

## Framework-level caches matter

Modern server-side rendering frameworks introduce internal response/data caches in addition to CDN caches. A bug can therefore exist entirely inside the application's framework cache, or arise from a chain such as:

```text
attacker input
   ↓
framework cache confusion
   ↓
stale/poisoned response
   ↓
CDN/browser cache
   ↓
client-side impact
```

This makes cache-key and cache-revalidation analysis increasingly important for modern applications.

## WebSocket security is becoming more state-aware

Recent research has emphasized cross-site WebSocket hijacking, GraphQL-over-WebSocket abuse, and state-aware WebSocket fuzzing. A useful model is:

```text
handshake → authentication → subscription → message → asynchronous event
```

Test authorization at every transition rather than treating the WebSocket as a single authenticated pipe.

## OAuth attacks are increasingly about edge semantics

Modern OAuth/OIDC research continues to examine redirect parsing, authorization-response handling, account linking, code injection, loopback/localhost assumptions, URL parsing, and the interaction between browser behavior and server-side token validation.

Do not reduce OAuth testing to “check PKCE.” Trace the complete identity-binding story:

```text
browser session
   ↕
OAuth transaction
   ↕
authorization code
   ↕
client/session binding
   ↕
identity assertion
   ↕
local account
```

## AI-assisted systems create new supply-chain trust boundaries

Where development or CI systems use AI agents, inspect whether untrusted repository text, issue content, pull requests, commits, or generated artifacts can influence privileged tool execution. The vulnerability is the **privilege crossing**, not the fact that the model produced an unusual sentence.

## Browser-side side channels remain fertile research territory

XS-Leaks, cache behavior, browser connection state, service workers, bfcache/disk-cache interactions, DOM clobbering, and other browser quirks can turn small information or integrity differences into meaningful cross-origin attacks. These are advanced topics and usually need a precise oracle.

## What this means for your workflow

When the obvious OWASP tests are exhausted, prioritize:

```text
1. Multi-layer parser disagreement
2. Authentication/authorization state transitions
3. Cache-key and cache-state differences
4. Race conditions in one-time operations
5. OAuth account/session binding
6. WebSocket state and Origin handling
7. Framework-specific SSR/cache behavior
8. CI/CD and AI-agent trust boundaries
9. Unicode and URL canonicalization
10. Cross-bug chains
```

These themes are reflected in recent PortSwigger research and its 2025 web-hacking-technique roundup.

---

# 17. API Security

OWASP's API Security Top 10:2023 remains an important companion taxonomy.

| API risk | Bug bounty focus |
|---|---|
| API1 BOLA | Object ownership across users/tenants |
| API2 Broken Authentication | Tokens, recovery, session management |
| API3 BOPLA | Excessive/unauthorized fields and properties |
| API4 Unrestricted Resource Consumption | Expensive operations, pagination, uploads, nested queries |
| API5 BFLA | Function/endpoint role bypass |
| API6 Sensitive Business Flows | Automation/abuse of high-value workflows |
| API7 SSRF | Server-side URL fetching |
| API8 Misconfiguration | Debug/admin/docs/CORS/errors |
| API9 Inventory Management | Old/hidden API versions and endpoints |
| API10 Unsafe Consumption of APIs | Trusting downstream data/response semantics |

## 17.1 BOPLA testing

A common mistake is checking only whether the resource is yours.

Also ask:

```text
Can I read fields I should not see?
Can I modify fields I should not control?
```

Example conceptual request:

```json
{
  "displayName": "Alice",
  "role": "user",
  "isVerified": true,
  "billingTier": "enterprise"
}
```

A field being accepted does not prove impact. Verify whether the server actually changes a privileged property.

## 17.2 API version drift

Compare:

```text
/v1/
/v2/
/v3/
/internal/
/beta/
/legacy/
```

Old endpoints are often less consistently protected than current ones.

## 17.3 Resource-consumption testing

Look for parameters that multiply server work:

- pagination size
- recursive structures
- expensive filters
- large batch requests
- complex GraphQL queries
- file conversions
- report generation
- image processing
- PDF creation

Do not turn a bounty program into a DoS test. Establish the existence of missing controls using small, safe requests and stop before service degradation.

---

# 18. OAuth / OIDC / SSO Testing

OAuth/OIDC failures are frequently authorization or authentication bugs disguised as redirect-flow problems.

OWASP's OAuth guidance emphasizes secure use of PKCE, redirect URIs, token binding/scoping, and modern grants.

## 18.1 Map the flow

```text
Client
  ↓
Authorization endpoint
  ↓
User authentication
  ↓
Consent
  ↓
Redirect URI
  ↓
Authorization code
  ↓
Token endpoint
  ↓
Access/ID token
  ↓
Application session
```

## 18.2 Test controls

### `state`

Ask whether the authorization response is bound to the browser session initiating the flow.

### PKCE

For flows using PKCE, verify that the code cannot be redeemed by a party lacking the verifier.

### Redirect URI

Test whether validation is exact enough to prevent attacker-controlled origins or paths.

Dangerous patterns include overly broad suffix/prefix matching, unsafe URL parsing, or accepting attacker-controlled nested URLs.

### Account linking

High-value scenario:

```text
Attacker controls OAuth account
Victim has application account
       ↓
Linking workflow incorrectly trusts an identifier
       ↓
Account takeover / unauthorized account linking
```

Never use a real victim account for proof. Use accounts you control.

### Token audience and issuer

Applications should not blindly accept tokens issued for another resource, client, or issuer.

### OIDC identity claims

The identity used to associate a login should come from validated OIDC semantics, not an arbitrary client-provided profile parameter.

---

# 19. GraphQL Testing

GraphQL changes the attack surface because one endpoint can expose a large query language.

## 19.1 Find it

Check likely endpoints:

```text
/graphql
/api/graphql
/v1/graphql
/query
```

Also inspect JavaScript bundles and network traffic.

## 19.2 Introspection

A simple probe is:

```graphql
{ __schema { queryType { name } } }
```

Introspection is not automatically a critical vulnerability. Its severity depends on what sensitive capabilities become materially easier to discover and exploit.

## 19.3 Authorization is the main hunt

For every query/mutation:

```text
User A → object A
User A → object B
User B → object A
```

Test nested fields as well as root operations.

A mutation can be vulnerable even when its corresponding query is correctly protected.

## 19.4 Aliases and rate limiting

GraphQL aliases can combine many operations into one HTTP request. Test whether rate limiting counts:

```text
HTTP request
```

or:

```text
logical operations / fields / cost
```

Use small proof-of-concept batches.

## 19.5 Nested query/resource abuse

Test whether query complexity is bounded.

Look for:

- deep nesting
- large result sets
- expensive relationships
- unbounded lists
- repeated aliases

Stop well before resource exhaustion.

---

# 20. WebSocket Testing

WebSockets are long-lived, stateful, bidirectional connections. Virtually any HTTP-side vulnerability class can reappear inside WebSocket messages.

## 20.1 Test the handshake

Check:

- Origin validation
- authentication
- cookies
- authorization to establish a socket
- alternate endpoint paths
- subprotocol handling

## 20.2 Test messages

For each message field ask:

```text
Can I modify the object ID?
Can I change the action?
Can I change the user/tenant?
Can I inject into a backend interpreter?
Can I invoke an admin message type?
```

## 20.3 Cross-site WebSocket hijacking

A browser may establish a WebSocket cross-origin using the victim's ambient authentication if the handshake is not adequately protected.

The impact is high when the socket permits authenticated actions or streams sensitive information.

## 20.4 State-aware fuzzing

Random payloads are often useless because the server expects a sequence:

```text
connect
 → authenticate
 → subscribe
 → send message
 → receive event
```

A better fuzzer preserves the required state and varies one message at a time.

---

# 21. HTTP Desync and Request Smuggling

Request smuggling occurs when intermediaries disagree about request boundaries.

Conceptually:

```text
Front-end sees request A
Back-end sees request A + attacker request B
```

## 21.1 High-level variants

Classic families include:

- CL.TE
- TE.CL
- TE.TE
- 0.CL / CL.0-style behaviors
- HTTP/2 downgrade/desync
- browser-powered desync
- early-response/desynchronization techniques

Modern research has expanded beyond the classic “two conflicting headers” model. Parser and timeout behavior, connection reuse, HTTP/2 translation, browser behavior, and early responses can matter.

## 21.2 Safe methodology

1. Determine the front-end/back-end architecture.
2. Establish whether connections are reused.
3. Use a harmless desync probe from a controlled environment.
4. Look for timing or response-queue anomalies.
5. Reproduce consistently.
6. Only then investigate impact such as cache poisoning or request routing manipulation.

Avoid aggressive smuggling probes against shared production infrastructure unless the program explicitly authorizes them.

## 21.3 What counts as evidence?

Strong evidence includes:

- reproducible connection desynchronization
- a request that is demonstrably interpreted differently by layers
- a controlled second request receiving attacker-influenced content

A random timeout is not sufficient.

---

# 22. Web Cache Poisoning and Cache Deception

Do not confuse these two.

### Cache poisoning

Attacker-controlled input causes a harmful response to be stored and replayed to other users.

### Web cache deception

A cache is tricked into storing a sensitive response as though it were a static/public resource.

## 22.1 Cache-key investigation

Model:

```text
Cache key = subset of request properties
```

Find inputs that influence the response but do not influence the cache key.

Potential candidates:

- headers
- host-related fields
- query parameters
- path normalization
- cookies
- content negotiation

A useful research workflow is to use a unique cache-buster during discovery so you don't accidentally poison shared content.

## 22.2 Modern framework angle

Server-side rendered frameworks and incremental/static caching can introduce application-internal caches that differ from the CDN cache.

Test:

```text
request variant
   ↓
framework cache
   ↓
CDN cache
```

A safe proof is one where the poisoned artifact contains an inert marker or controlled redirect in a dedicated test path, not a destructive payload.

---

# 23. Race Conditions and TOCTOU

A race exists when correctness depends on a timing assumption.

## 23.1 Classic pattern

```text
Check balance >= 100
        ↓
Withdraw 100
```

Two concurrent requests may both pass the check before either transaction commits.

## 23.2 Hunting methodology

1. Find an operation that is supposed to be one-time or atomic.
2. Establish its normal single-request behavior.
3. Identify the exact state transition.
4. Send a small synchronized burst using your own account.
5. Measure the resulting state.
6. Repeat enough times to determine whether the effect is deterministic or probabilistic.

## 23.3 Best targets

- coupon redemption
- referral rewards
- email verification
- password reset consumption
- account linking
- invitation acceptance
- resource reservations
- payment state transitions
- usage quotas
- API key rotation

Do not race destructive actions on production objects.

---

# 24. SSRF and Cloud Metadata

SSRF occurs when a server makes a network request influenced by an attacker.

Common features:

- URL import
- webhook validation
- image fetch
- PDF generation
- screenshot service
- remote repository import
- link preview
- URL health check

## 24.1 Establish the primitive

Start with a URL you control:

```text
https://oast.example.invalid/canary
```

or your approved OAST system.

Confirm:

```text
attacker input
   ↓
server-side request
   ↓
controlled callback
```

## 24.2 Impact questions

After confirming SSRF, determine what security boundary it crosses:

- can it reach internal-only web services?
- can it reach an application's own administrative interface?
- can it access cloud metadata?
- can it access internal service APIs?
- can it influence HTTP headers or methods?

Do not harvest cloud credentials from live infrastructure as a proof unless explicitly authorized. Usually you can establish the network reachability without extracting secrets.

## 24.3 URL parser bypasses

Modern SSRF bugs frequently involve parser discrepancies. Study:

- redirects
- alternate IP notations
- IPv6
- embedded credentials
- percent encoding
- DNS rebinding behavior
- normalization differences
- URL parser differences between validation and HTTP client

The right test is not “can I bypass the regex?” but:

```text
What URL did the validator think I supplied?
What host did the network client actually connect to?
```

---

# 25. Client-Side and Browser Attack Surface

Modern browser-side bugs include more than XSS.

## 25.1 DOM sinks

Inventory code paths reaching:

- `innerHTML`
- `outerHTML`
- `insertAdjacentHTML`
- dynamic script loading
- dangerous URL assignment
- DOM construction with untrusted markup
- `eval`-like execution

Trace data flow, not just strings.

## 25.2 CSP analysis

A Content Security Policy is a defense layer, not proof that XSS is impossible.

Test whether:

- untrusted scripts are allowed
- broad hosts are trusted
- JSONP-like endpoints are allowed
- script gadgets exist in trusted origins
- nonces are predictable/leaked/reused incorrectly

Do not report “CSP missing” as a critical issue without context.

## 25.3 Clickjacking

Consider whether high-impact state-changing actions can be embedded and triggered cross-origin.

The severity depends on the action and whether other browser protections prevent exploitation.

## 25.4 XS-Leaks

Side-channel techniques may reveal cross-origin state through:

- timing
- response size
- cache state
- browser behavior
- resource loading differences

These are nuanced and usually require a very specific oracle. Treat them as advanced research rather than generic scanner findings.

## 25.5 Browser-powered desync

Modern desync research demonstrates that some request-smuggling effects can be reached through browser-compatible traffic, expanding the practical attack surface beyond malformed raw HTTP that normal browsers would never send.

---

# 26. Common Bug-Bounty Chains

The best reports often combine individually low-severity primitives.

## Chain 1: Host trust → account takeover

```text
Untrusted host header
      ↓
reset URL generation
      ↓
attacker-controlled reset link
      ↓
account compromise
```

## Chain 2: BOLA → data export

```text
Object authorization failure
      ↓
read sensitive object
      ↓
export endpoint
      ↓
mass disclosure
```

## Chain 3: SSRF → internal admin surface

```text
SSRF
 ↓
internal application
 ↓
missing internal auth
 ↓
privileged action
```

## Chain 4: CORS → authenticated data theft

```text
Origin trust failure
 ↓
credentialed cross-origin read
 ↓
sensitive API response
```

## Chain 5: Race → business-rule bypass

```text
one-time action
 ↓
concurrent requests
 ↓
multiple successful commits
```

## Chain 6: Parser differential → authorization bypass

```text
WAF/validator interprets A
 ↓
backend interprets B
 ↓
security check bypass
```

## Chain 7: Supply-chain trust → privileged CI execution

```text
untrusted repo data
 ↓
privileged automation / agent
 ↓
secret/tool access
 ↓
unauthorized build/repository action
```

---

# 27. Tooling and Automation

Tools accelerate collection and comparison. They do not replace reasoning.

## 27.1 Core stack

### Manual

- Burp Suite
- browser DevTools
- Repeater / Intruder
- Comparer
- Logger / extensions appropriate to the program

### Discovery

- `subfinder`
- `amass`
- `assetfinder`
- `findomain`
- `httpx`
- `dnsx`
- certificate transparency sources

### Scanning / triage

- `nuclei`
- `nmap`
- carefully scoped crawlers

### Injection testing

- `sqlmap`
- `dalfox`
- application-specific GraphQL tooling

### Blind interaction

- an authorized OAST/interactsh-style service

## 27.2 Example passive-to-active workflow

```bash
subfinder -d example.com -silent -o subs.txt
httpx -l subs.txt -silent -status-code -title -tech-detect -o live.txt
```

Then manually prioritize:

```text
auth endpoints
API hosts
admin hosts
file processing
URL fetchers
webhooks
GraphQL
WebSockets
multi-tenant APIs
legacy versions
```

## 27.3 Nuclei mindset

Use templates as hypotheses.

Bad workflow:

```text
nuclei hit → instant report
```

Good workflow:

```text
nuclei hit
  ↓
read template / understand condition
  ↓
manual reproduction
  ↓
impact validation
  ↓
scope/policy check
  ↓
report
```

Automation frequently identifies configuration clues rather than reportable vulnerabilities.

---

# 28. Validation and False-Positive Control

Before reporting, run the **four-proof test**.

### Proof 1 — Trigger

Can you reproduce the behavior from a clean state?

### Proof 2 — Security boundary

Can you show which control failed?

### Proof 3 — Impact

Can you demonstrate a concrete security consequence using only authorized/test data?

### Proof 4 — Isolation

Can you show that the result is not caused by a browser extension, cache artifact, proxy behavior, old session, or unrelated system issue?

## 28.1 Compare clean vs exploit

Capture:

```text
Baseline request
Exploit request
Baseline response
Exploit response
Observed state change
```

This makes reports dramatically easier to reproduce.

## 28.2 Reproducibility score

Before reporting, ask:

```text
1/5 = happened once
3/5 = repeatable with preparation
5/5 = deterministic and simple
```

A complicated probabilistic bug can still be valid, but your report should explain the reliability and timing requirements.

---

# 29. Impact, Severity, and Reports

## 29.1 Report structure

Use this format:

```markdown
# Title

## Summary
One paragraph explaining the root cause and impact.

## Affected Endpoint
METHOD https://target.example/path

## Preconditions
What account/role/state is required.

## Steps to Reproduce
1. ...
2. ...
3. ...

## Expected Result
What should happen.

## Actual Result
What happens instead.

## Security Impact
What confidentiality, integrity, availability, authentication,
authorization, or business impact follows.

## Evidence
Relevant request/response excerpts, screenshots, timestamps,
and controlled test-account identifiers.

## Root Cause
What trust boundary or security control failed.

## Suggested Remediation
Specific server-side fix.
```

## 29.2 Strong titles

Weak:

```text
IDOR vulnerability
```

Strong:

```text
Authenticated user can read another tenant's invoice through /api/invoices/{id}
```

Weak:

```text
CORS misconfiguration
```

Strong:

```text
Credentialed cross-origin requests allow attacker-controlled origin to read authenticated /api/profile responses
```

## 29.3 Severity reality check

Use the impact actually proven.

Do not inflate:

```text
information disclosure → RCE
CORS header → account takeover
JWT decode → authentication bypass
stack trace → critical
no rate limit → account takeover
```

unless the complete chain is demonstrated.

---

# 30. Practical Checklists

## 30.1 Access control checklist

- [ ] Test two controlled accounts
- [ ] Test object ownership
- [ ] Test read/write/delete separately
- [ ] Test method changes
- [ ] Test tenant boundaries
- [ ] Test role changes
- [ ] Test direct endpoint access
- [ ] Test hidden APIs discovered in JavaScript
- [ ] Test CORS with a controlled origin
- [ ] Test JWT claims and server-side validation

## 30.2 Authentication checklist

- [ ] Login enumeration
- [ ] Registration enumeration
- [ ] Reset enumeration
- [ ] Password reset binding
- [ ] Reset replay
- [ ] Session rotation
- [ ] Session invalidation
- [ ] MFA enrollment/change/reset
- [ ] Recovery paths
- [ ] OAuth/OIDC state/PKCE/redirect/account linking

## 30.3 Injection checklist

- [ ] SQL
- [ ] NoSQL
- [ ] XSS/reflected/stored/DOM
- [ ] SSTI
- [ ] command injection
- [ ] XXE
- [ ] XPath/LDAP
- [ ] path traversal
- [ ] header injection
- [ ] parser differentials
- [ ] duplicate parameter behavior
- [ ] Unicode/canonicalization

## 30.4 API checklist

- [ ] BOLA
- [ ] BOPLA
- [ ] BFLA
- [ ] version drift
- [ ] undocumented endpoints
- [ ] mass assignment
- [ ] excessive data exposure
- [ ] resource limits
- [ ] sensitive business flows
- [ ] SSRF
- [ ] unsafe downstream API trust

## 30.5 Advanced checklist

- [ ] Request smuggling/desync
- [ ] Cache poisoning
- [ ] Cache deception
- [ ] Race conditions
- [ ] SSRF parser bypasses
- [ ] WebSocket authorization
- [ ] Cross-site WebSocket hijacking
- [ ] GraphQL aliases/complexity
- [ ] OAuth redirect/account-linking edge cases
- [ ] CI/CD trust boundaries
- [ ] source-map / debug exposure
- [ ] framework-specific caching/state behavior

---

# 31. Learning Path

## Stage 1 — Fundamentals

Master:

```text
HTTP
cookies
sessions
same-origin policy
CORS
TLS
DNS
reverse proxies
CDNs
REST
JSON
browser security
```

## Stage 2 — Core bug classes

Master:

```text
access control
authentication
SQLi
XSS
CSRF
SSRF
file upload
path traversal
XXE
SSTI
```

## Stage 3 — Business logic

Practice:

```text
state machines
workflow bypass
race conditions
multi-tenancy
sensitive business flows
abuse prevention
```

## Stage 4 — Modern infrastructure

Study:

```text
HTTP/2 and HTTP/3
request smuggling
CDN/cache behavior
GraphQL
WebSockets
OAuth/OIDC
service meshes
server-side rendering
cloud storage
CI/CD
supply-chain security
```

## Stage 5 — Research mindset

When you find something strange:

```text
Observe
 ↓
Form a hypothesis
 ↓
Change one variable
 ↓
Compare
 ↓
Identify the trust boundary
 ↓
Build a minimal proof
 ↓
Find impact
 ↓
Stop
```

The goal is to become good at **explaining why the system behaved incorrectly**, not merely collecting payloads.

---

# 32. Research Corpus: POCs, Write-Ups, Disclosures, and Case Studies

A serious bug bounty methodology cannot be built from OWASP categories alone. OWASP tells you **what class of failure to test**; public disclosures show you **how real systems actually fail**.

The objective is therefore not to memorize thousands of payloads. It is to build a continuously improving research corpus from:

- Public HackerOne disclosures and report examples
- Google Bug Hunters public reports
- Bugcrowd disclosures and researcher write-ups
- PortSwigger Research and Web Security Academy material
- OWASP WSTG, ASVS, Cheat Sheets, and project advisories
- Vendor security advisories and engineering postmortems
- GitHub Security Lab research
- Nuclei templates and their references
- Conference talks, blog posts, technical papers, and proof-of-concepts
- CVEs, CWEs, exploit analyses, and patch-diff research
- Your own validated notes, rejected findings, duplicates, and triage feedback

A useful principle is:

> **Public reports are training data for your methodology, not a payload shopping list.**

HackerOne's current guidance explicitly expects reports to explain the vulnerability, reproduction steps, and impact, and its quality-report guidance stresses clear reproduction, coverage, and supporting evidence. Google Bug Hunters likewise points researchers toward public reports to learn where others are focusing and how they build reports. citeturn394038search1turn394038search5turn394038search13

## 32.1 Do not pretend you can literally “read everything”

The public security corpus is too large and changes too quickly for a human to literally read every report, POC, blog, and disclosure.

The practical solution is **corpus-driven research**:

```text
Discover sources
      ↓
Collect relevant reports
      ↓
Normalize the technical details
      ↓
Extract the vulnerability primitive
      ↓
Identify the trust-boundary failure
      ↓
Generalize the technique
      ↓
Build a reusable test hypothesis
      ↓
Validate against an authorized target
      ↓
Record outcome + false-positive lessons
```

PortSwigger's annual research project is a good example of why curation matters: the security community produces a huge number of publications, yet reusable techniques can easily disappear inside the volume. The 2025 edition collected community nominations and expert-selected research, including parser differentials and new SAML exploitation techniques. citeturn394038search0turn394038search8

## 32.2 Source hierarchy

Not every public write-up has the same evidentiary value.

### Tier 1 — Primary technical evidence

Prefer:

- Original researcher write-up
- Original public bug-bounty report
- Vendor advisory
- Patch / commit / diff
- Official engineering postmortem
- Original conference research paper or presentation

### Tier 2 — High-quality secondary analysis

Useful:

- PortSwigger Research
- OWASP project documentation
- Google Bug Hunters educational material
- GitHub Security Lab analysis
- Maintainer-reviewed security research

### Tier 3 — Tool references

Useful for turning a known technique into repeatable detection:

- Nuclei templates
- Scanner checks
- Burp extensions
- Metasploit modules
- Public scripts

But treat a scanner hit as a **hypothesis**, not proof. Nuclei's own model is based around requests, matchers, and extractors that identify a condition; that is detection logic, not automatically a complete exploitation narrative. citeturn394038search3turn394038search7

### Tier 4 — Community summaries

Examples:

- Forum posts
- Reddit discussions
- Short social-media threads
- Aggregator sites
- Reposted PoCs without primary references

These are useful for discovering leads but should be independently verified.

## 32.3 What to extract from every useful report

Do not merely bookmark the report. Convert it into structured research notes.

```text
Report metadata
├── Target / product
├── Date
├── Researcher
├── Source URL
├── Program / advisory
└── Public disclosure status

Vulnerability
├── CWE / OWASP mapping
├── Primitive
├── Preconditions
├── Trust boundary crossed
├── Attacker capability
├── Affected component
└── Root cause

Exploitation
├── Entry point
├── Input
├── Processing step
├── State transition
├── Authorization decision
├── Parser / interpreter involved
├── Observable signal
├── Impact
└── Chain dependencies

Validation
├── Positive control
├── Negative control
├── Before/after comparison
├── Alternate account / role
├── Fresh session
├── Repeatability
└── False-positive checks
```

The most valuable field is usually **why it worked**.

For example:

```text
Not useful:
“Parameter X accepted payload Y.”

Useful:
“Parameter X was copied into an internal redirect target before the
server applied the allowlist. The allowlist validated the original
form, while the normalized value used later by the redirect handler
was attacker-controlled.”
```

The second note gives you a transferable technique.

## 32.4 Build a primitive library, not a payload library

Organize discoveries by primitive:

| Primitive | Core question | Typical manifestations |
|---|---|---|
| Authorization confusion | “Who does the server think I am?” | IDOR, BOLA, role bypass, tenant breakout |
| Parser differential | “Do two components interpret this differently?” | HTTP desync, duplicate parameters, MIME ambiguity |
| Trust-boundary confusion | “Which component is trusted to make this decision?” | Host header, forwarded headers, client-supplied metadata |
| State-machine failure | “Can I reach an invalid state?” | Race conditions, workflow abuse, payment logic |
| Canonicalization failure | “Are equivalent representations handled consistently?” | Unicode, path normalization, encoding ambiguity |
| Injection | “Does data become code?” | SQL, NoSQL, template, command, LDAP, XPath |
| Origin confusion | “Which origin/context is trusted?” | CORS, WebSocket, postMessage, OAuth redirect handling |
| Cache confusion | “Can one user's response become another user's cached response?” | Cache poisoning, deception, key normalization |
| Secret exposure | “Can an untrusted party observe or derive a secret?” | Tokens, logs, source maps, debug data |

A payload library ages badly. A primitive library stays useful.

## 32.5 Compare successful and rejected reports

This is one of the highest-value habits in bug bounty work.

For every interesting class, collect both:

```text
1. Accepted report
2. Rejected / informative report
3. Duplicate report
4. Non-impactful variant
```

Then ask:

```text
What made the accepted report different?
What evidence was missing from the rejected report?
What assumption about impact was wrong?
What scope rule changed the outcome?
What precondition separated the real bug from the false positive?
```

This teaches triage reality, not just exploitation theory.

## 32.6 Build “research cards” from reports

Use one compact card for each reusable technique.

```markdown
# Research Card: <Technique>

## Primitive
<What underlying failure makes this possible?>

## Trust Boundary
<Which two components disagree or trust the wrong party?>

## Preconditions
- Authentication state:
- Required role:
- Feature flag:
- Network position:
- Victim interaction:

## Attack Surface
- Endpoint:
- Method:
- Parameter:
- Header:
- Cookie:
- WebSocket / GraphQL operation:

## Observable Signal
<What proves the hypothesis?>

## False Positive Tests
- Negative control:
- Unauthenticated control:
- Alternate user:
- Fresh session:

## Impact
<Concrete attacker capability>

## Generalization
<Where else could the same primitive appear?>

## References
- <Primary report>
- <Vendor advisory>
- <Research paper>
```

## 32.7 Search by behavior, not only by vulnerability name

Instead of repeatedly searching:

```text
“IDOR bug bounty”
```

search for the system behavior:

```text
“different user object returned by changing identifier”
“tenant isolation failure API”
“authorization middleware bypass”
“duplicate parameter parser discrepancy”
“cache key authorization header”
“OAuth redirect URI parser discrepancy”
“WebSocket origin validation bypass”
“race condition coupon redemption”
“password reset token host header”
```

This exposes reports that may use a different taxonomy for the same underlying primitive.

## 32.8 Create a coverage matrix from the corpus

Track whether you have studied each major primitive.

```text
Access control
  [ ] Horizontal authorization
  [ ] Vertical authorization
  [ ] Multi-tenant isolation
  [ ] Method-level authorization
  [ ] Object-level authorization
  [ ] GraphQL field authorization

Authentication
  [ ] Recovery flows
  [ ] MFA logic
  [ ] Session invalidation
  [ ] OAuth/OIDC
  [ ] SAML
  [ ] Device / magic-link flows

Parser / protocol
  [ ] Duplicate parameters
  [ ] HTTP desync
  [ ] Path normalization
  [ ] Content-Type ambiguity
  [ ] Multipart parsing
  [ ] JSON parser differences

Business logic
  [ ] Race conditions
  [ ] State transitions
  [ ] Price manipulation
  [ ] Coupon abuse
  [ ] Inventory / reservation logic
  [ ] Subscription transitions

Client / browser
  [ ] DOM XSS
  [ ] postMessage
  [ ] CORS
  [ ] WebSocket
  [ ] Service workers
  [ ] Browser-powered desync

Infrastructure
  [ ] Cache behavior
  [ ] Reverse proxy behavior
  [ ] CDN behavior
  [ ] SSRF
  [ ] Cloud metadata exposure
  [ ] CI/CD trust boundaries
```

## 32.9 Turn every report into a hypothesis generator

Suppose a report says:

```text
“An attacker modified a host-related header and influenced
password-reset behavior.”
```

Do not copy the exact payload and stop.

Convert it into hypotheses:

```text
H1: Does user-controlled host metadata influence generated URLs?
H2: Does it influence cookie scope?
H3: Does it influence password-reset links?
H4: Does it influence redirects?
H5: Does it influence absolute URLs in email or API responses?
H6: Does an upstream proxy rewrite the header before validation?
H7: Do different endpoints normalize the header differently?
```

That is how a single report becomes a family of tests.

## 32.10 Build a personal “failed assumptions” database

Maintain a separate list of findings that looked real but were not.

```text
FALSE POSITIVE
Symptom: Header reflected in response
Why it looked real: Attacker input was visible
Why it failed: Reflection occurred only in an inert field
Missing condition: Security-sensitive sink
Lesson: Reflection ≠ exploitability
```

This is often more useful than a payload notebook.

---

# 33. True-Positive Validation and Detailed POC Engineering

The standard for a bug bounty finding should be:

> **A third party can reproduce the behavior, understand the security boundary that was violated, and verify a concrete attacker impact without guessing.**

A scanner result, reflected string, status-code difference, or suspicious header is not enough.

## 33.1 The True-Positive Gate

Before reporting, pass the finding through all of these gates.

```text
Gate 1 — Scope
    ↓
Gate 2 — Reproducibility
    ↓
Gate 3 — Security property violated
    ↓
Gate 4 — Attacker control demonstrated
    ↓
Gate 5 — Impact demonstrated
    ↓
Gate 6 — False-positive controls passed
    ↓
Gate 7 — Duplicate / known-issue check
    ↓
Gate 8 — Minimal, safe, deterministic POC
```

If a gate fails, the finding is a hypothesis, not a finished report.

## 33.2 Step 1 — Prove scope first

Record:

```text
Program:
Asset:
URL / API:
In-scope component:
Account required:
Tester role:
```

Never turn a technically interesting behavior into a report merely because it exists. Scope and impact are separate questions.

## 33.3 Step 2 — Establish a baseline

Every POC should begin with a normal request.

```http
GET /api/profile HTTP/2
Host: target.example
Cookie: session=<TEST_SESSION>
```

Record:

- status code
- response length
- key headers
- body behavior
- timing if relevant
- cache headers if relevant
- authorization state

Then make **one controlled change at a time**.

## 33.4 Step 3 — Use positive and negative controls

A strong POC contains both.

```text
Positive control:
The manipulated request triggers the security failure.

Negative control:
The same operation without the manipulated condition does not.
```

For authorization bugs, add an account control:

```text
User A owns object A.
User B attempts object A.
Expected: denial.
Observed: unauthorized access.
```

For injection, use a benign canary and a control value.

For SSRF, use a researcher-controlled callback endpoint only when the program rules permit it.

For XSS, prefer a harmless proof that demonstrates script execution without damaging the victim environment.

## 33.5 Step 4 — Isolate the security boundary

Every POC should answer:

```text
Who is the attacker?
What capability do they already have?
What capability should they NOT have?
What server-side decision is supposed to stop them?
Why does that decision fail?
What capability is gained?
```

Example:

```text
Attacker: authenticated standard user
Expected capability: read own invoices
Boundary: object-level authorization
Violation: invoice ID from another tenant is accepted
Impact: cross-tenant invoice disclosure
```

This is much stronger than saying “IDOR exists.”

## 33.6 Step 5 — Build the smallest deterministic POC

A good POC is:

- Minimal
- Repeatable
- Deterministic
- Safe
- Easy to copy
- Rich in evidence
- Low-noise

Avoid giant tool output dumps.

Prefer:

```text
Request
→ response excerpt
→ expected result
→ observed result
→ security impact
```

## 33.7 POC anatomy

Use this structure for almost every vulnerability.

```markdown
## Proof of Concept

### Preconditions
- Account/role:
- Session state:
- Required feature:
- Victim interaction:

### Step 1 — Baseline
<normal request>

### Step 2 — Trigger
<single changed input/request>

### Step 3 — Observation
<minimal response evidence>

### Step 4 — Security Property Violation
<what should have happened vs what happened>

### Step 5 — Impact Demonstration
<safe, concrete capability gained>

### Step 6 — Reproduction Notes
<repeatability, timing, environment, caveats>

### Expected
<secure behavior>

### Observed
<vulnerable behavior>
```

## 33.8 IDOR / BOLA POC standard

A weak report says:

```text
Change id=123 to id=124 and another object appears.
```

A strong report establishes ownership.

```text
User A → owns object 123
User B → owns object 124

Authenticated as User B:
GET /api/orders/123

Expected:
403 / 404 / equivalent authorization denial

Observed:
200 OK
Object belonging to User A returned
```

Then prove it again with a second object or account where practical.

The critical evidence is **cross-principal access**, not merely numeric ID manipulation.

## 33.9 Privilege-escalation POC standard

Demonstrate a role boundary.

```text
Account A: standard user
Account B: administrator

1. Observe administrator-only request.
2. Replay request from standard account.
3. Change only the authorization-relevant condition.
4. Verify whether the protected action succeeds.
5. Confirm action is genuinely privileged.
```

Do not claim “admin takeover” merely because an admin endpoint returns a response. Prove that the restricted operation succeeded.

## 33.10 XSS POC standard

Use a harmless payload where possible.

Evidence should show:

```text
Attacker-controlled input
        ↓
Application output context
        ↓
Browser interpretation
        ↓
Script execution
```

Then identify the context:

```text
HTML text
HTML attribute
JavaScript string
DOM sink
URL context
CSS context
Template context
```

Reflection by itself is not the same thing as exploitable XSS.

## 33.11 SQL / NoSQL / command / template injection POC standard

Do not jump immediately to destructive extraction.

Establish the interpreter boundary first.

```text
Input
 ↓
Parser / query builder / template engine
 ↓
Unexpected syntax interpretation
 ↓
Observable difference
```

A strong POC can use:

- Controlled boolean differences
- Benign syntax changes
- Safe timing probes
- Canary strings
- Non-destructive metadata access permitted by program rules

Only demonstrate additional impact when necessary and explicitly authorized.

## 33.12 SSRF POC standard

The safest useful proof is generally:

```text
Attacker input
      ↓
Server-side fetch
      ↓
Researcher-controlled callback
      ↓
Observed interaction
```

Document:

- outbound request evidence
- protocol if visible
- source IP or request metadata where safe
- whether redirects are followed
- whether DNS rebinding or alternative schemes matter
- whether the server reaches internal-only destinations

Do not access sensitive internal systems merely to “make the impact bigger.” A controlled callback is usually better evidence.

## 33.13 Authentication-bypass POC standard

Authentication bypass requires a clean boundary demonstration.

```text
Unauthenticated client
        ↓
Protected endpoint
        ↓
Expected: 401 / login / denial
Observed: authenticated-only function succeeds
```

Then test whether the bypass is:

- endpoint-specific
- method-specific
- role-specific
- session-specific
- temporary
- cache-dependent
- proxy-dependent

A one-off odd response is not enough.

## 33.14 Password-reset / account-takeover POC standard

Separate:

```text
Token exposure
```

from:

```text
Account takeover
```

A convincing POC explains the chain:

```text
Attacker controls condition X
        ↓
Password-reset artifact generated incorrectly
        ↓
Attacker can obtain or influence artifact Y
        ↓
Y is accepted by the recovery endpoint
        ↓
Account credential/session changes
```

Whenever possible, demonstrate the issue against a test account controlled by you.

## 33.15 Request-smuggling / desync POC standard

For parser-differential bugs, prove the **difference in message boundaries** rather than merely showing two conflicting headers.

A useful POC records:

```text
Front-end parser interpretation
        vs
Back-end parser interpretation
```

Then demonstrate a safe observable effect such as:

- a follow-up request receiving an unexpected response
- queue desynchronization
- request routing anomaly
- a controlled canary reaching the wrong logical request

Do not flood production systems. Desync testing can have collateral effects.

## 33.16 Host-header poisoning POC standard

Demonstrate the sensitive sink.

```text
Baseline:
Host: legitimate.example

Test:
Host: attacker-controlled.example

Observe:
- generated absolute URL
- password-reset link
- redirect target
- cookie Domain
- canonical URL
- cache key / cache object
```

The key is not “Host reflects.” The key is:

> **Attacker-controlled host metadata influences a security-sensitive operation.**

## 33.17 CORS POC standard

A strong CORS POC proves both:

```text
Origin is attacker-controlled
        ↓
Sensitive response is readable by attacker origin
```

Test:

```text
Origin: https://attacker.example
```

Then verify whether:

```text
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
```

actually exposes authenticated data.

A permissive CORS header on a non-sensitive endpoint may have little or no impact.

## 33.18 WebSocket POC standard

Test the handshake separately from message authorization.

```text
HTTP handshake
    ↓
Origin validation
    ↓
Authentication
    ↓
Connection established
    ↓
Message authorization
    ↓
Sensitive operation
```

A WebSocket security finding is much stronger when you show the exact point where a trust boundary fails.

## 33.19 Race-condition POC standard

A race-condition POC must prove **concurrency changes the security outcome**.

Use:

```text
Control:
One request → one expected state transition

Race:
N concurrent requests → invalid duplicate transition
```

Record:

- concurrency level
- success rate
- timing window
- whether behavior persists across sessions
- whether a lock/idempotency mechanism should have prevented it

Avoid unnecessary high-volume testing.

## 33.20 Cache-poisoning / cache-deception POC standard

Separate:

```text
Cache key manipulation
```

from:

```text
Cross-user impact
```

A strong demonstration shows:

```text
Attacker request
      ↓
Cache stores attacker-influenced response
      ↓
Victim-equivalent request
      ↓
Victim receives poisoned content
```

For cache deception, show that a sensitive response becomes retrievable under a cacheable representation.

## 33.21 Business-logic POC standard

Business-logic reports need a state model.

```text
State 1 → State 2 → State 3
            ↑
      attacker forces invalid transition
```

Document:

- intended state transition
- attacker-controlled input
- forbidden transition
- resulting state
- economic/security consequence

Examples:

```text
coupon redeemed twice
refund issued after shipment
subscription feature retained after downgrade
inventory reserved multiple times
trial converted into permanent access
```

The strongest proof demonstrates an invariant violation.

## 33.22 AI-assisted POC generation

AI can accelerate report construction, but it should not decide that a vulnerability is real.

Use AI for:

```text
Raw HTTP evidence
      ↓
Normalize
      ↓
Compare requests
      ↓
Explain likely root cause
      ↓
Draft reproduction steps
      ↓
Generate report structure
```

Do **not** use AI output as evidence.

The evidence must come from:

- actual requests
- actual responses
- reproducible state changes
- controlled callbacks
- test accounts
- logs you captured

A good workflow is:

```text
Human discovers anomaly
        ↓
AI proposes hypotheses
        ↓
Human tests each hypothesis
        ↓
Human records evidence
        ↓
AI organizes evidence
        ↓
Human verifies final report
```

## 33.23 Build a POC evidence bundle

For every serious finding, preserve a small evidence package.

```text
finding-name/
├── README.md
├── baseline-request.txt
├── exploit-request.txt
├── baseline-response.txt
├── exploit-response.txt
├── screenshots/
├── callback-evidence/
├── timeline.txt
└── notes.md
```

Use redaction before sharing.

Never include:

- real user passwords
- unrelated session tokens
- production secrets
- API keys
- private customer data
- credentials that are not necessary to prove the issue

## 33.24 Reproducibility matrix

Before submission, record:

| Test | Expected | Observed | Repeated | Notes |
|---|---|---|---|---|
| Baseline | Secure behavior | Secure behavior | Yes | Control |
| Trigger | Vulnerable behavior | Vulnerable behavior | Yes | Primary POC |
| Alternate session | Secure behavior | ? | ? | Rules out local state |
| Alternate account | Access denied | ? | ? | Proves authorization boundary |
| Fresh browser | Same security result | ? | ? | Rules out browser cache/state |
| Second object / path | Same class | ? | ? | Generalization |

The point is not to create paperwork. It is to prevent reporting a transient artifact.

## 33.25 Before/after diffing

For HTTP findings, save the requests and responses and compare them mechanically.

Useful differences include:

```text
Status code
Content length
Location
Set-Cookie
Cache-Control
Vary
Access-Control-*
Content-Type
Response body markers
Server timing
Redirect chain
```

For JSON, compare semantic fields rather than raw formatting.

For authorization findings, compare identity-bearing fields:

```text
user_id
account_id
tenant_id
organization_id
role
owner_id
resource_id
```

## 33.26 False-positive checklist

Before saying “confirmed,” ask:

```text
[ ] Is the behavior actually security-sensitive?
[ ] Did I prove attacker control?
[ ] Did I prove the security boundary?
[ ] Did I prove impact?
[ ] Did I test an expected negative case?
[ ] Did I test another account / session where relevant?
[ ] Could caching explain the result?
[ ] Could browser state explain the result?
[ ] Could an intermediary / proxy explain the result?
[ ] Could authorization legitimately allow this operation?
[ ] Is this only information disclosure with no meaningful impact?
[ ] Is it already documented or expected behavior?
[ ] Is it in scope?
[ ] Is it likely a duplicate?
```

## 33.27 “Interesting” versus “reportable”

Classify findings explicitly.

```text
Interesting
    ↓
Suspicious
    ↓
Reproducible
    ↓
Security-relevant
    ↓
Impactful
    ↓
In-scope
    ↓
Reportable
```

Examples:

```text
Reflected input
→ interesting
→ not automatically XSS

Admin endpoint discovered
→ interesting
→ not automatically auth bypass

Internal IP returned
→ interesting
→ not automatically SSRF

CORS wildcard
→ interesting
→ not automatically account takeover

Different status codes
→ interesting
→ not automatically user enumeration
```

## 33.28 Report template for a true positive

Use this as the default bug-bounty structure.

```markdown
# Title
[Asset] <precise vulnerability + security impact>

## Summary
<2–5 sentences describing the root cause and impact>

## Severity
<Program-defined severity or justified CVSS assessment>

## Affected Asset
<Host / application / endpoint / feature>

## Preconditions
<Account / role / victim interaction / feature state>

## Vulnerability Details
<What is broken and why>

## Root Cause
<Trust boundary / parser / authorization / state-machine failure>

## Steps to Reproduce
1. ...
2. ...
3. ...

## Request
```http
<minimal reproducible request>
```

## Response / Evidence
```text
<minimal relevant evidence>
```

## Expected Behavior
<secure outcome>

## Observed Behavior
<actual outcome>

## Impact
<concrete attacker capability>

## Security Boundary Violated
<who gained what they should not have>

## Reproducibility
<repeatability and test conditions>

## Suggested Remediation
<root-cause-level mitigation>

## Supporting Evidence
<screenshots / logs / callback proof>
```

This structure closely matches the spirit of current HackerOne quality guidance: clear title, detailed reproduction, impact, coverage, and supporting evidence. OWASP's WSTG likewise emphasizes that the report is a core deliverable and should make the risk understandable to both technical and non-technical readers. citeturn394038search5turn394038search6

## 33.29 POC quality levels

### Level 0 — Signal

```text
Scanner hit / reflection / anomaly
```

Not report-ready.

### Level 1 — Reproduction

```text
The same behavior can be repeated.
```

Still may not prove security impact.

### Level 2 — Security violation

```text
A defined security property is broken.
```

Usually reportable if in scope and meaningful.

### Level 3 — Impact demonstrated

```text
The attacker capability is explicitly proven.
```

Strong submission.

### Level 4 — Root cause + chain

```text
Root cause understood
+ impact proven
+ reliable reproduction
+ minimal chain
```

This is the standard to target for high-quality research.

## 33.30 Chain bugs only after each primitive is proven

Do not use weak findings to manufacture impact.

Bad:

```text
Open redirect
+ vague token reflection
= “account takeover”
```

Strong:

```text
Primitive A proven
        ↓
Primitive B proven
        ↓
Explicit attacker-controlled data flow
        ↓
Combined exploit works
        ↓
Concrete impact reproduced
```

Every link in the chain needs evidence.

## 33.31 Stopping rules

A mature bug bounty hunter also knows when to stop.

Stop when:

- impact is already proven
- further exploitation adds little evidence
- additional activity risks user data
- the next step crosses program boundaries
- the test becomes destructive
- a controlled test account is sufficient

The goal is to prove the bug, not to maximize damage.

## 33.32 POC review checklist

Before submitting:

```text
[ ] Scope verified
[ ] Asset verified
[ ] Vulnerability classification verified
[ ] Baseline captured
[ ] Trigger captured
[ ] Positive control passed
[ ] Negative control passed
[ ] Security boundary identified
[ ] Impact proven
[ ] Reproduction deterministic
[ ] Minimal request included
[ ] Sensitive data redacted
[ ] Duplicate check performed
[ ] Existing disclosure / advisory checked
[ ] Program-specific policy checked
[ ] No unnecessary destructive testing
[ ] Title describes the actual impact
[ ] Remediation targets root cause
```

## 33.33 The gold-standard research loop

Combine the entire guide into one operating loop:

```text
PUBLIC RESEARCH
     ↓
Extract primitive
     ↓
Generate hypothesis
     ↓
MAP TARGET
     ↓
Identify matching attack surface
     ↓
BASELINE
     ↓
Change one variable
     ↓
OBSERVE
     ↓
Reproduce
     ↓
FALSE-POSITIVE TESTS
     ↓
Security boundary proof
     ↓
Impact proof
     ↓
Minimal POC
     ↓
Duplicate / scope check
     ↓
REPORT
     ↓
TRIAGE FEEDBACK
     ↓
Update research card
     ↓
Improve next hypothesis
```

This creates a compounding advantage: every accepted, rejected, duplicate, and inconclusive result makes the next investigation better.

---

# 34. Primary References

## OWASP

- OWASP Top 10:2025 — https://owasp.org/Top10/
- OWASP Top 10:2025 Introduction — https://owasp.org/Top10/2025/0x00_2025-Introduction/
- OWASP API Security Top 10 — https://owasp.org/API-Security/editions/2023/en/0x00-toc/
- OWASP ASVS 5.0 — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/

## PortSwigger Web Security Academy / Research

- Web Security Academy — https://portswigger.net/web-security
- Request Smuggling Research — https://portswigger.net/research/request-smuggling
- Browser-Powered Desync — https://portswigger.net/research/browser-powered-desync-attacks
- Web Cache Poisoning — https://portswigger.net/research/practical-web-cache-poisoning
- GraphQL Security — https://portswigger.net/web-security/graphql
- WebSocket Security — https://portswigger.net/web-security/websockets
- Insecure Deserialization — https://portswigger.net/web-security/deserialization
- OAuth Authentication — https://portswigger.net/web-security/oauth
- Top 10 Web Hacking Techniques of 2025 — https://portswigger.net/research/top-10-web-hacking-techniques-of-2025

## Bug Bounty / Disclosure / Research Sources

- HackerOne — Submitting Reports — https://docs.hackerone.com/en/articles/8473994-submitting-reports
- HackerOne — Quality Reports — https://docs.hackerone.com/en/articles/8475116-quality-reports
- HackerOne — Post-Submission Guide — https://docs.hackerone.com/en/articles/15518592-post-submission-guide
- Google Bug Hunters — Report Overview and Public Reports — https://bughunters.google.com/report/vrp
- PortSwigger — Top 10 Web Hacking Techniques — https://portswigger.net/research/top-10-web-hacking-techniques
- PortSwigger — Top 10 Web Hacking Techniques of 2025 — https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- OWASP WSTG — Reporting — https://owasp.org/www-project-web-security-testing-guide/latest/5-Reporting/01-Reporting_Structure
- ProjectDiscovery — Nuclei Template Structure — https://docs.projectdiscovery.io/templates/structure
- ProjectDiscovery — Nuclei Template Research / Releases — https://projectdiscovery.io/blog/category/nuclei-templates/1
- GitHub Security Lab — https://securitylab.github.com/

## Further references

- MITRE CWE — https://cwe.mitre.org/
- CVE — https://www.cve.org/
- NIST Cybersecurity Resources — https://www.nist.gov/cybersecurity

---

# Final Hunter's Rule

Do not ask:

> “Which payload should I try?”

Ask:

> “What does the application believe, who is allowed to make it believe that, and what happens if that belief is wrong?”

That shift is the difference between scanner-driven testing and real vulnerability research.

---

## Version

**Guide version:** 2026-08

**Primary taxonomy:** OWASP Top 10:2025

**Companion references:** OWASP API Security Top 10:2023, OWASP ASVS 5.0, OWASP WSTG, current web-security research.
