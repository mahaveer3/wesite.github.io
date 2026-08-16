# Bug Bounty Hunter's Web Application Security Playbook — AI Agent Deep Research Edition

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
- [27.4. Specialist Tool Registry for AI Agents](#274-specialist-tool-registry-for-ai-agents)
- [28. Validation and False-Positive Control](#28-validation-and-false-positive-control)
- [28A. AI Agent Operating Specification](#28a-ai-agent-operating-specification)
- [28B. Machine-Readable Vulnerability Playbook Standard](#28b-machine-readable-vulnerability-playbook-standard)
- [28C. Specialist Playbook Examples](#28c-specialist-playbook-examples)
- [28D. Agent Tool Registry — Selection by Function](#28d-agent-tool-registry--selection-by-function)
- [28E. Tool Selection Matrix](#28e-tool-selection-matrix)
- [28F. Research-to-Agent Knowledge Pipeline](#28f-research-to-agent-knowledge-pipeline)
- [28G. Finding Validation Gate](#28g-finding-validation-gate)
- [28H. Safe POC Construction Standard](#28h-safe-poc-construction-standard)
- [28I. Chain Discovery Without Over-Exploitation](#28i-chain-discovery-without-over-exploitation)
- [28J. Report Generation Schema](#28j-report-generation-schema)
- [28K. Retest / Regression Model](#28k-retest--regression-model)
- [28L. AI Safety and Scope Guardrails](#28l-ai-safety-and-scope-guardrails)
- [28M. Recommended Agent Architecture](#28m-recommended-agent-architecture)
- [28N. Agent Quality Metrics](#28n-agent-quality-metrics)
- [28O. Lab-First Development Strategy](#28o-lab-first-development-strategy)
- [28P. Operating Principle for Autonomous Security Research](#28p-operating-principle-for-autonomous-security-research)
- [29. Impact, Severity, and Reports](#29-impact-severity-and-reports)
- [30. Practical Checklists](#30-practical-checklists)
- [31. Learning Path](#31-learning-path)
- [32. Research Corpus: POCs, Write-Ups, Disclosures, and Case Studies](#32-research-corpus-pocs-write-ups-disclosures-and-case-studies)
- [33. True-Positive Validation and Detailed POC Engineering](#33-true-positive-validation-and-detailed-poc-engineering)
- [34. Primary References](#34-primary-references)
- [35. The Final AI-Agent Architecture](#35-the-final-ai-agent-architecture)
- [36. Machine-Readable Contract Layer](#36-machine-readable-contract-layer)
- [37. Hypothesis Engine](#37-hypothesis-engine)
- [38. Differential Testing Engine](#38-differential-testing-engine)
- [39. True-Positive Gate 2.0](#39-true-positive-gate-20)
- [40. Safe POC Ladder](#40-safe-poc-ladder)
- [41. Research Intelligence System](#41-research-intelligence-system)
- [42. Vulnerability Coverage Matrix](#42-vulnerability-coverage-matrix)
- [43. Architecture-Aware Testing](#43-architecture-aware-testing)
- [44. Tool Selection as a Planning Problem](#44-tool-selection-as-a-planning-problem)
- [45. Tool Trust and Maintenance](#45-tool-trust-and-maintenance)
- [46. Benchmark-Driven Development](#46-benchmark-driven-development)
- [47. Duplicate and Novelty Engine](#47-duplicate-and-novelty-engine)
- [48. Severity and Impact Calibration](#48-severity-and-impact-calibration)
- [49. Report Quality Gate](#49-report-quality-gate)
- [50. Final Production Readiness Checklist](#50-final-production-readiness-checklist)
- [51. Definitive Operating Principle](#51-definitive-operating-principle)
- [52. Deep Research Edition — How an Advanced Agent Actually Reasons About Web Bugs](#52-deep-research-edition--how-an-advanced-agent-actually-reasons-about-web-bugs)
- [53. Advanced Authorization Research](#53-advanced-authorization-research)
- [54. Authentication Research at Protocol and State-Machine Level](#54-authentication-research-at-protocol-and-state-machine-level)
- [55. OAuth / OIDC / SAML Deep Model](#55-oauth--oidc--saml-deep-model)
- [56. Injection Research Beyond Payload Lists](#56-injection-research-beyond-payload-lists)
- [57. SSRF as a URL-Parsing and Trust-Policy Problem](#57-ssrf-as-a-url-parsing-and-trust-policy-problem)
- [58. Request Smuggling and Desynchronization as Parser Differential Analysis](#58-request-smuggling-and-desynchronization-as-parser-differential-analysis)
- [59. Web Cache Research as Key Computation Analysis](#59-web-cache-research-as-key-computation-analysis)
- [60. Race Conditions and TOCTOU at State-Transition Level](#60-race-conditions-and-toctou-at-state-transition-level)
- [61. Business Logic Research as Invariant Discovery](#61-business-logic-research-as-invariant-discovery)
- [62. File Uploads, Parsers, and Content-Type Confusion](#62-file-uploads-parsers-and-content-type-confusion)
- [63. Deserialization and Parser Differential Research](#63-deserialization-and-parser-differential-research)
- [64. Client-Side Security at Browser Semantics Level](#64-client-side-security-at-browser-semantics-level)
- [65. Prototype Pollution as a Multi-Stage Bug Class](#65-prototype-pollution-as-a-multi-stage-bug-class)
- [66. Subdomain Takeover and Dangling Infrastructure](#66-subdomain-takeover-and-dangling-infrastructure)
- [67. Cloud and Kubernetes Attack Paths](#67-cloud-and-kubernetes-attack-paths)
- [68. Supply-Chain and CI/CD Research](#68-supply-chain-and-cicd-research)
- [69. Differential Testing Engine — Research-Grade Specification](#69-differential-testing-engine--research-grade-specification)
- [70. Research Corpus Mining](#70-research-corpus-mining)
- [71. Duplicate and Novelty Analysis](#71-duplicate-and-novelty-analysis)
- [72. Severity as Evidence, Not Guesswork](#72-severity-as-evidence-not-guesswork)
- [73. Report Writing at Researcher Standard](#73-report-writing-at-researcher-standard)
- [74. Agent Failure Modes](#74-agent-failure-modes)
- [75. Advanced Agent Decision Tree](#75-advanced-agent-decision-tree)
- [76. Architecture-Specific Deep Testing Packs](#76-architecture-specific-deep-testing-packs)
- [77. Modern Research Priorities: 2025–2026](#77-modern-research-priorities-2025-2026)
- [78. What “Deep” Means for This Agent](#78-what-deep-means-for-this-agent)
- [79. Final Research-Grade Rule](#79-final-research-grade-rule)

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


## 27.4 Specialist Tool Registry for AI Agents

A serious AI bug-bounty agent should **not** have one giant undifferentiated tool list. It should maintain a capability registry and choose tools according to the current investigation state.

### Tool-selection rule

```text
Do not ask: "What tools do I have?"
Ask:    "What uncertainty am I trying to reduce?"

asset discovery      → discovery / OSINT tools
endpoint discovery   → crawlers / content discovery / JS analysis
behavior discovery   → proxy / browser / API tooling
candidate generation → scanners / signatures / fuzzers
validation           → differential requests / controlled accounts / OAST
impact confirmation  → minimal safe side effect
reporting             → evidence capture / structured finding store
```

### Confidence model

| Tool role | Typical output | Agent treatment |
|---|---|---|
| Discovery | candidate asset/endpoint | **Unverified** until resolved |
| Fingerprinting | technology/version clue | **Lead**, not proof |
| Passive scanner | suspicious behavior/configuration | **Candidate** |
| Active scanner | suspected vulnerability | **Candidate**, manually validate |
| Differential tester | measurable behavioral difference | **Strong evidence** when security-relevant |
| OAST/OOB | controlled callback | **Evidence of reachability**, not automatically impact |
| Exploit/PoC tool | demonstrated security boundary violation | **Validate scope and safety** |
| Reporter/evidence tool | reproducible artifact | **Supporting evidence**, not root-cause proof |

### 27.4.1 Recon, OSINT, and attack-surface mapping

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **OWASP Amass** | Attack-surface intelligence and asset relationships | Build an asset graph and enrich discovered infrastructure | Record source/confidence; do not assume every relationship is live |
| **Subfinder** | Passive subdomain discovery | Broad low-noise hostname enumeration | Resolve and HTTP-probe before deeper testing |
| **Assetfinder** | Domain/asset discovery | Lightweight secondary source for breadth | Correlate with other sources |
| **Findomain** | Multi-source domain discovery | Independent enumeration pass | De-duplicate and verify DNS |
| **Chaos** | Passive DNS/subdomain datasets | Historical/broad discovery | Treat results as candidates |
| **crt.sh** | Certificate Transparency search | Discover certificate-linked names | Confirm ownership and current DNS |
| **Censys** | Internet-wide host/certificate discovery | Enrich exposed infrastructure | Respect scope and asset ownership |
| **Shodan** | Internet-facing service/asset intelligence | Identify exposed services and banners | Banner ≠ vulnerability |
| **SecurityTrails** | DNS/history intelligence | Historical DNS and infrastructure pivoting | Historical records are not proof of current exposure |
| **urlscan.io** | Web crawl/search intelligence | Discover URLs, resources, domains and historical observations | Use only public/authorized intelligence as appropriate |
| **Wayback Machine / CDX** | Historical web resources | Recover old endpoints, JS, paths, parameters | Verify current behavior before testing |
| **gau** | Known URL collection from public sources | Build historical URL corpus | Filter stale/dead URLs |
| **waybackurls** | Wayback URL extraction | Quick historical endpoint discovery | Deduplicate and probe |
| **dnsx** | DNS resolution/probing | Resolve candidate hosts and records | Distinguish wildcard DNS from real assets |
| **puredns** | Mass DNS resolution/bruteforce workflows | High-volume resolution in controlled scope | Avoid unnecessary query volume |
| **massdns** | High-speed DNS resolution | Bulk candidate validation | Use rate controls |
| **CloudEnum** | Cloud asset enumeration | Discover cloud-hosted naming patterns | Confirm ownership before testing |
| **S3Scanner** | S3 bucket discovery/config checks | Candidate cloud-storage enumeration | Never download data merely to prove exposure |
| **MapCIDR** | CIDR/hostspace manipulation | Normalize network ranges for recon pipelines | Keep ranges strictly inside scope |

**Agent pattern:** run at least two independent discovery families when completeness matters. Store each observation as `asset + source + timestamp + confidence + evidence` rather than flattening everything into a plain text list. OWASP Amass's Open Asset Model is a useful model for this graph-oriented approach.

### 27.4.2 HTTP probing, crawling, content discovery, and endpoint mapping

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **httpx** (ProjectDiscovery) | HTTP probing, metadata and tech clues | Turn host candidates into live-web inventory | Verify protocol, status and host before deeper tests |
| **Katana** | Crawling/spidering | Discover links, APIs, JS references and endpoints | Use depth/concurrency appropriate to program rules |
| **Hakrawler** | Lightweight web crawling | Secondary endpoint discovery | Correlate with Katana and browser traffic |
| **gospider** | Spidering and JavaScript link extraction | Breadth-first URL discovery | Deduplicate and classify endpoints |
| **Feroxbuster** | Content discovery | Find hidden paths/files/directories | Positive status alone is insufficient; compare response semantics |
| **ffuf** | Fast web fuzzing | Parameter/path/header/value discovery | Build baselines and filter dynamic noise |
| **dirsearch** | Web path discovery | Alternate content-discovery engine | Use only in clearly authorized scope |
| **Gobuster** | DNS/dir/vhost discovery | Secondary discovery/fuzzing | Validate wildcard responses |
| **Wfuzz** | Generic web request fuzzing | Multi-location parameter testing | Prefer low-impact probes first |
| **Arjun** | HTTP parameter discovery | Discover hidden GET/POST parameters | Confirm that discovered parameters influence server behavior |
| **ParamSpider** | Parameterized URL collection | Historical/OSINT parameter corpus | Stale URLs require revalidation |
| **x8** | Hidden parameter discovery | Detect undocumented parameters | Compare baseline and mutated requests |
| **Kiterunner** | API route/content discovery | Enumerate APIs from wordlists/routes | Especially useful around API gateways and version drift |
| **LinkFinder** | Endpoint extraction from JavaScript | Recover API routes and secrets-shaped references | Extracting a string is not proof of exposure |
| **JSluice** | JavaScript analysis | Endpoint/secrets/static-analysis support | Review source-map and bundle context |
| **SecretFinder** | Regex-based secret/endpoint hints in JS | Fast triage of exposed client-side material | Verify whether values are actually sensitive/usable |
| **xnLinkFinder** | Endpoint extraction | Build endpoint corpus from JS/pages | Deduplicate and classify |
| **unfurl** | URL parsing/manipulation | Normalize and analyze URL components | Useful for parameter/canonicalization hypotheses |
| **uro** | URL normalization/deduplication | Reduce noisy historical URL sets | Do not remove variants that may encode behavior |
| **qsreplace** | Parameter value replacement | Systematic differential parameter testing | Preserve original request as baseline |

ProjectDiscovery officially positions `subfinder`, `httpx`, `katana`, `nuclei`, `naabu`, `interactsh`, and `proxify` as parts of its offensive-security toolkit family.

### 27.4.3 Proxy, browser, API, and interactive testing

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **Burp Suite Professional** | Intercepting proxy and manual web testing platform | Central request/response workspace, Repeater, Intruder, extensions | Treat third-party extensions as untrusted code and review them where practical |
| **OWASP ZAP** | Proxy, crawler, passive/active scanning, automation | Repeatable automated web-security workflows | Use passive scanning by default; active scanning only with explicit authorization |
| **mitmproxy** | Scriptable HTTP(S) proxy | Programmatic traffic observation/modification | Excellent bridge between browser traffic and agent code |
| **Caido** | Modern intercepting proxy | Human/agent-assisted HTTP testing | Use as an alternate interactive workflow |
| **Insomnia** | API client | Manual API exploration and request collections | Preserve authenticated context carefully |
| **Postman** | API client/collections | API inventory and controlled request replay | Never import real secrets into shared collections |
| **Hoppscotch** | Web API client | Lightweight API exploration | Useful for quick hypothesis checks |
| **curl** | Raw HTTP client | Minimal reproducible requests | Ideal for final PoC reproducibility |
| **HTTPie** | Human-friendly HTTP client | Quick request experiments | Keep final evidence reproducible with stable syntax |
| **Playwright** | Browser automation | Login flows, DOM behavior, SPA testing, screenshots | Use dedicated controlled accounts and deterministic sessions |
| **Puppeteer** | Chromium automation | Browser-state and client-side behavior testing | Useful when Chrome DevTools Protocol is needed |
| **Selenium** | Browser automation | Cross-browser regression and authenticated flows | More setup overhead; useful for compatibility checks |
| **browser-use frameworks / controlled browser agents** | Agentic browser interaction | Explore complex UI workflows | Must maintain explicit scope and action limits |

PortSwigger documents Burp extensions as a way to modify HTTP traffic, send additional requests, add Scanner checks, access Burp data, and build custom functionality via the Montoya API. The BApp Store is community-maintained, so an agent should treat extension code as third-party software and review its trust/data behavior before installing it.

ZAP provides an Automation Framework with YAML-defined jobs, authentication support, passive scanning, spidering, OpenAPI/SOAP/GraphQL import, active scanning, requester workflows, and outcome tests. Passive scanning is designed not to modify messages; active scanning is explicitly invasive and should only run against authorized targets.

### 27.4.4 Vulnerability discovery and signature-based detection

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **Nuclei** | Template-driven detection | Candidate generation, regression checks, technology-aware checks | Inspect the template and reproduce the underlying condition manually |
| **Nessus** | Broad vulnerability assessment | Coverage gaps and known-vulnerability inventory | Findings require application-specific validation in bounty contexts |
| **OpenVAS / Greenbone** | Vulnerability scanning | Infrastructure-side coverage | Not a substitute for web logic testing |
| **Nikto** | Web-server checks | Cheap configuration triage | High noise; validate every interesting result |
| **Nmap + NSE** | Network/service discovery and scripts | Service inventory and targeted checks | Keep ports/ranges scoped |
| **Naabu** | Fast port discovery | Turn host inventory into service inventory | Follow with HTTP/service identification |
| **RustScan** | Fast port scanning wrapper | Quick candidate port discovery | Confirm with authoritative service probes |
| **testssl.sh** | TLS configuration analysis | Crypto/TLS posture checks | Distinguish weak configuration from exploitable application impact |
| **sslyze** | TLS/SSL analysis | Programmatic TLS posture collection | Good structured output for agents |
| **WhatWeb** | Web technology fingerprinting | Stack fingerprinting and version clues | Fingerprint is hypothesis input, not vulnerability proof |
| **Wappalyzer** | Technology identification | Browser/application stack classification | Cross-check against response evidence |
| **BuiltWith** | Web technology intelligence | External technology mapping | Use as enrichment, not sole evidence |

### 27.4.5 Injection and input-handling specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **SQLMap** | Automated SQL injection testing | Candidate confirmation and DBMS fingerprinting on in-scope endpoints | Never dump unnecessary data; stop at minimal proof |
| **Ghauri** | SQL injection detection/exploitation alternative | Cross-engine confirmation and second-opinion validation | Use only against authorized targets |
| **NoSQLMap** | NoSQL injection workflows | Candidate testing for document/NoSQL databases | Framework-specific manual validation still required |
| **Commix** | Command injection automation | Candidate generation/validation | High impact; use conservative probes and scope controls |
| **Dalfox** | XSS scanner/parameter analysis | Reflected/DOM XSS candidate generation | Manually verify exploitability and browser context |
| **kxss** | Reflection detection | Find reflection candidates quickly | Reflection alone is not XSS |
| **XSStrike** | XSS analysis/fuzzing | Context analysis and candidate payload generation | Treat generated payloads as hypotheses |
| **tplmap** | SSTI discovery/testing | Template injection research | Framework identification improves signal |
| **SSTImap** | SSTI detection/analysis | Modern server-side template testing | Stop before unnecessary command execution |
| **commix** | OS command injection testing | Confirm command-execution sinks | Use benign side effects/canaries |
| **XXEinjector** | XXE testing workflows | Candidate generation when XML processing is identified | Prefer controlled OOB canaries |
| **crlfuzz** | CRLF/header injection discovery | Header parser/differential testing | Confirm actual response splitting or header injection effect |
| **dotdotpwn** | Path traversal testing | Legacy/native path traversal research | Keep depth and request volume constrained |
| **Gopherus** | Gopher payload construction | SSRF/internal protocol hypothesis building | Only generate protocol requests after confirming a permitted sink |

### 27.4.6 Parameter, authorization, and business-logic specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **Autorize (Burp extension)** | Authorization replay/comparison | Compare privileged vs unprivileged requests | Requires controlled accounts and careful state handling |
| **AuthMatrix (Burp extension)** | Authorization matrix testing | Systematically compare roles/users/actions | Strong candidate-generation aid, not final proof |
| **Auth Analyzer / similar role-comparison extensions** | Session/role comparison | Identify endpoint authorization inconsistencies | Verify server-side enforcement manually |
| **Param Miner (Burp extension)** | Hidden parameter/header discovery | Find undocumented inputs that alter behavior | Interesting parameter ≠ vulnerability |
| **Backslash Powered Scanner (Burp extension)** | Parser discrepancy/edge-case detection | Candidate generation for unusual input interpretation | Requires careful differential confirmation |
| **HTTP Request Smuggler (Burp extension)** | Desync/request-smuggling analysis | Identify CL/TE and parser differential candidates | Confirm front-end/back-end boundary behavior before reporting |
| **Turbo Intruder (Burp extension)** | High-speed controlled request engine | Race conditions, state transitions, large-but-bounded test matrices | Respect rate limits and program rules |
| **Logger++ (Burp extension)** | Enhanced request/response logging | Evidence collection and timeline correlation | Sanitize secrets before long-term storage |
| **Flow / session-management extensions** | Workflow inspection | Reconstruct state transitions | Validate actual server-side trust assumptions |

### 27.4.7 HTTP desync, parser differential, and protocol specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **HTTP Request Smuggler** | Smuggling detection research | Candidate desync testing from Burp | Use safe canary endpoints whenever possible |
| **smuggler** | Python-based request-smuggling research | Independent second opinion | Compare parser behavior, do not assume a timeout means smuggling |
| **h2csmuggler** | HTTP/2 cleartext upgrade/desync research | Explore h2c translation boundaries | Only test supported/authorized protocol paths |
| **HTTP/2 research tooling** | H2/H1 translation differences | Protocol downgrade and parser differential hypotheses | Require stable baseline and clear queue desynchronization evidence |
| **curl** | Precise HTTP framing | Reproduce low-level request differences | Record exact version/flags in evidence |
| **nghttp2 client tools** | HTTP/2 frame-level interaction | Protocol-specific validation | Useful for agent-controlled regression testing |

### 27.4.8 SSRF, OOB, callback, and blind-interaction specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **Interactsh** | OOB interaction server/client | Detect DNS/HTTP/SMTP/etc. callbacks from blind sinks | Callback proves reachability; impact still needs contextual validation |
| **Burp Collaborator** | OOB interaction infrastructure | SSRF/XXE/blind injection confirmation | Use program-permitted instances |
| **Canarytokens** | Controlled callback canaries | Low-noise blind interaction confirmation | Token hit alone does not establish privilege or data exposure |
| **SSRFmap** | SSRF testing workflows | Candidate endpoint/SSRF validation | Prefer canary services before sensitive internal targets |
| **Gopherus** | Internal protocol request construction | Identify protocol-level SSRF potential | Do not turn a validated SSRF into destructive internal actions |

ProjectDiscovery describes Interactsh as an out-of-band interaction gathering server/client, making it well suited to blind callback detection.

### 27.4.9 JWT, OAuth, OIDC, SSO, and identity specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **jwt_tool** | JWT analysis/testing | Algorithm, claim, key-handling hypotheses | Decoding a JWT is never by itself a vulnerability |
| **JOSE tooling (jose / node-jose / jose libraries)** | JWS/JWE/JWK parsing | Reproduce token-validation behavior programmatically | Match production parser/version where possible |
| **Burp JWT-related extensions** | Token inspection/mutation | Rapid auth hypothesis testing | Verify server-side semantics |
| **OIDC/OAuth test harnesses** | Protocol flow testing | State/nonce/PKCE/redirect/account-linking analysis | Prefer test identities and controlled clients |
| **oauth2-proxy test environments** | Reverse-proxy auth behavior labs | Reproduce edge cases safely | Use as a lab oracle, not as evidence about a target |
| **Keycloak test harnesses** | Identity-provider behavior testing | Build comparison labs for OIDC/SAML assumptions | Useful for reproducing standards edge cases |

### 27.4.10 GraphQL, API, and schema-focused specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **InQL** | GraphQL introspection/query tooling | Enumerate schema and construct test queries | Respect disabled introspection and program rules |
| **GraphQL Voyager** | Schema visualization | Understand object/relationship attack surface | Visualization is not proof of access |
| **GraphQL Cop** | GraphQL security checks | Candidate misconfiguration/DoS/authorization clues | Validate application-specific impact |
| **Clairvoyance** | GraphQL schema recovery research | Schema discovery when introspection is unavailable | Treat inferred schema as hypotheses |
| **Kiterunner** | API route discovery | Hidden/undocumented endpoint enumeration | Validate route ownership and auth |
| **Postman/Newman** | API collections + CLI execution | Regression and repeatable request sets | Keep credentials isolated |
| **Insomnia/Inso** | API collections + CLI | Alternate API regression workflow | Good fit for agent pipelines |
| **ZAP API Scan** | OpenAPI/SOAP/GraphQL-oriented scanning | Automated API candidate generation | ZAP's API scan is tuned for APIs and can import OpenAPI/SOAP/GraphQL definitions. |

### 27.4.11 Secrets, source-code, and supply-chain intelligence

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **TruffleHog** | Secret detection across repositories/integrations | Search public source, Git, cloud-integrated data for leaked credentials | A detected string is not proof it is valid; validate safely and revoke rather than abuse |
| **Gitleaks** | Git/file/stdin secret detection | Historical commit and repository secret discovery | Current project notes indicate it is feature-complete and focused on security fixes; evaluate newer alternatives where appropriate |
| **Betterleaks** | Successor/focused secret scanning work | Modern secret-detection pipelines | Treat detector output as candidate evidence |
| **GitGuardian** | Secret exposure monitoring | External exposure intelligence | Use official/authorized data access |
| **Semgrep** | Fast multi-language static analysis | Find insecure sinks and custom patterns in source | Map code finding to reachable production behavior |
| **CodeQL** | Variant/query-based code analysis | Deep source-level vulnerability research | Excellent for root-cause and variant analysis when source is available |
| **Joern** | Code property graph analysis | Complex dataflow/control-flow research | Best when source and build context are available |
| **Semgrep Supply Chain** | Dependency/reachable-risk analysis | Dependency and transitive-risk hypotheses | Validate reachability and deployment context |
| **OSV-Scanner** | Open-source dependency vulnerability scanning | Known-vulnerable dependency inventory | Version match ≠ exploitable deployment |
| **Syft** | SBOM generation | Build software-component inventory | Feed SBOM into dependency-risk reasoning |
| **Grype** | SBOM/image vulnerability matching | Match deployed artifacts to vulnerability databases | Confirm component/version actually ships |
| **Trivy** | Container/IaC/dependency scanning | Unified cloud-native security triage | Separate configuration findings from exploitable web bugs |
| **Gitleaks** | Historical and present secret search | Scan commits/working trees | False positives and revoked secrets need explicit classification |

TruffleHog documents integrations for Git, GitHub, Docker, AWS S3, Google Cloud Storage and other sources; Gitleaks supports Git, directory and stdin scanning and can preserve baselines for recurring scans.

### 27.4.12 Cloud, containers, and exposed infrastructure specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **Prowler** | Cloud security posture assessment | AWS/Azure/GCP control checks | Misconfiguration must be tied to a real exposure |
| **ScoutSuite** | Multi-cloud security auditing | Cloud posture inventory | Good for breadth, weak as sole exploit evidence |
| **CloudFox** | Cloud attack-path enumeration | AWS cloud privilege/identity mapping | Use only in owned/authorized cloud environments |
| **Pacu** | AWS security-testing framework | Controlled cloud security research | High-impact capability; keep permissions bounded |
| **CloudMapper** | AWS visual mapping/audit support | Graph cloud network exposure | Verify current state |
| **Kube-bench** | Kubernetes CIS benchmark checks | Cluster configuration hygiene | Not a web application proof by itself |
| **Kube-hunter** | Kubernetes security testing | Detect exposed cluster attack surfaces | Use only against explicitly authorized clusters |
| **Kubescape** | Kubernetes posture / compliance/security checks | Cloud-native inventory and misconfiguration triage | Validate exploitability and scope |
| **Falco** | Runtime detection | Observe runtime security events in owned environments | Defensive/observability role rather than bug bounty exploitation |
| **Nmap / NSE** | Service and protocol discovery | Map externally visible infrastructure | Correlate with application ownership |

### 27.4.13 CMS and framework-specific specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **WPScan** | WordPress enumeration/scanning | Plugin/theme/version and configuration triage | Verify current vulnerable code path |
| **Droopescan** | CMS enumeration | Drupal/Joomla/WordPress-style discovery | Fingerprinting only is not a vulnerability |
| **JoomScan** | Joomla assessment | CMS-specific endpoint/version checks | Validate affected component |
| **Nuclei technology templates** | Stack-specific checks | Fast version/config candidate discovery | Read the template logic before reporting |
| **Retire.js** | JavaScript dependency vulnerability identification | Client-side dependency inventory | Confirm loaded and reachable vulnerable code |
| **Dependency-Track** | Component/SBOM risk platform | Continuous dependency inventory | Excellent for organizations; less directly useful for anonymous bounty targets |

### 27.4.14 Fuzzing and differential-analysis specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **ffuf** | HTTP fuzzing | Parameter, path, header and value mutation | Always establish a response baseline |
| **Burp Intruder** | Request mutation engine | Targeted parameter matrix testing | Control concurrency and session state |
| **Turbo Intruder** | Programmable high-speed HTTP testing | Race conditions and finely controlled concurrency | Use only on safe endpoints/test accounts unless policy expressly allows more |
| **Radamsa** | General-purpose mutation/fuzzing | Parser robustness and file/input mutation | Run against lab/owned targets unless explicit scope permits |
| **AFL++** | Coverage-guided fuzzing | Native/parser research | Primarily for source/binary ownership and lab environments |
| **libFuzzer** | In-process coverage-guided fuzzing | Parser and library research | Best for owned code |
| **boofuzz** | Stateful protocol fuzzing | Custom protocol parsers | Lab/controlled systems only |
| **Peach** | Protocol/data fuzzing platform | Complex parser testing | Use only with explicit permission |
| **Schemathesis** | Property-based API testing from OpenAPI/GraphQL | Find edge cases and invariant failures automatically | Validate every generated case against business rules |
| **RESTler** | Stateful REST API fuzzing | Workflow-aware API testing | Excellent for state machines; requires careful scope/rate control |
| **Dredd** | API contract testing | Detect API/spec drift | Pair with security hypotheses rather than treating failures as vulnerabilities |

### 27.4.15 File, archive, serialization, and parser specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **ExifTool** | Metadata/file parsing | Identify server/client handling of uploaded media | Version/config context matters |
| **Binwalk** | Embedded/archive/file analysis | Investigate firmware or complex uploaded artifacts | Primarily lab/authorized research |
| **7-Zip / unzip / tar tooling** | Archive inspection | Understand archive nesting/path behavior | Useful for upload and extraction hypotheses |
| **ysoserial** | Java deserialization gadget research | Lab/source-assisted serialization research | Do not use destructive gadget chains against production unless explicitly authorized |
| **PHPGGC** | PHP gadget-chain research | Source/framework-assisted deserialization research | Use in controlled environments |
| **marshalsec** | Java marshaling/deserialization research | Protocol/deserialization labs | Controlled validation only |
| **Semgrep / CodeQL** | Serialization sink discovery | Identify reachable deserialization code paths | Prefer source-level proof before dynamic exploitation |

### 27.4.16 Browser and client-side security specialists

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **Chrome DevTools** | Browser network/DOM/runtime inspection | DOM XSS, storage, CSP, CORS, service-worker debugging | Capture exact browser context for findings |
| **Firefox Developer Tools** | Browser diagnostics | Cross-browser behavior differences | Useful for browser-specific parser/security behavior |
| **Playwright** | Automated browser testing | Reproduce auth/UI workflows and DOM sinks | Use deterministic sessions |
| **DOM Invader** | PortSwigger browser-assisted DOM XSS testing | Discover DOM sinks/sources | Treat evidence as browser-context specific |
| **Lighthouse** | Web quality/performance audit | Secondary configuration insight | Security findings require independent validation |
| **Retire.js** | Client dependency vulnerability detection | Identify old JS libraries | Confirm vulnerable code path is loaded and reachable |

### 27.4.17 Evidence, reporting, and data normalization

| Tool | Primary capability | Best agent use | Validation note |
|---|---|---|---|
| **jq** | JSON processing | Normalize API/scanner output for agent pipelines | Keep raw evidence too |
| **yq** | YAML processing | Parse scanner/config output | Preserve original files |
| **ripgrep (rg)** | Fast text search | Search source, logs, bundles and reports | Do not treat a string match as exploit evidence |
| **jq/yq + JSON Schema** | Structured validation | Enforce finding-record formats | Strong choice for agent memory/state |
| **CyberChef** | Encoding/decoding analysis | Decode tokens/parameters for hypothesis generation | Decoding is not decryption or proof |
| **MITRE CVE/CWE data** | Vulnerability/weakness mapping | Normalize findings for reports | Use authoritative identifiers when available |
| **SARIF tooling** | Standardized scanner findings | Aggregate SAST/security results | Normalize before triage; scanners can duplicate the same root cause |

### 27.4.18 A–Z specialist index

This index is intentionally alphabetic so an agent can search by tool name as well as capability.

```text
A  Amass, Arjun, Assetfinder, AuthMatrix, Autorize
B  Backslash Powered Scanner, Binwalk, Browser DevTools, Burp Suite
C  Censys, Chaos, Clairvoyance, CloudEnum, CloudFox, Commix, CyberChef
D  Dalfox, Dirsearch, Droopescan
E  ExifTool
F  Feroxbuster, Findomain, ffuf, Firefox DevTools
G  gau, Ghauri, GitGuardian, Gitleaks, gospider, Gobuster, GraphQL Cop
H  Hakrawler, HTTP Request Smuggler, HTTPie, h2csmuggler
I  InQL, Interactsh
J  Joern, JoomScan, jq
K  Katana, Keycloak lab tooling, Kiterunner, Kube-bench, Kube-hunter, Kubescape
L  LinkFinder, libFuzzer, Lighthouse
M  MassDNS, masscan, MapCIDR, mitmproxy, Nmap, Nikto
N  Naabu, Newman, Nessus, nuclei, NoSQLMap
O  OpenVAS, OWASP Amass, OWASP ZAP
P  Param Miner, ParamSpider, Prowler, Postman, puredns, Puppeteer, Playwright
Q  (Use query-specific tooling rather than one generic scanner)
R  Radamsa, RESTler, Retire.js, ripgrep, RustScan
S  ScoutSuite, Schemathesis, SecretFinder, Semgrep, Shodan, smuggler, SQLMap, SSRFmap, SSTImap, Subfinder
T  Turbo Intruder, TruffleHog, Trivy, testssl.sh
U  unfurl, uro
V  (Use vulnerability-specific validators rather than broad catch-all tools)
W  Wayback/CDX, waybackurls, Wappalyzer, wfuzz, WhatWeb
X  x8, XSStrike, xnLinkFinder
Y  yq
Z  ZAP, ZAP API Scan
```

### 27.4.19 Agent capability registry schema

Do not hard-code tool selection in prose. Store tool metadata as structured records.

```yaml
name: nuclei
category: vulnerability_detection
capabilities:
  - signature_detection
  - candidate_generation
inputs:
  - http_targets
  - templates
outputs:
  - candidate_findings
strengths:
  - scalable
  - reproducible
limitations:
  - template_dependent
  - false_positives_possible
trust_level: candidate_generator
validation_required: true
preferred_stage:
  - reconnaissance
  - candidate_generation
  - regression
safe_default: true
active_testing: depends_on_template
scope_required: true
```

For each tool, the agent should store at least:

```text
name
version
category
capabilities
input types
output types
active/passive classification
scope sensitivity
rate-limit sensitivity
state/session requirements
noise profile
known limitations
validation requirement
recommended workflow stage
reproducibility characteristics
license / operational constraints
official documentation URL
```

### 27.4.20 Tool orchestration rules

**Rule 1 — Discovery tools should converge, not compete.**

Run independent discovery sources, normalize results, and preserve provenance:

```text
subfinder + amass + CT + historical URLs
              ↓
       normalize / dedupe
              ↓
       DNS resolution
              ↓
       HTTP probing
              ↓
       attack-surface graph
```

**Rule 2 — Scanner output is a hypothesis.**

```text
scanner → candidate
candidate → reproduction
reproduction → security-boundary proof
security-boundary proof → impact
impact → report
```

**Rule 3 — Independent confirmation increases confidence.**

For important findings, prefer:

```text
scanner A
  +
manual request
  +
independent observation/tool
  =
stronger confidence
```

Do not create artificial confidence by running five wrappers around the same underlying detection rule.

**Rule 4 — Prefer the least invasive tool that can answer the question.**

```text
passive evidence
   ↓
small differential request
   ↓
controlled OOB callback
   ↓
minimal safe proof
   ↓
stop
```

**Rule 5 — Preserve raw evidence.**

Every automated result should retain:

```text
raw input
raw output
command/configuration
version
timestamp
scope identifier
normalized finding
agent interpretation
validation status
```

**Rule 6 — Treat extensions and downloaded templates as code.**

BApps, Nuclei templates, custom scripts, wordlists, browser extensions, and third-party plugins can alter requests or access credentials. Review provenance and isolate secrets. PortSwigger explicitly notes that BApps are third-party code and recommends reviewing source; the same principle should be applied to any agent plugin.

### 27.4.21 Recommended specialist stacks by investigation goal

| Investigation goal | Recommended first stack | Second opinion |
|---|---|---|
| External attack-surface mapping | Amass + Subfinder + DNSx + httpx | Censys/Shodan + CT |
| API discovery | Katana + Kiterunner + Arjun + JS analysis | ZAP API Scan + Postman/Newman |
| Hidden parameters | Arjun + ParamSpider + Param Miner + x8 | ffuf/Wfuzz |
| Access-control research | Burp + Autorize/AuthMatrix + controlled accounts | ZAP + custom request diff |
| XSS | Burp + Dalfox + DOM Invader | XSStrike + browser replay |
| SQL injection | Burp + SQLMap | Ghauri + manual differential tests |
| SSRF | Burp + Interactsh/Collaborator | SSRFmap + manual parser analysis |
| Desync/request smuggling | Burp + HTTP Request Smuggler | smuggler + low-level curl/H2 tools |
| Race conditions | Burp + Turbo Intruder | custom concurrent HTTP client |
| GraphQL | InQL + browser/proxy | ZAP GraphQL support + Clairvoyance |
| Secrets / source exposure | TruffleHog + Gitleaks | GitGuardian + CodeQL/Semgrep |
| Dependency/supply chain | Syft + OSV-Scanner + Grype/Trivy | Semgrep Supply Chain |
| Cloud exposure | Prowler + ScoutSuite + CloudFox | provider-specific native tooling |
| Web crawling/regression | Katana + Playwright | ZAP Automation Framework |

### 27.4.22 What the AI agent must NEVER infer from a tool alone

```text
200 OK                 ≠ authorization bypass
403 → 200              ≠ access-control bypass
reflection             ≠ XSS
JWT decodes            ≠ JWT vulnerability
CORS: *                ≠ exploitable credentialed CORS
Open redirect          ≠ account takeover
SSRF callback          ≠ cloud compromise
stack trace            ≠ critical vulnerability
CVE/version match     ≠ exploitable target
DNS record             ≠ takeover
secret-looking string  ≠ active credential
scanner hit            ≠ reportable vulnerability
```

The agent must require a **security-property proof** appropriate to the vulnerability class before moving a result from `candidate` to `validated`.

### 27.4.23 Official-source maintenance rule

Tool ecosystems change. Keep this registry maintainable:

1. Prefer the vendor/project's official documentation and source repository.
2. Record `last_verified` for tool metadata.
3. Re-check tool status before relying on an old project.
4. Distinguish maintained projects from archived/deprecated tools.
5. Keep the command syntax out of the knowledge model when a dedicated tool adapter can expose structured inputs/outputs.
6. Pin versions in reproducible agent environments.

This matters particularly for fast-moving ecosystems such as ProjectDiscovery, Burp extensions, browser automation, and secrets tooling. ProjectDiscovery publishes its current open-source tool family centrally; PortSwigger maintains current BApp/extension documentation; ZAP's Automation Framework is designed for repeatable YAML-driven workflows.

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

HackerOne's current guidance explicitly expects reports to explain the vulnerability, reproduction steps, and impact, and its quality-report guidance stresses clear reproduction, coverage, and supporting evidence. Google Bug Hunters likewise points researchers toward public reports to learn where others are focusing and how they build reports.

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

PortSwigger's annual research project is a good example of why curation matters: the security community produces a huge number of publications, yet reusable techniques can easily disappear inside the volume. The 2025 edition collected community nominations and expert-selected research, including parser differentials and new SAML exploitation techniques.

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

But treat a scanner hit as a **hypothesis**, not proof. Nuclei's own model is based around requests, matchers, and extractors that identify a condition; that is detection logic, not automatically a complete exploitation narrative.

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

This structure closely matches the spirit of current HackerOne quality guidance: clear title, detailed reproduction, impact, coverage, and supporting evidence. OWASP's WSTG likewise emphasizes that the report is a core deliverable and should make the risk understandable to both technical and non-technical readers.

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


# 28A. AI Agent Operating Specification

This section defines how an AI security agent should convert the knowledge in this document into a repeatable, auditable workflow.

The agent is **not** a vulnerability scanner with a chat interface. It is an evidence-driven investigator. Every tool call should answer a question, reduce uncertainty, or collect evidence.

## 28A.1 Agent Mission

```text
MISSION =
  maximize(validated security findings)
  subject to authorization + safety + reproducibility + minimal impact
```

The agent should optimize for **validated findings per unit of target noise**, not the number of requests sent or the number of scanner alerts produced.

### Core invariants

1. Scope is immutable during an investigation unless the operator explicitly changes it.
2. A tool result is an observation, not proof.
3. A candidate finding must have a stated hypothesis.
4. A confirmed finding must demonstrate a security-boundary violation.
5. Impact must be reproduced with the minimum safe interaction.
6. Exploitation should stop once sufficient evidence exists.
7. Every final claim must map to evidence.
8. Every evidence artifact must be reproducible by another tester.
9. Destructive, privacy-invasive, or high-volume actions require an explicit authorization gate.
10. The agent must preserve an audit trail of decisions, not only HTTP traffic.

## 28A.2 Agent State Machine

```text
SCOPE_RECEIVED
      ↓
SCOPE_PARSED
      ↓
ASSET_DISCOVERY
      ↓
ASSET_NORMALIZATION
      ↓
ATTACK_SURFACE_MODELLED
      ↓
HYPOTHESIS_GENERATED
      ↓
TEST_PLAN_CREATED
      ↓
TEST_EXECUTED
      ↓
OBSERVATION_NORMALIZED
      ↓
DIFFERENTIAL_ANALYSIS
      ├── insufficient evidence → NEW_TEST
      ├── likely false positive → CLOSED_FP
      └── security signal → IMPACT_VALIDATION
                              ↓
                        TRUE_POSITIVE?
                         ├─ no → CLOSED
                         └─ yes
                              ↓
                        MINIMAL_SAFE_POC
                              ↓
                        EVIDENCE_PACKAGE
                              ↓
                        REPORT_DRAFT
                              ↓
                        HUMAN_REVIEW / SUBMISSION
                              ↓
                        RETEST
```

### Terminal states

| State | Meaning |
|---|---|
| `CLOSED_FP` | Evidence strongly supports a false positive. |
| `CLOSED_NO_IMPACT` | Anomalous behavior exists but no meaningful security property was violated. |
| `CLOSED_SCOPE` | Asset or technique is not authorized. |
| `VALIDATED` | Security boundary violation reproduced. |
| `POC_READY` | Minimal safe proof is complete. |
| `REPORT_READY` | Evidence and wording pass quality gates. |
| `RETEST_CONFIRMED` | Previous issue remains reproducible. |
| `RETEST_FIXED` | Previous issue is no longer reproducible under the same test conditions. |

## 28A.3 Scope Object

The agent should transform the program policy into a normalized object before active testing begins.

```yaml
scope:
  program: "example-program"
  allowed_assets:
    domains:
      - "*.example.com"
    applications:
      - "https://app.example.com"
  excluded_assets:
    - "status.example.com"
    - "third-party.example.net"
  excluded_techniques:
    - denial_of_service
    - social_engineering
    - spam
  rate_limit:
    requests_per_second: 2
    burst: 3
  authentication:
    allowed_accounts:
      - account_A
      - account_B
  data_policy:
    use_test_data_only: true
    never_download_bulk_records: true
  safe_testing:
    destructive_actions: false
    external_callbacks: true
```

The agent should refuse to infer authorization from domain ownership alone. Program policy, engagement rules, or written authorization is the authority.

## 28A.4 Investigation Object

```json
{
  "investigation_id": "INV-2026-0001",
  "asset": "https://app.example.com",
  "surface": "REST_API",
  "hypothesis": {
    "class": "broken_access_control",
    "statement": "user A may access object belonging to user B"
  },
  "actors": ["account_A", "account_B"],
  "baseline": [],
  "mutations": [],
  "observations": [],
  "confidence": 0,
  "status": "TESTING",
  "evidence": [],
  "decision_log": []
}
```

## 28A.5 Tool Selection Contract

A tool should be selected because it is the best instrument for the current uncertainty.

```yaml
tool_selection:
  question: "Which endpoints expose parameters worth testing?"
  stage: "attack_surface_mapping"
  preferred_tools:
    - katana
    - gau
    - waybackurls
    - arjun
  fallback_tools:
    - hakrawler
    - ffuf
  output_required:
    - normalized_urls
    - methods
    - parameters
  validation:
    required: true
  safety:
    max_requests_per_host: 500
```

### Selection principles

```text
Choose tool because:
  capability matches hypothesis
  + output is machine-readable
  + operational cost is acceptable
  + target technology is compatible
  + false-positive profile is understood
  + authorization allows the technique
```

Do not choose tools because they are popular, have a large template count, or produce many findings.

## 28A.6 Tool Trust Model

Every external tool and template should have a trust profile.

```yaml
trust_profile:
  source:
    provenance: official_project_or_verified_repository
    version: pinned
  execution:
    sandboxed: true
    network_policy: restricted
  result_quality:
    discovery: high
    confirmation: low
  maintenance:
    last_review: "YYYY-MM-DD"
  agent_policy:
    auto_execute: false
    human_approval_required:
      - destructive
      - credential_testing
      - high_volume
```

### Trust classes

| Class | Meaning | Agent behavior |
|---|---|---|
| T0 | Pure parser/formatter | Auto-use on collected data |
| T1 | Low-risk passive discovery | Auto-use within scope |
| T2 | Active enumeration | Rate-limit and scope-check |
| T3 | Candidate vulnerability testing | Execute only with explicit policy allowance |
| T4 | High-impact validation | Human approval / dedicated lab preferred |
| T5 | Destructive or dangerous | Do not auto-execute against production |

## 28A.7 Observation Normalization

HTTP responses should be converted into structured observations rather than stored only as raw text.

```json
{
  "request": {
    "method": "GET",
    "url_template": "/api/users/{id}",
    "headers_classified": ["authorization", "accept"],
    "body_hash": "..."
  },
  "response": {
    "status": 200,
    "length": 1842,
    "content_type": "application/json",
    "body_hash": "...",
    "headers": {
      "cache_control": "private"
    }
  },
  "side_effects": [],
  "timing_ms": 221,
  "identity": "account_A",
  "timestamp": "..."
}
```

Raw credentials, session tokens, API keys, and personal data should be redacted from the agent's long-term knowledge store.

## 28A.8 Differential Testing Engine

The central analysis primitive is controlled comparison.

### Comparison dimensions

```text
status code
response length
response structure
JSON keys
redirect destination
headers
cache state
cookies
timing distribution
error class
side effects
resource ownership
identity / role
```

### Minimum comparison model

```yaml
differential_test:
  baseline:
    actor: account_A
    request_variant: original
  mutant:
    actor: account_A
    request_variant: object_id_from_account_B
  compare:
    - authorization_result
    - object_identity
    - response_structure
    - side_effects
  decision:
    security_boundary_crossed_if:
      - actor_A_receives_object_B_data
```

The agent should avoid declaring a vulnerability from a single status-code difference. A redirect, generic error, WAF block, CSRF change, or cache variation may explain the signal.

## 28A.9 Evidence Graph

The agent should maintain a graph linking each conclusion to evidence.

```text
Finding F-001
 ├── Hypothesis H-001
 ├── Baseline B-001
 ├── Trigger T-001
 ├── Differential D-001
 ├── Impact I-001
 ├── POC P-001
 └── Evidence E-001..E-006
```

Every report sentence should be traceable to one or more evidence nodes.

## 28A.10 Confidence Scoring

Use confidence as a decision aid, not as a substitute for proof.

```yaml
confidence:
  hypothesis: 0.70
  technical_signal: 0.85
  reproducibility: 1.00
  security_boundary_violation: 1.00
  impact: 0.90
  false_positive_risk: 0.10
```

Suggested interpretation:

| Confidence | Agent action |
|---:|---|
| 0.00–0.29 | Gather more context |
| 0.30–0.59 | Generate additional hypotheses/tests |
| 0.60–0.79 | Differential validation |
| 0.80–0.94 | Impact validation |
| 0.95–1.00 | Report candidate, subject to evidence gate |

Never convert a probability into “confirmed” unless the mandatory validation criteria are satisfied.

## 28A.11 Stop Conditions

The agent should stop active testing when any of the following is true:

```text
1. Vulnerability is sufficiently demonstrated.
2. Further testing would create materially greater impact without improving proof.
3. Testing approaches a destructive boundary.
4. Target data is no longer clearly test data.
5. Scope becomes ambiguous.
6. Rate-limit / availability risk is increasing.
7. Evidence is already sufficient for a report.
```

A strong agent knows when **not** to continue.

---

# 28B. Machine-Readable Vulnerability Playbook Standard

Every vulnerability module in this README should be convertible into the following structure.

```yaml
playbook:
  id: "VULN-ID"
  name: "Human readable name"
  owasp_mapping: []
  cwe_mapping: []
  surfaces: []
  prerequisites: []

  look_for: []
  where_to_look: []

  hypotheses:
    - id: "H-001"
      statement: "..."
      signals: []

  discovery:
    passive: []
    active: []

  test_methodology:
    baseline: []
    mutations: []
    observations: []

  differential_tests: []

  expected_vulnerable_behavior: []
  false_positive_checks: []

  validation_gate:
    must_prove: []
    must_not_rely_only_on: []

  safe_poc:
    objective: "..."
    minimum_action: "..."
    prohibited_actions: []

  impact:
    confidentiality: []
    integrity: []
    availability: []
    business: []

  chaining:
    prerequisites: []
    candidate_links: []

  evidence:
    required: []

  report:
    title_pattern: "..."
    summary: "..."
    remediation: "..."

  retest:
    original_condition: []
    fixed_condition: []
```

This structure should be used for A01–A10 and for cross-cutting classes such as HTTP desync, cache poisoning, OAuth, GraphQL, race conditions, and WebSocket flaws.

---

# 28C. Specialist Playbook Examples

## 28C.1 Broken Access Control / IDOR / BOLA

### What to look for

```text
object identifiers
user IDs
tenant IDs
order IDs
document IDs
UUIDs
numeric database IDs
GraphQL node IDs
download references
admin-only functions
role-specific API routes
```

### Where to look

```text
REST paths
query parameters
JSON bodies
GraphQL variables
WebSocket messages
file download endpoints
export/report functions
mobile API traffic
background-job status endpoints
```

### Test methodology

Use at least two controlled identities where possible.

```text
A1 owns object X
A2 owns object Y

Baseline:
  A1 → X = allowed

Mutation:
  A1 → Y

Compare:
  authorization result
  object identity
  response data
  side effects
```

### Expected vulnerable behavior

The lower-privileged or unrelated identity receives or modifies another identity's object without an authorization decision that should permit it.

### False positives

```text
resource is intentionally public
object belongs to shared organization
backend returns generic metadata only
object identifier is not security-sensitive
response is cached but not actually authorized to the actor
```

### Safe PoC

Demonstrate one controlled cross-account access using test accounts and the smallest object possible. Do not enumerate thousands of IDs.

### Impact

```text
horizontal data access
cross-tenant exposure
unauthorized modification
privilege escalation
financial/business workflow manipulation
```

### Evidence

Capture:

```text
A1 authenticated baseline
A2 owns resource
A1 requests A2 resource
server response
identity context
resource ownership proof
```

### Report wording

Describe **who can access what they should not access, why the authorization layer fails, and the concrete security impact**.

---

## 28C.2 Stored / Reflected / DOM XSS

### What to look for

```text
HTML contexts
attribute contexts
JavaScript contexts
URL contexts
template rendering
client-side sinks
innerHTML / outerHTML
insertAdjacentHTML
eval-like execution paths
postMessage handlers
URL fragment processing
```

### Agent method

```text
1. Find controllable input.
2. Identify reflection/storage location.
3. Identify output encoding.
4. Identify execution context.
5. Determine whether the browser interprets the value as code.
6. Reproduce using a benign proof that establishes script execution without harmful action.
```

### False positives

Reflection alone is not XSS.

```text
escaped HTML
text-only DOM sink
CSP blocks execution
sanitizer transforms content safely
response is never rendered in a browser context
```

### Safe PoC

Use an innocuous browser-execution indicator and avoid credential theft, session exfiltration, destructive actions, or attacks against other users.

### Impact

Tie impact to the vulnerable execution context:

```text
self-XSS
stored XSS affecting privileged reviewers
cross-user session context
administrative workflow compromise
```

The agent should not inflate self-XSS into account takeover without a demonstrated chain.

---

## 28C.3 SSRF

### What to look for

```text
URL fetchers
webhooks
image importers
PDF generators
URL previews
callback URLs
integrations
SSO metadata fetchers
remote file importers
DNS resolution services
```

### Test methodology

Use a controlled callback endpoint whenever possible.

```text
attacker-controlled URL
        ↓
application fetches URL
        ↓
controlled callback observed
        ↓
confirm server-side network access
```

Only after confirming SSRF should the agent reason about internal-address reachability, subject to program policy.

### False positives

```text
client-side request only
browser prefetch
DNS-only lookup without server-side fetch
proxy/WAF-generated callback
image CDN fetching on behalf of the user
```

### Safe PoC

Prefer a unique canary domain/token that proves the server made the request. Avoid accessing real internal services or cloud metadata unless explicitly authorized.

### Evidence

```text
unique callback token
request timestamp
source IP / network metadata if available
application request containing canary
```

---

## 28C.4 HTTP Request Smuggling / Desynchronization

### What to look for

```text
reverse proxy + origin combinations
HTTP/1.1 front-end/backend splits
HTTP/2 downgrades
connection reuse
CL/TE parser disagreement
TE/TE differences
CL.0 behavior
browser-powered desync
web cache interactions
```

PortSwigger's current research explicitly covers browser-powered desync and CL.0 variants in addition to classic parser differential scenarios. See https://portswigger.net/web-security/request-smuggling/browser and https://portswigger.net/web-security/request-smuggling/exploiting.

### Agent methodology

```text
1. Fingerprint front-end and back-end layers.
2. Establish a safe baseline.
3. Determine protocol and connection reuse behavior.
4. Test parser differential hypotheses conservatively.
5. Seek a harmless differential indicator.
6. Validate on a dedicated endpoint or lab-like route where possible.
7. Stop before causing cross-user request corruption.
```

### False positives

```text
network timeout
WAF rejection
single-parser parsing error
connection reset unrelated to desync
inconsistent load-balancer routing
```

### Safe PoC

Use a harmless endpoint and a non-sensitive marker. Do not target login, payment, account-management, or other high-impact routes for persistence or victim interaction.

---

## 28C.5 Race Conditions / TOCTOU

### What to look for

```text
coupon redemption
balance changes
password reset tokens
email changes
invitation acceptance
membership changes
file processing
withdrawals
inventory claims
one-time actions
```

### Agent methodology

```text
Identify invariant:
  "one token can be redeemed once"

Create baseline:
  one request succeeds

Concurrent test:
  small, controlled request set

Observe:
  duplicate success
  inconsistent state
  negative balance
  duplicate resource creation
```

Use the smallest concurrency level necessary. Availability impact is a primary safety boundary.

### Validation gate

A timing difference alone is insufficient. The agent needs a violated state invariant, such as the same single-use action being accepted more than once.

---

## 28C.6 Authentication / Session Failures

### Test dimensions

```text
login state machine
password reset
email verification
MFA enrollment/recovery
session rotation
logout invalidation
remember-me tokens
device trust
OAuth/OIDC transitions
account recovery
rate controls
```

### Differential method

Compare the same action across:

```text
unauthenticated
authenticated user A
authenticated user B
expired session
revoked session
wrong step in workflow
```

Do not infer authentication bypass from a successful response unless the protected resource or action is actually reached.

---

## 28C.7 GraphQL

### Test surfaces

```text
schema discovery
queries
mutations
aliases
fragments
variables
nested resolvers
batching
field-level authorization
introspection configuration
persisted queries
subscriptions
```

### High-value hypothesis

```text
UI blocks field X
BUT
API resolver accepts field X
```

The agent should compare authorization at the **resolver/field level**, not merely at the endpoint level.

---

## 28C.8 OAuth / OIDC / SSO

### Test surfaces

```text
authorization endpoint
redirect URI handling
state
nonce
PKCE
client identity
response mode
token exchange
account linking
login CSRF
identity provider switching
logout
```

The agent should model the trust relationship between relying party, authorization server, browser, and identity provider rather than treating OAuth as a collection of parameters.

---

## 28C.9 Web Cache Poisoning / Cache Deception

### Test methodology

```text
1. Identify cache boundary.
2. Determine cache key dimensions.
3. Determine which attacker-controlled headers/parameters affect response.
4. Establish an isolated harmless cache marker.
5. Request the victim-facing cache key.
6. Check whether the marker persists for subsequent requests.
```

### Validation rule

A different response for the tester is not enough. The agent should establish **cache persistence or incorrect reuse across requests**.

---

# 28D. Agent Tool Registry — Selection by Function

The following registry is intentionally role-based. Tool availability, licensing, project health, and target compatibility must be verified before deployment.

## Discovery / Asset Enumeration

| Tool | Primary role | Typical agent stage | Validation |
|---|---|---|---|
| Amass | asset discovery / graph-based enumeration | recon | DNS/HTTP confirmation |
| Subfinder | passive subdomain discovery | recon | DNS resolution + HTTP probe |
| Findomain | subdomain discovery | recon | DNS/HTTP confirmation |
| Assetfinder | lightweight asset discovery | recon | DNS/HTTP confirmation |
| Chaos | ProjectDiscovery dataset-based discovery | recon | scope + freshness check |
| crt.sh | certificate transparency discovery | recon | DNS confirmation |
| SecurityTrails | DNS / historical intelligence | OSINT | ownership confirmation |
| Censys | host/certificate intelligence | OSINT | scope confirmation |
| Shodan | internet-exposed service discovery | OSINT | target ownership + freshness |
| ZoomEye | exposure discovery | OSINT | scope confirmation |
| Netlas | internet asset intelligence | OSINT | scope confirmation |

## DNS / Network

| Tool | Role | Agent use |
|---|---|---|
| dnsx | DNS resolution / records | normalize assets |
| MassDNS | high-speed DNS resolution | large inventories with strict rate controls |
| puredns | mass DNS resolution / brute-force workflow | candidate validation |
| Naabu | port discovery | service discovery |
| Nmap | service/version/protocol enumeration | targeted service validation |
| Masscan | very high-speed port discovery | controlled scope with explicit rate limits |
| RustScan | fast port discovery | candidate port confirmation |

## HTTP Probing / Crawling

| Tool | Role | Agent use |
|---|---|---|
| httpx | HTTP probing / metadata | normalize live web surface |
| Katana | crawling / endpoint discovery | application mapping |
| Hakrawler | lightweight crawling | fallback discovery |
| gau | historical URL discovery | passive endpoint hypotheses |
| waybackurls | historical URL collection | legacy attack surface |
| gospider | crawler | link/JS discovery |
| Feroxbuster | content discovery | hidden paths / files |
| ffuf | directory/parameter/vhost fuzzing | controlled active discovery |
| dirsearch | content discovery | alternative enumeration |

## Parameter / Endpoint Discovery

| Tool | Role | Agent stage |
|---|---|---|
| Arjun | HTTP parameter discovery | input-surface mapping |
| ParamSpider | parameterized URL discovery | passive + active hypothesis generation |
| x8 | hidden parameter discovery | differential testing |
| Kiterunner | API route discovery | API surface mapping |
| LinkFinder | JS endpoint extraction | client-side recon |
| SecretFinder | client-side secret candidate discovery | JS review |
| Retire.js | vulnerable JS component detection | client-side dependency review |

## Fuzzing / Mutation

| Tool | Role | Agent use |
|---|---|---|
| ffuf | HTTP fuzzing | endpoint/parameter hypotheses |
| wfuzz | request fuzzing | legacy/advanced fuzzing workflows |
| boofuzz | protocol fuzzing | non-HTTP protocol research |
| radamsa | mutation-based fuzzing | parser robustness in owned/lab targets |
| AFL++ | coverage-guided native fuzzing | source/native components |
| libFuzzer | in-process fuzzing | parser/library validation |
| Jazzer | JVM fuzzing | Java parser/component testing |
| Atheris | Python fuzzing | Python parser/component testing |

## Proxy / Interactive Web Testing

| Tool | Role | Agent integration |
|---|---|---|
| Burp Suite | interception, repeater, scanner, extensions | primary interactive layer |
| OWASP ZAP | proxy/scanning/automation | programmable alternative |
| mitmproxy | programmable interception | Python-based automation |
| Caido | modern web proxy workflow | manual/API investigation |

Burp extensions should be treated as third-party code and pinned/reviewed before agent execution. PortSwigger's current extension documentation is centered on the Montoya API. See https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/tutorials.

## Vulnerability Candidate Generation

| Tool | Primary specialization |
|---|---|
| Nuclei | template-driven detection |
| Nikto | web server checks |
| ZAP | automated web checks |
| OpenVAS / Greenbone | broader vulnerability assessment |
| Nessus | infrastructure / vulnerability assessment |
| Nuclei templates | reusable detection logic |

### Agent rule

```text
Scanner result
    ↓
Candidate
    ↓
Reproduce manually / independently
    ↓
Differential validation
    ↓
Impact validation
```

Never report a scanner result verbatim.

## SQL / Database Injection

| Tool | Role |
|---|---|
| SQLmap | automated SQL injection assessment |
| Ghauri | SQL injection testing |
| NoSQLMap | NoSQL injection testing |
| nosqli | NoSQL injection research |
| Commix | command injection candidate testing |

Use automation only after the parameter and application behavior are understood. Avoid uncontrolled extraction against real data.

## XSS / Client-Side Security

| Tool | Role |
|---|---|
| Dalfox | XSS parameter analysis |
| XSStrike | XSS discovery / analysis |
| kxss | reflected parameter candidate identification |
| DOM Invader | browser-assisted DOM XSS investigation |
| Semgrep | source-level client-side pattern discovery |

## SSRF / OAST

| Tool | Role |
|---|---|
| Interactsh | controlled out-of-band callbacks |
| Burp Collaborator | OAST callback infrastructure |
| Canarytokens | controlled interaction indicators |
| webhook.site | simple controlled HTTP callback testing |

Use unique per-test tokens to correlate callbacks. Do not use third-party callback endpoints that expose sensitive headers or request content without understanding their retention policy.

## HTTP Desync / Request Smuggling

| Tool / capability | Specialization |
|---|---|
| Burp HTTP Request Smuggler | desync research and detection |
| custom raw HTTP harness | controlled parser-differential experiments |
| HTTP/2-capable client | protocol downgrade / H2 testing |
| browser-powered desync workflow | browser-realistic connection-state testing |

Current PortSwigger research explicitly documents browser-powered desync and CL.0 techniques, so an agent should not restrict its model to classic CL.TE / TE.CL terminology.

## API / GraphQL

| Tool | Specialization |
|---|---|
| InQL | GraphQL discovery/testing |
| Clairvoyance | GraphQL schema inference research |
| Kiterunner | API route discovery |
| Postman | API workflow modeling |
| Insomnia | API testing |
| GraphQL Voyager | schema visualization |

## Authorization / Access Control

| Tool | Specialization |
|---|---|
| Burp Autorize | authorization differential testing |
| AuthMatrix | authorization matrix testing |
| Burp Repeater | manual identity/object mutation |
| custom request harness | multi-account differential testing |

These are most useful when combined with a structured identity/object matrix rather than run as isolated scanners.

## Secrets / Credentials / Supply Chain

| Tool | Role |
|---|---|
| Gitleaks | secrets in git/content |
| TruffleHog | secret discovery and verification |
| GitGuardian | secret detection / monitoring |
| detect-secrets | secret scanning |
| Semgrep | code/dataflow security patterns |
| Semgrep Supply Chain | dependency/SCA analysis |
| osv-scanner | open-source vulnerability analysis |
| Syft | SBOM generation |
| Grype | vulnerability scanning against SBOM/filesystems |
| Trivy | container/filesystem/IaC/dependency security |
| Snyk CLI | dependency/container/IaC analysis |

## Static Analysis / Code Security

| Tool | Primary strength |
|---|---|
| Semgrep | developer-friendly code/dataflow rules |
| CodeQL | deep semantic code analysis |
| Joern | code property graph analysis |
| Semgrep Assistant / platform workflows | triage and rule-assisted analysis |
| Bearer | sensitive-data and application security analysis |
| SonarQube | code quality + security patterns |

## Cloud Security

| Tool | Role |
|---|---|
| Prowler | AWS/Azure/GCP cloud security assessment |
| ScoutSuite | multi-cloud posture assessment |
| Pacu | AWS security testing framework |
| CloudFox | cloud attack-surface and identity analysis |
| Steampipe | SQL-like cloud inventory/querying |
| Cartography | infrastructure/relationship graphing |
| kube-bench | Kubernetes CIS benchmark assessment |
| kube-hunter | Kubernetes security assessment |
| Falco | runtime security monitoring |

Cloud tools should only be used against explicitly authorized cloud tenants/accounts. Never infer that an exposed cloud identifier authorizes access.

## Containers / Kubernetes

| Tool | Role |
|---|---|
| Trivy | image/filesystem/IaC scanning |
| Syft | SBOM generation |
| Grype | SBOM/image vulnerability matching |
| Dockle | container image audit |
| kube-bench | Kubernetes benchmark checks |
| kube-hunter | Kubernetes exposure testing |
| Kubescape | Kubernetes posture / policy analysis |

## Windows / Active Directory / Enterprise Identity

These tools belong in a separate authorized enterprise-testing mode rather than a normal public web bounty profile.

| Tool | Specialization |
|---|---|
| BloodHound | identity / relationship graphing |
| NetExec | network/Windows enumeration |
| Impacket | Windows protocol tooling |
| Certipy | AD CS security assessment |
| Responder | name-resolution / credential exposure research |
| ldapsearch | LDAP queries |
| CrackMapExec successor workflows | enterprise enumeration |

The agent should default these to **T4/T5** handling because credential capture, relay, lateral movement, and persistence can rapidly become high impact.

## Mobile / Client Applications

| Tool | Role |
|---|---|
| MobSF | mobile application security assessment |
| jadx | Android decompilation |
| apktool | Android resource/smali analysis |
| Frida | dynamic instrumentation |
| Objection | mobile runtime exploration |
| mitmproxy | mobile traffic analysis |

Only apply mobile tooling where the program explicitly includes the relevant mobile application and testing activity.

## Browser Automation / Application Behavior

| Tool / framework | Role |
|---|---|
| Playwright | deterministic browser workflows |
| Selenium | browser automation |
| Puppeteer | Chromium automation |
| Chrome DevTools Protocol | browser instrumentation |
| DOM Invader | DOM XSS research |
| browser network logs | client-side request graphing |

The agent should prefer browser automation when the vulnerability depends on DOM state, service workers, redirects, client-side authorization assumptions, or browser-only protocol behavior.

## Evidence / Reproduction

| Tool | Role |
|---|---|
| curl | deterministic HTTP reproduction |
| HTTPie | human-readable API reproduction |
| jq | structured JSON extraction |
| yq | YAML/structured data processing |
| Wireshark | packet/protocol evidence |
| tcpdump | packet capture |
| mitmproxy flows | request/response evidence |
| Burp project files | reproducible HTTP evidence |

---

# 28E. Tool Selection Matrix

The agent should select the narrowest useful toolchain.

| Goal | Primary | Secondary | Confirmation |
|---|---|---|---|
| Subdomain discovery | Subfinder / Amass | Findomain / CT logs | DNSx + HTTPx |
| Live web inventory | HTTPx | Nmap | curl/browser |
| Endpoint discovery | Katana | gau / Wayback | Burp/curl |
| Hidden paths | ffuf | Feroxbuster | manual request |
| Hidden parameters | Arjun / x8 | ParamSpider | manual differential |
| XSS candidates | Dalfox | XSStrike / DOM Invader | browser PoC |
| SQLi candidate | SQLmap | Ghauri | manual controlled differential |
| SSRF | Interactsh | Collaborator | unique callback |
| Authorization | Autorize/AuthMatrix | Repeater | two-account proof |
| GraphQL | InQL | Clairvoyance | manual resolver test |
| Desync | HTTP Request Smuggler | custom harness | harmless differential |
| Cache | Burp + custom requests | browser | cache persistence proof |
| Secrets | Gitleaks/TruffleHog | GitHub search | validity/permission check |
| SCA | osv-scanner/Grype/Trivy | Semgrep | affected-component validation |
| Cloud posture | Prowler | ScoutSuite | provider-native confirmation |
| Code semantics | CodeQL | Semgrep/Joern | source/dataflow review |

The agent should prefer a **small complementary stack** over redundant scanning.

---

# 28F. Research-to-Agent Knowledge Pipeline

Public reports, POCs, write-ups, advisories, and research should become structured knowledge rather than copied payload collections.

```text
SOURCE
  ↓
AUTHENTICITY CHECK
  ↓
NORMALIZE
  ↓
EXTRACT PRIMITIVE
  ↓
IDENTIFY PRECONDITIONS
  ↓
MODEL TRUST BOUNDARY
  ↓
CREATE HYPOTHESES
  ↓
BUILD SAFE TEST
  ↓
TEST IN AUTHORIZED TARGET / LAB
  ↓
VALIDATE
  ↓
UPDATE KNOWLEDGE CARD
```

## Research Card

```yaml
research_card:
  id: "RC-0001"
  source_type: "public_report"
  source_url: "https://example.invalid/report"
  source_date: "YYYY-MM-DD"
  vulnerability_class: "..."
  primitive: "parser_confusion"
  affected_component: "reverse-proxy"
  preconditions: []
  observable_signals: []
  variants: []
  false_positives: []
  safe_validation: []
  impact_model: []
  related_tools: []
  confidence: "medium"
  last_verified: "YYYY-MM-DD"
```

### Source-quality ranking

```text
Tier 1
  vendor advisory
  official project documentation
  reproducible primary research
  accepted/verified bounty disclosure

Tier 2
  high-quality technical write-up with reproduction
  trusted conference research
  established security research blog

Tier 3
  secondary summaries
  social-media posts
  unverified POCs
  copied exploit repositories
```

Do not train an agent's operational assumptions from Tier 3 material without independent verification.

---

# 28G. Finding Validation Gate

A finding should pass all applicable gates before it becomes reportable.

```text
[G1] In Scope?
  ↓ yes
[G2] Reproducible?
  ↓ yes
[G3] Security Boundary Violated?
  ↓ yes
[G4] False Positive Explanations Eliminated?
  ↓ yes
[G5] Concrete Impact?
  ↓ yes
[G6] Minimum Safe PoC Exists?
  ↓ yes
[G7] Evidence Package Complete?
  ↓ yes
[G8] Duplicate / Known Issue Check?
  ↓ yes
REPORTABLE
```

### Evidence gate

```yaml
evidence_gate:
  scope_proof: required
  baseline: required
  trigger: required
  affected_behavior: required
  impact: required
  reproduction_steps: required
  timestamps: recommended
  screenshots: optional
  raw_http: recommended
  sensitive_data: minimized
```

### Not enough

```text
"Nuclei says vulnerable"
"Response was 500"
"Header reflected my input"
"CORS header exists"
"Endpoint returned 200"
"Token is long"
"There is a version number matching a CVE"
```

Each of these is a **signal** that requires context and validation.

---

# 28H. Safe POC Construction Standard

A good POC should prove the vulnerability while minimizing harm.

## POC ladder

```text
Level 0 — observation
Level 1 — controlled input reflection / behavior change
Level 2 — controlled security-boundary violation
Level 3 — controlled business impact using test data
Level 4 — chain demonstrating additional impact
```

Stop at the lowest level that conclusively establishes severity.

### POC requirements

```yaml
poc:
  scope: confirmed
  target: exact
  prerequisites: []
  setup: []
  steps: []
  expected: "..."
  actual: "..."
  evidence: []
  cleanup: []
  safety_notes: []
```

Never include real credentials, private keys, customer records, or unnecessary secret material in the report.

---

# 28I. Chain Discovery Without Over-Exploitation

The agent may reason about chains as a graph of trust-boundary changes.

```text
weak primitive
   ↓
new capability
   ↓
new access
   ↓
new trust boundary
   ↓
business impact
```

Examples:

```text
IDOR
  + sensitive export endpoint
  → cross-user disclosure

XSS
  + privileged review workflow
  → privileged action execution

SSRF
  + internal administrative service
  → server-side trust-boundary expansion

OAuth account-linking flaw
  + weak identity binding
  → account takeover path

request desynchronization
  + cache interaction
  → persistent response manipulation

race condition
  + single-use business action
  → state invariant violation
```

The agent should **demonstrate only the minimum portion of the chain required to prove the security impact**.

---

# 28J. Report Generation Schema

```yaml
report:
  title: "[Vulnerability] in [component] allows [impact]"
  severity:
    rationale: "..."
  asset: "..."
  summary: "..."
  root_cause: "..."
  prerequisites: []
  reproduction:
    - step: 1
      action: "..."
      evidence: "..."
  expected_behavior: "..."
  actual_behavior: "..."
  impact: "..."
  safe_poc: "..."
  remediation: "..."
  evidence:
    - id: "E-001"
      description: "..."
  retest_plan: "..."
```

### Title rule

A title should describe **vulnerability + affected component + consequence**.

Bad:

```text
IDOR found
```

Better:

```text
Cross-tenant authorization bypass in invoice API exposes another customer's invoice metadata
```

### Impact rule

Do not write:

```text
"This could be critical."
```

Write what was actually demonstrated:

```text
"Account A, without authorization, can retrieve account B's invoice metadata by changing the invoice identifier in the API request."
```

---

# 28K. Retest / Regression Model

Every validated finding should produce a retest specification.

```yaml
retest:
  finding_id: "F-001"
  original_endpoint: "..."
  original_prerequisites: []
  original_trigger: "..."
  expected_fixed_behavior: "request rejected / object inaccessible"
  regression_steps: []
  residual_risk_questions:
    - "same bug through alternate API route?"
    - "same issue through mobile client?"
    - "same authorization gap through GraphQL?"
```

A fix on one route should not automatically be assumed to fix the underlying authorization rule.

---

# 28L. AI Safety and Scope Guardrails

AI agents are especially vulnerable to over-testing because they can generate requests faster than a human can review them.

### Mandatory controls

```text
scope allow-list
request budget
per-host concurrency limit
per-endpoint mutation budget
credential isolation
secret redaction
PII minimization
high-impact action blocklist
human approval for T4/T5 techniques
full audit logging
automatic stop conditions
```

### Examples of default-blocked production actions

```text
mass password guessing
credential stuffing
mail bombing
bulk record extraction
destructive uploads
file deletion
service disruption
large-scale queue flooding
financial transaction execution
real-user session hijacking
```

The agent may discuss these categories conceptually or operate against purpose-built labs where the activity is authorized.

---

# 28M. Recommended Agent Architecture

```text
                ┌──────────────────────┐
                │   Scope / Policy     │
                └──────────┬───────────┘
                           ↓
                ┌──────────────────────┐
                │ Attack-Surface Model │
                └──────────┬───────────┘
                           ↓
                ┌──────────────────────┐
                │ Hypothesis Generator │
                └──────────┬───────────┘
                           ↓
        ┌──────────────────┴──────────────────┐
        ↓                                     ↓
┌───────────────┐                     ┌────────────────┐
│ Tool Selector │                     │ Manual Logic  │
└───────┬───────┘                     └───────┬────────┘
        └──────────────────┬──────────────────┘
                           ↓
                ┌──────────────────────┐
                │ Test Executor       │
                └──────────┬───────────┘
                           ↓
                ┌──────────────────────┐
                │ Observation Store   │
                └──────────┬───────────┘
                           ↓
                ┌──────────────────────┐
                │ Differential Engine │
                └──────────┬───────────┘
                           ↓
                ┌──────────────────────┐
                │ Validation Engine   │
                └──────────┬───────────┘
                           ↓
           ┌───────────────┴────────────────┐
           ↓                                ↓
┌─────────────────────┐          ┌──────────────────────┐
│ Safe POC Generator  │          │ False-Positive Gate │
└──────────┬──────────┘          └──────────────────────┘
           ↓
┌──────────────────────┐
│ Evidence Graph       │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Report Generator     │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Retest / Regression  │
└──────────────────────┘
```

## Recommended data stores

```text
asset_inventory
endpoint_inventory
request_response_store
hypothesis_store
research_cards
finding_store
evidence_graph
report_store
retest_store
policy_store
```

## Recommended interfaces

```text
HTTP client
browser automation
DNS resolver
OAST callback client
source-code analyzer
Git repository reader
cloud inventory reader
structured evidence writer
report renderer
```

Use a consistent interface so a new security tool can be swapped into the agent without rewriting the reasoning layer.

---

# 28N. Agent Quality Metrics

Measure the agent with metrics that reward correctness.

```text
candidate → validated conversion rate
validated → accepted conversion rate
false-positive rate
duplicate rate
mean requests per validated finding
mean time to validation
coverage of attack-surface classes
percentage of findings with complete evidence
retest accuracy
scope violations
high-impact action prevented
```

A lower raw finding count can represent a **better** agent if validation precision improves substantially.

---

# 28O. Lab-First Development Strategy

Before allowing a new agent capability on real targets, test it on controlled applications.

Recommended intentionally vulnerable training targets include:

- OWASP Juice Shop
- OWASP WebGoat
- OWASP Mutillidae II
- PortSwigger Web Security Academy labs
- custom applications designed around the agent's target hypothesis

OWASP describes Juice Shop as an intentionally insecure application covering the OWASP Top 10 and many additional real-world flaws.

A lab benchmark should measure whether the agent can:

```text
1. find the vulnerability
2. distinguish it from similar behavior
3. produce a minimal safe POC
4. explain the root cause
5. state the exact impact
6. produce reproducible evidence
7. avoid unnecessary exploitation
```

The current OWASP WSTG explicitly organizes testing around information gathering, configuration/deployment, identity, authentication, authorization, session management, input validation, error handling, cryptography, business logic, client-side testing, and API testing, making it a useful backbone for these agent benchmarks.

---

# 28P. Operating Principle for Autonomous Security Research

The agent should reason in this order:

```text
What is in scope?
        ↓
What does the application expose?
        ↓
What trust boundaries exist?
        ↓
What assumptions does the application make?
        ↓
Which assumption could be false?
        ↓
What observation would distinguish the hypotheses?
        ↓
What is the lowest-risk test that can produce that observation?
        ↓
Did the test reproduce the security property violation?
        ↓
What is the minimum evidence needed?
        ↓
Stop.
```

This is the central operating philosophy of the AI bug-bounty agent.

> **Do not maximize exploitation. Maximize justified knowledge.**

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

**Guide version:** 2026-08-16

**Primary taxonomy:** OWASP Top 10:2025

**Companion references:** OWASP API Security Top 10:2023, OWASP ASVS 5.0, OWASP WSTG, current web-security research.

---

# 35. The Final AI-Agent Architecture

This repository is designed as a **human-readable security specification plus a machine-readable execution layer**.

The README answers *why* and *what*. The companion schemas and playbooks answer *how the agent represents and validates the work*.

The canonical package layout is:

```text
ai-bug-bounty-agent/
├── README.md
├── schemas/
│   ├── scope.schema.json
│   ├── tool.schema.json
│   ├── test-case.schema.json
│   ├── evidence.schema.json
│   ├── finding.schema.json
│   ├── report.schema.json
│   ├── retest.schema.json
│   ├── playbook.schema.json
│   └── research-card.schema.json
├── playbooks/
│   └── core.yaml
├── tools/
│   └── tools.yaml
├── policies/
│   └── safety.yaml
├── benchmarks/
│   └── benchmark.yaml
├── templates/
└── agent-workflow.md
```

The agent should treat the schemas as contracts. A malformed finding, incomplete evidence bundle, or finding without validation evidence should fail validation before it can enter the reporting state.

## 35.1 Agent state machine

```text
SCOPE_CONFIRMED
      |
      v
ASSET_INVENTORY
      |
      v
ATTACK_SURFACE_MODEL
      |
      v
HYPOTHESIS_GENERATED
      |
      v
TEST_PLANNED
      |
      v
TESTING
      |
      v
OBSERVATION_CAPTURED
      |
      v
DIFFERENTIAL_ANALYSIS
      |
      +----> FALSE_POSITIVE / REJECTED
      |
      v
VALIDATION_GATE
      |
      +----> REJECTED / NEEDS_MORE_EVIDENCE
      |
      v
VALIDATED
      |
      v
IMPACT_VALIDATED
      |
      v
POC_READY
      |
      v
EVIDENCE_READY
      |
      v
REPORT_READY
      |
      v
REPORTED
      |
      v
RETESTED
```

The agent must never jump directly from `scanner alert` to `report ready`.

## 35.2 Agent invariants

The following properties must hold throughout the workflow:

1. **Scope invariant:** every active request maps to a currently authorized asset and permitted test class.
2. **Evidence invariant:** every material claim has corresponding evidence.
3. **Attribution invariant:** the observed effect must be attributable to the tested input and not merely coincidental.
4. **Boundary invariant:** a confirmed vulnerability requires a broken security property or trust boundary.
5. **Reproducibility invariant:** a finding should be repeatable unless the vulnerability class is inherently non-deterministic and the evidence establishes that fact.
6. **Minimal-impact invariant:** once sufficient proof exists, the agent stops escalating the PoC.
7. **Data-minimization invariant:** collect the minimum amount of production data required to prove the issue.

---

# 36. Machine-Readable Contract Layer

The schemas in `schemas/` are the authoritative data contracts for an implementation.

## 36.1 Scope contract

`scope.schema.json` represents program rules, allowed assets, exclusions, rate limits, credentials, and prohibited actions.

The agent should refuse active testing when any of the following is unresolved:

```text
asset authorization = unknown
program policy = unknown
credential ownership = unknown
high-risk operation permission = unknown
```

## 36.2 Test-case contract

Every active test should have:

```yaml
- test_id
- hypothesis
- target
- tool
- baseline
- mutation
- expected_observation
- false_positive_checks
- stop_conditions
- risk
```

This makes every request explainable before it is sent.

## 36.3 Observation contract

An observation is not a finding. It is a fact captured from the system:

```yaml
observation:
  timestamp: "2026-08-16T07:00:00+05:30"
  request_ref: "req-001"
  response_ref: "resp-001"
  status_code: 403
  response_length: 421
  selected_headers:
    cache-control: "private"
  normalized_fingerprint: "..."
  notes:
    - "No object data returned"
```

The agent should preserve raw evidence where permitted, while storing normalized features for differential reasoning.

## 36.4 Finding contract

A finding contains a hypothesis, validation state, evidence, impact, and report data. Its critical status field is one of:

```text
candidate
 testing
 validated
 rejected
 duplicate
 reported
 retested
```

Only `validated` or later states may be treated as confirmed vulnerability findings.

## 36.5 Evidence contract

The evidence chain should record the causal sequence:

```text
baseline
  -> mutation
  -> observation
  -> differential
  -> security-boundary violation
  -> impact confirmation
```

A screenshot without a causal chain is weak evidence. A scanner alert without reproducibility is weak evidence. A successful payload without impact is often incomplete evidence.

---

# 37. Hypothesis Engine

The agent should not generate hypotheses from vulnerability names alone. It should derive them from **observable application properties**.

### Inputs to the hypothesis engine

- asset type
- endpoint structure
- authentication state
- user roles
- identifiers
- HTTP methods
- content types
- parser boundaries
- technology fingerprints
- state transitions
- historical URLs
- client-side sinks
- API schemas
- error behavior
- cache behavior
- trust relationships

### Hypothesis generation rules

For each surface, generate a small ranked set rather than hundreds of unstructured tests.

```text
Observation:
  Endpoint accepts `user_id` and returns account-specific JSON.

Hypotheses:
  H1 = horizontal authorization bypass
  H2 = intentionally public API
  H3 = server-side cache confusion
  H4 = stale data from a shared cache

Best first test:
  Compare two controlled principals using the minimum identifier mutation.
```

The hypothesis engine should record why each hypothesis was generated:

```yaml
hypothesis:
  id: H-001
  type: horizontal_access_control_bypass
  signal:
    - user_controlled_object_id
    - authenticated_endpoint
  confidence: 0.62
  cheapest_discriminating_test: T-001
```

The preferred test is the one that **most efficiently distinguishes competing explanations while minimizing risk**.

---

# 38. Differential Testing Engine

Differential analysis is one of the most important capabilities for an AI bug-bounty agent.

The agent should compare:

```text
baseline vs mutation
principal A vs principal B
role low vs role high
valid identifier vs invalid identifier
fresh request vs cached request
HTTP/1.1 vs HTTP/2 where permitted
before state transition vs after state transition
sequential vs concurrent
browser navigation vs direct request
```

### 38.1 Comparison dimensions

At minimum compare:

- status code
- response body
- normalized response body
- content type
- important headers
- cookies
- redirects
- response length
- timing ranges
- cache headers
- authentication context
- object ownership
- server-side side effects

### 38.2 Avoiding naive diffs

The agent must normalize dynamic fields before concluding that two responses differ.

Possible dynamic fields include:

```text
request IDs
CSRF tokens
timestamps
nonce values
session identifiers
tracking IDs
randomized JSON fields
analytics markup
```

A useful differential engine should maintain:

```yaml
comparison:
  raw_difference_score: 0.74
  normalized_difference_score: 0.31
  semantic_difference:
    authorization_state_changed: true
    object_owner_changed: false
    protected_data_exposed: true
```

The goal is **semantic difference**, not merely byte difference.

---

# 39. True-Positive Gate 2.0

A scanner finding becomes a confirmed vulnerability only after passing all required gates.

```text
GATE 0  Scope confirmed
GATE 1  Target exists
GATE 2  Hypothesis has a plausible security property
GATE 3  Baseline captured
GATE 4  Controlled mutation performed
GATE 5  Differential signal observed
GATE 6  Security-boundary violation demonstrated
GATE 7  False-positive explanations tested
GATE 8  Reproduction confirmed
GATE 9  Impact established
GATE 10 Minimal safe PoC produced
GATE 11 Evidence complete
GATE 12 Report claim <= evidence
```

If a gate fails, status returns to `candidate`, `needs_more_evidence`, or `rejected`.

### 39.1 Confidence model

A useful implementation can combine:

```text
confidence =
  reproducibility
  × attribution
  × boundary_violation
  × evidence_quality
  × impact_certainty
  − false_positive_risk
```

Do not expose a fake precision score such as `97.4% vulnerability confidence` unless the model is calibrated against benchmark data.

---

# 40. Safe POC Ladder

The POC should escalate only as far as necessary.

```text
Level 0: passive evidence
Level 1: harmless reflection / marker
Level 2: researcher-controlled data access
Level 3: controlled authorization boundary violation
Level 4: controlled state change
Level 5: high-impact demonstration only when explicitly allowed
```

The default stopping condition is:

> **Once the security boundary and realistic impact are established, stop.**

Examples:

### SSRF

Prove server-side reachability with a unique researcher-controlled OAST interaction before considering deeper internal access.

### IDOR/BOLA

Use two controlled accounts and synthetic objects instead of downloading real customer records.

### Stored XSS

Use a researcher-owned account/content item and a harmless execution marker.

### Race conditions

Use synthetic resources and measure a controlled state invariant rather than testing against real payments or irreversible actions.

### Request desynchronization

Prefer a lab or explicit program allowance and stop after a deterministic harmless canary demonstrates parser disagreement.

---

# 41. Research Intelligence System

The agent should learn from public research without turning reports into payload-copying exercises.

## 41.1 Research-source classes

```text
HackerOne reports
Bugcrowd disclosures
Google Bug Hunters reports
PortSwigger research
OWASP projects
CVE / CWE / advisories
vendor security advisories
GitHub Security Lab
ProjectDiscovery research
conference papers
security blogs
capture-the-flag write-ups
public PoCs
```

## 41.2 Research-card extraction

Every useful source becomes a normalized research card:

```yaml
source:
claim:
primitive:
preconditions:
observable_signal:
validation_strategy:
transferable_architectures:
false_positive_risks:
limitations:
```

The important question is not:

> “What payload did the researcher use?”

It is:

> “What invariant, parser assumption, trust relationship, or state transition made the bug possible?”

## 41.3 Research deduplication

Two reports describing different payloads may represent the same underlying primitive.

The research engine should cluster by:

```text
root cause
trust boundary
parser behavior
state invariant
authorization model
protocol semantics
impact mechanism
```

This prevents the knowledge base from becoming a giant collection of duplicate payloads.

---

# 42. Vulnerability Coverage Matrix

The final agent should treat the following as a minimum coverage set.

| Family | Core coverage | Modern extensions |
|---|---|---|
| Access control | IDOR/BOLA, BFLA, privilege escalation | multi-tenant isolation, GraphQL resolver auth, object traversal |
| Authentication | login, sessions, recovery | MFA, OAuth/OIDC, SAML, account linking, token confusion |
| Injection | SQLi, XSS, command injection | SSTI, NoSQL, LDAP, XPath, expression languages, header injection |
| SSRF | direct/blind SSRF | parser differentials, redirect handling, cloud metadata |
| File handling | upload validation | parser chains, archive extraction, transformation pipelines |
| Business logic | workflow abuse | concurrency, state machines, pricing, quotas, invitations |
| Client-side | DOM XSS | postMessage, XS-Leaks, DOM clobbering, service workers, CSP |
| API | REST | GraphQL, gRPC, webhooks, versioning, mass assignment |
| Protocol | HTTP/1.1 | HTTP/2, HTTP/3, h2c, connection reuse, desync |
| Caching | cache poisoning | cache deception, key normalization, CDN/origin divergence |
| Data integrity | unsafe deserialization | signed data confusion, webhook trust, update mechanisms |
| Supply chain | dependency exposure | CI/CD actions, build provenance, package confusion |
| Cloud | exposed storage | IAM paths, workload identity, metadata, serverless boundaries |
| Infrastructure | exposed services | Kubernetes, ingress/controller boundaries, service mesh |
| CMS | plugin/theme flaws | supply-chain and abandoned component analysis |

---

# 43. Architecture-Aware Testing

The agent must classify the application architecture before selecting playbooks.

## SPA / modern frontend

Prioritize:

```text
API authorization
client-side routing assumptions
DOM sinks
postMessage
service workers
OAuth/OIDC
GraphQL
WebSockets
```

## API-first backend

Prioritize:

```text
BOLA/BFLA
mass assignment
schema/version drift
rate limits
JWT/OAuth
webhooks
GraphQL/gRPC
```

## Microservices

Prioritize:

```text
service-to-service authorization
identity propagation
host routing
SSRF
internal APIs
header trust
cache boundaries
message queues
```

## Cloud/serverless

Prioritize:

```text
SSRF
metadata/identity boundaries
storage policies
function invocation
API gateways
IAM
secrets
build/deploy trust
```

## CDN/WAF/reverse-proxy stack

Prioritize:

```text
cache behavior
host routing
request normalization
HTTP desync
header trust
origin exposure
```

---

# 44. Tool Selection as a Planning Problem

The agent should choose the next tool based on the current information gap.

```yaml
question: "What public endpoints exist?"
preferred_tools:
  - gau
  - waybackurls
  - katana

question: "Which discovered hosts actually speak HTTP?"
preferred_tools:
  - httpx

question: "Which hidden parameters may influence authorization?"
preferred_tools:
  - arjun
  - x8

question: "Is this blind callback behavior server-side?"
preferred_tools:
  - interactsh

question: "Could a reflection be executable?"
preferred_tools:
  - browser_manual_testing
  - burp_suite
  - dalfox

question: "Is this scanner result a real authorization violation?"
preferred_tools:
  - burp_suite
  - autorize
  - authmatrix

question: "Are front-end and back-end HTTP parsers disagreeing?"
preferred_tools:
  - http_request_smuggler
  - smuggler
  - controlled_manual_analysis
```

The agent should not run five overlapping tools when one tool plus a manual validation step answers the question more safely.

---

# 45. Tool Trust and Maintenance

Security tooling changes continuously. The agent must not assume a tool is current merely because it is well known.

Each tool record should track:

```yaml
version_checked:
source_of_truth:
maintenance_status:
license:
known_limitations:
validation_required:
```

A current example is useful: Gitleaks remains a widely used secret scanner, but its project currently states that it is feature-complete and that new feature work is shifting to Betterleaks. Therefore an agent's tool registry should preserve **capability + maintenance status**, not merely the tool name. citeturn864775search1turn864775search6

Likewise, Interactsh is designed specifically for out-of-band interaction detection and supports HTTP(S), DNS, SMTP(S), LDAP and other interaction paths, making it a natural OAST component for SSRF/blind callback validation. citeturn864775search0

FFUF remains a general-purpose web fuzzer with content discovery, virtual-host discovery, parameter fuzzing, and POST-data fuzzing capabilities. citeturn864775search4

The agent should periodically re-check tool documentation before invoking uncommon flags or newly added features.

---

# 46. Benchmark-Driven Development

Do not judge the agent by the number of requests it sends or the number of scanner findings it produces.

Judge it by:

```text
How many true vulnerabilities did it validate?
How many false positives did it suppress?
How often were its POCs reproducible?
How often did it violate scope?           -> target: 0
How often did it cause destructive impact? -> target: 0
How much evidence did each finding contain?
How efficiently did it reach validated findings?
```

The companion `benchmarks/benchmark.yaml` defines the minimum evaluation set.

Recommended validation stages:

```text
Stage 1: unit-test schemas
Stage 2: synthetic observations
Stage 3: intentionally vulnerable local labs
Stage 4: controlled staging applications
Stage 5: authorized bug-bounty targets with human oversight
```

Do not begin with autonomous testing of production targets.

---

# 47. Duplicate and Novelty Engine

A useful agent must distinguish:

```text
new vulnerability
same root cause / new endpoint
same root cause / duplicate impact
same endpoint / new vulnerability
known public issue
informational weakness
scanner duplicate
```

Similarity should consider:

```text
asset
endpoint
parameter
root cause
security property
impact
request pattern
response fingerprint
```

A new endpoint does not automatically mean a new bug.

A different payload does not automatically mean a new bug.

A new chain may justify a separate report only when it creates materially distinct security impact or satisfies program policy.

---

# 48. Severity and Impact Calibration

The agent must separate **technical exploitability** from **business impact**.

For every validated finding record:

```yaml
impact:
  confidentiality: none|low|medium|high
  integrity: none|low|medium|high
  availability: none|low|medium|high
  privilege_change: none|user|admin|service
  tenant_boundary: none|same_tenant|cross_tenant
  user_scope: one|few|many|all
  business_function: "..."
```

Never inflate severity solely because a vulnerability class sounds severe.

For example:

```text
SSRF detected
    != automatically critical

XSS reflected
    != automatically account takeover

IDOR
    != automatically large-scale disclosure

Open redirect
    != automatically a security vulnerability
```

The report must state the **demonstrated** impact and clearly separate supported inference from unverified worst-case possibilities.

---

# 49. Report Quality Gate

Before submitting, the agent should answer:

```text
[ ] Is the target definitely in scope?
[ ] Is the vulnerability reproducible?
[ ] Is there a security-boundary violation?
[ ] Did I test credible false-positive explanations?
[ ] Did I preserve the baseline?
[ ] Is the POC minimal and safe?
[ ] Did I avoid unrelated user data?
[ ] Is the claimed impact directly supported?
[ ] Can another researcher reproduce this without guessing?
[ ] Did I avoid duplicate reporting?
[ ] Is remediation specific to the root cause?
```

If any critical item is unanswered, do not submit.

---

# 50. Final Production Readiness Checklist

A production-oriented implementation should not be considered complete until all of the following exist:

- [ ] strict JSON schemas
- [ ] vulnerability playbooks
- [ ] tool registry
- [ ] scope policy engine
- [ ] state machine
- [ ] hypothesis engine
- [ ] differential analysis engine
- [ ] true-positive validation gate
- [ ] evidence store
- [ ] safe PoC generator
- [ ] report generator
- [ ] duplicate/novelty engine
- [ ] retest engine
- [ ] benchmark suite
- [ ] lab corpus
- [ ] tool maintenance metadata
- [ ] audit logging
- [ ] secret redaction
- [ ] rate-limit enforcement
- [ ] human approval gates for high-impact actions

The companion files included with this README provide the baseline contracts and examples for these components.

---

# 51. Definitive Operating Principle

The complete agent loop is:

```text
RECON
  ↓
MAP THE ATTACK SURFACE
  ↓
FORM COMPETING HYPOTHESES
  ↓
SELECT THE CHEAPEST SAFE DISCRIMINATING TEST
  ↓
ESTABLISH A BASELINE
  ↓
MUTATE ONE VARIABLE
  ↓
OBSERVE
  ↓
DIFFERENTIATE
  ↓
TRY TO DISPROVE THE FINDING
  ↓
VALIDATE THE SECURITY-BOUNDARY VIOLATION
  ↓
VALIDATE IMPACT
  ↓
CREATE THE MINIMUM SAFE POC
  ↓
PACKAGE REPRODUCIBLE EVIDENCE
  ↓
CHECK DUPLICATES
  ↓
REPORT
  ↓
RETEST
```

The agent should optimize for **high-confidence security knowledge per unit of risk**, not maximum request volume and not maximum exploitation.

---

## Companion Machine-Readable Package

The companion files are distributed with this README in the `ai-bug-bounty-agent/` directory. The schemas are deliberately separated from prose so an implementation can load them independently.

### Current package contents

```text
schemas/      strict data contracts
playbooks/    vulnerability workflows
 tools/        capability-aware tool registry
policies/     safety and operational controls
benchmarks/   evaluation criteria
agent-workflow.md  concise execution state machine
```

### Current taxonomy note

OWASP Top 10:2025 is the primary taxonomy. OWASP's current official project page lists A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, and A10 Mishandling of Exceptional Conditions. citeturn864775search2

The agent should therefore use OWASP Top 10:2025 as the top-level awareness taxonomy while using more granular playbooks for actual testing.

---

# Version and Completion Status

**Version:** 2026-08-16

**Status:** AI-agent specification baseline complete

**Primary taxonomy:** OWASP Top 10:2025

**Companion standards:** OWASP API Security Top 10:2023, OWASP ASVS 5.0, OWASP WSTG, current web-security research.

**Important:** “Complete” here means a complete baseline architecture and coverage specification for an AI bug-bounty agent. Tool versions, public research, program policies, and vulnerability techniques change continuously; the tool registry and research corpus must therefore be maintained as living data.

---

# 52. Deep Research Edition — How an Advanced Agent Actually Reasons About Web Bugs

> This section deliberately goes beyond checklist-level guidance. It is organized around vulnerability primitives, parser differentials, state transitions, authorization decisions, data-flow boundaries, protocol semantics, and business invariants. The agent should treat each section as a hypothesis generator and validation model, not as a payload recipe.

## 52.1 The primitive-first model

A mature agent should not begin with a vulnerability label such as `IDOR`, `SSRF`, or `XSS`. Begin with a primitive:

- **Identity primitive:** who is the requester?
- **Authority primitive:** what action is the requester permitted to perform?
- **Object primitive:** which resource is being acted upon?
- **Property primitive:** which fields may be read or written?
- **Parser primitive:** which component interprets the same bytes, URL, header, or document?
- **State primitive:** which state transition is assumed to be atomic?
- **Trust primitive:** which component trusts data produced by another component?
- **Origin primitive:** which browser origin, host, tenant, or security principal is assumed?
- **Freshness primitive:** which value is assumed to be recent, unique, or single-use?
- **Resource primitive:** which operation consumes disproportionate CPU, memory, queue, storage, bandwidth, or downstream requests?
- **Serialization primitive:** which format is interpreted differently by producers and consumers?
- **Secret primitive:** which token, key, identifier, or capability is assumed to remain confidential?

The vulnerability class is the consequence of one or more broken primitives.

### Agent rule

For every candidate, record:

```yaml
primitive:
  actor: "authenticated_user_A"
  authority: "manage_own_invoice"
  object: "invoice_B"
  trust_boundary: "API -> billing-service"
  invariant: "actor may only modify invoices belonging to actor"
  observed_violation: true
```

This forces the agent to explain **why** a response is vulnerable rather than simply matching a scanner signature.

---

# 53. Advanced Authorization Research

## 53.1 Authorization is a relation, not a boolean

Many systems expose an apparent check such as `isAuthenticated == true`, but real authorization is generally a relation:

```text
Decision = f(subject, tenant, role, action, object, relationship, state, context)
```

A testing agent should therefore vary one dimension at a time before combining dimensions.

### Test dimensions

| Dimension | Examples |
|---|---|
| Subject | user A, user B, service account |
| Tenant | tenant A, tenant B |
| Role | member, manager, admin |
| Action | read, create, update, delete, approve, export |
| Object | owned, shared, unowned, archived |
| Relationship | owner, collaborator, approver, stranger |
| State | draft, pending, approved, cancelled |
| Context | UI, API, mobile API, webhook, background job |

### The authorization matrix

For a high-value endpoint, construct:

```text
             object owner
             yes       no
subject role
member       allow     deny
manager      allow     policy-dependent
admin        allow     allow
anonymous    deny      deny
```

The exact matrix changes by application. The important point is that the agent should infer the intended matrix from application behavior and documentation, then test for deviations.

## 53.2 Horizontal authorization

Horizontal failures occur when peers can cross each other's object boundary.

High-value object identifiers include:

- integer IDs
- UUIDs
- opaque IDs
- invoice IDs
- attachment IDs
- message IDs
- organization IDs
- project IDs
- API keys
- reset-token references
- export-job IDs
- WebSocket channel IDs

### Deep test sequence

1. Establish a known-good request for object A owned by account A.
2. Establish a known-good request for object B owned by account B.
3. Confirm that the two objects differ materially.
4. Replay the request as account A with object B's identifier.
5. Compare authorization decision, body, side effects, timing, pagination metadata, nested fields, and response headers.
6. Repeat through alternate endpoints that reference the same object.
7. Test read, update, delete, export, share, and secondary actions independently.
8. Check whether the UI hides an operation that the API still permits.

### Hidden authorization surfaces

Do not restrict testing to ordinary REST endpoints. Re-evaluate the same object relationship through:

- bulk APIs
- search endpoints
- autocomplete
- export functions
- asynchronous jobs
- attachment download routes
- GraphQL resolvers
- WebSocket messages
- webhook verification endpoints
- admin-side APIs
- mobile-specific APIs
- legacy versions
- internal endpoints accidentally exposed through the public gateway

## 53.3 Identifier transformations

A system may validate one representation but use another internally. Test conceptual transformations rather than a fixed payload list:

```text
integer -> string
UUID -> uppercase/lowercase
opaque ID -> alternate serialization
path segment -> query parameter
object ID -> nested JSON field
single ID -> array of IDs
scalar -> comma-separated list
string -> Unicode-normalized equivalent
JSON number -> floating representation where accepted
```

The agent must treat any successful transformation as **candidate evidence only** until the ownership boundary is proven violated.

## 53.4 Property-level authorization

A server may correctly protect the object but incorrectly trust fields inside it.

Example model:

```json
{
  "display_name": "Alice",
  "role": "member",
  "tenant_id": "tenant-A",
  "is_verified": true
}
```

The agent should build a property classification:

```yaml
property: role
client_writable: expected=false
security_sensitive: true
observed_behavior: accepted
```

High-value property classes:

- role / permissions
- tenant / organization ownership
- account status
- verification state
- billing state
- payment amount
- approval state
- moderation state
- feature flags
- email ownership
- recovery settings

The agent should distinguish **mass assignment**, **over-posting**, **hidden field trust**, and ordinary mutable profile fields.

## 53.5 Function-level authorization

Do not infer authorization from the UI. Build a function inventory:

```text
GET object
POST object
PUT object
PATCH object
DELETE object
POST approve
POST export
POST rotate-key
POST impersonate
POST invite
POST transfer
POST restore
```

Test whether changing only the action boundary changes the required authority.

## 53.6 Multi-tenant isolation

Multi-tenancy deserves its own model:

```text
user -> organization -> project -> resource
```

For each object, determine the authoritative tenant source:

- token claim
- session state
- path parameter
- request body
- database relation
- gateway-derived context

A classic failure occurs when the application validates one tenant identifier but performs the database lookup using another.

The agent should therefore test for **cross-tenant reference inconsistencies** rather than merely searching for numeric IDs.

---

# 54. Authentication Research at Protocol and State-Machine Level

Authentication is a sequence of states, not merely a login endpoint.

## 54.1 Model the authentication state machine

```text
anonymous
  ↓
identifier-known
  ↓
challenge-issued
  ↓
challenge-validated
  ↓
authenticated
  ↓
step-up-required
  ↓
privileged-session
```

For every transition, ask:

- What evidence allows the transition?
- Is that evidence bound to the right identity?
- Can it be replayed?
- Can it be used on another session?
- Can it be completed out of order?
- Is it invalidated after use?
- Is it bound to the intended client?

## 54.2 Account recovery as an authentication protocol

Treat password reset, email change, phone change, backup-code recovery, and support-assisted recovery as alternative authentication channels.

For each channel inventory:

```yaml
channel:
  issuer:
  recipient:
  token:
  binding:
  lifetime:
  single_use:
  rotation:
  invalidation:
  rate_limit:
  notification:
```

A reset token that is technically unpredictable can still be unsafe if it is:

- not bound to the requested account
- accepted after password change
- reusable
- leaked through logs or referrers
- reflected into another origin
- accepted on the wrong host
- transferable between sessions

## 54.3 Session semantics

Test session lifecycle transitions:

```text
login -> session issuance
login -> privilege elevation
password change -> session invalidation
logout -> token invalidation
MFA enablement -> session reevaluation
role change -> permission reevaluation
account lock -> session behavior
```

The important question is not merely whether a cookie exists; it is **whether authority changes cause session state to be recomputed correctly**.

---

# 55. OAuth / OIDC / SAML Deep Model

## 55.1 Build the trust graph

Represent the relationship explicitly:

```text
Browser
  |
  v
Client Application ---- redirect ----> Authorization Server
        |                                  |
        |                                  v
        +-------------------------- Token Endpoint
                                           |
                                           v
                                      Resource Server
```

Each edge creates a trust assumption.

## 55.2 OAuth hypotheses

The agent should test the conceptual classes of:

- redirect URI validation weaknesses
- authorization-code substitution
- state mishandling
- CSRF-like authorization response confusion
- PKCE binding failures
- client confusion / mix-up conditions
- token audience confusion
- issuer confusion
- scope over-granting
- code reuse
- token reuse after security-state changes
- incorrect client identity assumptions

The agent must avoid calling any OAuth anomaly a vulnerability until the affected identity or authorization boundary is demonstrated.

## 55.3 OIDC claims validation

Treat these claims as security decisions, not ordinary profile fields:

```text
iss
sub
aud
azp
nonce
exp
nbf
iat
email_verified
acr
amr
```

The agent should determine which component validates each claim and whether another component subsequently trusts a less authoritative copy.

## 55.4 SAML

Model:

```text
Identity Provider
      ↓
Assertion
      ↓
Service Provider
      ↓
Local Session
```

Important questions include:

- Which fields establish identity?
- Which fields establish audience?
- Is signature verification performed over the authoritative representation?
- Is the assertion bound to the intended recipient and service?
- Can an assertion be replayed?
- Are parser transformations creating multiple semantic interpretations?

The agent should prioritize **semantic validation failures** instead of blindly trying historical payloads.

---

# 56. Injection Research Beyond Payload Lists

## 56.1 Injection is an interpreter-boundary problem

A generic injection model is:

```text
Attacker-controlled data
        ↓
String / object construction
        ↓
Interpreter boundary
        ↓
Unexpected syntax or semantics
```

The agent should identify the interpreter before selecting a test strategy.

Possible interpreters:

```text
SQL
NoSQL query language
LDAP
XPath
OS command shell
Template engine
Expression language
JSON parser
XML parser
CSV/Formula interpreter
HTML parser
JavaScript
CSS
URL parser
GraphQL parser
```

## 56.2 Context classification

For an input location, determine:

```yaml
context:
  transport: json
  semantic_type: string
  sink: sql-query
  quoting: single
  encoding_layers:
    - json
    - application decoding
```

This matters because a string that is harmless in one context can become syntax in another.

## 56.3 SQL injection hypothesis ladder

Do not begin with maximum-impact payloads. Establish:

1. Is the parameter interpreted as data?
2. Does a syntax boundary exist?
3. Does a semantic change occur?
4. Can the result be reproduced under controlled conditions?
5. Is the behavior consistent with server-side interpretation rather than application error handling?
6. Can the impact be demonstrated with the least invasive evidence?

## 56.4 Blind injection

For blind behaviors, distinguish:

```text
response differential
vs
boolean semantic differential
vs
time differential
vs
out-of-band interaction
```

Time-based evidence should be statistically compared against a baseline. A single slow request is weak evidence.

## 56.5 Template injection

Identify the template family through application behavior and error semantics before using specialized tests. A mature agent tracks:

```text
source -> template compilation -> expression evaluation -> output encoding
```

The strongest evidence is a demonstrable transition from data rendering to template semantics, not merely an error message containing a recognizable engine name.

---

# 57. SSRF as a URL-Parsing and Trust-Policy Problem

SSRF testing should be modeled as:

```text
Attacker input
   ↓
URL parser
   ↓
Canonicalization / normalization
   ↓
DNS resolution
   ↓
Connection policy
   ↓
HTTP client
   ↓
Redirect handling
   ↓
Response processing
```

Each layer can disagree with the previous one.

## 57.1 SSRF hypotheses

Consider separately:

- direct server-side fetching
- redirect-based SSRF
- DNS rebinding behavior
- alternate schemes
- hostname normalization
- IPv4/IPv6 interpretation
- proxy trust
- allowlist/denylist disagreement
- URL parser discrepancies
- internal service discovery
- metadata service exposure
- webhook fetchers
- document/image importers
- PDF renderers
- screenshot services
- link previewers

## 57.2 OAST evidence model

A blind interaction should establish:

```text
request identifier
   ↓
unique canary
   ↓
interaction timestamp
   ↓
source metadata
   ↓
correlation with exact test request
```

The agent should not claim SSRF solely because a URL was accepted. The strongest evidence demonstrates that the target server performed an outbound interaction.

## 57.3 SSRF impact ladder

```text
URL accepted
  < server-side outbound request
  < attacker-controlled endpoint reached
  < internal-only destination reached
  < sensitive internal API reached
  < credential/service-token exposure
  < authenticated action on internal service
```

The agent should stop at the lowest level that proves the finding unless the program explicitly permits deeper validation.

---

# 58. Request Smuggling and Desynchronization as Parser Differential Analysis

Request smuggling is best understood as a disagreement over **message boundaries**.

```text
Frontend parser
      |
      | interpretation A
      v
request boundary
      |
      v
Backend parser
      |
      | interpretation B
      v
request boundary
```

## 58.1 Parser graph

For every candidate path, map:

```text
client
 → CDN
 → WAF
 → reverse proxy
 → load balancer
 → application server
 → framework
```

Then ask which component terminates the connection and which component reuses it.

## 58.2 Differential dimensions

The agent should classify parser differences involving:

- content-length handling
- transfer-encoding handling
- duplicate headers
- whitespace normalization
- line-ending handling
- HTTP/2 to HTTP/1 translation
- connection reuse
- trailers
- request body termination
- malformed-but-tolerated syntax
- early response behavior

## 58.3 CL.0 and browser-powered desync

Do not limit the agent to classic TE/CL combinations. Current research documents CL.0 and client-side desynchronization where browser-compatible requests can create connection-state problems. citeturn189387search5turn189387search8turn189387search11

The agent should therefore include a **desync decision tree**:

```text
Can front-end and back-end disagree on body termination?
        |
       yes
        ↓
Is connection reuse involved?
        |
       yes
        ↓
Can a subsequent request inherit parser state?
        |
       yes
        ↓
Can a harmless canary prove cross-request influence?
```

A test that merely returns an unusual status code is not enough.

---

# 59. Web Cache Research as Key Computation Analysis

Cache vulnerabilities are often caused by the mismatch:

```text
Application semantics != Cache key semantics
```

## 59.1 Build the cache-key model

Identify candidate inputs:

```text
scheme
host
path
query
selected headers
cookies
authorization state
content negotiation
language
encoding
method
request body
```

Then determine which inputs actually influence the cached representation.

## 59.2 Cache poisoning hypothesis

A strong methodology is:

```text
1. Establish cacheable baseline.
2. Identify a candidate unkeyed input.
3. Modify only that input.
4. Observe whether the origin response changes.
5. Determine whether the changed representation is cached.
6. Request the same resource from a clean client.
7. Establish cross-user or cross-session effect.
```

The key proof is not “the header changed the response.” It is **whether the changed response became available to an unrelated requester**.

## 59.3 Cache deception

Model the discrepancy between:

```text
URL appears static to cache
vs
application resolves it as dynamic/private content
```

A strong validation requires evidence that a cache actually stores the sensitive representation and serves it to an unauthorized context.

---

# 60. Race Conditions and TOCTOU at State-Transition Level

A race exists when correctness depends on an operation being atomic but the implementation performs separable checks and state changes.

Generic model:

```text
check(resource_state)
        ↓
   attacker-controlled gap
        ↓
modify(resource_state)
```

## 60.1 Race hypothesis classes

- duplicate redemption
- double spending
- concurrent password reset
- concurrent email change
- invitation acceptance
- coupon redemption
- quota bypass
- balance transitions
- account recovery state
- one-time action reuse
- approval workflow

## 60.2 Test methodology

The agent should distinguish:

```text
parallel requests
vs
same-session concurrency
vs
cross-session concurrency
vs
queue-level duplication
```

And record:

```yaml
race_test:
  concurrency_level: 5
  synchronization_point: "request body fully sent"
  observed_successes: 2
  expected_successes: 1
```

Do not label a race from a transient duplicate response. Establish the invariant that was violated.

---

# 61. Business Logic Research as Invariant Discovery

Business-logic testing is where checklist-driven scanners fail most often.

## 61.1 Extract invariants

Look for rules such as:

```text
A discount can be redeemed once.
A refund cannot exceed the payment.
A user cannot approve their own request.
A completed order cannot return to pending.
A member cannot transfer ownership.
A verification step must precede a privileged action.
A seat cannot be allocated twice.
```

Represent them explicitly:

```yaml
invariant:
  name: "refund_not_greater_than_payment"
  precondition: "payment.completed == true"
  constraint: "refund_amount <= paid_amount"
  security_impact: "financial_loss"
```

## 61.2 State-machine abuse

Test transitions, not only endpoints:

```text
created → pending → approved → completed
```

Try legitimate actions in illegitimate order, duplicated transitions, stale tokens, conflicting actors, and concurrent transitions.

The agent should search for **missing edges in the authorization/state graph** rather than merely malformed requests.

---

# 62. File Uploads, Parsers, and Content-Type Confusion

File upload vulnerabilities should be modeled as a pipeline:

```text
upload
 → MIME detection
 → extension validation
 → storage
 → transformation
 → antivirus/scanner
 → parser
 → preview
 → download
 → browser/rendering
```

Every transition is a possible disagreement.

## 62.1 Questions to answer

- Which layer decides the file type?
- Is validation performed before or after transformation?
- Is the stored object accessible directly?
- Is the original or transformed file later parsed?
- Does the browser receive attacker-controlled content with an executable media type?
- Is the filename used in filesystem paths, HTML, logs, or headers?
- Are archives recursively unpacked?
- Are image/PDF/document parsers invoked?

The agent should distinguish **upload acceptance** from a demonstrable security impact.

---

# 63. Deserialization and Parser Differential Research

The broad primitive is:

```text
Producer representation
        ↓
serialization format
        ↓
consumer parser
        ↓
object/model
```

Potential weaknesses emerge when different components disagree about the semantic meaning of the same structure.

Relevant families include:

- JSON parsing differences
- YAML object construction
- XML entity handling
- multipart parsing
- protobuf/gRPC semantics
- PHP serialization
- Java serialization
- .NET serialization
- Python object serialization
- browser DOM parsing
- URL parser discrepancies

An agent should first identify **parser and object-construction boundaries**, then determine whether attacker-controlled data crosses from untrusted representation into privileged behavior.

---

# 64. Client-Side Security at Browser Semantics Level

## 64.1 DOM XSS data-flow model

```text
source → transformation → sanitizer → sink
```

Typical source categories:

```text
URL
fragment
postMessage
storage
referrer
cross-window data
server response
WebSocket message
```

Typical sink categories:

```text
HTML insertion
script execution
URL navigation
event-handler assignment
DOM parser APIs
```

The agent should track whether a value is:

```text
attacker-controlled
partially controlled
trusted by same-origin policy
sanitized
encoded
contextually escaped
```

## 64.2 DOM clobbering and prototype pollution

These should be treated as **language/runtime semantic attacks** rather than ordinary reflected XSS.

For prototype pollution, the agent should model:

```text
source
 → property path
 → merge/assignment primitive
 → prototype mutation
 → gadget
 → security impact
```

A pollution primitive without a meaningful gadget or security effect may be lower-value or non-reportable depending on program policy.

## 64.3 postMessage

Model:

```text
sender origin
receiver origin
message type
validation
trusted action
```

The key question is whether an attacker-controlled origin can invoke a privileged message handler.

---

# 65. Prototype Pollution as a Multi-Stage Bug Class

Prototype pollution should be tested in three separate stages:

```text
1. Pollution primitive
2. Observable polluted property
3. Security-relevant gadget
```

A mature agent should not stop after stage 1.

Potential gadget classes include:

- authorization flags
- template configuration
- child-process options
- URL handling
- request configuration
- object serialization
- security middleware configuration

The proof should demonstrate the minimum safe chain necessary to establish impact.

---

# 66. Subdomain Takeover and Dangling Infrastructure

Subdomain takeover is a lifecycle/infrastructure ownership problem.

Model:

```text
DNS record
   ↓
provider/service endpoint
   ↓
resource ownership
   ↓
claimability
```

A dangling DNS record is not automatically a takeover. The agent must establish:

1. the DNS record points to an external service;
2. the service reports that the resource is unclaimed or otherwise claimable;
3. the tester can safely demonstrate control in an authorized manner;
4. the claimed resource is actually associated with the target origin.

False positives are common because providers often return generic error pages that look similar to vulnerable states.

---

# 67. Cloud and Kubernetes Attack Paths

Cloud testing should focus on **identity and trust relationships**, not just exposed metadata.

## 67.1 IAM graph

Represent:

```text
principal
  ↓
role
  ↓
policy
  ↓
resource
  ↓
action
```

For an SSRF or credential exposure chain, the relevant questions are:

- what identity is exposed?
- what permissions does it possess?
- what resource can those permissions affect?
- is the resulting action inside the bug-bounty scope?

## 67.2 Kubernetes

Model:

```text
pod
 → service account
 → RBAC
 → API server
 → secrets/configmaps/workloads
```

An exposed endpoint is not automatically a vulnerability. Validate whether the exposed identity or endpoint breaks a security boundary.

---

# 68. Supply-Chain and CI/CD Research

A01:A03 and A08-style failures require a provenance model:

```text
source
 → dependency
 → build
 → artifact
 → deployment
 → runtime
```

The agent should ask where integrity is assumed but not cryptographically or administratively enforced.

High-value research areas:

- dependency confusion
- typosquatting
- unpinned dependencies
- compromised build steps
- artifact substitution
- unsigned releases
- CI token exposure
- pull-request trust boundaries
- fork permissions
- workflow injection
- release automation
- package publication workflows
- build cache trust

The test must remain within the program's authorized scope and avoid publishing or executing malicious artifacts against third parties.

---

# 69. Differential Testing Engine — Research-Grade Specification

## 69.1 Test tuple

Every test should be represented as:

```yaml
experiment:
  hypothesis: H
  baseline: B
  mutation: M
  expected_difference: D
  observation: O
  interpretation: I
  confidence: C
```

## 69.2 One-variable-at-a-time rule

Initially mutate one semantic variable. Multi-variable mutations are useful later for chaining but are poor for determining causality.

## 69.3 Multiple-baseline rule

Where timing, caching, or nondeterminism matters, establish enough baseline samples to estimate ordinary variation.

Conceptually:

```text
baseline distribution
vs
mutated distribution
```

rather than:

```text
one request
vs
one request
```

## 69.4 Evidence hierarchy

Prefer evidence in this order:

1. deterministic authorization violation;
2. deterministic cross-user/cross-tenant effect;
3. deterministic security-state change;
4. deterministic controlled out-of-band interaction;
5. repeatable semantic response difference;
6. error/message anomaly;
7. fingerprint-only signal.

The lower the evidence tier, the stronger the validation requirement.

---

# 70. Research Corpus Mining

An advanced agent should treat public research as a dataset, not as a list of payloads.

## 70.1 Source classes

Prioritize:

- HackerOne disclosed reports
- Bugcrowd public disclosures
- vendor advisories
- OWASP projects
- PortSwigger research and labs
- Google Bug Hunters material
- GitHub Security Lab
- CVE/NVD records
- ProjectDiscovery research
- security conference papers
- academic papers
- researcher blogs
- framework security advisories
- cloud provider security bulletins

OWASP WSTG is currently developing its 5.0 release while v4.2 remains a versioned release, so an agent should record the exact WSTG version used in a knowledge card. citeturn189387search9

## 70.2 Research-card format

```yaml
research_card:
  title:
  source:
  publication_date:
  affected_technology:
  root_primitive:
  preconditions:
  attack_surface:
  parser_or_state_issue:
  exploit_path:
  validation_signal:
  false_positive_risks:
  impact:
  defensive_boundary:
  transferable_pattern:
  related_cases:
```

The transferable pattern is more important than the original target.

## 70.3 Accepted vs rejected reports

The agent should mine both accepted and rejected reports because rejected reports expose:

- false-positive patterns
- insufficient impact
- out-of-scope conditions
- duplicate patterns
- evidence gaps
- misunderstood product behavior

A rejection should never be treated as evidence that the underlying technique is invalid. Store the reason and compare it with later cases.

---

# 71. Duplicate and Novelty Analysis

A high-quality agent needs a novelty engine.

Represent a finding by semantic features:

```yaml
fingerprint:
  primitive:
  endpoint_role:
  affected_object:
  trust_boundary:
  impact:
  root_cause:
```

Two findings with different URLs may be duplicates if they share the same underlying root cause and impact boundary.

Conversely, two findings with the same apparent symptom may be distinct if their root causes or security boundaries differ.

The agent should compare:

```text
same root cause?
same endpoint family?
same affected boundary?
same impact?
same remediation?
```

---

# 72. Severity as Evidence, Not Guesswork

The agent should separate:

```text
technical capability
from
security impact
from
business impact
```

A finding record should contain:

```yaml
impact:
  confidentiality: none|low|medium|high
  integrity: none|low|medium|high
  availability: none|low|medium|high
  privilege_change: none|user|admin
  tenant_boundary: none|cross-user|cross-tenant
  business_effect:
```

Do not inflate impact by chaining hypothetical steps that were never demonstrated. Distinguish:

```text
observed impact
plausible impact
hypothetical maximum impact
```

Only the first should be presented as proven.

---

# 73. Report Writing at Researcher Standard

A high-quality report should let a technically competent reviewer reproduce the finding without guessing.

## Required structure

```text
Title
Affected asset
Prerequisites
Summary
Security boundary
Exact reproduction
Baseline request/response
Trigger request/response
Differential explanation
Impact
Evidence
Root-cause hypothesis
Remediation direction
```

## Strong vs weak statements

Weak:

> The endpoint seems vulnerable to IDOR.

Strong:

> Account A can retrieve an invoice belonging to Account B by changing the object reference from the identifier observed in Account A's legitimate request to an identifier owned by Account B. The server returns the protected invoice data without an authorization denial.

The second statement describes an observed security-boundary violation rather than naming a tool result.

---

# 74. Agent Failure Modes

An advanced agent needs an explicit failure taxonomy.

## F1 — Scanner anchoring

The agent assumes a scanner result is correct.

**Correction:** require manual validation.

## F2 — Payload anchoring

The agent repeatedly tries known payloads without understanding the parser context.

**Correction:** infer interpreter and context first.

## F3 — Status-code anchoring

The agent treats `200`, `302`, `403`, or `500` as proof.

**Correction:** compare security semantics, not status alone.

## F4 — Single-sample timing

The agent infers a timing vulnerability from one slow response.

**Correction:** use controlled repeated baselines.

## F5 — UI anchoring

The agent assumes hidden UI controls are secure controls.

**Correction:** test the authoritative backend function.

## F6 — Chain inflation

The agent reports a maximum theoretical chain.

**Correction:** distinguish observed from hypothetical impact.

## F7 — Scope drift

The agent follows a chain into an out-of-scope third party.

**Correction:** treat scope as a hard graph constraint.

## F8 — Tool fetishism

The agent uses a familiar tool even when its model does not fit the problem.

**Correction:** tool selection must follow the hypothesis.

## F9 — Duplicate blindness

The agent finds the same root cause on many endpoints and creates multiple redundant reports.

**Correction:** semantic root-cause clustering.

## F10 — Evidence insufficiency

The agent finds a genuine anomaly but cannot reproduce it.

**Correction:** do not promote the finding until evidence gates pass.

---

# 75. Advanced Agent Decision Tree

```text
START
  |
  +-- Is target explicitly in scope?
  |      |
  |      +-- no → STOP
  |
  +-- What architecture is present?
  |      |
  |      +-- SPA/API → API + browser model
  |      +-- server-rendered → server + browser model
  |      +-- microservices → trust-graph model
  |      +-- CDN/WAF/reverse proxy → parser/cache model
  |
  +-- What security primitive is exposed?
  |
  +-- Generate 1..N hypotheses
  |
  +-- Select minimum-risk experiment
  |
  +-- Establish baseline
  |
  +-- Mutate one semantic variable
  |
  +-- Observe
  |
  +-- Differential analysis
  |
  +-- Security-boundary violation?
  |      |
  |      +-- no → revise hypothesis / stop
  |
  +-- Impact demonstrated?
  |      |
  |      +-- no → candidate only
  |
  +-- False-positive checks passed?
  |      |
  |      +-- no → reject candidate
  |
  +-- Reproducible?
  |      |
  |      +-- no → insufficient evidence
  |
  +-- Minimal safe PoC
  |
  +-- Chain only if necessary to demonstrate material impact
  |
  +-- Generate evidence bundle
  |
  +-- Duplicate/novelty check
  |
  +-- Report
  |
  +-- Retest after remediation
END
```

---

# 76. Architecture-Specific Deep Testing Packs

## 76.1 SPA + REST API

Prioritize:

```text
authorization
API version drift
BOLA/BFLA
property-level authorization
JWT/OIDC
CORS
WebSocket
client-side routing
source maps
GraphQL if present
```

## 76.2 Microservices

Prioritize:

```text
service-to-service trust
header propagation
internal identity
mTLS assumptions
JWT audience confusion
serialization
message queues
webhooks
SSRF
cache boundaries
```

## 76.3 CDN/WAF/reverse-proxy architecture

Prioritize:

```text
parser differences
cache keys
host/proto headers
HTTP/2 downgrades
origin confusion
request normalization
route discrepancy
```

## 76.4 Multi-tenant SaaS

Prioritize:

```text
tenant IDs
organization membership
shared links
exports
background jobs
search indexes
attachments
billing
invitation flows
admin delegation
```

## 76.5 OAuth-centric application

Prioritize:

```text
redirect handling
state/nonce
PKCE
issuer/audience validation
account linking
identity binding
session transition
logout/revocation
```

---

# 77. Modern Research Priorities: 2025–2026

The agent should maintain a living research queue instead of freezing its knowledge around the OWASP Top 10.

OWASP Top 10:2025 lists A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, and A10 Mishandling of Exceptional Conditions. citeturn189387search2turn189387search10

For APIs, OWASP's 2023 model explicitly emphasizes authorization failures, unrestricted sensitive business flows, SSRF, inventory problems, and unsafe API consumption. citeturn189387search0turn189387search6

Current PortSwigger research also demonstrates why the agent must treat desync as a broader parser-state problem: browser-powered request smuggling, CL.0, client-side desync, and pause-based desync extend the classic model. citeturn189387search5turn189387search8turn189387search11

The research backlog should therefore continuously watch:

- browser-powered desync
- HTTP/2 and HTTP/3 translation flaws
- parser differential vulnerabilities
- cache key and cache partitioning failures
- multi-tenant authorization boundaries
- OAuth/OIDC identity-binding failures
- API business-flow abuse
- supply-chain trust boundaries
- AI-assisted development pipelines
- prototype pollution and runtime gadgets
- modern server-side template/expression execution
- cloud identity-chain weaknesses
- WebSocket authorization/state bugs
- GraphQL execution and batching behavior
- service-to-service trust failures
- serialization/protobuf/parser confusion

PortSwigger's 2025 web-hacking research roundup collected 63 nominated research pieces before selecting its final ten, which is a useful model for maintaining a living research corpus rather than treating one checklist as exhaustive. citeturn189387search1turn189387search12

---

# 78. What “Deep” Means for This Agent

This book is considered deep only when the agent can answer all of these questions for a candidate vulnerability:

1. **What primitive is being violated?**
2. **Which component makes the security decision?**
3. **What exact input reaches that component?**
4. **What parser/state machine interprets it?**
5. **What invariant should hold?**
6. **What experiment isolates the hypothesis?**
7. **What alternative explanations exist?**
8. **What evidence distinguishes them?**
9. **What is the minimum safe proof?**
10. **What material impact is actually demonstrated?**
11. **Can the finding be reproduced independently?**
12. **Is it novel or a duplicate root cause?**
13. **What remediation would remove the primitive?**
14. **How can the agent retest the same security property later?**

If the agent cannot answer these questions, it should keep the item at `candidate` status.

---

# 79. Final Research-Grade Rule

> **Do not teach the agent to look for vulnerabilities. Teach it to model systems, identify violated security invariants, design controlled experiments, eliminate competing explanations, prove impact with minimal evidence, and preserve enough structure to reproduce the result.**

That is the difference between an automated scanner wrapper and an AI security researcher.

# 80. Deep Playbook Atlas

This section is intentionally organized as **research hypotheses**, not as a list of payloads. An agent should treat each item as a hypothesis family and instantiate it only when the target's architecture, state, parameters, or observations justify doing so.

## 80.1 Universal research contract

For every hypothesis, the agent should capture:

```yaml
hypothesis:
  id: "unique-id"
  primitive: "security-property-under-test"
  preconditions: []
  assets: []
  actors: []
  baseline: {}
  mutations: []
  expected_secure_behavior: []
  expected_vulnerable_behavior: []
  alternative_explanations: []
  negative_controls: []
  validation_gate:
    reproducibility: true
    security_boundary_violation: true
    impact_evidence: true
  safe_poc:
    minimum_change: true
    destructive_actions: false
  evidence: []
  report_claim: ""
```

The agent must distinguish four states:

```text
UNTESTED → CANDIDATE → VALIDATED → REPORTABLE
             ↘ FALSE_POSITIVE
             ↘ INCONCLUSIVE
             ↘ DUPLICATE_CANDIDATE
```

A candidate must never be silently promoted to a confirmed finding.

## 80.2 Hypothesis construction rules

Generate a hypothesis only when at least one of these signals exists:

1. **Authority boundary signal** — object IDs, roles, tenants, ownership fields, privileged operations, or alternate principals.
2. **Interpreter signal** — a value is parsed by SQL, a template engine, shell, LDAP, XPath, expression language, JSONPath, regex, HTML, JavaScript, or another interpreter.
3. **Parser disagreement signal** — multiple components can disagree about message framing, URL parsing, content type, encoding, canonicalization, or compression.
4. **State-transition signal** — the workflow has steps, approvals, quotas, balances, invitations, tokens, or irreversible transitions.
5. **Trust-boundary signal** — client → API, CDN → origin, proxy → application, browser → server, service → metadata endpoint, CI → artifact registry, or tenant → tenant.
6. **Data-provenance signal** — untrusted data is copied into a security-sensitive context.
7. **Asymmetry signal** — one role, endpoint, protocol, method, content type, or client observes behavior that another does not.

The absence of a signal is not proof of security, but it is a reason to deprioritize the hypothesis.

# 81. Broken Access Control: Deep Hypothesis Families

## 81.1 Horizontal object authorization

**Primitive:** principal A can access an object owned by principal B.

**Look for:** stable object identifiers, direct REST resources, document IDs, invoice IDs, team IDs, message IDs, project IDs, media IDs, and export/download routes.

**Method:** establish a same-role baseline using an object owned by the authenticated principal; obtain a second object belonging to another authorized test principal; substitute only the object reference while keeping all other request properties constant.

**Validation:** prove the response contains or mutates data that is bound to the second principal. A generic `200` alone is insufficient.

**False positives:** public assets, shared resources, synthetic IDs, cache replay, or endpoints intentionally supporting cross-user collaboration.

**Chain ideas:** object disclosure → write primitive → privilege escalation; read primitive → sensitive workflow leakage.

## 81.2 Vertical function authorization

Test whether a lower-privilege principal can invoke a function normally reserved for a higher-privilege role. Compare a real administrative request with the same request from the lower-privilege account and preserve all request fields except the authorization context.

## 81.3 Tenant-boundary confusion

Model `tenant_id`, organization ID, account ID, and ownership claims as a graph. Test whether one identifier controls routing while another controls authorization. Particularly examine endpoints that accept both a resource identifier and a tenant identifier.

## 81.4 Bulk authorization divergence

Look for batch endpoints, imports, exports, bulk-edit operations, GraphQL lists, and asynchronous jobs where validation may occur once per batch rather than per object. A secure implementation should enforce authorization on every security-relevant object in the batch.

## 81.5 Method-switch authorization

Compare `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and semantically equivalent RPC methods. A router or middleware layer may enforce authorization differently by method.

## 81.6 Identifier aliasing

Check whether multiple identifiers resolve to the same resource: numeric IDs, UUIDs, slugs, external IDs, legacy IDs, opaque references, or encoded forms. A resource may be protected on one identifier path but exposed on another.

## 81.7 Hidden-field trust

Look for client-supplied fields such as `role`, `owner`, `approved`, `status`, `tenant`, `is_admin`, `account_type`, or workflow stage. The agent should test whether the server derives these values or trusts them.

## 81.8 Async authorization gaps

Compare synchronous and asynchronous versions of the same function: export creation vs export download, upload submission vs processing, job creation vs job status, message enqueue vs message retrieval.

## 81.9 Pre-signed resource authorization

Determine whether access to a signed URL remains valid after ownership changes, deletion, logout, or permission revocation. Test only with test data and observe whether the intended lifecycle is enforced.

# 82. Authentication and Session Research

## 82.1 Authentication state-machine reconstruction

Represent every account as states such as:

```text
ANONYMOUS
→ PASSWORD_VERIFIED
→ MFA_PENDING
→ AUTHENTICATED
→ STEP_UP_REQUIRED
→ PASSWORD_RESET_PENDING
→ RECOVERY_PENDING
→ DISABLED
→ DELETED
```

For each transition, ask which credentials or proofs are required and whether an earlier proof can be reused after state changes.

## 82.2 MFA enrollment race

Test whether enrollment and verification are strongly bound to the same authenticated session and account. The core hypothesis is cross-session or cross-account binding failure, not merely whether MFA exists.

## 82.3 MFA recovery downgrade

Compare the security strength of normal authentication and recovery channels. A strong login followed by a weak recovery mechanism is a downgrade path.

## 82.4 Session invalidation

Test whether password change, password reset, logout-all, account disablement, privilege change, and MFA enrollment invalidate prior sessions or tokens as intended.

## 82.5 Session fixation / upgrade confusion

Determine whether an anonymous session can become authenticated without replacing or securely rotating the session identifier when a rotation is required by the application's threat model.

## 82.6 Cross-device recovery binding

Look for recovery flows where device A initiates a reset and device B can complete a sensitive step without a sufficiently bound transaction token.

## 82.7 Account enumeration as an oracle

Treat status codes, response sizes, timing, error wording, rate-limit behavior, and downstream state changes as possible identity or account-existence oracles. Require statistical comparison rather than a single timing sample.

## 82.8 Login throttling model

Measure rate limits across IP, account, device, session, identifier, and endpoint dimensions. A control applied only to one dimension may be bypassable through another, but the agent must stay within program limits and avoid disruptive volume.

# 83. Password Reset and Account Recovery

## 83.1 Token entropy and predictability

Do not rely on visual randomness. Determine whether tokens are high-entropy, single-use, time-limited, audience-bound, and invalidated after successful use.

## 83.2 Reset-token audience confusion

A token intended for password reset should not be accepted as a login token, email-verification token, API token, or privilege-elevation token unless explicitly designed that way.

## 83.3 Host/Origin dependency

Investigate whether recovery links or generated URLs trust attacker-controlled routing metadata. Validate only within the authorized workflow and use a harmless test account.

## 83.4 Recovery token reuse

Check replay after successful reset, password change, email change, and explicit revocation.

## 83.5 Recovery identity-switch

Look for workflows in which a token authorizes an action while a separate client-supplied identifier selects the account being modified.

## 83.6 Recovery race

Model password-reset and email-change operations as state transitions and test whether two concurrent legitimate-looking transitions can produce a state that sequential execution would forbid.

# 84. OAuth, OIDC, and SAML Deep Hypotheses

## 84.1 Trust-graph model

Represent:

```text
Browser
  ↓
Client / RP
  ↓
Authorization Server / IdP
  ↓
Callback / Token Endpoint
  ↓
Session / Account Linker
```

Then annotate every token, code, redirect, issuer, audience, nonce, state value, PKCE challenge, and account identifier with its intended owner and verifier.

## 84.2 Redirect URI canonicalization

Test whether the registered redirect URI and the verifier normalize URLs identically. Look for parser discrepancies rather than blindly testing one malformed URL.

## 84.3 State binding

Determine whether the authorization response is bound to the initiating browser session and intended transaction. A valid response alone is not proof of a flaw.

## 84.4 PKCE binding

For public clients, model the relationship between authorization code and PKCE challenge. A secure flow should ensure that a stolen code cannot be redeemed without the corresponding verifier when PKCE is required.

## 84.5 Issuer confusion

In OIDC, determine whether the relying party validates the issuer and discovery metadata consistently. Test only with controlled IdPs or approved test identities.

## 84.6 Audience confusion

Verify that tokens intended for one resource or client are not accepted by another due to incomplete audience validation.

## 84.7 Subject/account-link confusion

Model how external identity claims map to internal accounts. Look for unsafe account linking based solely on mutable or non-unique attributes.

## 84.8 SAML assertion trust

Evaluate issuer, signature, destination, audience, recipient, time conditions, subject confirmation, and account mapping as separate invariants. Never treat a valid signature as proof that the assertion is correctly authorized.

# 85. API Security Deep Atlas

## 85.1 Resource-level authorization

Apply the access-control matrix independently to every resource path and nested relationship.

## 85.2 Function-level authorization

Inventory endpoints by role and compare semantically equivalent functions across API versions.

## 85.3 Property-level authorization

For JSON objects, identify fields that are server-controlled versus client-settable. Test whether update operations allow security-sensitive fields to cross that boundary.

## 85.4 Mass assignment

Compare a minimal accepted object with an object containing additional benign test fields. Identify whether unknown or server-managed properties alter security-sensitive state.

## 85.5 Excessive data exposure

Compare API responses to the minimum fields actually rendered by the client. Do not assume unused fields are safe simply because the front end ignores them.

## 85.6 Pagination boundary flaws

Test first/last/negative/large/page-token transitions and verify that authorization is enforced across page boundaries and continuation tokens.

## 85.7 Filter authorization

Check whether filters can select objects outside the caller's authorized set even when direct object retrieval is correctly protected.

## 85.8 Export and reporting APIs

Exports are high-value boundaries because they frequently bypass ordinary UI authorization checks and execute asynchronously.

## 85.9 API version drift

Compare `/v1`, `/v2`, mobile endpoints, legacy subdomains, partner APIs, and deprecated routes. A security control missing in one generation is a classic regression pattern.

## 85.10 Content negotiation divergence

Test whether the same resource is processed differently as JSON, form data, multipart, XML, or another supported representation. Authorization and validation must remain equivalent.

# 86. GraphQL Deep Research

## 86.1 Schema discovery from legitimate application behavior

Build a field/type/operation map from observed client traffic and authorized introspection behavior.

## 86.2 Resolver authorization divergence

A type may be protected while an individual resolver or nested field is not. Compare the same object through different query paths.

## 86.3 Alias and batching behavior

Determine whether repeated operations are subject to per-object authorization, rate limits, and business rules.

## 86.4 Mutation vs query controls

Compare read, create, update, delete, and custom mutations for the same object family.

## 86.5 GraphQL persisted-query drift

Check whether persisted queries have stronger controls than ad-hoc requests and whether authorization is enforced at execution rather than only query registration.

# 87. WebSocket and Real-Time Security

## 87.1 Connection authorization

Identify what identity is established at handshake time and what identity is assumed afterward.

## 87.2 Message-level authorization

A correctly authenticated socket can still expose cross-tenant messages if message-level authorization is absent.

## 87.3 Channel/topic confusion

Model subscriptions and topics as protected objects, not just strings.

## 87.4 Origin trust

Determine whether the server treats browser-controlled `Origin` metadata as sufficient authorization. It should not be used as a substitute for real authentication/authorization.

## 87.5 Reconnect semantics

Check whether reconnects restore a previous privileged subscription state without re-validating authorization.

# 88. Injection Research Atlas

## 88.1 Interpreter inventory

For every attacker-controlled value, identify every parser/interpreter it may encounter. Examples include SQL, NoSQL, LDAP, XPath, template engines, shell commands, expression languages, HTML, JavaScript, and URL parsers.

## 88.2 Context classification

Classify the insertion point before choosing a test. The same characters can be data in one context and syntax in another.

## 88.3 SQL injection hypothesis ladder

1. Identify whether input reaches a query boundary.
2. Establish a benign baseline.
3. Test a minimal semantic perturbation.
4. Compare a positive and negative control.
5. Determine whether the behavior is deterministic.
6. Validate impact using the least invasive read-only demonstration available.

## 88.4 Blind injection

When no direct output exists, use paired controls and observable side effects. Avoid relying on a single timing result; require repeated measurements and a statistically meaningful separation.

## 88.5 NoSQL/operator confusion

Look for structured input that is interpreted as a query object rather than a scalar string. Verify the intended data type and server-side schema behavior before declaring a finding.

## 88.6 Template injection

Identify whether the value is rendered by a template engine and whether evaluation occurs in an isolated expression context. The agent should first prove evaluation with a harmless arithmetic expression before exploring impact.

## 88.7 Expression-language injection

Inventory expression engines and framework-specific evaluation boundaries. Distinguish parsing from execution and validate only harmless computation initially.

## 88.8 LDAP/XPath injection

Model which components are interpolated and whether escaping is context-aware. Validate with syntactic predicates and observable result changes rather than arbitrary destructive queries.

# 89. SSRF and URL Trust Models

## 89.1 URL parser pipeline

Model:

```text
Input → normalization → parser → DNS → connection → redirect → protocol handler → application
```

A secure filter must make the relevant security decision using semantics that agree with the component that eventually connects.

## 89.2 DNS rebinding hypothesis

Only pursue where the program permits asynchronous DNS resolution and the testing environment safely supports controlled domains.

## 89.3 Redirect trust

Determine whether a permitted first-hop URL can redirect to a forbidden destination and whether validation is applied to every hop.

## 89.4 Alternate address representations

Analyze canonicalization and equivalence classes for loopback/private/link-local targets. Avoid treating one string representation as the whole problem.

## 89.5 IPv4/IPv6 differential

Compare policy enforcement between address families where the target application supports both.

## 89.6 Metadata access

Where authorized, prove only the minimum harmless metadata access necessary to establish the trust-boundary violation. Do not retrieve secrets.

## 89.7 SSRF via non-HTTP protocols

Inventory URL handlers and client libraries. The attack surface may include file, FTP, gopher-like, custom schemes, or application-specific connectors. The agent should stop at demonstrating the parser/protocol boundary unless program rules authorize deeper testing.

# 90. HTTP Desynchronization and Parser Differential Atlas

## 90.1 Component graph

Represent every request hop:

```text
browser/client → CDN → WAF → load balancer → proxy → framework → application
```

For each hop record protocol version, framing rules, header normalization, connection reuse, and timeout behavior where observable.

## 90.2 Framing disagreement

Test whether two components derive different request boundaries from the same message. The security property is **consistent framing**, not merely the presence of both `Content-Length` and `Transfer-Encoding`.

## 90.3 Header normalization disagreement

Investigate case, whitespace, duplicates, obsolete forms, HTTP/2 translation, and proxy-specific normalization only within safe controlled requests.

## 90.4 CL.0 hypothesis

Model whether a front-end and back-end disagree about whether body bytes belong to a request, especially when a backend ignores the body for a method/path combination.

## 90.5 Browser-powered desync

For browser-exposed endpoints, consider whether a browser can create a message sequence that becomes dangerous when interpreted differently by downstream servers. The proof should use a non-destructive endpoint.

## 90.6 Protocol downgrade

Compare HTTP/2 or HTTP/3 frontends with HTTP/1.1 backends where protocol translation exists. The translation boundary itself is an attack surface.

# 91. Web Cache Research

## 91.1 Cache-key model

Infer which request components determine the cache key: method, path, query, selected headers, host, scheme, content negotiation, cookies, or normalized variants.

## 91.2 Unkeyed-input hypothesis

Identify response-influencing inputs that are not reflected in the cache key. Validate with a harmless canary value and a fresh request from an independent client.

## 91.3 Cache poisoning vs cache deception

Separate response substitution from accidental storage or exposure of user-specific content. They are different security properties and require different evidence.

## 91.4 Cache partitioning

Check whether caches appropriately separate tenants, authorization contexts, origins, and content negotiation variants.

## 91.5 Invalidation failures

Test whether security-sensitive state changes invalidate related cached representations as intended.

# 92. Browser-Side Security Atlas

## 92.1 DOM XSS source-sink graph

Record:

```text
source → transformations → sanitization → sink → parser → execution
```

The agent should identify whether a security-sensitive transformation actually occurs before the sink.

## 92.2 Trusted Types / CSP interaction

Determine whether browser mitigations are actually enforced for the relevant sink and whether different execution contexts have different policies.

## 92.3 postMessage trust

Model sender origin validation, message schema validation, and action authorization separately.

## 92.4 Cross-origin data leaks

Investigate whether attacker-controlled origins can infer sensitive state through responses, timing, rendering behavior, or observable browser side effects. Require a deterministic signal before classifying an XS-Leak.

## 92.5 CORS policy graph

Analyze allowed origins, credentials mode, preflight behavior, wildcard handling, and response exposure as independent controls.

## 92.6 Clickjacking / framing

Determine whether sensitive state-changing operations can be framed and whether the application's threat model requires frame restrictions.

## 92.7 Service worker scope

Treat service workers as long-lived authority over URLs within their scope. Test registration scope, update behavior, and origin binding.

# 93. Prototype Pollution and Object-Semantics Research

## 93.1 Primitive identification

Determine whether attacker-controlled keys can modify inherited object state or merge targets unexpectedly.

## 93.2 Reachability

A pollution primitive is not automatically a reportable security issue. Prove an observable security-sensitive consequence such as authorization confusion, configuration override, or code-path selection.

## 93.3 Gadget discovery

Model the flow:

```text
pollution primitive → affected property → security-sensitive consumer → impact
```

## 93.4 Client-side pollution

Separate browser-side object prototype manipulation from server-side consequences. Do not report a library-level primitive without proving application reachability and impact.

# 94. File Upload and Parser Pipelines

## 94.1 Upload trust model

Model filename, MIME type, content bytes, extension, storage location, post-processing, and retrieval behavior separately.

## 94.2 Extension/MIME disagreement

Determine which layer decides whether the upload is allowed and which layer later interprets it.

## 94.3 Content transformation

Image resizing, document conversion, antivirus scanning, archive extraction, OCR, and media transcoding introduce secondary parsers and trust boundaries.

## 94.4 Path/storage separation

Verify whether uploaded content is served from an execution-enabled or trusted origin and whether tenant isolation is maintained.

## 94.5 Archive extraction

Model extraction path normalization, symlink handling, duplicate entries, file count/size limits, and post-extraction processing. Use harmless test archives and respect program limits.

# 95. Deserialization and Structured-Data Trust

## 95.1 Parser inventory

Identify every structured-data format consumed by the system: JSON, XML, YAML, Java serialization, PHP serialization, protobuf, message packs, custom binary formats, and framework-specific session formats.

## 95.2 Type confusion

Test whether the server assumes a type or class based on client-controlled metadata.

## 95.3 Gadget reachability

Distinguish “deserialization occurs” from “security-sensitive gadget chain is reachable.” The latter requires evidence of a dangerous effect.

## 95.4 Integrity boundaries

Determine whether serialized state is integrity-protected and bound to the intended principal and purpose.

# 96. Business Logic and State-Machine Research

## 96.1 Extract invariants

For every workflow write statements such as:

```text
A discount must never reduce price below policy floor.
A refund cannot exceed captured amount.
An invitation cannot elevate its recipient beyond inviter authority.
A completed verification cannot be reused for a different account.
A workflow step cannot be skipped without equivalent proof.
```

These invariants are the actual test targets.

## 96.2 Transition bypass

Test whether the system permits forbidden state transitions through alternate endpoints, HTTP methods, UI paths, asynchronous jobs, or legacy APIs.

## 96.3 Quantity invariants

Look for count, balance, quota, credit, inventory, seat, or limit calculations that can be manipulated through repeated or concurrent legitimate operations.

## 96.4 Price and currency semantics

Model rounding, currency conversion, minimum/maximum amounts, discount application order, tax calculation order, and client/server disagreement.

## 96.5 Referral/invitation flows

Analyze who can create, redeem, transfer, revoke, and re-use an invitation or referral token and whether the token is bound to the intended actor/context.

# 97. Race Conditions and TOCTOU

## 97.1 Invariant race

Define the state that must never be simultaneously true and identify two operations that individually pass validation but conflict when interleaved.

## 97.2 Check/use separation

Look for:

```text
check permission → delay → mutate state
reserve resource → later finalize
validate coupon → redeem coupon
check balance → debit balance
check quota → consume quota
```

## 97.3 Concurrency experiment

Use the minimum concurrency that demonstrates the issue. Record ordering, request IDs, timestamps, and final state. Avoid high-volume stress if a small race is sufficient.

## 97.4 Queue/worker races

A vulnerability may exist between API acceptance and asynchronous worker execution even when the synchronous endpoint appears secure.

# 98. Cloud and Kubernetes Trust Graphs

## 98.1 IAM graph

Model principals, roles, resources, trust policies, service identities, and delegation edges.

## 98.2 Metadata trust boundary

If an SSRF primitive reaches cloud metadata, distinguish network reachability from credential retrieval and from usable privilege. Demonstrate only what is needed.

## 98.3 Container-to-control-plane boundaries

Inspect whether service accounts, workload identities, metadata proxies, or mounted credentials expose more authority than intended.

## 98.4 Kubernetes admission and RBAC

Model who can create pods, bind roles, impersonate identities, read secrets, or modify workloads. Test in authorized lab/engagement environments.

## 98.5 Namespace/tenant isolation

Treat namespace separation as a security boundary only when the platform's authorization policy actually relies on it.

# 99. CI/CD and Supply-Chain Research

## 99.1 Provenance graph

Model:

```text
source → build → dependency resolution → artifact → registry → deploy → runtime
```

Identify where integrity and identity are re-established at each transition.

## 99.2 Dependency confusion

Determine how package names are resolved and whether private/public namespace collisions are possible. Do not publish or inject malicious packages against real infrastructure without explicit authorization.

## 99.3 Build-trigger trust

Analyze pull-request workflows, branch protections, fork execution, secret exposure, deployment credentials, and artifact promotion logic.

## 99.4 Artifact substitution

Check signatures, digests, provenance attestations, and registry permissions rather than relying on mutable tags.

## 99.5 Workflow input injection

Identify whether untrusted pull-request metadata, issue titles, branch names, or commit messages become shell commands, workflow expressions, or deployment parameters.

# 100. Framework-Specific Research Layer

A mature agent should maintain framework adapters rather than assuming generic behavior.

## 100.1 Next.js / SSR frameworks

Model server/client component boundaries, route handlers, middleware, server actions, static rendering, dynamic rendering, caching, and request metadata propagation.

## 100.2 Django / Flask / FastAPI

Map middleware order, route decorators, exception handlers, object-level authorization, serializer validation, and async/sync boundaries.

## 100.3 Spring

Model filter chains, controller mappings, method security, serialization, expression languages, and actuator exposure.

## 100.4 Rails

Model controller filters, strong parameters, route constraints, signed identifiers, Active Record authorization assumptions, and background jobs.

## 100.5 Laravel

Model middleware, gates/policies, mass assignment, signed routes, queues, storage, and serialization.

## 100.6 Express / Node.js

Model middleware order, trust proxy configuration, route normalization, body-parser behavior, template rendering, and asynchronous job boundaries.

## 100.7 ASP.NET

Model middleware pipelines, authorization policies, model binding, antiforgery, claims transformation, serialization, and reverse-proxy integration.

# 101. HTTP Protocol Variant Research

## 101.1 HTTP/1.1

Analyze request framing, duplicate headers, connection reuse, normalization, and intermediary differences.

## 101.2 HTTP/2

Analyze protocol translation, pseudo-header semantics, stream handling, header compression boundaries, and downgrade paths.

## 101.3 HTTP/3 / QUIC

Where supported and authorized, model differences introduced by QUIC transport and HTTP/3 semantics, especially at proxy/CDN boundaries.

## 101.4 Method semantics

Compare behavior of standard and less-common methods only when the server advertises or accepts them. A method-level security discrepancy is meaningful only when it crosses a real authorization or integrity boundary.

# 102. Encoding, Canonicalization, and Unicode

## 102.1 Canonicalization pipeline

For every sensitive identifier, URL, filename, origin, header, and path, record the transformation sequence before and after validation.

## 102.2 Unicode normalization

Determine whether different components normalize strings differently and whether the discrepancy can change an authorization, routing, or identity decision.

## 102.3 Encoding layers

Model URL encoding, percent encoding, HTML encoding, JSON escaping, Unicode escapes, base64, compression, and nested encodings as distinct representations rather than interchangeable strings.

## 102.4 Path normalization

Compare routing, filesystem, proxy, and authorization normalization rules. A security decision made on one path representation can fail if execution uses another.

# 103. Error Handling and Exceptional Conditions

## 103.1 Fail-open vs fail-closed

For every rejected request, ask what the system does if a dependency times out, returns malformed data, or becomes unavailable. Security controls should not silently disappear on exceptional paths.

## 103.2 Partial transaction states

Look for operations that update some systems and not others after an exception. Inconsistent state can become a privilege or integrity vulnerability.

## 103.3 Retry semantics

Retries can duplicate side effects. Test whether idempotency keys or transaction identifiers are used where repeated requests can cause security-sensitive duplication.

## 103.4 Error-message privilege leaks

Different errors can reveal authorization state, resource existence, or internal policy. Validate whether the information materially assists unauthorized actions.

# 104. Logging, Detection, and Audit Integrity

## 104.1 Security-event coverage

Identify critical actions and whether they generate durable, attributable events.

## 104.2 Audit-log authorization

Determine whether attackers can modify, suppress, or generate misleading audit records.

## 104.3 Correlation integrity

Check whether request IDs, actor identities, and operation IDs remain consistent through asynchronous processing.

## 104.4 Alerting gaps

Treat missing alerts as a separate finding from prevention failure. Severity should depend on the real detection consequence, not assumed SOC capabilities.

# 105. Research Experiment Design

## 105.1 Controlled experiment

Every high-confidence test should have:

```text
H0 = secure behavior explains observation
H1 = security-boundary violation explains observation
```

The agent should actively attempt to disprove H1 before reporting it.

## 105.2 Negative controls

A negative control is a request expected not to trigger the behavior. For example, change an irrelevant parameter while holding the suspected trigger constant.

## 105.3 Positive controls

When safe, use a known-valid operation or deliberately authorized test case to demonstrate that the application path is reachable and functioning.

## 105.4 Repetition rule

Timing, race, cache, and intermittent parser behaviors require repetition. The agent must record sample count, distribution, and environmental noise rather than selecting the most favorable sample.

## 105.5 Single-variable mutation

Change one security-relevant variable at a time whenever possible. Multiple simultaneous mutations make causal inference weak.

## 105.6 Causal confidence

Prefer evidence where the candidate mutation produces a specific, reproducible effect that disappears when the mutation is reverted.

# 106. Tool Orchestration at Expert Level

The agent should choose tools by **information gain**, not by popularity.

```yaml
selection:
  question: "What unknown am I trying to resolve?"
  preferred_tool:
    capability: "best-fit-capability"
    evidence_quality: "high|medium|low"
  complementary_tools: []
  avoid_if:
    - duplicate_information
    - excessive_scope
    - destructive_behavior
```

A mature orchestration sequence is:

```text
passive discovery
→ low-noise active discovery
→ application-aware crawling
→ manual hypothesis generation
→ narrow automation
→ differential validation
→ evidence collection
```

The agent should not run the largest scanner simply because it is available.

# 107. Research Corpus → Agent Learning Loop

## 107.1 Source hierarchy

Prefer primary sources in this order:

1. vendor/security-team disclosure or advisory
2. original researcher write-up
3. official bug-bounty disclosure
4. authoritative framework/tool documentation
5. high-quality independent reproduction
6. secondary summaries

## 107.2 Research-card extraction

Each source should become a card containing:

```yaml
research_card:
  source:
  date:
  affected_component:
  primitive:
  preconditions:
  root_cause:
  exploit_path:
  observables:
  validation_method:
  false_positives:
  mitigations:
  novelty:
  transferable_principles:
```

## 107.3 Transfer principle extraction

Do not teach the agent merely that “researcher X used payload Y.” Teach it:

```text
What architectural condition made the technique possible?
What parser/state assumption failed?
What observation distinguished it from normal behavior?
What variants should be considered on another stack?
```

# 108. Novelty and Duplicate Reasoning

A sophisticated agent should compare findings using a feature vector:

```yaml
novelty_features:
  root_cause:
  affected_boundary:
  attack_primitive:
  endpoint_family:
  privilege_required:
  impact:
  exploit_precondition:
```

Two findings with different URLs may still be the same underlying bug. Conversely, two reports on the same endpoint may represent genuinely different root causes.

The agent should therefore compare **root cause and security impact**, not only URLs or payloads.

# 109. POC Engineering Standard

A good POC contains the minimum evidence necessary to prove the claim.

## Required structure

```text
1. Preconditions
2. Baseline request
3. Triggering request
4. Exact observed difference
5. Security boundary violated
6. Impact demonstration
7. Reproduction count
8. Cleanup / rollback
```

## POC minimization rule

Prefer:

```text
read-only proof
>
state-changing proof
>
destructive proof
```

Only move downward when the higher level cannot establish the security property and the engagement explicitly authorizes deeper validation.

# 110. Severity Calibration

Severity should be derived from evidence, not the vulnerability label.

The agent should separately score:

```text
attacker prerequisites
exploit reliability
confidentiality impact
integrity impact
availability impact
scope of affected principals
cross-tenant impact
persistence
chain dependencies
```

It should explicitly mark assumptions that are not demonstrated.

# 111. Report Generation Rules

A research-grade report should make the vulnerability independently reproducible.

## Required claims

Every major claim must map to evidence.

```yaml
claim:
  text:
  evidence_refs: []
  demonstrated: true
  assumed: false
```

## Forbidden report behavior

The agent must not:

- claim access to data it did not observe
- claim account takeover without proving the required boundary
- claim code execution from a parser primitive alone
- inflate impact through hypothetical multi-step chains
- hide uncertainty
- omit the baseline behavior
- omit material prerequisites

# 112. Retest and Regression Intelligence

A retest should compare the original hypothesis with the new implementation rather than merely rerun the same payload.

```yaml
retest:
  original_root_cause:
  original_security_invariant:
  original_evidence:
  new_behavior:
  control_result:
  regression_status:
  residual_risk:
```

A fix that blocks one payload but leaves the primitive reachable should be investigated as a potential incomplete remediation.

# 113. Agent Self-Critique Loop

Before reporting, the agent must answer:

1. What is the strongest alternative explanation?
2. What observation would disprove my hypothesis?
3. Have I reproduced the result?
4. Have I shown a real security-boundary violation?
5. Have I demonstrated impact rather than inferred it?
6. Am I accidentally relying on scanner confidence?
7. Could this be a duplicate or known behavior?
8. Is my PoC the least invasive proof?
9. Is every report claim supported by evidence?
10. Would a security reviewer reproduce this from my report alone?

If any critical answer is “no,” the state should remain `CANDIDATE` or `INCONCLUSIVE`.

# 114. Expert Coverage Matrix

The agent should maintain coverage across these dimensions:

| Dimension | Minimum coverage |
|---|---|
| Identity | login, recovery, MFA, sessions, federation |
| Authorization | object, function, property, tenant, workflow |
| Input handling | SQL, NoSQL, template, expression, LDAP, XPath, command, path |
| Browser | DOM XSS, CSP, CORS, postMessage, XS-Leaks, service workers |
| Protocol | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, SSE |
| API | REST, GraphQL, gRPC, webhooks |
| State | race, TOCTOU, async jobs, retries, idempotency |
| Caching | poisoning, deception, partitioning, invalidation |
| File handling | upload, archive, parser, transformation |
| Cloud | IAM, metadata, workload identity, storage, queues |
| Supply chain | dependencies, build, provenance, artifacts, deployment |
| Business logic | money, quotas, invitations, approvals, lifecycle |
| Infrastructure | DNS, CDN, WAF, proxy, service mesh |

# 115. Definition of Done for the Book

This book should not be considered complete merely because another vulnerability name has been added.

A domain is considered **deeply covered** only when it has:

```text
[ ] attack primitive model
[ ] threat assumptions
[ ] architecture variants
[ ] hypothesis families
[ ] reconnaissance signals
[ ] test methodology
[ ] differential experiments
[ ] expected secure behavior
[ ] vulnerable behavior
[ ] negative controls
[ ] false-positive taxonomy
[ ] validation gates
[ ] minimal safe POC method
[ ] impact model
[ ] chaining model
[ ] evidence requirements
[ ] duplicate/novelty guidance
[ ] severity guidance
[ ] report template
[ ] retest logic
[ ] machine-readable playbook
[ ] benchmark cases
```

This definition of done is deliberately stricter than “OWASP category covered.”

# 116. Final Principle for the AI Bug Hunter

The goal is not to create an agent that can generate the most payloads.

The goal is to create an agent that can **discover security invariants, formulate falsifiable hypotheses, run controlled experiments, reject its own false positives, prove real impact with minimal evidence, and communicate the result so another researcher can independently reproduce it.**

That is the standard by which every future section, tool integration, and research card should be evaluated.


# 51. Deep Coverage Completion Standard

This section freezes the definition of "deep coverage" used by the AI agent. A vulnerability family is not considered complete merely because its name, CWE, or a few payload examples are present. Each family must have an attack model, a decision model, an experiment model, evidence rules, and a machine-readable representation.

## 51.1 Mandatory depth fields

Every vulnerability family must answer all of the following:

1. **Security primitive** — what security property is being broken?
2. **Threat model** — attacker capability, victim role, trust level, and required state.
3. **Security invariant** — what must always remain true if the application is secure?
4. **Architecture variants** — monolith, reverse proxy, CDN, API gateway, microservice, browser client, worker, serverless, queue, webhook, third-party integration.
5. **State model** — relevant session, authorization, workflow, cache, retry, or protocol state.
6. **Input/control points** — every attacker-influenced field, header, path, object reference, cookie, token claim, uploaded artifact, callback, or timing event.
7. **Hypothesis families** — multiple plausible ways the invariant could fail.
8. **Baseline experiment** — a known-good observation under a controlled identity and state.
9. **Mutation strategy** — one variable changed at a time unless interaction is itself the hypothesis.
10. **Expected secure behavior** — what a correct implementation should do.
11. **Expected vulnerable behavior** — what would constitute a meaningful security-boundary violation.
12. **Observable set** — status, body, headers, cache state, side effects, timing, error class, downstream callbacks, state changes.
13. **Negative controls** — tests designed to explain away the observation without invoking a vulnerability.
14. **Positive controls** — where safe and authorized, a known-valid change demonstrating that the measurement can detect the condition.
15. **False-positive taxonomy** — common benign explanations and how to distinguish them.
16. **Validation gate** — minimum evidence required before classification as a true positive.
17. **Safe PoC** — smallest reproducible demonstration that proves the security boundary failure.
18. **Impact model** — confidentiality, integrity, availability, privilege, tenant isolation, financial, reputational, or workflow impact.
19. **Chaining model** — plausible follow-on vulnerabilities and explicit prerequisites.
20. **Evidence model** — immutable request/response pairs, identities, timestamps, state, screenshots, and reproduction notes.
21. **Report model** — concise title, root cause, reproduction, impact, evidence, remediation, and scope context.
22. **Retest model** — exact behavior to repeat after remediation.
23. **Benchmark model** — positive, negative, ambiguous, and regression cases.

## 51.2 Completion rule

A family is marked `deep_complete` only when all 23 fields exist in both human-readable documentation and machine-readable playbook form, and at least one benchmark exists for each major hypothesis family.

# 52. Deep Playbook: Broken Access Control and Multi-Tenant Isolation

## 52.1 Security primitive

The core property is **authorization correctness**: the principal performing an operation must be authorized for the specific resource, property, action, and tenant context.

A mature agent should treat authorization as a matrix, not a single boolean. Model:

`principal × resource × action × property × tenant × workflow state × channel`.

## 52.2 Hypothesis families

- Horizontal object access: one principal accesses another principal's object.
- Vertical function access: a lower-privilege principal invokes a higher-privilege function.
- Property-level write bypass: a caller can modify fields that should be server-controlled.
- Tenant escape: object references or service calls cross tenant boundaries.
- Mixed-tenant aggregation: list/search/export endpoints return objects outside the principal's tenant.
- Alternate endpoint authorization: a protected action is exposed through another route or version.
- Method confusion: authorization is implemented for one HTTP verb but not a semantically equivalent method.
- GraphQL resolver gap: top-level authorization exists while nested resolvers lack equivalent checks.
- WebSocket message gap: connection is authorized but individual message types are not.
- Asynchronous job gap: a job is created by one principal and later executed in another security context.
- Cache cross-user leakage: authorization is correct at origin but absent from an intermediate cache key.
- Export/reporting bypass: a privileged report function exposes data beyond the caller's normal object permissions.

## 52.3 Experiment design

Build at least two identities with different permissions and, where possible, two tenants. For every candidate operation record:

`identity, tenant, object_owner, action, endpoint, method, object_reference, baseline_result`.

Then mutate exactly one authorization dimension at a time. The agent must avoid treating different response codes alone as proof. A stronger result is a changed authorization decision plus access to data or a state transition demonstrably owned by another principal.

## 52.4 Negative controls

- Public or intentionally shareable objects.
- Objects belonging to the same test principal.
- Stale cached responses.
- Synthetic identifiers that happen to map to a public object.
- Administrative behavior intentionally exposed to service accounts.
- UI hiding a function while the documented API legitimately permits it.

## 52.5 Evidence standard

The evidence bundle should contain two identities, two ownership contexts, baseline and mutated requests, exact responses, object ownership proof, and a minimal demonstration of unauthorized read or state change. Avoid bulk extraction.

# 53. Deep Playbook: Authentication, Recovery, Sessions, and Identity State

Authentication must be modeled as a state machine rather than as a single login request.

## 53.1 State model

`anonymous → challenge → authenticated → elevated → reauthenticated → revoked → expired → recovered`.

The agent should inventory every transition and identify which credentials, factors, cookies, device bindings, or recovery artifacts authorize each transition.

## 53.2 Hypothesis families

- Account-recovery identity confusion.
- Recovery-token reuse or failure to invalidate.
- Session fixation or session continuity across privilege changes.
- Logout/revocation that does not invalidate server-side authorization state.
- MFA state desynchronization across channels.
- Remembered-device state not bound to the correct account.
- Password-reset and login identifiers normalized differently.
- Case, Unicode, whitespace, or canonicalization differences in identities.
- OAuth/OIDC account-linking confusion.
- Alternate authentication endpoints with weaker controls.
- Session cookie scope or partitioning errors.
- Concurrent-session policy bypass.

## 53.3 Validation principle

A valid finding requires evidence that the attacker-controlled state changes the authenticated identity or authorization state in a way the application did not intend. Mere response differences, generic account-existence signals, or rate-limit observations are not sufficient without the security impact defined by the program.

# 54. Deep Playbook: OAuth, OIDC, SAML, JWT, and SSO Trust Graphs

## 54.1 Trust graph

Represent the identity system as:

`browser → client → authorization server → identity provider → redirect endpoint → token endpoint → resource server → account-linking logic`.

Each edge is a trust transfer. The agent should ask what exact identifier crosses each edge, who can influence it, and what validation is performed before the next trust decision.

## 54.2 Hypothesis families

- Redirect URI policy mismatch.
- Authorization-response substitution.
- Client or tenant confusion.
- State validation gaps.
- PKCE binding errors.
- Token audience or issuer confusion.
- Cross-client token acceptance.
- Account-linking identity ambiguity.
- Identity-provider initiated login edge cases.
- SAML audience/recipient/destination validation gaps.
- Assertion-to-account mapping ambiguities.
- JWT algorithm/key/issuer/audience validation inconsistencies.
- Token accepted in a context different from the one it was minted for.
- Logout state inconsistencies across relying parties.

## 54.3 Evidence standard

The agent should prove the exact identity or authorization confusion, not merely demonstrate that a parameter can be changed. Evidence must show which trust edge was violated.

# 55. Deep Playbook: Injection as Interpreter Confusion

Injection is best modeled as a failure to preserve the intended data/code boundary within an interpreter.

## 55.1 Interpreter map

For every input, identify all possible sinks:

- SQL and database query languages.
- NoSQL query operators.
- LDAP filters.
- XPath/XQuery.
- OS command invocation.
- Template/expression languages.
- HTML/DOM/JavaScript contexts.
- CSS and URL contexts.
- XML parsers.
- Serialization formats.
- Search/query DSLs.
- Shell-like wrappers and subprocess APIs.

## 55.2 Hypothesis generation

The agent should trace input transformations from source to sink and record each parser boundary. A hypothesis becomes strong when the same value is interpreted differently between stages.

## 55.3 Differential methodology

Compare:

`literal input → encoded input → structurally changed input → semantically equivalent normalized input`.

The objective is not to maximize payload creativity. It is to detect a measurable change in the interpreter's meaning while keeping the surrounding request constant.

## 55.4 Validation

Require evidence that application semantics, not merely generic error handling, changed in an attacker-controlled way. Avoid destructive database commands, shell execution, or broad data extraction when a non-destructive oracle is sufficient.

# 56. Deep Playbook: SSRF and URL/Network Policy Differentials

## 56.1 SSRF decomposition

Split the problem into:

`input parser → canonicalizer → policy checker → resolver → proxy/client → destination → downstream authorization`.

A bypass exists when two stages disagree about the identity of the destination or the acceptability of the destination.

## 56.2 Hypothesis families

- Parser versus policy-checker disagreement.
- DNS resolution versus policy-checker disagreement.
- Redirect target not revalidated.
- IPv4/IPv6 canonicalization differences.
- Alternate textual address representations.
- Scheme or protocol confusion.
- Userinfo/authority parsing ambiguity.
- Proxy versus origin interpretation differences.
- Metadata service exposure.
- Internal service exposure through webhook/callback functionality.
- Credential propagation to unintended destinations.
- Service-mesh or sidecar reachability.

## 56.3 Validation hierarchy

1. Prove the application performs a server-side request.
2. Prove attacker influence over the destination.
3. Prove a destination class normally outside the application's intended trust boundary is reachable.
4. Demonstrate the smallest safe effect.
5. Stop before harvesting secrets or accessing unrelated internal systems.

# 57. Deep Playbook: HTTP Desynchronization and Parser Differential Analysis

## 57.1 Core model

Desynchronization is a disagreement about where one message ends and another begins. Model every intermediary:

`client → CDN → WAF → proxy → gateway → application server`.

For each hop record:

`protocol, framing rules, connection reuse, normalization, header handling, timeout behavior, response queuing`.

## 57.2 Families to model

- Content-Length versus Transfer-Encoding disagreement.
- Transfer-Encoding normalization differences.
- HTTP/2-to-HTTP/1.1 downgrade differences.
- Connection-state poisoning.
- CL.0 behavior.
- Browser-powered/client-side desync.
- Pause-based timing desync.
- Response-queue poisoning.
- Request routing inconsistencies.
- Host authority interpretation differences.

PortSwigger's current research explicitly treats browser-powered desync and CL.0 as important extensions of request-smuggling research; the agent should therefore not reduce desync testing to the classic CL.TE/TE.CL taxonomy. citeturn804084search7turn804084search10turn804084search12

## 57.3 Validation

Desync testing requires an explicit non-destructive oracle. Favor isolated test paths, unique markers, and controlled connection lifecycles. Never escalate to third-party requests or persistent poisoning merely to strengthen a finding when a connection-state oracle already proves the differential.

# 58. Deep Playbook: Cache Key, Cache Partition, and Cache-Deception Analysis

## 58.1 Cache model

Represent a cache as:

`key = f(host, path, query, selected headers, cookies, method, content-negotiation, framework normalization)`.

The agent should infer the effective key empirically by comparing semantically equivalent requests with controlled changes.

## 58.2 Hypotheses

- Unkeyed attacker-controlled input reflected into cached content.
- Different authorization contexts map to the same cache object.
- Query/path normalization causes collisions.
- Host or header normalization differs between cache and origin.
- Cache stores private content without the correct partition.
- Deceptive path classification makes sensitive content cacheable.

## 58.3 Validation

Use unique non-sensitive markers, multiple clients, and explicit cache-hit evidence. Separate origin behavior from cache behavior before attributing impact.

# 59. Deep Playbook: Race Conditions, TOCTOU, and Concurrency Invariants

## 59.1 Invariant-first model

Examples of invariants:

- A one-time token can be redeemed once.
- A balance cannot become negative through concurrent operations.
- A coupon cannot be consumed twice.
- A privilege change cannot be committed after revocation.
- A rate limit counts all concurrent attempts against the same policy.

## 59.2 Test design

The agent should first identify the invariant and the commit boundary, then synchronize multiple logically equivalent operations around the narrowest possible window. Evidence should show a state that cannot be produced by any valid serial execution.

## 59.3 False positives

- Eventual consistency misread as a race.
- Read-after-write replication lag.
- Idempotent duplicate requests.
- Asynchronous UI updates.
- Test harness timing artifacts.

# 60. Deep Playbook: File Uploads, Parsing, and Content-Processing Pipelines

Treat upload handling as a pipeline:

`transport → filename → MIME detection → extension handling → decompression → parser → transformation → storage → retrieval → secondary consumer`.

## 60.1 Hypotheses

- Validation occurs at a different stage than the dangerous parser.
- Filename and content-type are trusted inconsistently.
- Archive expansion changes the effective file path.
- Conversion service interprets attacker-controlled content differently from the web layer.
- Stored content is later executed or rendered in a different security context.
- Metadata is consumed by a privileged secondary service.

## 60.2 Evidence

Prefer proving an unsafe processing decision with a harmless marker or deliberately benign test artifact. Avoid weaponized documents when parser behavior can be established with non-destructive samples.

# 61. Deep Playbook: Deserialization and Type-Confusion Boundaries

Map every serialization boundary:

`client → gateway → service → queue → worker → datastore`.

For each boundary determine:

- format;
- parser implementation;
- type-resolution rules;
- polymorphism;
- trusted metadata;
- class/module resolution;
- schema validation;
- canonicalization.

Hypotheses include type confusion, unsafe polymorphic binding, schema mismatch, and differential interpretation across services.

Validation must demonstrate a security-relevant type transition or trust-boundary violation without requiring arbitrary code execution.

# 62. Deep Playbook: Business Logic and Sensitive Business Flows

The agent must reconstruct the business process before testing it.

## 62.1 State-machine representation

`state_0 --action--> state_1 --action--> state_2`.

For every transition record:

`actor, prerequisites, server-side checks, object ownership, monetary/quantity effect, reversibility, idempotency`.

## 62.2 Hypothesis families

- Skipping required transitions.
- Reordering operations.
- Repeating one-time operations.
- Cross-account operation substitution.
- Client-controlled price/quantity/role state.
- Negative or boundary values.
- Inconsistent server-side validation across channels.
- Parallel execution of mutually exclusive actions.
- Approval/review state bypass.
- Invitation or organization-management abuse.
- Referral/credit/reward duplication.

OWASP's API Top 10 explicitly recognizes unrestricted access to sensitive business flows as a separate risk, underscoring why an agent must analyze business invariants rather than limit itself to traditional injection classes. citeturn804084search1

# 63. Deep Playbook: Browser Security and Modern Client-Side Boundaries

## 63.1 Browser trust surfaces

Model:

`origin → document → storage → DOM → parser → JavaScript → worker/service worker → postMessage → navigation → fetch → cookies → cache`.

## 63.2 Hypotheses

- DOM sink reachable from attacker-controlled source.
- Origin confusion in `postMessage` sender/receiver validation.
- Unsafe target origin assumptions.
- URL/parser canonicalization differences.
- Storage isolation mistakes.
- Service-worker scope or lifecycle assumptions.
- Cross-origin data leakage through browser side channels.
- CSP assumptions contradicted by actual script-loading behavior.
- Client-side desynchronization using browser-compatible requests.

## 63.3 Validation

The agent should prove a browser security boundary violation in the minimum environment required. It should distinguish reflected application behavior from a browser-enforced policy failure.

# 64. Deep Playbook: Prototype Pollution and Object-Model Integrity

Model prototype pollution as three separate stages:

`primitive → polluted state → security-relevant gadget/effect`.

A candidate is incomplete if it only shows a write primitive with no security consequence. The agent should identify the object merge, path assignment, recursive traversal, or deserializer responsible, then determine whether a trusted consumer inherits the polluted value.

False positives include data-only pollution that is isolated to an attacker-owned object or is normalized before reaching a privileged consumer.

# 65. Deep Playbook: Webhooks, Callbacks, and Asynchronous Trust

Webhooks create a second authorization surface because the receiver trusts a message that arrives asynchronously.

Hypotheses:

- Signature verification over an ambiguous canonical representation.
- Replay acceptance beyond the intended window.
- Event type confused across tenants.
- Endpoint URL controlled by a lower-trust principal.
- Callback follows redirects into unintended destinations.
- Authentication applied to the synchronous request but not the asynchronous worker.
- Event ordering or duplicate-delivery creates a business-logic race.

The agent should model the original actor, event producer, transport, verifier, queue, and consumer as separate trust zones.

# 66. Deep Playbook: GraphQL Resolver and Schema-Level Authorization

GraphQL requires analysis at four levels:

`endpoint → operation → field → resolver/data source`.

Hypotheses:

- Introspection/metadata exposure that reveals sensitive operations.
- Field-level authorization gaps.
- Resolver authorization omitted for nested objects.
- Alias or fragment expansion bypasses a field restriction.
- Batch or query-composition differences bypass resource controls.
- Mutations enforce authorization differently from reads.
- Error behavior reveals hidden schema or authorization state.

The agent should construct a field/action matrix rather than treating the GraphQL endpoint as a single resource.

# 67. Deep Playbook: API Inventory, Version Drift, and Deprecated Surfaces

The inventory model is:

`host × API version × environment × authentication mode × route × operation × schema`.

The agent should correlate documentation, client binaries, frontend references, traffic, and observed endpoints. A deprecated version is not a vulnerability merely because it exists; the relevant question is whether the older surface has a materially weaker security boundary or exposes unintended functionality.

OWASP API Security explicitly identifies improper inventory management as API9:2023. citeturn804084search1

# 68. Deep Playbook: Unrestricted Resource Consumption

Model both technical and business resources:

`CPU, memory, storage, database work, network, email, SMS, third-party API calls, identity verification, GPU/time-intensive processing`.

Hypotheses should be based on the resource multiplier:

`attacker cost → target cost`.

Validation should use the smallest safe request count or workload sufficient to establish disproportionate consumption, with explicit program constraints and rate limits.

# 69. Deep Playbook: Unsafe Consumption of Third-Party APIs

Treat third-party data as **untrusted input**, even when it arrives through a trusted integration.

Model:

`third-party source → parser → normalization → validation → internal trust decision → downstream action`.

Hypotheses include malformed upstream fields, type confusion, trust amplification, signature/identity confusion, and unsafe URL/callback values. OWASP API10:2023 specifically identifies unsafe consumption of APIs as a risk. citeturn804084search1

# 70. Deep Playbook: Software Supply Chain and Build/Release Integrity

The agent should reason about provenance rather than merely scanning dependencies.

Model:

`source → dependency resolver → build → artifact → registry → deployment → runtime`.

Hypotheses:

- Dependency confusion.
- Typosquatting or namespace confusion.
- Mutable dependency resolution.
- Unpinned build inputs.
- CI secrets exposed to untrusted build stages.
- Artifact provenance mismatch.
- Unreviewed automation executing attacker-influenced files.
- Release channel or package metadata confusion.
- Build/test environments crossing trust boundaries.

Validation should avoid publishing packages or modifying release infrastructure. A program-authorized lab or safe proof of the trust-boundary flaw is preferred.

# 71. Deep Playbook: Cloud, IAM, Containers, and Kubernetes Trust Graphs

Represent the environment as:

`identity → role → permission → resource → trust relationship → workload → service account → secret → control plane`.

Hypotheses include excessive trust, unintended role assumption, cross-tenant or cross-account access, workload identity confusion, exposed management interfaces, and secret propagation across service boundaries.

A web bug-bounty agent should stop at the first independently reproducible boundary violation unless the program explicitly authorizes deeper cloud validation.

# 72. Deep Playbook: Exception, Error, Retry, and Fail-Open Behavior

Exceptional conditions are security-relevant state transitions.

The agent should inject safe failures around:

`timeouts, upstream failures, malformed but validly transportable data, duplicate callbacks, partial commits, expired credentials, dependency failures, retries, cancellation, and failover`.

Hypotheses:

- Fail-open authorization.
- Retry bypass of one-time checks.
- Partial transaction commit.
- Error path with weaker validation.
- Fallback endpoint with weaker authentication.
- Cache population on error responses.
- Logging or audit failure that hides a security decision.

OWASP Top 10:2025 explicitly introduces Mishandling of Exceptional Conditions as A10, so this class must be first-class in the agent's coverage model.

# 73. Deep Playbook: Observability, Audit, and Detection Integrity

Logging failures are not merely operational problems. They can become security issues when an attacker can:

- bypass an audit event;
- alter the actor identity recorded;
- cause high-value actions to appear benign;
- induce unbounded logging or alert suppression;
- exploit inconsistent timestamps or correlation IDs;
- create contradictory audit trails across services.

The agent should compare application state against emitted audit events for the same controlled action.

# 74. Deep Playbook: Canonicalization, Unicode, Encoding, and Normalization

Every security comparison should be mapped across layers:

`raw bytes → transport decoding → Unicode normalization → URL/path normalization → application parser → policy comparison → sink`.

Hypotheses arise when validation is performed on one representation while execution occurs on another.

The agent should maintain a transformation ledger that records the exact representation at each stage and identifies where equivalence classes diverge.

# 75. Deep Playbook: File Paths, Routing, and Resource Confusion

Model:

`HTTP path → router → canonicalizer → filesystem/object store → authorization → application resource`.

Hypotheses include normalization mismatch, encoded separator handling, case sensitivity differences, route shadowing, and authorization applied before canonicalization rather than after. The evidence standard is proof that the security decision was made on a different resource identity from the one actually served.

# 76. Deep Playbook: HTTP Method, Content Negotiation, and Semantic Drift

The agent should compare semantically equivalent operations across:

`GET/POST/PUT/PATCH/DELETE`, content types, alternate representations, method overrides, and API versions.

The key question is not whether an endpoint accepts an unexpected method; it is whether a security control is attached to a representation rather than to the actual state-changing operation.

# 77. Deep Playbook: CORS, CSRF, and Browser Credential Boundaries

Model browser credential attachment separately from application authorization.

Hypotheses include:

- Cross-origin credentialed read.
- Origin validation differences across endpoints.
- CSRF protection applied to one representation but not another.
- Same-site assumptions invalidated by deployment topology.
- Token-based APIs that still expose browser-credentialed state changes.
- Preflight/actual-request policy mismatch.

A finding should demonstrate a real attacker-origin capability rather than simply the presence of a permissive header.

# 78. Deep Playbook: Host, Forwarded, Authority, and Origin-Identity Confusion

Applications often reconstruct their own URL or security context from intermediary headers. Model:

`client header → proxy normalization → trusted-header reconstruction → application logic → generated link/cookie/redirect`.

Hypotheses include password-reset poisoning, redirect trust, cookie-domain confusion, cache-key poisoning, origin policy bypass, and tenant-routing confusion. The agent must distinguish harmless reflection from a security decision that consumes attacker-controlled authority data.

# 79. Deep Playbook: Multi-Channel and Multi-Client Consistency

Security rules should remain consistent across:

`web UI, mobile API, public API, GraphQL, WebSocket, background worker, email link, admin console, support tooling`.

The agent should create a **control parity matrix**. A security control implemented in one channel but absent in another is a high-value hypothesis source.

# 80. Deep Playbook: Chaining and Impact Graphs

A chain is not a list of bugs. It is a graph where each edge is justified by a prerequisite and security effect.

Represent:

`finding A --enables--> capability B --reaches--> trust boundary C --produces--> impact D`.

The agent should reject chains that depend on speculative assumptions. Each edge must have evidence or a clearly stated unverified dependency.

# 81. Deep Research Corpus Mining Standard

The research corpus should be mined for **root causes and transferable primitives**, not copied payloads.

## 81.1 Research-card extraction

For each public report or write-up extract:

- application architecture;
- vulnerability primitive;
- preconditions;
- attacker capabilities;
- exact trust boundary crossed;
- discovery signal;
- hypothesis that led to the finding;
- dead ends;
- validation evidence;
- impact;
- chain dependencies;
- disclosure acceptance/rejection reason when available;
- novelty characteristics;
- defensive root cause.

## 81.2 Corpus normalization

Normalize equivalent findings under a common primitive taxonomy. Preserve the source-specific technique as a variant, not as the primitive itself.

## 81.3 Research reliability

Source confidence should distinguish:

`official standard > vendor advisory > primary researcher disclosure > accepted bounty report > community write-up > unattributed payload repository`.

No single source should be treated as authoritative merely because it is popular.

# 82. Hypothesis Generation Engine 2.0

The agent should generate hypotheses from four inputs:

1. **Architecture evidence**
2. **Observed application behavior**
3. **Research-derived patterns**
4. **Security invariants**

A hypothesis score should consider:

`prior plausibility × attack-surface evidence × control weakness evidence × testability ÷ cost`.

The agent should prioritize hypotheses that are both high-value and experimentally distinguishable.

# 83. Differential Testing Engine 2.0

Differential testing should compare:

- identities;
- roles;
- tenants;
- methods;
- encodings;
- canonical forms;
- protocol versions;
- cache states;
- parser paths;
- concurrency levels;
- authenticated versus anonymous state;
- pre- and post-transition states.

The agent should preserve the **single-variable principle** until an interaction is itself the hypothesis.

## 83.1 Observation vectors

Represent a response as:

`status, headers, body fingerprint, semantic fields, timing distribution, cache indicators, side effects, downstream callbacks, state delta`.

Do not use raw byte differences alone as the classifier.

# 84. Negative-Control Library

A mature agent needs a reusable library of tests that should produce a negative result when a suspected vulnerability is absent.

Examples:

- same-user object;
- public object;
- random invalid object;
- expired token;
- different tenant with no object;
- known-safe encoding;
- cache-busting marker;
- no-op state change;
- serial versus concurrent execution;
- alternate endpoint that should share policy.

The purpose is to eliminate benign explanations before reporting.

# 85. Evidence Graph and Reproducibility

Every finding should form a graph:

`scope → asset → observation → hypothesis → test → request → response → state change → impact → report claim`.

Every report claim should point to at least one evidence node. Every evidence node should contain enough metadata to reproduce the observation within the same authorized environment.

# 86. Agent Self-Critique Gate

Before a finding is promoted to `confirmed`, the agent must answer:

1. What else could explain the observation?
2. What security invariant was violated?
3. Can the observation be reproduced?
4. What is the smallest proof?
5. Is the impact directly demonstrated or inferred?
6. Is this likely a duplicate of a known issue?
7. Did the test exceed program constraints?
8. Would a program reviewer consider the evidence sufficient without trusting the agent's narrative?

If any critical answer is unknown, keep the finding in `candidate` or `needs_validation` state.

# 87. Severity Calibration Engine 2.0

Severity should be derived from the demonstrated security property, not the presence of a scary primitive.

The agent should separately score:

`exploitability, required privileges, user interaction, blast radius, confidentiality impact, integrity impact, availability impact, business impact, scope crossing`.

A chain may increase impact, but the report must distinguish the primary validated flaw from dependent assumptions.

# 88. Retest and Regression Intelligence

A retest is not merely rerunning the original request.

The agent must determine whether remediation:

- removed the root cause;
- blocked the tested path but left an alternate path;
- changed the parser boundary;
- changed behavior only for the tested identity;
- moved the vulnerability to another endpoint;
- introduced a regression elsewhere.

The original hypothesis, evidence, and invariant should be preserved so the retest measures the same security property.

# 89. Architecture Packs

The agent should activate architecture-specific packs when evidence indicates:

- CDN + origin.
- WAF + reverse proxy.
- API gateway + microservices.
- GraphQL gateway + REST services.
- Browser SPA + JSON API.
- Serverless + managed services.
- Kubernetes ingress + service mesh.
- OAuth/OIDC centralized identity.
- Mobile client + public API.
- Webhook/event-driven backend.
- Queue/worker asynchronous processing.

Each pack modifies the hypothesis priority and the set of applicable differential tests.

# 90. Completion Matrix

The project is considered complete when every major family has:

`deep documentation + machine-readable playbook + tool mapping + negative controls + evidence schema + validation gate + benchmark + report template + retest model`.

No family is marked complete solely because the README contains a descriptive paragraph.

# 91. Final Operational Contract

The AI bug-bounty agent should optimize for **validated security signal**, not the number of requests, scanner alerts, payloads generated, or candidate findings.

The final operational rule is:

> Discover broadly, hypothesize deliberately, test differentially, validate skeptically, prove minimally, chain only when justified, document reproducibly, and stop when the security claim is established.

