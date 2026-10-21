# Security advisory digest

Quarterly dependency-security review / customer-questionnaire backup. Every advisory record below was pulled live from the GitHub Advisory Database (global advisories API) at the time this digest was generated — nothing is reproduced from memory. Follow-up tracking: [Security advisory follow-ups (#1)](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/1).

---

## 1. Log4Shell — Apache Log4j 2

- **GHSA ID:** GHSA-jfh8-c2jp-5v3q
- **CVE:** CVE-2021-44228
- **Severity:** critical — CVSS 3.1 score 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H`)
- **Affected package:** `org.apache.logging.log4j:log4j-core` (Maven). Per the advisory, only `log4j-core` is directly affected; `org.apache.logging.log4j:log4j-api` should be kept at the same version for compatibility.
- **Affected versions:**
  - `>= 2.13.0, < 2.15.0`
  - `>= 2.0-beta9, < 2.3.1`
  - `>= 2.4, < 2.12.2`
- **Patched version:** `2.15.0` is the first patched release for the 2.13+ line. Backported fixes also shipped in `2.3.1` and `2.12.2` (with an additional `2.12.3` release noted in the advisory). The advisory's remediation guidance is to move to `2.16.0`, which disables JNDI by default and removes message-lookup support entirely.
- **Tracking:** [issue #2](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/2)

**What it is:** Remote code injection in Log4j via the LDAP JNDI parser. Log4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the LDAP JNDI parser. Apache Log4j2 <= 2.14.1 JNDI features used in configuration, log messages and parameters do not protect against attacker-controlled LDAP and other JNDI-related endpoints: an attacker who can control log messages or log-message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. Logging untrusted or user-controlled data with a vulnerable version — including error traces, authentication failures and other unexpected vectors of user-controlled input — can result in RCE against the application.

**Notes from the live record:**
- The 2.15.0 patch did not disable attacker-controlled JNDI lookups in all situations; the residual issue is tracked separately as CVE-2021-45046 / GHSA-7rjr-3q55-vv33.
- Log4j v1 is end-of-life, receives no patch for this issue, and is vulnerable to other RCE vectors; migration to 2.16.0 is recommended.
- The record also lists secondary affected Maven packages: `com.guicedee.services:log4j-core` (last affected `1.2.1.2-jre17`), `org.xbib.elasticsearch:log4j` (`6.3.2.1`), `uk.co.nichesolutions.logging.log4j:log4j-core` (`2.6.3-CUSTOM`), and `org.ops4j.pax.logging:pax-logging-log4j2` (ranges patched at `1.9.2`, `1.10.8`, `1.11.10` and `2.0.11`).
- CWEs: CWE-20, CWE-400, CWE-502, CWE-917. Record published 2021-12-10; last modified 2025-10-22.

---

## 2. Heartbleed — OpenSSL

- **GHSA ID:** GHSA-w8r8-w5w4-4w4v
- **CVE:** CVE-2014-0160
- **Severity:** high — CVSS 3.1 score 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Affected package:** OpenSSL. Note: the live GHSA record carries no machine-readable package/version block (the advisory database entry has an empty `affected` array), so the affected range below is taken from the advisory's own text.
- **Affected versions:** OpenSSL 1.0.1 before 1.0.1g (both the TLS and DTLS implementations)
- **Patched version:** 1.0.1g
- **Tracking:** [issue #5](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/5)

**What it is:** The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to `d1_both.c` and `t1_lib.c` — the Heartbleed bug.

**Notes from the live record:** CWEs CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer) and CWE-125 (Out-of-bounds Read). Record published 2022-05-13; last modified 2025-10-22. This GHSA record is marked `unreviewed` (imported rather than GitHub-reviewed).

---

## 3. Most recent npm advisories (high and critical)

**What the scan returned.** The npm ecosystem was scanned for currently listed advisories at high and critical severity. The undated ecosystem queries returned, as their newest listings, GHSA-f2ph-cmg5-wxc8 (critical, `storybook`, published 2026-10-21T17:23:29Z) and GHSA-86wm-68pq-5jwq (high, `@apostrophecms/import-export`, published 2026-10-21T13:51:21Z). Follow-up queries of the same scan over publish-date windows additionally returned GHSA-gfr2-rv44-r23c (high, `markdown-it`, 2026-10-20T20:28:44Z), GHSA-jm63-cq47-j5jp (high, `@modelcontextprotocol/server`, 2026-10-20T20:07:29Z) and GHSA-qx66-fv34-fjm8 (critical, TanStack Start packages, 2026-10-15T20:22:20Z). Those five are the most recent high/critical npm advisories the scan returned, listed below most-recent-first.

### 3.1 GHSA-f2ph-cmg5-wxc8 — storybook

- **GHSA ID:** GHSA-f2ph-cmg5-wxc8
- **CVE:** CVE-2026-114125
- **Severity:** critical
- **Affected package:** `storybook` (npm). The record also lists scoped packages such as `@storybook/core` and `@storybook/core-server` with the same per-major boundaries.
- **Affected versions / patched version:**
  - `>= 8.0.0, < 8.6.19` → patched `8.6.19`
  - `>= 9.0.0, < 9.1.21` → patched `9.1.21`
  - `>= 10.0.0, < 10.6.2` → patched `10.6.2`
  - `>= 11.0.0-alpha.0, < 11.0.0-alpha.6` → patched `11.0.0-alpha.6`
- **Summary:** Missing origin validation in Storybook preview allows code injection from malicious websites. A malicious website may be able to cause unauthorized file changes in a developer's project while an affected Storybook development server is running; under additional conditions a changed file could be executed by a local runtime with the developer's privileges. Not impacted if the dev server is never opened in a browser, or if a built version of Storybook is used. Published 2026-10-21T17:23:29Z.
- **Tracking:** [issue #3](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/3)

### 3.2 GHSA-86wm-68pq-5jwq — @apostrophecms/import-export

- **GHSA ID:** GHSA-86wm-68pq-5jwq
- **CVE:** CVE-2026-113711
- **Severity:** high — CVSS 3.1 score 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected package:** `@apostrophecms/import-export` (npm)
- **Affected versions:** `< 3.7.0`. The advisory text confirms `3.6.2` as affected and notes the issue may affect earlier 3.x releases carrying the same big-upload import implementation (exact introduction version unverified per the advisory author).
- **Patched version:** `3.7.0`
- **Summary:** Unauthenticated resource exhaustion via pre-auth aposBigUpload processing. The affected import API routes invoke `self.apos.http.bigUploadMiddleware()` before the actual import handler performs its authentication check, so unauthenticated requests can reach the `aposBigUpload` `start`, `chunk` and `end` operations — creating server-side upload state, writing chunk data to upload storage, triggering temporary-file processing and attacker-controlled cleanup amplification — before authentication is enforced. Published 2026-10-21T13:51:21Z.
- **Tracking:** [issue #6](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/6)

### 3.3 GHSA-gfr2-rv44-r23c — markdown-it

- **GHSA ID:** GHSA-gfr2-rv44-r23c
- **CVE:** CVE-2026-111758
- **Severity:** high — CVSS 3.1 score 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected package:** `markdown-it` (npm)
- **Affected versions / patched version:**
  - `>= 14.1.0, < 14.3.3` → patched `14.3.3`
  - `>= 15.0.0, < 15.0.3` → patched `15.0.3`
- **Summary:** Quadratic-time rendering of a single multi-line link reference definition with default options (regression since 14.0). A link reference definition whose label or title is never closed is O(n²): continuation lines are pulled lazily with `str += lineContent` and the subsequent `charCodeAt`/`slice` calls flatten the V8 cons-string, copying everything collected so far. A ~400 KB request body blocks the Node.js event loop for about 18 seconds and an ~800 KB body for about 74 seconds. Reachable with default options — no opt-in required. Published 2026-10-20T20:28:44Z.
- **Tracking:** [issue #10](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/10)

### 3.4 GHSA-jm63-cq47-j5jp — @modelcontextprotocol/server

- **GHSA ID:** GHSA-jm63-cq47-j5jp
- **CVE:** CVE-2026-111770
- **Severity:** high — CVSS 3.1 score 7.7 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H`)
- **Affected package:** `@modelcontextprotocol/server` (npm)
- **Affected versions:** `>= 2.0.0, < 2.3.0`
- **Patched version:** `2.3.0` (a code change is also required: the SDK now refuses to be shared, so an affected app must build a new `McpServer`/transport per request or per session, or use `createMcpHandler()` with a factory)
- **Summary:** Shared transport or server instances delivered one HTTP client's messages to another. Messages were matched to a connection by JSON-RPC `id` alone, and SDK clients number requests from 0, so ids collide in normal use. Affected when more than one client can reach the HTTP endpoint and the transport or server is created once at startup instead of once per request or per session. Published 2026-10-20T20:07:29Z.
- **Tracking:** [issue #11](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/11)

### 3.5 GHSA-qx66-fv34-fjm8 — TanStack Start packages

- **GHSA ID:** GHSA-qx66-fv34-fjm8
- **CVE:** CVE-2026-102989
- **Severity:** critical — CVSS 3.1 score 9.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)
- **Affected packages / versions / patched version:**
  - `@tanstack/start-server-core` `>= 1.143.12, < 1.169.39` → patched `1.169.39`
  - `@tanstack/react-start` `>= 1.143.12, < 1.168.60` → patched `1.168.60`
  - `@tanstack/solid-start` `>= 1.143.12, < 1.168.57` → patched `1.168.57`
  - `@tanstack/vue-start` `>= 1.143.12, < 1.168.56` → patched `1.168.56`
- **Summary:** Unauthenticated reflected XSS in TanStack Start server-function responses. An unauthenticated attacker can craft a URL to a server function in an affected TanStack Start app; if someone opens the link, the app can return attacker-controlled HTML from its own origin and run the attacker's JavaScript there, able to access same-origin data available to that visitor and make requests with their authority. The fix limits client-supplied server-function input to public fields and validates responses at the server boundary. Published 2026-10-15T20:22:20Z.
- **Tracking:** [issue #4](https://github.com/mcpmark-eval-liuhezi/advisory-followups/issues/4)

---

## 4. Organization check — published repository security advisories

**What the check turned up: no published repository security advisories were found.**

- The account is a member of one organization visible to this tooling: **mcpmark-eval-liuhezi** (no sub-teams).
- The organization-wide advisory listing (`/orgs/mcpmark-eval-liuhezi/security-advisories`) could not be read: it returned **HTTP 403 — "Resource not accessible by personal access token"**, both with and without a `state=published` filter.
- As a fallback, repository-level security-advisory listings were checked for the organization's repositories. Every repository that returned a result returned an **empty list `[]`** — including shanghai-trip-plan, pub-quiz-internet-culture, throwback-friday, aapl-options-onboarding, onboarding-runbook-demo, deploy-runbook, cbdc-reading-list, agent-lab-notes, github-automation-audit, apple-equity-research, dependency-watch-2, minimist-audit and security-review-dryrun.
- A few repositories returned HTTP 404 for that endpoint, i.e. no advisory listing was available for them: transformer-repro-notes, q3-ai-spend-review, release-notes-bot, oncall-handover-runbook, workflow-demo-sandbox.
- **Conclusion:** no published repository security advisories were found. Because the org-wide endpoint was inaccessible to the token, this conclusion rests on repository-level checks of the visible repositories rather than an organization-wide listing.
