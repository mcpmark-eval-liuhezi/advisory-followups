# Security advisory digest

Quarterly dependency-security review / customer-questionnaire backup. Every advisory record below was pulled live from the GitHub Advisory Database (global advisories API) at the time this digest was generated — nothing is reproduced from memory.

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

**What it is:** Remote code injection in Log4j. Log4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the LDAP JNDI parser. Apache Log4j2 <= 2.14.1 JNDI features used in configuration, log messages and parameters do not protect against attacker-controlled LDAP and other JNDI-related endpoints: an attacker who can control log messages or log-message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. Logging untrusted or user-controlled data with a vulnerable version — including error traces, authentication failures and other unexpected vectors of user-controlled input — can result in RCE against the application.

**Notes from the live record:**
- The 2.15.0 patch did not disable attacker-controlled JNDI lookups in all situations; the residual issue is tracked separately as CVE-2021-45046 / GHSA-7rjr-3q55-vv33.
- Log4j v1 is end-of-life, receives no patch for this issue, and is vulnerable to other RCE vectors; migration to 2.16.0 is recommended.
- The record also lists secondary affected Maven packages: `com.guicedee.services:log4j-core` (last affected `1.2.1.2-jre17`), `org.xbib.elasticsearch:log4j` (`6.3.2.1`), `uk.co.nichesolutions.logging.log4j:log4j-core` (`2.6.3-CUSTOM`), and `org.ops4j.pax.logging:pax-logging-log4j2` (ranges patched at `1.9.2`, `1.10.8`, `1.11.10` and `2.0.11`).
- Record published 2021-12-10; last modified 2025-10-22.

---

## 2. Heartbleed — OpenSSL

- **GHSA ID:** GHSA-w8r8-w5w4-4w4v
- **CVE:** CVE-2014-0160
- **Severity:** high — CVSS 3.1 score 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Affected package:** OpenSSL. Note: the live GHSA record carries no machine-readable package/version block (the advisory database entry has an empty `affected` array), so the affected range below is taken from the advisory's own text.
- **Affected versions:** OpenSSL 1.0.1 before 1.0.1g
- **Patched version:** 1.0.1g

**What it is:** The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to `d1_both.c` and `t1_lib.c` — the Heartbleed bug.

**Notes from the live record:** CWEs CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer) and CWE-125 (Out-of-bounds Read). Record published 2022-05-13; last modified 2025-10-22. This GHSA record is marked `unreviewed` (imported rather than GitHub-reviewed).

---

## 3. Most recent npm advisories (high and critical)

A scan of the npm ecosystem for currently listed high and critical advisories was run against the GitHub advisory API. The five most recently published advisories returned by that scan are listed below.

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
- **Summary:** Missing origin validation in Storybook preview allows code injection from malicious websites. A malicious website may be able to cause unauthorized file changes in a developer's project while an affected Storybook development server is running; under additional conditions a changed file could be executed by a local runtime with the developer's privileges. Published 2026-10-21T17:23:29Z.

### 3.2 GHSA-86wm-68pq-5jwq — @apostrophecms/import-export

- **GHSA ID:** GHSA-86wm-68pq-5jwq
- **CVE:** CVE-2026-113711
- **Severity:** high — CVSS 3.1 score 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
- **Affected package:** `@apostrophecms/import-export` (npm)
- **Affected versions:** `< 3.7.0`. The advisory text confirms `3.6.2` as affected and notes the issue may affect earlier 3.x releases carrying the same big-upload import implementation (exact introduction version unverified per the advisory author).
- **Patched version:** `3.7.0`
- **Summary:** Unauthenticated resource exhaustion via pre-auth aposBigUpload processing. The affected import API routes invoke `self.apos.http.bigUploadMiddleware()` before the actual import handler performs its authentication check, so unauthenticated requests can reach the `aposBigUpload` `start`, `chunk` and `end` operations — creating server-side upload state, writing chunk data to upload storage, triggering temporary-file processing and attacker-controlled cleanup amplification — before authentication is enforced. Published 2026-10-21T13:51:21Z.

### 3.3 GHSA-qx66-fv34-fjm8 — TanStack Start packages

- **GHSA ID:** GHSA-qx66-fv34-fjm8
- **CVE:** CVE-2026-102989
- **Severity:** critical — CVSS 3.1 score 9.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)
- **Affected packages / versions / patched version:**
  - `@tanstack/start-server-core` `>= 1.143.12, < 1.169.39` → patched `1.169.39`
  - `@tanstack/react-start` `>= 1.143.12, < 1.168.60` → patched `1.168.60`
  - `@tanstack/solid-start` `>= 1.143.12, < 1.168.57` → patched `1.168.57`
  - `@tanstack/vue-start` `>= 1.143.12, < 1.168.56` → patched `1.168.56`
- **Summary:** Unauthenticated reflected XSS in TanStack Start server-function responses. An unauthenticated attacker can craft a URL to a server function in an affected TanStack Start app; if someone opens the link, the app can return attacker-controlled HTML from its own origin and run the attacker's JavaScript there, able to access same-origin data available to that visitor and make requests with their authority. Published 2026-10-15T20:22:20Z.

### 3.4 GHSA-pq7j-f95f-qfcv — @anthropic-ai/claude-code

- **GHSA ID:** GHSA-pq7j-f95f-qfcv
- **CVE:** CVE-2026-86063
- **Severity:** high
- **Affected package:** `@anthropic-ai/claude-code` (npm)
- **Affected versions:** `< 2.1.179`
- **Patched version:** `2.1.179`
- **Summary:** Claude Code plugin hash-pin bypass. The plugin install flow checked out a marketplace's pinned commit SHA using `git checkout` without verifying that the resulting HEAD matched the pinned SHA; an attacker controlling a plugin's upstream repository could create a branch named identically to the pinned 40-character SHA so the checkout silently resolved to the attacker's branch tip, installing attacker-controlled code and bypassing the pinned hash. Published 2026-10-15T20:22:07Z.

### 3.5 GHSA-x586-xvc8-g7q6 — Qwik

- **GHSA ID:** GHSA-x586-xvc8-g7q6
- **CVE:** CVE-2026-84994
- **Severity:** high
- **Affected packages / versions / patched version:**
  - `@builder.io/qwik` `< 1.20.0` → patched `1.20.0`
  - `@qwik.dev/core` `< 2.0.0-beta37` → patched `2.0.0-beta37`
- **Summary:** Crashing any Qwik server via a Resource thenable. A Qwik server in the default configuration can be crashed with one unauthenticated HTTP request; during qwik-json body parsing, `ResourceSerializer.$fill$` resolves a QRL for an unregistered symbol, the rejection is orphaned, and Node terminates the process under its default unhandled-rejection policy. One unauthenticated request crashes the server, and looping keeps every replica dead. Published 2026-10-15T20:22:00Z.

---

## 4. Organization check — published repository security advisories

The authenticated account (HeziLiu) is a member of one organization visible to these credentials: **mcpmark-eval-liuhezi** (no teams).

- The organization-level query for published repository security advisories (`GET /orgs/mcpmark-eval-liuhezi/security-advisories?state=published`) was **not accessible** with the current personal access token — the API returned `403 Resource not accessible by personal access token`.
- As a fallback, the organization's security/advisory-named public repositories were checked individually: `security-audit`, `security-tracker`, `security-watchtower`, `security-review`, `advisory-sweep`, `sec-advisory-log`, `lodash-advisory-tracker`, `lodash-advisory-audit`, `log4shell-audit`, `log4shell-audit-2026`, `log4shell-advisory-notes`, `log4shell-remediation`. **Every one of these returned an empty advisory list — no published repository security advisories were found.**
- Private repositories in the organization (e.g. `security-triage`, `npm-advisory-audit-2026`, `log4j-advisory-report`, `advisory-brief-2026-10`, `advisory-remediation-tracker`, `dependency-security-review`) returned `404 Not Found` on the repository security-advisories endpoint with this token, so their advisories could not be enumerated.

**Conclusion:** no published repository security advisories were found in any organization repository that could be reached; the org-wide listing itself is blocked by the current token's permissions and would need a token with the appropriate organization/security-advisories scope to complete.
