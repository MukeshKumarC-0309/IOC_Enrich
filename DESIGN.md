# IOC Enrichment & Triage Tool — Design Document

## 1. Scope

**Indicator types supported (v1):** IP addresses and domains only.
**Explicitly deferred:** file hashes. Reason: VirusTotal's hash endpoint returns
a different data shape (AV engine detections vs. reputation score),
AbuseIPDB doesn't support hashes at all, and ATT&CK mapping for hashes would
require a separate malware-family lookup path. Adding this now would roughly
double the project's scope for a secondary priority. Noted as future work.

## 2. Sources & Verdict Thresholds

### AbuseIPDB
- Field used: `abuseConfidenceScore` (0–100, community-reported)
- Score > 75 → **malicious**
- Score 25–75 → **suspicious**
- Score < 25 → **clean**

### VirusTotal
- Field used: `last_analysis_stats` (malicious vendor count / total engines queried)
- Threshold is a **ratio**, not a raw count, since total engines queried varies
  per lookup (~70–90).
- malicious/total ≥ 10% → **malicious**
- 3–10% → **suspicious**
- < 3% → **clean**
- Note: VT carries *less* weight than AbuseIPDB in aggregation (see §3) because
  AV-engine flagging is noisier than community abuse reporting.

### URLhaus
- URLhaus is a curated **blocklist**, not a reputation/scoring engine — it can
  only confirm malicious, never vouch for clean.
- Match found → **malicious**
- No match → **not_found** (informative — "not on this blocklist" — but NOT
  treated as "clean")
- Query fails / error → **query_error** (no information gained)
- There is deliberately **no "clean" state** for URLhaus.

## 3. Aggregation Logic (deterministic, no ML/agent involved)

**Step 1 — URLhaus override:** if URLhaus returns a match, aggregated verdict
is forced to `malicious` regardless of AbuseIPDB/VT results. A confirmed
blocklist hit outweighs statistical AV noise. **Exception — high-volume host
suppression (added Phase 4):** a match carrying **`url_count >= 750`** does
**not** force `malicious`; the override is suppressed and the verdict falls
through to normal AbuseIPDB/VT voting (Step 2). This guards against
shared-hosting / CDN domains that are themselves benign but *host* malicious
content uploaded by others (e.g. `github.com`, observed at `url_count: 7930`
with VirusTotal 0/91 clean). When suppressed, the output flag
**`urlhaus_high_volume_host: true`** is set so the raw match is not lost even
though it does not drive the verdict; `url_count < 750` behaves exactly as
before.

> *Threshold caveat (provisional):* based on **one observed FP** (github.com,
> `url_count: 7930`) and **one observed collateral downgrade** of a real
> malware host (91.92.242.236, `url_count: 853`, `malicious → suspicious`).
> Needs more shared-hosting samples to calibrate properly. **Known limitation,
> not resolved in v1.**

**Step 2 — fallback (URLhaus not_found or query_error):** fall back to
AbuseIPDB and VT, weighted so AbuseIPDB's verdict carries more influence than
VT's (e.g. AbuseIPDB malicious → aggregated malicious even if VT is only
suspicious; AbuseIPDB suspicious + VT malicious → aggregated malicious, they
reinforce).

**Step 3 — genuine disagreement:** when AbuseIPDB and VT verdicts are at
opposite ends (one malicious, other clean), the aggregated verdict downgrades
to `suspicious` — **never silently resolves to clean**. `disagreement: true`
is set in the output.

## 4. Confidence Scoring

Based **only** on agreement between the two voting sources (AbuseIPDB, VT).
URLhaus is excluded from this tally — it structurally cannot "agree" toward
clean, so it's tracked separately as an override flag, not counted as a vote.

- **High** — AbuseIPDB and VT verdicts match exactly
- **Medium** — verdicts are adjacent (e.g. malicious + suspicious)
- **Low** — verdicts are at opposite ends (contradiction)

## 5. Recommendation Field

Deterministic lookup from confidence level (not free text per case):
- `high` → "Consistent signal across sources"
- `medium` → "Partial signal — review before escalation"
- `low` → "Sources disagree — manual review required before action"

## 6. MITRE ATT&CK Mapping

Rule-based, minimum viable set. Output is a **list** (an indicator can match
more than one rule).

- AbuseIPDB category in {brute-force, ssh, web-attack} → **T1110** (Brute
  Force / Credential Access)
- URLhaus match OR AbuseIPDB category in {C2, malware-distribution} →
  **T1071** (Application Layer Protocol / Command and Control)
- No rule matches → empty list (never force a guess)

> **Refined in §10.C (final rule set):** T1110 = AbuseIPDB category IDs
> {5, 18, 22} — "web-attack" (21) is **dropped**; T1071 = URLhaus match with
> `url_count < 750` only (the AbuseIPDB C2/malware branch is dropped, and
> high-volume shared-hosting matches are excluded — §3.1). See §10.C.

Rationale for these two techniques specifically: they represent different
stages/goals of an attack — T1110 serves Credential Access (getting in),
T1071 serves Command and Control (maintaining a channel after getting in) —
so the mapping logic needs to reason about attacker intent implied by the
report category, not just "bad IP → pick a technique."

## 7. Output Schema

```json
{
  "indicator": "1.2.3.4",
  "indicator_type": "ip",
  "sources": {
    "abuseipdb": {"status": "ok", "score": 82, "verdict": "malicious"},
    "virustotal": {"status": "ok", "malicious_ratio": "6/78", "verdict": "suspicious"},
    "urlhaus": {"status": "not_found"}
  },
  "status": "ok",
  "aggregated_verdict": "malicious",
  "urlhaus_override": false,
  "urlhaus_high_volume_host": false,
  "disagreement": false,
  "single_source": false,
  "mitre_technique": ["T1110"],
  "confidence": "high",
  "recommendation": "Consistent signal across sources",
  "timestamp": "2026-08-05T00:00:00Z"
}
```

**`status`** is `"ok"` for any usable assessment and `"error"` when no
reputation source returned data (§10.D). In the error case both
`aggregated_verdict` and `confidence` are `null` (never the string `"error"`),
while `recommendation` still carries an actionable string. `single_source` is
`true` when exactly one source voted. See §10.D–F for the full semantics.

## 8. Mode

**Single-indicator only for v1.** Batch processing with rate-limit-aware
queueing (VT free tier ≈ 4 req/min) is deliberately deferred — introduces
partial-failure handling and progress/resumability concerns that are a
separate problem from the core enrichment logic. Documented as a "Next
Steps" item in the README, not built.

## 9. Explicitly Out of Scope for v1

- File hash indicators
- Batch/queue processing
- LLM/agent-based disagreement resolution (kept fully deterministic and
  testable by design)
- Full MITRE ATT&CK matrix coverage (only T1110/T1071 mapped; more rules can
  be added later without changing the architecture)

## 10. Design Clarifications (Phase 2 prep)

These clarifications resolve ambiguities surfaced while prepping Phase 2.
They **refine** §1–9 without overriding any locked decision. Decided by the
project owner on 2026-08-06.

### 10.A Domain indicators & the single-voter path

- AbuseIPDB has no domain endpoint. For a **domain** indicator the voting
  pool is **VirusTotal alone**; the URLhaus override (§3.1) still applies on
  top.
- AbuseIPDB is shown in `sources` as **N/A / unavailable** — never omitted,
  and never treated as a "clean" vote.
- Any **single-voter** verdict reports `confidence: medium` plus a new
  boolean `single_source: true`. Confidence here reflects *lack of
  corroboration*, not verdict strength — so it is `medium` regardless of
  whether the lone verdict is clean, suspicious, or malicious.
- Dedicated recommendation string, parameterized by the source that voted:
  `"Single-source signal (<source> only) — corroborate before escalation."`
- **Interaction:** a URLhaus match on a domain forces
  `aggregated_verdict: malicious` with `urlhaus_override: true`, while
  `confidence` stays `medium` + `single_source: true` (§4 excludes URLhaus
  from the confidence tally; the blocklist certainty lives in the override
  flag, not in confidence).

### 10.B Full aggregation truth table (AbuseIPDB × VT)

| AbuseIPDB ↓ / VT → | clean | suspicious | malicious |
|---|---|---|---|
| **malicious**  | suspicious *(disagreement)* | malicious | malicious |
| **suspicious** | suspicious | suspicious | malicious |
| **clean**      | clean | suspicious | suspicious *(disagreement)* |

Collapsed rule:
1. Both clean → `clean`
2. malicious + clean (either order, opposite ends) → `suspicious`,
   `disagreement: true`
3. At least one malicious, neither clean → `malicious`
4. Otherwise (any suspicious present) → `suspicious`

**Note — weighting is now rationale-only.** With these choices the table is
fully symmetric: no cell's outcome depends on *which* source holds *which*
verdict. The §3.2 "AbuseIPDB weighted higher" statement is therefore retained
as **conceptual rationale only** and does not flip any aggregated verdict.
This is intentional: the tool **favors recall over precision** — it is a
human-in-the-loop triage aid, so a missed threat costs more than a false
positive an analyst clears in a minute. Do not "fix" recall-driven false
positives by quietly raising thresholds; that would undo this decision.

### 10.C ATT&CK category mapping — concrete AbuseIPDB IDs

- AbuseIPDB returns **numeric category IDs**, not the names used in §6; the
  mapping matches **directly on IDs**, never via string labels.
- **T1110** maps from AbuseIPDB category IDs **{5 FTP Brute-Force,
  18 Brute-Force, 22 SSH}**. Both **21 Web App Attack** and **16 SQL
  Injection** are **excluded** — neither is a credential-access signal (web
  app attack / injection are exploitation, ≈ T1190, out of scope), and neither
  is forced into a technique it doesn't fit (§6 "never force a guess").
  *This supersedes §6's inclusion of "web-attack" in the T1110 rule.*
- **T1071** fires **only on a URLhaus match with `url_count < 750`**. The §6
  branch "AbuseIPDB category in {C2, malware-distribution}" is **dropped**:
  those categories do not exist in AbuseIPDB's taxonomy. Category **20
  (Exploited Host)** was considered as a proxy and **rejected** — too
  weak/indirect a signal next to URLhaus's confirmed blocklist match. URLhaus
  is the sole, honest C2/malware signal.
- **High-volume shared-hosting exclusion (Phase 4).** A URLhaus match with
  `url_count >= 750` does **not** drive T1071, using the **same
  `URLHAUS_HIGH_VOLUME_THRESHOLD`** as the §3.1 override (the constant is
  shared, not duplicated). Rationale: a match too unreliable to drive the
  aggregated verdict is too unreliable to drive technique attribution. So
  `github.com` (url_count 7930) yields `mitre_technique: []`, not `["T1071"]`.
- **Domain limitation (known, not a bug):** T1110 is **structurally
  unreachable for domains** — AbuseIPDB never runs on a domain, so there are no
  categories to match, and no substitute (e.g. domain-pattern heuristic) is
  invented. For domains, only T1071 (via URLhaus) can ever appear. Note in the
  README.
- **Independence from aggregation (Rule 3):** the mapping is evaluated against
  **raw source data only** — it does not depend on the aggregated verdict or on
  `urlhaus_override`. An IP can surface **both** T1071 (URLhaus match) and
  T1110 (its own AbuseIPDB categories) independently. `[]` results only when no
  source yielded a usable signal — a lone surviving source still maps.
  - *Note on the shared threshold:* excluding high-volume matches from T1071
    does **not** breach this principle. Rule 3 forbids letting *verdict
    confidence* gate technique evidence; the `url_count >= 750` check instead
    judges the *underlying signal itself* unreliable, which applies equally to
    the verdict (§3.1) and to attribution. It shares a reliability threshold,
    not a verdict decision.

### 10.D Voting-source errors & zero-voter handling

A voter that times out, rate-limits (429), returns invalid-key (401/403), or
returns malformed data counts as **"did not vote,"** recorded in `sources`
with an error status (mirroring URLhaus `query_error`). Behavior keys off the
**count of voters (AbuseIPDB, VT) that returned a real verdict**:

- **2 voters** → §3 / §4 as written (`high` / `medium` / `low`).
- **1 voter** (domain, or one voter errored) → `single_source: true`,
  `confidence: medium` (reuses §10.A).
- **0 voters + URLhaus match** → `aggregated_verdict: malicious`,
  `urlhaus_override: true`, `confidence: low` (status stays `ok` — the
  blocklist match is usable data).
- **0 voters + no URLhaus info** → no usable data: `aggregated_verdict: null`,
  `confidence: null`, **`status: "error"`**.

**`error` is a status, not a verdict.** It lives in a separate `status` field
(`"ok"` | `"error"`), never as a 4th value alongside
malicious/suspicious/clean. In the error case both `aggregated_verdict` and
`confidence` are `null` — "no data in, no data out," kept consistent across
both fields rather than emitting a weak-but-real `low` (which properly means
"we have signal and it's contradictory/weak", a different state). The tool
must **never** emit `clean` when it has no data — that would violate §3.3's
spirit via a different path.

### 10.E Recommendation lookup (extended)

Recommendation is a **deterministic lookup over the defined situation** (not
confidence alone, and not free text per case — consistent with §5's intent).
The classifier is evaluated as **ordered guard clauses, most-authoritative
first**, so the error case is branched on as a distinct precondition — never
discovered by elimination through the other rows, which would read a `null`
verdict/confidence. Guard order:

`status == "error"` → `urlhaus_override` → `single_source` → two-voter
`confidence`.

| # | Situation (guard) | verdict | confidence | recommendation |
|---|---|---|---|---|
| 1 | `status == "error"` | null | null | "Insufficient data — sources unavailable; retry or investigate manually" |
| 2 | `urlhaus_override`, 0 voters | malicious | low | "Malicious per URLhaus blocklist; reputation sources unavailable — verdict rests on blocklist alone" |
| 3 | `urlhaus_override`, ≥1 voter | malicious | per voters | "Confirmed malicious — listed on URLhaus blocklist" |
| 4 | `single_source` (no override) | per that voter | medium | "Single-source signal (<source> only) — corroborate before escalation" |
| 5 | two voters agree | per §3 | high | "Consistent signal across sources" |
| 6 | two voters adjacent | per §3 | medium | "Partial signal — review before escalation" |
| 7 | two voters, opposite ends | suspicious + `disagreement` | low | "Sources disagree — manual review required before action" |

Notes:
- The override recommendation stays **silent on voters** (they're already in
  the `sources` block); a recommendation names data only when it changes the
  *instruction* — which is why row 4 names its lone source but rows 2–3 don't.
- `confidence: low` appears in rows 2, 3 (when voters contradict), and 7; the
  cases are disambiguated by the `urlhaus_override` / `disagreement` flags.
- Row 1 still emits a **non-null** `recommendation`: the field is analyst
  *instruction*, which stays valid even when the indicator assessment is null.

### 10.F Output schema additions (relative to §7)

- New field **`status`** (`"ok"` | `"error"`), now shown in the §7 schema.
- New field **`single_source`** (boolean; `false` on the normal two-voter IP
  path).
- New field **`urlhaus_high_volume_host`** (boolean; `true` when a URLhaus
  match had `url_count >= 750` and its override was therefore suppressed —
  §3.1). The `urlhaus` source entry still carries the raw `url_count`.
- **`aggregated_verdict`** may be **`null`** (error case) but never takes the
  string `"error"`; likewise **`confidence`** may be `null` in the error case.

**Per-source `status` (every source carries one).** No-data
(`not_applicable`) is kept distinct from tried-and-failed (`error` /
`query_error`) — different failure semantics get different words:

| Source | status values | extra fields |
|---|---|---|
| `abuseipdb` | `ok` / `not_applicable` / `error` | `ok`: `score`, `verdict` · `not_applicable`: prose `reason` · `error`: code `reason` |
| `virustotal` | `ok` / `error` | `ok`: `malicious_ratio`, `verdict` · `error`: code `reason` |
| `urlhaus` | `match` / `not_found` / `query_error` | `match`: `url_count` · `query_error`: code `reason` |

- `not_applicable` is AbuseIPDB on a domain; its `reason` is a human sentence
  (a structural, permanent fact — nobody retries it).
- URLhaus failure is `query_error`, not `error`: a blocklist-lookup failure is
  semantically distinct from a voter failure (§2).
- AbuseIPDB raw category IDs are **not** echoed here — their derived result is
  `mitre_technique` (avoids two representations of the same data).

**Error `reason` codes** (machine-readable — supports retry logic, metrics,
and failure-type dashboards without parsing prose):

| code | meaning |
|---|---|
| `timeout` | request exceeded `HTTP_TIMEOUT` and was abandoned |
| `rate_limit` | API returned HTTP 429 (quota / rate limit hit) |
| `invalid_key` | missing or rejected credentials (HTTP 401 / 403) |
| `http_error` | other non-200 response, or a connection-level failure |
| `malformed` | HTTP 200 but unparseable / unexpected shape (incl. VirusTotal `total == 0`) |

### 10.G Implementation edge cases

Defensive choices for cases §1–9 don't explicitly cover. Each leans the way
the design already leans (recall over precision, never resolve to clean, no
hidden knobs). Decided by the project owner on 2026-08-06.

- **VirusTotal `total == 0`** (no engines returned data) → treated as a
  **non-vote** (`malformed`, per §10.D), because the §2 verdict is a *ratio*
  and the ratio is undefined with zero engines. Never forced to `clean`
  (would violate §3.3's spirit). Flows through the §10.D voter-count
  machinery as a missing voter.
- **AbuseIPDB category matching** — AbuseIPDB returns categories **per
  report**, not one category per IP. The client collects the **union of
  distinct category IDs across all reports** in the lookback window, and the
  §6/§10.C ATT&CK rule fires when **any** reported category is in the mapped
  set (any of {5, 18, 22} → T1110). Recall-favoring, consistent with
  §10.B: a single credible brute-force report surfaces for a human rather than
  being suppressed.
- **AbuseIPDB lookback window** — the confidence score and category set depend
  on `maxAgeInDays`, unspecified in §1–9. Defaulted to **90 days**
  (AbuseIPDB's own doc default), overridable via `.env`
  (`ABUSEIPDB_MAX_AGE_DAYS`). Shorter = fresher but less history; longer =
  more history but staler reports can inflate the score.
- **URLhaus non-`ok`/`no_results` statuses** (invalid host, missing auth,
  etc.) and any non-200 HTTP response map to the URLhaus **`query_error`**
  state (no information gained).
- **IPv6** is accepted by the indicator classifier; both AbuseIPDB and
  VirusTotal support IPv6 lookups.
