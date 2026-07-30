# PRD: `kubectl trivy analyze` — AI-Assisted Vulnerability Triage

**Status:** Refined — course-informed (see §7 for resolved/deferred decisions)
**Owner:** Brandon
**Created:** 2026-07-28
**Refined:** 2026-07-30
**Context:** Platform 101 → Building with the Claude API, Project 1

---

## 1. Background

This is Project 1 for the "Building with the Claude API" course. The assignment calls for
a properly-built API analysis tool: structured tool-use output instead of prose parsing,
prompt caching for large context, streaming, and Batch API for bulk sweeps — with a
token/cost table as the artifact (cost per analysis before vs. after caching and model
routing).

`kubectl-trivy` (this repo) already does the hard part of sourcing real data: it discovers
every container image running in a namespace and pulls raw Trivy vulnerability-scan JSON
per image (see `docs/spec.md`). Today that JSON is reduced to per-severity counts via
`jq`-style parsing and printed as a table. This PRD scopes a `kubectl trivy analyze`
subcommand that replaces the counting step with an LLM triage pass — turning "214 findings,
18 HIGH" into "2 things you actually need to patch this week" — and produces the token/cost
comparison the course project asks for, grounded in a real workload instead of synthetic
data.

**This PRD has been refined** after completing the course material on structured outputs,
prompt caching, and the Batch API. The refinement corrected several assumptions in the
original draft (see §5.1–§5.4) and resolved the open questions from §7 of the draft. It
now unblocks the tech-spec/ADR work (issue #2).

---

## 2. Problem Statement

The existing `kubectl trivy` output aggregates by severity only. A cluster scan routinely
returns hundreds of findings per image; severity alone doesn't tell an operator which of
those findings are actually reachable, already fixed upstream, or safe to defer. Humans
end up re-deriving that judgment by hand, per finding, every scan. There's also no answer
to "what would this cost to run against our whole fleet, on every deploy?" — the question
FDEs are asked constantly and rarely have a real number for.

## 3. Goals

- Replace severity-count aggregation with per-finding AI triage: exploitability in context,
  fix availability, and a recommended action.
- Structured tool-use output — the model fills a typed schema, not prose the CLI re-parses.
  The tool call is forced (not left to the model's discretion) so every finding is
  guaranteed a structured verdict.
- Two-tier model routing: Haiku 4.5 for bulk triage, Opus 5 escalation for ambiguous /
  high-severity calls, using an escalation signal that's independent of the triage verdict
  itself (see §5.1).
- Prompt caching across the shared triage policy + system prompt, since it's identical
  across every image in a sweep — sized and configured to actually hit on both models used
  (see §5.3).
- Batch API for whole-namespace/whole-cluster sweeps (non-interactive, latency-insensitive),
  one entry per finding.
- Streaming for the single-image interactive explain path.
- Produce a real, reproducible token/cost table: naive vs. +routing vs. +caching vs. +batch,
  computed from actual API `usage` fields once implementation lands — not illustrative
  numbers presented as real.

## 4. Non-Goals

- Auto-remediation (opening PRs, patching images, restarting workloads). Analysis only.
- Persisting scan history / trend tracking across runs (no database — matches the existing
  tool's non-goals in `docs/spec.md`).
- A "submit now, check later" async mode. `analyze` is one synchronous, blocking CLI
  invocation from scan through triage results (see §5.4) — no batch handle is persisted
  for a later, separate invocation to pick up.
- Replacing Trivy's scan engine or vulnerability database. This layer only triages Trivy's
  existing output.
- A hosted/multi-tenant service. This is a CLI plugin, same as v1.
- Live cluster-exposure context (Service type, NetworkPolicy, ingress) for MVP. Triage runs
  on image + finding data only; see §7 for the reasoning and what would be needed to add it
  later.

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  kubectl trivy scan -n <ns>  (existing Go, unchanged)            │
│    getImages()  →  trivy image --server ... --format json        │
│    per-image raw Trivy scan JSON                                 │
└───────────────────────────────┬───────────────────────────────────┘
                                 │  vuln JSON blobs, one per image
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  kubectl trivy analyze  (new subcommand, same binary)             │
│                                                                     │
│  1. Batch submit: one Messages Batch request per finding, using   │
│     a forced tool-use call instead of jq/regex parsing            │
│  2. Model routing: Haiku 4.5 triage → Opus 5 escalation, on a     │
│     self-reported signal decoupled from the triage verdict        │
│  3. Prompt caching: cache_control on the shared system prompt +   │
│     triage policy, sized and TTL'd to actually hit on both models │
│  4. Streaming: single-image interactive "explain this CVE" path   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.1 Structured tool-use instead of prose/jq parsing

Every finding in a Trivy report is triaged via a single, **forced** tool call — not free
text, and not left to the model's discretion via `tool_choice: "auto"`:

```json
{
  "name": "triage_vulnerability",
  "description": "Record a triage verdict for one CVE found in a container image scan",
  "strict": true,
  "input_schema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "cve_id": {"type": "string"},
      "severity": {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]},
      "exploitable_in_context": {"type": "boolean"},
      "fix_available": {"type": "boolean"},
      "recommended_action": {
        "type": "string",
        "enum": ["patch_now", "schedule", "accept_risk"]
      },
      "needs_escalation": {
        "type": "boolean",
        "description": "True if this call is not confident and should be re-triaged by a larger model."
      },
      "reasoning": {"type": "string"}
    },
    "required": [
      "cve_id", "severity", "exploitable_in_context", "fix_available",
      "recommended_action", "needs_escalation"
    ]
  }
}
```

Request-level: `tool_choice: {"type": "tool", "name": "triage_vulnerability"}`. This
guarantees `tool_use.input` is produced for every finding — the model can't answer with
prose instead of a tool call. The model receives the raw (trimmed) Trivy finding plus
whatever cluster context is available (image only for MVP — see §7) — not asked to write
prose that gets re-parsed.

**Change from the original draft:** `recommended_action` no longer carries a
`needs_human_review` value. Mixing a routing signal into the verdict enum forced the model
to conflate "what should happen to this CVE" with "am I confident enough to answer this
myself," and forced the CLI's action-summary logic (§6.1) to special-case an enum member
that isn't actually an action. `needs_escalation` is now a separate, independent boolean —
the escalation rule in §5.2 reads it directly, never the verdict.

`recommended_action` also drops the implicit `clean` state from the original schema: an
image with zero findings has nothing to triage, so `CLEAN` in §6.1 is a CLI-computed
per-image summary state (no findings returned), not a per-finding model output. Keeping it
out of the enum keeps the schema honest about what the model is actually asked to decide.

### 5.2 Model routing — Haiku triage, Opus escalation

- **Pass 1 (Haiku 4.5):** every finding across every image gets a `triage_vulnerability`
  call. This is the bulk of volume — typically 80–95% of CVEs in a real scan are
  LOW/MEDIUM with no real ambiguity.
- **Escalation trigger — re-run through Opus 5 with fuller context if *any* of:**
  1. `needs_escalation: true` — the model's own signal that it isn't confident.
  2. `severity` is CRITICAL/HIGH **and** `exploitable_in_context: true` — the original
     draft's rule.
  3. `severity` is CRITICAL/HIGH **and** `recommended_action: "accept_risk"` — added during
     this refinement. This closes the specific failure mode named in the original draft's
     open questions: a false `accept_risk` verdict on a serious CVE where Haiku judged it
     unexploitable is exactly the highest-consequence error this tool can make, and it
     wouldn't have triggered escalation under clause 2 alone (clause 2 only fires when
     `exploitable_in_context` is true). Clause 3 forces a second look specifically at
     "serious CVE, but I'm dismissing it" verdicts.
- This is the routing decision the course project explicitly asks to demonstrate, and it's
  the primary cost lever in the results table below. The exact thresholds (which severities,
  whether MEDIUM should ever escalate) are a tuning question that needs a real eval set —
  see §7. The three-clause structure above is the shipped starting point, not the final
  calibration.

### 5.3 Prompt caching

The system prompt (triage instructions, the tool schema, the org's risk policy) is
identical across every finding in a sweep, so `cache_control` goes on the last block of
that shared prefix; the varying per-finding Trivy data goes in the user turn, uncached.

**Two corrections from the original draft, both course-informed:**

1. **Minimum cacheable prefix differs by model, and Haiku 4.5's is high.** Claude Opus 5's
   minimum is 512 tokens, but Haiku 4.5's is 4096 tokens — and Haiku 4.5 runs the bulk pass
   (§5.2). If the shared system prompt (triage instructions + tool schema + risk policy)
   comes in under 4096 tokens, it silently won't cache on Haiku 4.5 at all —
   `cache_creation_input_tokens` reports 0 with no error. The original draft's caching
   section didn't account for this. Action: either write a system prompt substantial enough
   to clear 4096 tokens on its own (a real, detailed risk policy plus a few worked
   triage examples usually gets there), or accept that caching benefit is Opus-escalation-only
   and say so explicitly in the cost report rather than assuming it applies everywhere.
2. **TTL: use the 1-hour cache (`ttl: "1h"`), not the 5-minute default.** The original
   draft assumed "a cluster sweep is dozens-to-hundreds of images hitting the same cached
   prefix within minutes." That's true for the *scan* step, but §5.4 batches every finding
   through the Batch API, and Batch API gives no guarantee that entries from one sweep are
   processed within 5 minutes of each other — only that they complete within the batch's
   processing window. A 5-minute TTL risks the cache expiring between batch entries under
   normal queueing, silently reverting every subsequent entry to a full-price write. The
   1-hour TTL costs a 2x write premium instead of 1.25x, but breaks even at 3 reads instead
   of 2 — trivially cleared by a sweep of dozens-to-hundreds of findings, and far more
   resilient to batch scheduling variance.

**Cache-hit rate is a benchmarking output, not a design assumption.** The original draft's
"84.7% cache hit rate" was illustrative but stated as if measured. §6.4 replaces that with
a methodology: report `cache_read_input_tokens` / (`cache_read_input_tokens` +
`cache_creation_input_tokens` + `input_tokens`) from real `usage` data once implementation
lands.

### 5.4 Batch API for whole-cluster sweeps

One `messages.batches.create()` request per sweep, **one entry per finding** —
`custom_id` keyed to image digest + CVE ID, matching the pattern the original draft's
`custom_id` scheme already implied. Considered and rejected: one entry per image with all
of that image's findings triaged via parallel tool calls in a single response. Per-image
batching cuts the request count sharply (8 images vs. 1,847 findings in the PRD's own
example), but a single response has to hold a `tool_use` block per finding — an image with
214 findings risks that response hitting `max_tokens` and truncating mid-list, and a batch
entry that truncates can't be resumed the way a live request can (see `shared/tool-use-concepts.md`
on `pause_turn` — that recovery path assumes a live, resumable conversation, which a batch
entry is not). Per-finding batching trades request count for reliability and clean failure
isolation: one bad finding fails one entry, not the image's other 213.

Poll `processing_status` until `"ended"`; stream results via `messages.batches.results(id)`
keyed by `custom_id` — batch results are not ordered. Batch pricing is ~50% off standard
rates — a second multiplier on top of caching, both shown in the cost table (§6.4).

**Execution model: synchronous and in-memory, no local persistence.** `kubectl trivy
analyze` is a single blocking CLI invocation, start to finish: it scans, submits the batch,
polls `processing_status` in a loop until `"ended"`, assembles results, and prints them —
all within one process, one run. The raw per-image Trivy JSON, and the image/pod ↔
`custom_id` mapping needed to reassemble batch results, live only in memory for the
duration of that run and are discarded when the process exits. Nothing is written to disk
or a local store between the scan step and the printed output; this is what keeps the
"no database" Non-Goal (§4) true even though §5.4 introduces an inherently asynchronous
API in the middle of the pipeline.

This means the command blocks for however long the batch takes to process — the Batch API
gives no fixed turnaround guarantee, so a large sweep could mean a multi-minute (or longer)
wait with nothing printed until polling resolves. §6.1's sample output should show a
progress line during this wait (`Submitting batch (1,847 findings)... polling...`) rather
than implying the results table appears instantly after `Scanning... done`. If real-world
batch latency turns out to make this UX untenable, an async "submit now, check later" mode
is the natural follow-up — but that's new scope (a batch-ID-to-something mapping needs to
persist somewhere, which reopens the no-database Non-Goal), not something to build
speculatively now.

### 5.5 Streaming

Reserved for the interactive path (`kubectl trivy analyze --detail <image>` /
`explain <cve-id>`) where a user wants a live explanation of one finding. Not used for the
batch sweep, which is async by nature. The triage tool call itself (Haiku or Opus, forced
tool use) is a bounded classification task and doesn't need extended thinking; the
interactive explain path may enable adaptive thinking on Opus 5 if reasoning depth turns
out to matter for a good explanation — left as an implementation-time tuning call, not a
PRD-level decision.

---

## 6. Expected Output

### 6.1 Default summary — reprioritized by actionability, not raw severity counts

```
$ kubectl trivy analyze -n production

Found 12 pods in namespace production (8 unique images)
Remote Trivy Server: trivy.internal:8080
Scanning... done (8 images, 1,847 total findings)
Submitting batch (1,847 findings)... polling... done in 4m12s
Triage: Haiku 4.5 (1,847 findings) → Opus 5 escalation (23 findings)

┌──────────────────────┬─────────────┬──────────┬────────────────────────────────────────┐
│ IMAGE                │ ACTION      │ CRITICAL │ TOP FINDING                             │
├──────────────────────┼─────────────┼──────────┼────────────────────────────────────────┤
│ web-api:2.4.1        │ PATCH_NOW   │ 2        │ CVE-2024-XXXX openssl — exploitable,    │
│                       │             │          │ internet-facing                         │
│ auth-service:1.9.0    │ SCHEDULE    │ 0        │ CVE-2023-XXXX — fix available, no       │
│                       │             │          │ known exploit path yet                  │
│ nginx:1.19.1          │ ACCEPT_RISK │ 0        │ CVE-2022-XXXX — no network path in       │
│                       │             │          │ this deployment                         │
│ redis:6.0-alpine      │ CLEAN       │ 0        │ —                                        │
└──────────────────────┴─────────────┴──────────┴────────────────────────────────────────┘

2 images need immediate action · 3 scheduled · 3 clean

kubectl trivy analyze -n production --detail web-api:2.4.1   (full reasoning per CVE)
kubectl trivy analyze -n production -o json                  (structured output)
kubectl trivy analyze -n production --cost-report             (token/cost breakdown)
kubectl trivy analyze -n production --legacy                  (severity-sorted table, v1 style)
```

`PATCH_NOW` / `SCHEDULE` / `ACCEPT_RISK` map 1:1 to `recommended_action` on the
highest-priority finding for that image. `CLEAN` is not a model output — it's what the CLI
prints when an image has zero findings. `--legacy` prints the original severity-count table
from `docs/spec.md` and stays available as a fallback (see §7).

### 6.2 `--detail <image>` — per-CVE reasoning from the tool-use output

```
IMAGE: web-api:2.4.1   PODS: web-api-7d9f, web-api-8a2c
FINDINGS: 214 total (2 critical, 18 high, 96 medium, 98 low)

┌ CVE-2024-XXXX — openssl 3.0.2  [CRITICAL] ────────────────────────────────┐
│ Triaged by: opus-5 (escalated from haiku — reason: severity+exploitable)  │
│ Action: PATCH_NOW · Exploitable in context: true                          │
│ Fix available: yes → 3.0.13                                               │
│ Reasoning: web-api-svc is an internet-facing LoadBalancer exposing the    │
│ vulnerable TLS renegotiation path. Fix is a minor-version bump.           │
└─────────────────────────────────────────────────────────────────────────┘

┌ CVE-2023-YYYY — libxml2 2.9.10  [HIGH] ───────────────────────────────────┐
│ Triaged by: haiku-4.5                                                     │
│ Action: ACCEPT_RISK · Exploitable in context: false                       │
│ Fix available: yes → 2.9.14                                               │
│ Reasoning: Parsing path only reachable via internal admin CLI, no         │
│ Service exposes it, no untrusted input reaches it.                       │
└─────────────────────────────────────────────────────────────────────────┘

... 212 more findings (196 auto-accepted at haiku confidence)
```

### 6.3 `-o json` — structured tool-use payload underlying both views above

```json
{
  "image": "web-api:2.4.1",
  "pods": ["web-api-7d9f", "web-api-8a2c"],
  "summary": {"critical": 2, "high": 18, "medium": 96, "low": 98},
  "findings": [
    {
      "cve_id": "CVE-2024-XXXX",
      "package": "openssl",
      "installed_version": "3.0.2",
      "severity": "CRITICAL",
      "triaged_by": "opus-5",
      "escalated": true,
      "escalation_reason": "severity_and_exploitable",
      "exploitable_in_context": true,
      "fix_available": true,
      "fixed_version": "3.0.13",
      "recommended_action": "patch_now",
      "needs_escalation": false,
      "reasoning": "web-api-svc is an internet-facing LoadBalancer...",
      "usage": {
        "input_tokens": 220,
        "output_tokens": 340,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 1600
      }
    }
  ]
}
```

`usage` mirrors the Messages API response field names directly (`input_tokens`,
`output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`) instead of the
original draft's ad hoc `{"input", "output", "cached"}` shape — this is what feeds the cost
report in §6.4 without a translation layer.

### 6.4 `--cost-report` — the course deliverable

**This table is illustrative structure only, not measured data.** The original draft
presented specific numbers (`$0.076`/image, `84.7%` cache hit rate, `25x` reduction) as if
they were real — they were estimates dressed up as results. This refinement replaces them
with the exact computation `--cost-report` will perform once implementation lands
(tracked in issue #4), using real `usage` data summed across every API call in a run:

```
COST REPORT — <namespace> (<N> images, <M> findings)

                        Naive (Opus, no cache)  +Haiku routing  +Caching  +Batch API
Cost/image                     <computed>          <computed>    <computed>  <computed>
Cost/100-image cluster         <computed>          <computed>    <computed>  <computed>

Escalated to Opus: <count>/<M> findings (<pct>)
Cache hit rate: <cache_read> / (<cache_read> + <cache_creation> + <input>)
Batch discount: 50% (Anthropic-published rate, not measured)

Total this run: <sum of actual billed cost from usage>  (vs <naive equivalent> — <ratio>x reduction)
```

Per-column methodology:

- **Naive (Opus, no cache):** every finding triaged by Opus 5 directly, no `cache_control`,
  no Batch API — priced at standard Messages API rates from `usage.input_tokens` /
  `usage.output_tokens`.
- **+Haiku routing:** apply the §5.2 routing rule; bulk findings priced at Haiku 4.5 rates,
  escalated findings at Opus 5 rates.
- **+Caching:** same routing, but with `cache_control` per §5.3; cost computed from actual
  `cache_read_input_tokens` (~0.1x) and `cache_creation_input_tokens` (2x, at the 1-hour TTL)
  reported by the API, not assumed.
- **+Batch API:** same as +Caching, with the published ~50% Batch API discount applied to
  the batch-processed portion.

This section will be filled with real numbers from a benchmarking run against a real
namespace once `kubectl trivy analyze` is implemented — that run is the actual "course
deliverable," not this table.

---

## 7. Open Design Questions — Resolved

The original draft's open questions are resolved below, per issue #1's acceptance
criteria. None are left ambiguous; where full resolution isn't possible without
implementation-time data, the deferral and its reasoning are stated explicitly.

- **Actionability framing (was: riskiest bet).** **Resolved: ship as the default output.**
  Sorting by `PATCH_NOW`/`SCHEDULE`/`ACCEPT_RISK`/`CLEAN` instead of raw severity is the
  tool's actual value-add, and gating it behind a flag until a formal eval set exists would
  ship a v2 that does the same thing as v1. Instead, the specific failure mode named in the
  original draft — a false `accept_risk` verdict with real consequences — gets a concrete
  interim safety net rather than a "needs an eval set" deferral: escalation rule clause 3
  in §5.2 forces every CRITICAL/HIGH finding that Haiku wants to dismiss as `accept_risk`
  through Opus for a second look, before it ever reaches the user. `--legacy` (§6.1) stays
  available as a severity-sorted fallback. A formal eval set to calibrate false-negative
  rate is real, necessary follow-up work — deferred to a post-launch milestone (added to
  §8) because it needs production triage data this tool doesn't have until it ships, not
  because the risk is being ignored.
- **Cluster-context input (was: how much to fetch via `client-go`).** **Resolved: MVP ships
  image-only context, no exposure fetching.** Formalized as Non-Goal in §4. Fetching Service
  exposure, NetworkPolicy, and ingress data via `client-go` would meaningfully improve
  `exploitable_in_context` accuracy, but it roughly doubles the K8s RBAC surface this tool
  needs (read access to `services`, `networkpolicies`, `ingresses`, not just `pods`) and is
  a second project's worth of scope on top of the AI-triage work this PRD is actually
  chartered to deliver. Ship without it, document the limitation in `--detail` output
  (already implied by "no known exploit path yet"-style reasoning being image-scoped), and
  scope live exposure context as an explicit future milestone once the core triage loop is
  proven.
- **Escalation thresholds (was: needs tuning against a real eval set).** **Resolved as a
  shipped starting heuristic, explicitly not final.** §5.2's three-clause rule (self-reported
  `needs_escalation`, severity+exploitable, severity+accept_risk) is the initial design —
  it's a defensible hybrid of model-reported confidence and rule-based severity gating, which
  matches standard escalation-routing practice (route on task difficulty/uncertainty, not
  severity alone). Tuning the exact boundaries (should MEDIUM ever escalate? does
  `needs_escalation` fire too often and blow the routing-cost benefit?) requires real triage
  data this project doesn't have pre-launch. This is the one open question that stays a
  documented deferral rather than a full resolution — tracked as follow-up in §8.
- **Where the analysis layer lives.** **Resolved: same Go binary, new subcommand, Go
  Anthropic SDK.** Confirms the original draft's lean. A separate process/service would
  need its own deployment story, its own auth to the cluster or to the primary binary's
  output, and breaks the "one artifact, no external shell dependencies" goal `docs/spec.md`
  already commits to for v1. Nothing about the AI triage work changes that calculus.

## 8. Milestones

1. ~~Course material on structured outputs / caching / batch (in progress) → refine this PRD.~~
   **Done — this refinement.**
2. Tech spec + ADRs for the concrete decisions above (model routing thresholds, schema
   versioning, Go SDK vs. alternative, caching key design) — issue #2.
3. Baseline maintenance: bring `kubectl-trivy` up to current Go/Trivy versions (blocks
   using the current Go Anthropic SDK cleanly) — issue #3.
4. Implementation plan + build, including the real `--cost-report` benchmarking run — issue #4.
5. **New:** Post-launch — build an eval set from real triage data to calibrate the
   escalation thresholds (§7) and measure false-`accept_risk` rate. Not a launch blocker;
   tracked as follow-up once the tool has run against real clusters.

---

## 9. References

- `docs/spec.md` — v1 technical spec for the existing scan/table pipeline
- `docs/plan.md` — v1 refinement plan (Go/dependency upgrade, container discovery)
- Course: Platform 101 → Building with the Claude API, Project 1
- Issue #2 (tech spec + ADRs), #3 (Go/Trivy upgrade), #4 (implementation) — companion work
  items that build on this refined PRD
