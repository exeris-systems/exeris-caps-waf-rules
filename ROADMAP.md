# exeris-caps-waf-rules — Roadmap

Status: **poc**. Version line: **0.1.x**. Licence: Exeris Commercial License (ADR-023), entitlement id
`exeris-caps-waf-rules`.

Milestones are versions, not dates. Dates appear only on what has shipped; nothing has shipped yet.

> **`1.0.0` is not on this roadmap.** It is a gate, described in the last section. Status moves
> `poc` → `snapshot` → `released`.

---

## Where this sits

Layer 3 gateway policy cap. Provides `WafPolicy.evaluate(WafRequest) → WafDecision`, built through
`WafPolicies.defaultCoreRules(mode)`, with `BLOCK` / `DETECT` / `DISABLED` modes. The default rule set
(`CoreWafRuleSet`) is a list of case-insensitive keyword rules in six categories (SQL, scripting, path
traversal, command execution, protocol violation, header abuse) matched by an Aho-Corasick-style automaton
(`FastKeywordTrie`) over path, query and header values, with a URI-length limit and checks on request
framing and URL-override headers. Percent-encoding is decoded in repeated rounds before matching, and a
value still encoded after three rounds is refused. Detect mode reports the matched rule
(`WafDecision.detect`). Zero runtime dependencies; no `@Requires`. 11 tests across two classes.

**This roadmap does not promise a ruleset.** Rule-language items below are capabilities to add; their
size is decided as they are taken up.

**Upstream constraints this repo does not own:**

| Constraint | Effect here | Owner |
|---|---|---|
| Kernel licence gate (ADR-088, ADR-089) in kernel `0.13.0-SNAPSHOT` | Entitlement resolvable only from that line | `exeris-kernel` |
| `RequestFilterChain` contract (ADR-099) | 0.2.0 binds to it | `exeris-caps-service-boundary-core` |
| ADR on the response-side seam (gateway-core 0.2.0) | Entry condition: no policy cap starts its 0.2.0 before it is accepted | `exeris-caps-gateway-core`, `exeris-docs` |
| HLA §3.2 lists `waf-rules` for Bot Blocker / API Gateway, but the HLA §3.3 API Gateway row and the whitepaper SKU composition omit it | The SKU already composes it | `exeris-docs` |
| Request body access in the kernel `HttpExchange` | Body inspection depends on a bounded, buffered view | `exeris-kernel` |

---

## 0.1.0 — the code PR

- [ ] Defects found in the pre-import review are fixed in the import, each with a test
- [ ] Code imported; repository files and ADR link stubs added
- [ ] `@Provides(WafPolicy)` at contract `0.1.0`
- [ ] Kernel `0.13.0-SNAPSHOT`; SDK `0.12.0` and tooling `0.10.0` pins aligned
- [ ] Artefacts stay `0.1.0-SNAPSHOT` until kernel `0.13.0` is released; a non-snapshot `0.1.0` is cut only after that
- [ ] Licence enforcement: `WafRulesEntitlement` (id `exeris-caps-waf-rules`), `META-INF/services`
      registration, TCK test and boot test against the kernel's Phase 0 gate
- [ ] `build.yml` green on JDK 25 and 26; `cap-manifest.json` committed through the two-pass build

**Exit gate:** `mvn verify` green on both JDK rows; entitlement test fails without the id.

## 0.2.0 — bind to `RequestFilterChain`

Follows the gateway-core PR that replaces its `PolicyChain`.

- [ ] Optional `@Requires(RequestFilterChain, "[0.1.0,0.2.0)")` and a `WafServiceBoundaryBinding` in `api`,
      in an early admission phase (`PRE_ADMISSION`), on the pattern of `exeris-caps-rate-limiting`;
      replaces the SKU-side `WafGatewayPolicy`
- [ ] Blocked-request response shape (status, body, `Content-Type`) fixed in the binding, not per SKU
- [ ] The decision shape carried by the binding covers block and detect, with the matched rule reported
- [ ] Consume the canonical path produced once before the chain (gateway-core 0.2.0 canonicalisation ADR);
      until then the cap decodes on its own, as the 0.1.0 code does
- [ ] Align `HLA §3.2` / §3.3 composition lists through an `exeris-docs` PR

## 0.3.0 — Independent security review

- [ ] Covered by the API Gateway SKU review (one review; scope: the SKU and every composed cap); this
      repository's public API and documented behaviour are listed in that scope
- [ ] Threat model written and committed alongside the code
- [ ] Findings handled through `SECURITY.md` private reporting
- [ ] Fixes released, each with a regression test

## 0.4.0 — re-measurement and snapshot

- [ ] Evaluation measured in the `exeris-benchmarks` harness on the reference profile, with a benign and an attack corpus, published there; no figure stated here
- [ ] Snapshot artefact on GitHub Packages; status `poc` → `snapshot`

## 0.5.0 — rule language and body inspection

Taken up after the SKU review, so the review sees the binding and decision shape first.

- [ ] Regular-expression rules on a linear-time engine (no backtracking), custom rules through the public API,
      per-rule enable/disable, per-route mode
- [ ] Request-body inspection over a bounded, buffered view, once the kernel exposes one

---

## 1.0.0 — a gate, not a milestone

Entry condition: a rule-set coverage statement exists and is backed by a corpus, the review is closed, and
the rule language of 0.5.0 is in place. Then `WafPolicy` freezes, a semver gate is added, and the status becomes
`released`. A WAF cap does not claim coverage it has not tested.

## Deliberately out of scope

- Bot fingerprinting (`bot-fingerprinting`, enterprise-private): separate cap.
- TLS and rate limiting: `tls-termination` and `rate-limiting`.
