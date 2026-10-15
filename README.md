# exeris-caps-waf-rules

A Layer 7 rule engine as an Exeris capability. `WafPolicy` evaluates a `WafRequest` (method, URI, query, headers) against a rule set and returns a `WafDecision`.

Status: proof of concept, built against `exeris-kernel` 0.13.0-SNAPSHOT on JDK 25 LTS. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 3 — Gateway policy, in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi` (the entitlement requirement, and the allocator that lends the room a percent-encoded value is decoded into) and `exeris-sdk-annotations` (`provided`). `WafPolicy` is a function from an immutable `WafRequest` to a `WafDecision`; the contract names no transport, socket or kernel type, and an evaluation keeps no state between calls.
- **Provides** (`@Provides`, contract version 0.1.0): `WafPolicy`.
- **Requires:** no other capability.
- **Wall (ADR-055):** `eu.exeris.caps.waf.api` is the cross-cap surface; `eu.exeris.caps.waf.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

## What the source contains

- A `WafRule` belongs to a `WafCategory`: SQL injection, cross-site scripting, path traversal, remote code execution, protocol violation or malicious header.
- `WafMode` is `BLOCK` (a match yields a decision with `isAllowed() == false`), `DETECT` (a match yields an allowed decision that reports the first rule matched) or `DISABLED` (no inspection).
- `WafPolicies` builds a policy from the built-in core rule set (`CoreWafRuleSet`) or from custom rules.
- `DefaultWafPolicy` matches the path, query, URI and header values, as received and percent-decoded, against an Aho-Corasick keyword automaton (`FastKeywordTrie`); evaluating a request none of whose values contains `%` or `+` allocates nothing, on any thread, and a request that does borrows its decode room once, as a `LoanedBuffer` from the kernel allocator, and returns it when the evaluation ends. The borrow allocates what the allocator allocates for one: with the Community allocator about 120 bytes, a buffer object, a record and a queue node around its pooled memory. Where no allocator is reachable the room is a new `char[]` per evaluation. `WafAllocationTest` measures each of these with one virtual thread per evaluation.

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

The upstreams are not on Maven Central. `exeris-sdk` and `exeris-tooling` are built from source, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md) — signed licence manifest.
- [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md) — capability entitlement enforcement.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-caps-waf-rules` is a `commercial` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

Its entitlement id is `exeris-caps-waf-rules`, the artifactId ([ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md), [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md)).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
