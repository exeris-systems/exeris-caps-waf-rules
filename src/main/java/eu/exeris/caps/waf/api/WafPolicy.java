package eu.exeris.caps.waf.api;

/**
 * Service contract for evaluating inbound requests against Layer 7 application security rules.
 *
 * <p>Takes an immutable {@link WafRequest} and returns a {@link WafDecision}, keeping no state between calls.
 * The contract names no transport, socket or kernel type (ADR-055).
 *
 * @since 0.1.0
 */
@FunctionalInterface
public interface WafPolicy {

    /**
     * Inspects the given HTTP request for security policy violations.
     *
     * @param request the request metadata; never null
     * @return the policy decision: allowed, blocked with the rule that matched, or allowed with the rule
     *         that matched when the policy only detects; never null
     */
    WafDecision evaluate(WafRequest request);
}
