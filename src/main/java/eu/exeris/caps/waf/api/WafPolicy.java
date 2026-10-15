package eu.exeris.caps.waf.api;

/**
 * Service contract for evaluating inbound requests against Layer 7 application security rules.
 *
 * <p>Implemented as a pure function: takes an immutable {@link WafRequest} and returns a
 * {@link WafDecision}. Zero transport, socket, or kernel coupling (ADR-055).
 *
 * @since 0.1.0
 */
@FunctionalInterface
public interface WafPolicy {

    /**
     * Inspects the given HTTP request for security policy violations.
     *
     * @param request the request metadata; never null
     * @return the policy decision (allow or block with reason); never null
     */
    WafDecision evaluate(WafRequest request);
}
