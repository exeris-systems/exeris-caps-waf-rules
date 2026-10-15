package eu.exeris.caps.waf.api;

/**
 * Result of evaluating an inbound request against the active WAF rule set.
 *
 * @since 0.1.0
 */
public record WafDecision(
        boolean isAllowed,
        WafCategory category,
        String ruleId,
        String matchedToken,
        String description
) {
    private static final WafDecision ALLOWED = new WafDecision(true, null, null, null, null);

    /**
     * @return the shared decision for a request that matched no rule; its {@code ruleId} is {@code null}
     */
    public static WafDecision allow() {
        return ALLOWED;
    }

    /**
     * A decision that lets the request through but reports the rule it matched, as {@link WafMode#DETECT} does.
     */
    public static WafDecision detect(WafCategory category, String ruleId, String matchedToken, String description) {
        return new WafDecision(true, category, ruleId, matchedToken, description);
    }

    /**
     * @return {@code true} when the request is allowed although a rule matched it
     */
    public boolean isDetected() {
        return isAllowed && ruleId != null;
    }

    /**
     * A decision that refuses the request and reports the rule it matched, as {@link WafMode#BLOCK} does.
     */
    public static WafDecision block(WafCategory category, String ruleId, String matchedToken, String description) {
        return new WafDecision(false, category, ruleId, matchedToken, description);
    }
}
