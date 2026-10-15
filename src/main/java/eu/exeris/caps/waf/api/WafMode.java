package eu.exeris.caps.waf.api;

/**
 * Enforcement mode of the WAF policy.
 *
 * @since 0.1.0
 */
public enum WafMode {
    /** A matching request yields a decision with {@code isAllowed() == false}; what the caller does with it is the caller's. */
    BLOCK,
    /** A matching request yields a decision with {@code isAllowed() == true} that reports the first rule matched. */
    DETECT,
    /** No inspection: every request yields {@link WafDecision#allow()}. */
    DISABLED
}
