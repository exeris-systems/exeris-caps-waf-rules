package eu.exeris.caps.waf.api;

/**
 * Enforcement mode of the WAF policy.
 *
 * @since 0.1.0
 */
public enum WafMode {
    /** Actively rejects malicious requests with HTTP 403 Forbidden. */
    BLOCK,
    /** Inspects and flags requests without dropping or short-circuiting. */
    DETECT,
    /** Bypasses inspection completely. */
    DISABLED
}
