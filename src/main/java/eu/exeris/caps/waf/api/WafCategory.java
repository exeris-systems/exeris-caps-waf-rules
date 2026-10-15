package eu.exeris.caps.waf.api;

/**
 * High-level threat category identified by the WAF inspection engine.
 *
 * @since 0.1.0
 */
public enum WafCategory {
    SQL_INJECTION,
    XSS,
    PATH_TRAVERSAL,
    RCE,
    PROTOCOL_VIOLATION,
    MALICIOUS_HEADER
}
