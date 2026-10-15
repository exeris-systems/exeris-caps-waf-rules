package eu.exeris.caps.waf.api;

/**
 * Definition of a single WAF detection rule.
 *
 * @since 0.1.0
 */
public record WafRule(
        String id,
        String name,
        WafCategory category,
        String patternOrKeyword,
        String description
) {}
