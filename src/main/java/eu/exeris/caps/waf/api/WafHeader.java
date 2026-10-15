package eu.exeris.caps.waf.api;

/**
 * Decoupled representation of an HTTP header for WAF inspection.
 *
 * @since 0.1.0
 */
public record WafHeader(String name, String value) {
    public WafHeader {
        if (name == null) {
            throw new IllegalArgumentException("Header name cannot be null");
        }
        if (value == null) {
            value = "";
        }
    }
}
