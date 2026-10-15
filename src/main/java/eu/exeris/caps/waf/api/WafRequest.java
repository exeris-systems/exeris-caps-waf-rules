package eu.exeris.caps.waf.api;

import java.util.List;

/**
 * Inbound HTTP request payload presented to the WAF policy for decision evaluation.
 *
 * @since 0.1.0
 */
public record WafRequest(
        String method,
        String uri,
        String rawPath,
        String rawQuery,
        List<WafHeader> headers
) {
    public WafRequest {
        if (method == null) method = "GET";
        if (uri == null) uri = "/";
        if (rawPath == null) rawPath = uri;
        if (rawQuery == null) rawQuery = "";
        headers = (headers == null) ? List.of() : List.copyOf(headers);
    }
}
