package eu.exeris.caps.waf.internal;

import eu.exeris.caps.waf.api.WafCategory;
import eu.exeris.caps.waf.api.WafDecision;
import eu.exeris.caps.waf.api.WafHeader;
import eu.exeris.caps.waf.api.WafMode;
import eu.exeris.caps.waf.api.WafPolicy;
import eu.exeris.caps.waf.api.WafRequest;
import eu.exeris.caps.waf.api.WafRule;

import java.util.List;

/**
 * High-performance, zero-allocation implementation of {@link WafPolicy}.
 *
 * <p>Uses a compiled {@link FastKeywordTrie} automaton to evaluate URIs, queries, and headers
 * in sub-microsecond time without generating heap garbage on the clean inspection path.
 *
 * @since 0.1.0
 */
public final class DefaultWafPolicy implements WafPolicy {

    private static final int MAX_URI_LENGTH = 4096;
    private static final int MAX_DECODE_ROUNDS = 3;

    private final WafMode mode;
    private final FastKeywordTrie automaton;

    public DefaultWafPolicy(WafMode mode, List<WafRule> rules) {
        this.mode = (mode != null) ? mode : WafMode.BLOCK;
        this.automaton = FastKeywordTrie.compile(rules != null ? rules : CoreWafRuleSet.defaultRules());
    }

    @Override
    public WafDecision evaluate(WafRequest request) {
        if (mode == WafMode.DISABLED) {
            return WafDecision.allow();
        }

        // 1. Protocol & Boundary Validation
        String uri = request.uri();
        if (uri != null && uri.length() > MAX_URI_LENGTH) {
            return decide(WafCategory.PROTOCOL_VIOLATION, "PROTO-001", "URI_TOO_LONG", "Request URI exceeds maximum permissible length (" + MAX_URI_LENGTH + ")");
        }

        // 2. Scan Path, Query String and Headers, each in every decoded form
        WafDecision verdict = inspect(request.rawPath(), null);
        if (verdict != null) {
            return verdict;
        }
        verdict = inspect(request.rawQuery(), null);
        if (verdict != null) {
            return verdict;
        }
        if (uri != null && !uri.equals(request.rawPath())) {
            verdict = inspect(uri, null);
            if (verdict != null) {
                return verdict;
            }
        }

        // 3. Scan Headers (Names & Values)
        List<WafHeader> headers = request.headers();
        final int headerCount = headers.size();
        for (int i = 0; i < headerCount; i++) {
            WafHeader header = headers.get(i);
            String name = header.name();

            // Detect dangerous routing bypass headers; the token is the canonical name, never request text
            if ("x-original-url".equalsIgnoreCase(name)) {
                return decide(WafCategory.MALICIOUS_HEADER, "HDR-001", "x-original-url", "Restricted proxy override header detected");
            }
            if ("x-rewrite-url".equalsIgnoreCase(name)) {
                return decide(WafCategory.MALICIOUS_HEADER, "HDR-001", "x-rewrite-url", "Restricted proxy override header detected");
            }

            verdict = inspect(header.value(), name);
            if (verdict != null) {
                return verdict;
            }
        }

        return WafDecision.allow();
    }

    /**
     * Inspects a value as received and after each round of percent-decoding, so that a payload encoded more
     * than once is matched as the decoded form a backend would eventually act on. A value that is still
     * changing after {@link #MAX_DECODE_ROUNDS} rounds is refused.
     *
     * @return the decision for a match or violation, or {@code null} when the value is clean
     */
    private WafDecision inspect(String value, String headerName) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String current = value;
        for (int round = 0; ; round++) {
            if (current.indexOf('\0') >= 0) {
                return decide(WafCategory.PROTOCOL_VIOLATION, "PROTO-002", "NULL_BYTE", "Null byte character injection detected");
            }
            WafRule match = automaton.findFirstMatch(current);
            if (match != null) {
                String desc = (headerName == null)
                        ? match.description()
                        : "Header '" + safeName(headerName) + "' triggered " + match.description();
                return decide(match.category(), match.id(), match.patternOrKeyword(), desc);
            }
            String next = normalize(current);
            if (next.equals(current)) {
                return null;
            }
            if (round >= MAX_DECODE_ROUNDS) {
                return decide(WafCategory.PROTOCOL_VIOLATION, "PROTO-003", "EXCESSIVE_ENCODING", "Value is encoded more times than permitted");
            }
            current = next;
        }
    }

    /** Header names are request text: keep token characters only, bounded. */
    private static String safeName(String name) {
        int n = Math.min(name.length(), 64);
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            char c = name.charAt(i);
            boolean token = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            sb.append(token ? c : '?');
        }
        return sb.toString();
    }

    private static String normalize(String str) {
        if (str.indexOf('%') < 0 && str.indexOf('+') < 0) {
            return str;
        }
        int len = str.length();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = str.charAt(i);
            if (c == '%' && i + 2 < len) {
                int d1 = hexDigit(str.charAt(i + 1));
                int d2 = hexDigit(str.charAt(i + 2));
                if (d1 >= 0 && d2 >= 0) {
                    sb.append((char) ((d1 << 4) | d2));
                    i += 2;
                    continue;
                }
            } else if (c == '+') {
                sb.append(' ');
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private WafDecision decide(WafCategory category, String ruleId, String token, String desc) {
        if (mode == WafMode.BLOCK) {
            return WafDecision.block(category, ruleId, token, desc);
        }
        return WafDecision.detect(category, ruleId, token, desc);
    }
}
