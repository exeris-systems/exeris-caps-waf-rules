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
 * Keyword-matching implementation of {@link WafPolicy}.
 *
 * <p>Matches the rules' keywords case-insensitively (A to Z) in the path, the query, the request URI
 * and every header value, each in the form received and after each round of percent-decoding
 * ({@code +} reads as a space). A value still changing after the permitted rounds is refused.
 *
 * <p>Allocation: evaluating a request allocates nothing in steady state, whether it is clean, matches a rule
 * or violates the protocol checks. Decoding runs over a thread-confined {@code char[]} reused across calls,
 * the keyword scan reads primitive arrays, and every decision a request can receive is built when the policy is
 * constructed (the shared {@link WafDecision#allow()} for a clean request). What allocates is the one-time
 * growth of the calling thread's scratch buffer to the longest percent-encoded value it has evaluated, and its
 * first call. {@code WafAllocationTest} measures plain clean, percent-encoded clean and matching requests.
 *
 * @since 0.1.0
 */
public final class DefaultWafPolicy implements WafPolicy {

    private static final int MAX_URI_LENGTH = 4096;
    private static final int MAX_DECODE_ROUNDS = 3;
    private static final int INITIAL_SCRATCH = 512;

    private static final ThreadLocal<char[][]> SCRATCH = ThreadLocal.withInitial(() -> new char[][] {new char[INITIAL_SCRATCH]});

    private final WafMode mode;
    private final FastKeywordTrie automaton;

    /** Decision per rule index for a match in the path, query or URI. */
    private final WafDecision[] matchDecisions;
    /** Decision per rule index for a match in a header value. */
    private final WafDecision[] headerMatchDecisions;
    private final WafDecision uriTooLong;
    private final WafDecision nullByte;
    private final WafDecision excessiveEncoding;
    private final WafDecision originalUrlHeader;
    private final WafDecision rewriteUrlHeader;

    public DefaultWafPolicy(WafMode mode, List<WafRule> rules) {
        this.mode = (mode != null) ? mode : WafMode.BLOCK;
        this.automaton = FastKeywordTrie.compile(rules != null ? rules : CoreWafRuleSet.defaultRules());

        List<WafRule> compiled = automaton.rules();
        this.matchDecisions = new WafDecision[compiled.size()];
        this.headerMatchDecisions = new WafDecision[compiled.size()];
        for (int i = 0; i < matchDecisions.length; i++) {
            WafRule r = compiled.get(i);
            matchDecisions[i] = decision(r.category(), r.id(), r.patternOrKeyword(), r.description());
            headerMatchDecisions[i] = decision(r.category(), r.id(), r.patternOrKeyword(),
                    "Header value triggered " + r.description());
        }
        this.uriTooLong = decision(WafCategory.PROTOCOL_VIOLATION, "PROTO-001", "URI_TOO_LONG",
                "Request URI exceeds maximum permissible length (" + MAX_URI_LENGTH + ")");
        this.nullByte = decision(WafCategory.PROTOCOL_VIOLATION, "PROTO-002", "NULL_BYTE",
                "Null byte character injection detected");
        this.excessiveEncoding = decision(WafCategory.PROTOCOL_VIOLATION, "PROTO-003", "EXCESSIVE_ENCODING",
                "Value is encoded more times than permitted");
        // The token is the canonical name, never request text
        this.originalUrlHeader = decision(WafCategory.MALICIOUS_HEADER, "HDR-001", "x-original-url",
                "Restricted proxy override header detected");
        this.rewriteUrlHeader = decision(WafCategory.MALICIOUS_HEADER, "HDR-001", "x-rewrite-url",
                "Restricted proxy override header detected");
    }

    @Override
    public WafDecision evaluate(WafRequest request) {
        if (mode == WafMode.DISABLED) {
            return WafDecision.allow();
        }

        // 1. Protocol & Boundary Validation
        String uri = request.uri();
        if (uri != null && uri.length() > MAX_URI_LENGTH) {
            return uriTooLong;
        }

        // 2. Scan Path, Query String and URI, each in every decoded form
        char[][] scratch = SCRATCH.get();
        WafDecision verdict = inspect(request.rawPath(), matchDecisions, scratch);
        if (verdict != null) {
            return verdict;
        }
        verdict = inspect(request.rawQuery(), matchDecisions, scratch);
        if (verdict != null) {
            return verdict;
        }
        if (uri != null && !uri.equals(request.rawPath())) {
            verdict = inspect(uri, matchDecisions, scratch);
            if (verdict != null) {
                return verdict;
            }
        }

        // 3. Check header names against the restricted override headers; scan header values
        List<WafHeader> headers = request.headers();
        final int headerCount = headers.size();
        for (int i = 0; i < headerCount; i++) {
            WafHeader header = headers.get(i);
            String name = header.name();

            if ("x-original-url".equalsIgnoreCase(name)) {
                return originalUrlHeader;
            }
            if ("x-rewrite-url".equalsIgnoreCase(name)) {
                return rewriteUrlHeader;
            }

            verdict = inspect(header.value(), headerMatchDecisions, scratch);
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
     * <p>The first decoding round reads the string and writes the thread's scratch buffer; later rounds
     * decode that buffer in place, which is possible because decoding never lengthens a value.
     *
     * @return the decision for a match or violation, or {@code null} when the value is clean
     */
    private WafDecision inspect(String value, WafDecision[] matchTable, char[][] scratch) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        if (value.indexOf('\0') >= 0) {
            return nullByte;
        }
        int rule = automaton.findFirstMatchIndex(value, value.length());
        if (rule >= 0) {
            return matchTable[rule];
        }
        if (value.indexOf('%') < 0 && value.indexOf('+') < 0) {
            return null;
        }

        char[] buf = scratch[0];
        if (buf.length < value.length()) {
            buf = new char[Math.max(value.length(), buf.length * 2)];
            scratch[0] = buf;
        }
        int len = decodeInto(value, buf);
        for (int round = 1; ; round++) {
            if (len < 0) {
                return null;
            }
            if (round > MAX_DECODE_ROUNDS) {
                return excessiveEncoding;
            }
            if (indexOfNul(buf, len)) {
                return nullByte;
            }
            rule = automaton.findFirstMatchIndex(buf, len);
            if (rule >= 0) {
                return matchTable[rule];
            }
            len = decodeInPlace(buf, len);
        }
    }

    private static boolean indexOfNul(char[] buf, int len) {
        for (int i = 0; i < len; i++) {
            if (buf[i] == '\0') {
                return true;
            }
        }
        return false;
    }

    /**
     * Percent-decodes {@code src} into {@code dst}.
     *
     * @return the decoded length, or -1 when nothing was decoded
     */
    private static int decodeInto(String src, char[] dst) {
        int len = src.length();
        int o = 0;
        boolean changed = false;
        for (int i = 0; i < len; i++) {
            char c = src.charAt(i);
            if (c == '%' && i + 2 < len) {
                int d1 = hexDigit(src.charAt(i + 1));
                int d2 = hexDigit(src.charAt(i + 2));
                if (d1 >= 0 && d2 >= 0) {
                    dst[o++] = (char) ((d1 << 4) | d2);
                    i += 2;
                    changed = true;
                    continue;
                }
            } else if (c == '+') {
                dst[o++] = ' ';
                changed = true;
                continue;
            }
            dst[o++] = c;
        }
        return changed ? o : -1;
    }

    /**
     * Percent-decodes {@code buf[0, len)} in place; the write index never passes the read index.
     *
     * @return the decoded length, or -1 when nothing was decoded
     */
    private static int decodeInPlace(char[] buf, int len) {
        int o = 0;
        boolean changed = false;
        for (int i = 0; i < len; i++) {
            char c = buf[i];
            if (c == '%' && i + 2 < len) {
                int d1 = hexDigit(buf[i + 1]);
                int d2 = hexDigit(buf[i + 2]);
                if (d1 >= 0 && d2 >= 0) {
                    buf[o++] = (char) ((d1 << 4) | d2);
                    i += 2;
                    changed = true;
                    continue;
                }
            } else if (c == '+') {
                buf[o++] = ' ';
                changed = true;
                continue;
            }
            buf[o++] = c;
        }
        return changed ? o : -1;
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private WafDecision decision(WafCategory category, String ruleId, String token, String desc) {
        if (mode == WafMode.BLOCK) {
            return WafDecision.block(category, ruleId, token, desc);
        }
        return WafDecision.detect(category, ruleId, token, desc);
    }
}
