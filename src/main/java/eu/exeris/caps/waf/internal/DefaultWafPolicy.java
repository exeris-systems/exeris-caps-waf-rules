package eu.exeris.caps.waf.internal;

import eu.exeris.caps.waf.api.WafCategory;
import eu.exeris.caps.waf.api.WafDecision;
import eu.exeris.caps.waf.api.WafHeader;
import eu.exeris.caps.waf.api.WafMode;
import eu.exeris.caps.waf.api.WafPolicy;
import eu.exeris.caps.waf.api.WafRequest;
import eu.exeris.caps.waf.api.WafRule;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import eu.exeris.kernel.spi.memory.MemoryAllocator;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.List;

/**
 * Keyword-matching implementation of {@link WafPolicy}.
 *
 * <p>Matches the rules' keywords case-insensitively (A to Z) in the path, the query, the request URI
 * and every header value, each in the form received and after each round of percent-decoding
 * ({@code +} reads as a space). A value still changing after the permitted rounds is refused.
 *
 * <p>Allocation: a request none of whose values contains {@code %} or {@code +} allocates nothing, whether it is
 * clean or matches a rule or violates the protocol checks: the keyword scan reads primitive arrays and every
 * decision a request can receive is built when the policy is constructed (the shared {@link WafDecision#allow()}
 * for a clean request). A request that has such a value needs room to decode into, and borrows it once, for the
 * longest of those values, as a {@link LoanedBuffer} from a {@link MemoryAllocator}, in try-with-resources and
 * returned when the evaluation ends; nothing is kept between calls and no thread holds state, so the cost does not
 * depend on which thread evaluates or how long it lives. The borrow costs what the allocator charges for one: the
 * kernel's pooled buffers reuse their memory, and the objects that wrap it are the allocator's, not this class's.
 * The allocator is the one given at construction, else {@link KernelProviders#MEMORY_ALLOCATOR} when it is bound
 * where {@link #evaluate} runs, which the kernel does around every request handler. With neither, an evaluation
 * that needs room decodes into a new {@code char[]} of the size it needs. {@code WafAllocationTest} measures the
 * requests that need no borrow, and the borrowing ones against a recycling allocator, each on a new virtual thread
 * per evaluation.
 *
 * @since 0.1.0
 */
public final class DefaultWafPolicy implements WafPolicy {

    private static final int MAX_URI_LENGTH = 4096;
    private static final int MAX_DECODE_ROUNDS = 3;
    private static final int BYTES_PER_CHAR = Character.BYTES;

    private final WafMode mode;
    /** Where decode room is borrowed from; {@code null} reads {@link KernelProviders#MEMORY_ALLOCATOR} on use. */
    private final MemoryAllocator allocator;
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

    /**
     * Creates a policy that borrows decode room from the allocator the kernel binds around a request handler.
     *
     * @param mode  the enforcement mode; {@code null} selects {@link WafMode#BLOCK}
     * @param rules the rules; {@code null} selects the built-in set
     */
    public DefaultWafPolicy(WafMode mode, List<WafRule> rules) {
        this(mode, rules, null);
    }

    /**
     * Creates a policy that borrows decode room from {@code allocator}.
     *
     * @param mode      the enforcement mode; {@code null} selects {@link WafMode#BLOCK}
     * @param rules     the rules; {@code null} selects the built-in set
     * @param allocator where an evaluation borrows decode room; {@code null} reads
     *                  {@link KernelProviders#MEMORY_ALLOCATOR} when it is bound at the evaluation
     */
    public DefaultWafPolicy(WafMode mode, List<WafRule> rules, MemoryAllocator allocator) {
        this.allocator = allocator;
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

        // 2. Room to decode into, borrowed for this evaluation only and only when a value can need it
        int decodeChars = longestEncoded(request, uri);
        if (decodeChars == 0) {
            return scan(request, uri, null);
        }
        MemoryAllocator source = allocator != null ? allocator : boundAllocator();
        if (source == null) {
            return scan(request, uri, MemorySegment.ofArray(new char[decodeChars]));
        }
        try (LoanedBuffer room = source.allocateNetwork(Math.multiplyExact(decodeChars, BYTES_PER_CHAR))) {
            return scan(request, uri, room.segment());
        }
    }

    private static MemoryAllocator boundAllocator() {
        return KernelProviders.MEMORY_ALLOCATOR.isBound() ? KernelProviders.MEMORY_ALLOCATOR.get() : null;
    }

    /** The length of the longest value {@link #scan} may decode, or 0 when it decodes none. */
    private static int longestEncoded(WafRequest request, String uri) {
        int longest = encodedLength(request.rawPath(), 0);
        longest = encodedLength(request.rawQuery(), longest);
        if (uri != null && !uri.equals(request.rawPath())) {
            longest = encodedLength(uri, longest);
        }
        List<WafHeader> headers = request.headers();
        for (int i = 0, n = headers.size(); i < n; i++) {
            longest = encodedLength(headers.get(i).value(), longest);
        }
        return longest;
    }

    private static int encodedLength(String value, int longest) {
        if (value == null || value.length() <= longest || (value.indexOf('%') < 0 && value.indexOf('+') < 0)) {
            return longest;
        }
        return value.length();
    }

    /**
     * Scans the path, query, URI and headers of a request.
     *
     * @param room where values are decoded; may be {@code null} only when no value contains {@code %} or
     *             {@code +}, and otherwise holds at least the length of the longest such value
     */
    private WafDecision scan(WafRequest request, String uri, MemorySegment room) {
        WafDecision verdict = inspect(request.rawPath(), matchDecisions, room);
        if (verdict != null) {
            return verdict;
        }
        verdict = inspect(request.rawQuery(), matchDecisions, room);
        if (verdict != null) {
            return verdict;
        }
        if (uri != null && !uri.equals(request.rawPath())) {
            verdict = inspect(uri, matchDecisions, room);
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

            verdict = inspect(header.value(), headerMatchDecisions, room);
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
     * <p>The first decoding round reads the string and writes {@code room}; later rounds decode that room in
     * place, which is possible because decoding never lengthens a value.
     *
     * @return the decision for a match or violation, or {@code null} when the value is clean
     */
    private WafDecision inspect(String value, WafDecision[] matchTable, MemorySegment room) {
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

        int len = decodeInto(value, room);
        for (int round = 1; ; round++) {
            if (len < 0) {
                return null;
            }
            if (round > MAX_DECODE_ROUNDS) {
                return excessiveEncoding;
            }
            if (indexOfNul(room, len)) {
                return nullByte;
            }
            rule = automaton.findFirstMatchIndex(room, len);
            if (rule >= 0) {
                return matchTable[rule];
            }
            len = decodeInPlace(room, len);
        }
    }

    private static boolean indexOfNul(MemorySegment buf, int len) {
        for (int i = 0; i < len; i++) {
            if (buf.getAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, i) == '\0') {
                return true;
            }
        }
        return false;
    }

    /**
     * Percent-decodes {@code src} into {@code dst}, one UTF-16 code unit per char index.
     *
     * @return the decoded length, or -1 when nothing was decoded
     */
    private static int decodeInto(String src, MemorySegment dst) {
        int len = src.length();
        int o = 0;
        boolean changed = false;
        for (int i = 0; i < len; i++) {
            char c = src.charAt(i);
            if (c == '%' && i + 2 < len) {
                int d1 = hexDigit(src.charAt(i + 1));
                int d2 = hexDigit(src.charAt(i + 2));
                if (d1 >= 0 && d2 >= 0) {
                    dst.setAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, o++, (char) ((d1 << 4) | d2));
                    i += 2;
                    changed = true;
                    continue;
                }
            } else if (c == '+') {
                dst.setAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, o++, ' ');
                changed = true;
                continue;
            }
            dst.setAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, o++, c);
        }
        return changed ? o : -1;
    }

    /**
     * Percent-decodes {@code buf[0, len)} in place; the write index never passes the read index.
     *
     * @return the decoded length, or -1 when nothing was decoded
     */
    private static int decodeInPlace(MemorySegment buf, int len) {
        int o = 0;
        boolean changed = false;
        for (int i = 0; i < len; i++) {
            char c = buf.getAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, i);
            if (c == '%' && i + 2 < len) {
                int d1 = hexDigit(buf.getAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, i + 1));
                int d2 = hexDigit(buf.getAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, i + 2));
                if (d1 >= 0 && d2 >= 0) {
                    buf.setAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, o++, (char) ((d1 << 4) | d2));
                    i += 2;
                    changed = true;
                    continue;
                }
            } else if (c == '+') {
                buf.setAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, o++, ' ');
                changed = true;
                continue;
            }
            buf.setAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, o++, c);
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
