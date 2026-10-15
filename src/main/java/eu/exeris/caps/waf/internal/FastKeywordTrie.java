package eu.exeris.caps.waf.internal;

import eu.exeris.caps.waf.api.WafRule;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.TreeSet;

/**
 * Immutable, thread-safe Aho-Corasick multi-keyword search automaton.
 *
 * <p>Built once, then read-only. The automaton is compiled to a complete transition table over the
 * characters the keywords use (every other character leads back to the start), held in primitive
 * arrays, so a scan reads those arrays and allocates nothing: no boxing, no iterator, no result
 * object other than the {@link WafRule} or rule index it returns. Matching is case-insensitive for
 * the characters A to Z only.
 *
 * <p>The scan is a single pass over the input, linear in its length.
 *
 * @since 0.1.0
 */
public final class FastKeywordTrie {

    private static final int ASCII = 128;

    /** Character to alphabet class for characters below {@link #ASCII}; 0 means "not a keyword character". */
    private final int[] asciiClass;
    /** Sorted keyword characters at or above {@link #ASCII}; the class of {@code wide[i]} is {@code wideClass[i]}. */
    private final char[] wide;
    private final int[] wideClass;
    private final int classes;
    /** {@code next[state * classes + class]}: the complete transition function. */
    private final int[] next;
    /** Index into {@link #rules} of the first rule matched on entering a state, or -1. */
    private final int[] out;
    private final WafRule[] rules;

    private FastKeywordTrie(int[] asciiClass, char[] wide, int[] wideClass, int classes,
                            int[] next, int[] out, WafRule[] rules) {
        this.asciiClass = asciiClass;
        this.wide = wide;
        this.wideClass = wideClass;
        this.classes = classes;
        this.next = next;
        this.out = out;
        this.rules = rules;
    }

    /**
     * Builds an automaton from the specified collection of WAF rules. Rules without a keyword are skipped.
     *
     * @param rules the rules containing keywords to match
     * @return the compiled, immutable automaton
     */
    public static FastKeywordTrie compile(List<WafRule> rules) {
        List<WafRule> kept = new ArrayList<>();
        List<String> keywords = new ArrayList<>();
        TreeSet<Character> alphabet = new TreeSet<>();
        for (WafRule rule : rules) {
            String kw = rule.patternOrKeyword();
            if (kw == null || kw.isEmpty()) {
                continue;
            }
            String lower = asciiLowerCase(kw);
            kept.add(rule);
            keywords.add(lower);
            for (int i = 0; i < lower.length(); i++) {
                alphabet.add(lower.charAt(i));
            }
        }

        int[] asciiClass = new int[ASCII];
        List<Character> wideChars = new ArrayList<>();
        int classes = 1;
        for (char c : alphabet) {
            if (c < ASCII) {
                asciiClass[c] = classes++;
            } else {
                wideChars.add(c);
            }
        }
        char[] wide = new char[wideChars.size()];
        int[] wideClass = new int[wide.length];
        for (int i = 0; i < wide.length; i++) {
            wide[i] = wideChars.get(i);
            wideClass[i] = classes++;
        }

        // Build the keyword trie in growable arrays.
        int[][] children = new int[16][];
        int[] first = new int[16];
        int states = 1;
        children[0] = new int[classes];
        Arrays.fill(first, -1);
        for (int k = 0; k < keywords.size(); k++) {
            String kw = keywords.get(k);
            int state = 0;
            for (int i = 0; i < kw.length(); i++) {
                int cls = classOf(asciiClass, wide, wideClass, kw.charAt(i));
                if (children[state][cls] == 0) {
                    if (states == children.length) {
                        children = Arrays.copyOf(children, states * 2);
                        int old = first.length;
                        first = Arrays.copyOf(first, states * 2);
                        Arrays.fill(first, old, first.length, -1);
                    }
                    children[states] = new int[classes];
                    children[state][cls] = states++;
                }
                state = children[state][cls];
            }
            if (first[state] < 0) {
                first[state] = k;
            }
        }

        // Breadth-first: complete the transition function and inherit matches along failure links.
        int[] failure = new int[states];
        int[] next = new int[states * classes];
        int[] out = Arrays.copyOf(first, states);
        Queue<Integer> queue = new ArrayDeque<>();
        for (int cls = 1; cls < classes; cls++) {
            int child = children[0][cls];
            next[cls] = child;
            if (child != 0) {
                failure[child] = 0;
                queue.add(child);
            }
        }
        while (!queue.isEmpty()) {
            int state = queue.poll();
            if (out[state] < 0) {
                out[state] = out[failure[state]];
            }
            for (int cls = 0; cls < classes; cls++) {
                int child = children[state][cls];
                int viaFailure = next[failure[state] * classes + cls];
                if (child != 0) {
                    failure[child] = viaFailure;
                    next[state * classes + cls] = child;
                    queue.add(child);
                } else {
                    next[state * classes + cls] = viaFailure;
                }
            }
        }
        return new FastKeywordTrie(asciiClass, wide, wideClass, classes, next, out, kept.toArray(new WafRule[0]));
    }

    private static int classOf(int[] asciiClass, char[] wide, int[] wideClass, char c) {
        if (c < ASCII) {
            return asciiClass[c];
        }
        int idx = Arrays.binarySearch(wide, c);
        return idx >= 0 ? wideClass[idx] : 0;
    }

    /** Folds only A-Z, the same fold the scan applies to its input. */
    private static String asciiLowerCase(String text) {
        char[] chars = text.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] >= 'A' && chars[i] <= 'Z') {
                chars[i] = (char) (chars[i] + 32);
            }
        }
        return new String(chars);
    }

    /** @return the rules this automaton can report, in the order {@link #findFirstMatchIndex} indexes them */
    public List<WafRule> rules() {
        return List.of(rules);
    }

    /**
     * Scans the input text in a single pass.
     *
     * @param text input sequence (e.g. URI, query string, header value)
     * @return the first matched {@link WafRule}, or {@code null} if none matches
     */
    public WafRule findFirstMatch(CharSequence text) {
        if (text == null) {
            return null;
        }
        int rule = findFirstMatchIndex(text, text.length());
        return rule < 0 ? null : rules[rule];
    }

    /**
     * Scans the first {@code length} characters of {@code text} in a single pass. Allocation-free.
     *
     * @return the index, in {@link #rules()}, of the first rule matched, or -1
     */
    public int findFirstMatchIndex(CharSequence text, int length) {
        int state = 0;
        for (int i = 0; i < length; i++) {
            state = next[state * classes + classOf(text.charAt(i))];
            int rule = out[state];
            if (rule >= 0) {
                return rule;
            }
        }
        return -1;
    }

    /**
     * Scans the first {@code length} characters of {@code text} in a single pass. Allocation-free.
     *
     * @return the index, in {@link #rules()}, of the first rule matched, or -1
     */
    public int findFirstMatchIndex(char[] text, int length) {
        int state = 0;
        for (int i = 0; i < length; i++) {
            state = next[state * classes + classOf(text[i])];
            int rule = out[state];
            if (rule >= 0) {
                return rule;
            }
        }
        return -1;
    }

    /**
     * Scans the first {@code length} UTF-16 code units held in {@code text}, which are read as
     * {@link ValueLayout#JAVA_CHAR} at index {@code 0} to {@code length - 1}, in a single pass. Allocation-free.
     *
     * @return the index, in {@link #rules()}, of the first rule matched, or -1
     */
    public int findFirstMatchIndex(MemorySegment text, int length) {
        int state = 0;
        for (int i = 0; i < length; i++) {
            state = next[state * classes + classOf(text.getAtIndex(ValueLayout.JAVA_CHAR_UNALIGNED, i))];
            int rule = out[state];
            if (rule >= 0) {
                return rule;
            }
        }
        return -1;
    }

    private int classOf(char c) {
        if (c < ASCII) {
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + 32);
            }
            return asciiClass[c];
        }
        int idx = Arrays.binarySearch(wide, c);
        return idx >= 0 ? wideClass[idx] : 0;
    }
}
