package eu.exeris.caps.waf.internal;

import eu.exeris.caps.waf.api.WafRule;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;

/**
 * Immutable, thread-safe Aho-Corasick multi-keyword search automaton.
 *
 * <p>Constructed once at startup. Evaluates text in a single pass $O(L)$ with zero heap
 * allocations on the search path, providing sub-microsecond pre-filtering.
 *
 * @since 0.1.0
 */
public final class FastKeywordTrie {

    private final TrieNode root;

    private FastKeywordTrie(TrieNode root) {
        this.root = root;
    }

    /**
     * Builds an automaton from the specified collection of WAF rules.
     *
     * @param rules the rules containing keywords to match
     * @return the compiled, immutable automaton
     */
    public static FastKeywordTrie compile(List<WafRule> rules) {
        TrieNode root = new TrieNode('\0');

        // 1. Build basic keyword trie
        for (WafRule rule : rules) {
            String kw = rule.patternOrKeyword();
            if (kw == null || kw.isEmpty()) {
                continue;
            }
            String lowerKw = asciiLowerCase(kw);
            TrieNode current = root;
            for (int i = 0; i < lowerKw.length(); i++) {
                char c = lowerKw.charAt(i);
                current = current.children.computeIfAbsent(c, TrieNode::new);
            }
            if (current.matches == null) {
                current.matches = new ArrayList<>(1);
            }
            current.matches.add(rule);
        }

        // 2. Compute failure and dictionary links using BFS
        Queue<TrieNode> queue = new ArrayDeque<>();
        for (TrieNode child : root.children.values()) {
            child.failure = root;
            queue.add(child);
        }

        while (!queue.isEmpty()) {
            TrieNode current = queue.poll();
            for (Map.Entry<Character, TrieNode> entry : current.children.entrySet()) {
                char c = entry.getKey();
                TrieNode child = entry.getValue();

                TrieNode fail = current.failure;
                while (fail != null && !fail.children.containsKey(c)) {
                    fail = fail.failure;
                }
                child.failure = (fail != null) ? fail.children.get(c) : root;

                // Inherit matches from failure node
                if (child.failure != null && child.failure.matches != null && !child.failure.matches.isEmpty()) {
                    if (child.matches == null) {
                        child.matches = new ArrayList<>(child.failure.matches.size());
                    }
                    child.matches.addAll(child.failure.matches);
                }

                queue.add(child);
            }
        }

        // 3. Flatten child transitions into compact immutable lookups
        root.freeze();
        return new FastKeywordTrie(root);
    }

    /** Folds only A-Z, the same fold {@link #findFirstMatch} applies to the input. */
    private static String asciiLowerCase(String text) {
        char[] chars = text.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] >= 'A' && chars[i] <= 'Z') {
                chars[i] = (char) (chars[i] + 32);
            }
        }
        return new String(chars);
    }

    /**
     * Scans the input text in a single pass without allocating objects on the heap.
     *
     * @param text input sequence (e.g. URI, query string, header value)
     * @return the first matched {@link WafRule}, or {@code null} if no threats are found
     */
    public WafRule findFirstMatch(CharSequence text) {
        if (text == null || text.length() == 0) {
            return null;
        }

        TrieNode current = root;
        final int len = text.length();

        for (int i = 0; i < len; i++) {
            char c = text.charAt(i);
            // Fast ASCII lowercase conversion without String allocation
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + 32);
            }

            TrieNode next = current.getChild(c);
            while (next == null && current != root) {
                current = current.failure;
                next = current.getChild(c);
            }

            current = (next != null) ? next : root;

            if (current.matches != null && !current.matches.isEmpty()) {
                return current.matches.get(0);
            }
        }

        return null;
    }

    /**
     * Internal node representation.
     */
    private static final class TrieNode {
        final char character;
        Map<Character, TrieNode> children = new HashMap<>(4);
        TrieNode failure;
        List<WafRule> matches;

        TrieNode(char character) {
            this.character = character;
        }

        TrieNode getChild(char c) {
            return children.get(c);
        }

        void freeze() {
            children = Collections.unmodifiableMap(children);
            for (TrieNode child : children.values()) {
                child.freeze();
            }
        }
    }
}
