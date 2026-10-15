package eu.exeris.caps.waf;

import eu.exeris.caps.waf.api.WafCategory;
import eu.exeris.caps.waf.api.WafRule;
import eu.exeris.caps.waf.internal.FastKeywordTrie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("FastKeywordTrie Unit Tests")
class FastKeywordTrieTest {

    @Test
    @DisplayName("Empty or clean input returns null match")
    void testCleanInput() {
        FastKeywordTrie trie = FastKeywordTrie.compile(List.of(
                new WafRule("SQLI-1", "Union", WafCategory.SQL_INJECTION, "union select", "desc"),
                new WafRule("XSS-1", "Script", WafCategory.XSS, "<script", "desc")
        ));

        assertThat(trie.findFirstMatch(null)).isNull();
        assertThat(trie.findFirstMatch("")).isNull();
        assertThat(trie.findFirstMatch("/api/v1/users?name=john")).isNull();
    }

    @Test
    @DisplayName("Matches keywords case-insensitively without allocations")
    void testCaseInsensitiveMatching() {
        FastKeywordTrie trie = FastKeywordTrie.compile(List.of(
                new WafRule("SQLI-1", "Union", WafCategory.SQL_INJECTION, "union select", "desc"),
                new WafRule("XSS-1", "Script", WafCategory.XSS, "<script", "desc")
        ));

        WafRule match1 = trie.findFirstMatch("SELECT * FROM t WHERE id=1 UnIoN SeLeCt 1,2");
        assertThat(match1).isNotNull();
        assertThat(match1.id()).isEqualTo("SQLI-1");

        WafRule match2 = trie.findFirstMatch("<ScRiPt>alert(1)</ScRiPt>");
        assertThat(match2).isNotNull();
        assertThat(match2.id()).isEqualTo("XSS-1");
    }

    @Test
    @DisplayName("Handles overlapping keyword patterns correctly")
    void testOverlappingPatterns() {
        FastKeywordTrie trie = FastKeywordTrie.compile(List.of(
                new WafRule("LFI-1", "Dot dot", WafCategory.PATH_TRAVERSAL, "..", "desc"),
                new WafRule("LFI-2", "Dot dot slash", WafCategory.PATH_TRAVERSAL, "../", "desc")
        ));

        WafRule match = trie.findFirstMatch("/files/../../etc/passwd");
        assertThat(match).isNotNull();
        assertThat(match.category()).isEqualTo(WafCategory.PATH_TRAVERSAL);
    }

    @Test
    @DisplayName("A keyword with a non-ASCII upper-case letter matches the same text")
    void nonAsciiKeywordMatchesItself() {
        eu.exeris.caps.waf.api.WafRule rule = new eu.exeris.caps.waf.api.WafRule(
                "T-1", "t", eu.exeris.caps.waf.api.WafCategory.XSS, "\u00c4bc", "d");
        FastKeywordTrie trie = FastKeywordTrie.compile(java.util.List.of(rule));
        assertThat(trie.findFirstMatch("x\u00c4bcx")).isNotNull();
        assertThat(trie.findFirstMatch("xabcx")).isNull();
    }
}
