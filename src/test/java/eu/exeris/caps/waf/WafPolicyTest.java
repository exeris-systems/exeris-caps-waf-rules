package eu.exeris.caps.waf;

import eu.exeris.caps.waf.api.WafCategory;
import eu.exeris.caps.waf.api.WafDecision;
import eu.exeris.caps.waf.api.WafHeader;
import eu.exeris.caps.waf.api.WafMode;
import eu.exeris.caps.waf.api.WafPolicies;
import eu.exeris.caps.waf.api.WafPolicy;
import eu.exeris.caps.waf.api.WafRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("WafPolicy Unit Tests")
class WafPolicyTest {

    private final WafPolicy policy = WafPolicies.defaultCoreRules();

    @Test
    @DisplayName("Legitimate benign requests are allowed")
    void testBenignRequestAllowed() {
        WafRequest req = new WafRequest(
                "GET",
                "/api/v1/products?category=electronics&limit=20",
                "/api/v1/products",
                "category=electronics&limit=20",
                List.of(
                        new WafHeader("Host", "api.example.com"),
                        new WafHeader("User-Agent", "Mozilla/5.0"),
                        new WafHeader("Accept", "application/json")
                )
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isTrue();
        assertThat(decision.category()).isNull();
    }

    @Test
    @DisplayName("SQL Injection in query string is blocked")
    void testSqlInjectionInQueryBlocked() {
        WafRequest req = new WafRequest(
                "GET",
                "/api/v1/users?id=1%20union%20select%201,2,3",
                "/api/v1/users",
                "id=1 union select 1,2,3",
                List.of()
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.SQL_INJECTION);
        assertThat(decision.ruleId()).isEqualTo("SQLI-101");
    }

    @Test
    @DisplayName("XSS injection in query string is blocked")
    void testXssInjectionBlocked() {
        WafRequest req = new WafRequest(
                "GET",
                "/search?q=<script>alert(document.cookie)</script>",
                "/search",
                "q=<script>alert(document.cookie)</script>",
                List.of()
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.XSS);
    }

    @Test
    @DisplayName("Path Traversal in URI path is blocked")
    void testPathTraversalBlocked() {
        WafRequest req = new WafRequest(
                "GET",
                "/static/../../etc/passwd",
                "/static/../../etc/passwd",
                "",
                List.of()
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.PATH_TRAVERSAL);
    }

    @Test
    @DisplayName("Remote Command Execution attempt in query is blocked")
    void testRceBlocked() {
        WafRequest req = new WafRequest(
                "POST",
                "/api/v1/exec",
                "/api/v1/exec",
                "cmd=echo%201%20|%20bash",
                List.of()
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.RCE);
    }

    @Test
    @DisplayName("Restricted proxy override header is blocked")
    void testMaliciousHeaderBlocked() {
        WafRequest req = new WafRequest(
                "GET",
                "/api/v1/admin",
                "/api/v1/admin",
                "",
                List.of(
                        new WafHeader("X-Original-URL", "/internal/admin/secret")
                )
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.MALICIOUS_HEADER);
    }

    @Test
    @DisplayName("Excessive URI length triggers Protocol Violation")
    void testExcessiveUriLength() {
        String longUri = "/api/bench?" + "a".repeat(4100);
        WafRequest req = new WafRequest(
                "GET",
                longUri,
                "/api/bench",
                "a".repeat(4100),
                List.of()
        );

        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.PROTOCOL_VIOLATION);
    }

    @Test
    @DisplayName("DETECT mode identifies violation without blocking")
    void testDetectModeAllows() {
        WafPolicy detectPolicy = WafPolicies.defaultCoreRules(WafMode.DETECT);
        WafRequest req = new WafRequest(
                "GET",
                "/api/v1/users?id=1%20union%20select%201",
                "/api/v1/users",
                "id=1 union select 1",
                List.of()
        );

        WafDecision decision = detectPolicy.evaluate(req);
        assertThat(decision.isAllowed()).isTrue();
    }

    private static WafRequest query(String rawQuery) {
        return new WafRequest("GET", "/x?" + rawQuery, "/x", rawQuery, List.of());
    }

    @Test
    @DisplayName("A payload encoded twice is matched as its decoded form")
    void doubleEncodedTraversalIsBlocked() {
        WafDecision decision = policy.evaluate(query("file=..%255cwindows"));
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.category()).isEqualTo(WafCategory.PATH_TRAVERSAL);

        assertThat(policy.evaluate(query("q=1%2520union%2520select%25201")).isAllowed()).isFalse();
    }

    @Test
    @DisplayName("A value still encoded after the permitted decoding rounds is refused")
    void excessiveEncodingIsRefused() {
        WafDecision decision = policy.evaluate(query("a=%25252525252541"));
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.ruleId()).isEqualTo("PROTO-003");
    }

    @Test
    @DisplayName("A null byte is refused in the query and in header values, raw or encoded")
    void nullByteIsRefusedEverywhere() {
        assertThat(policy.evaluate(query("f=a%00b")).ruleId()).isEqualTo("PROTO-002");
        assertThat(policy.evaluate(query("f=a%2500b")).ruleId()).isEqualTo("PROTO-002");
        WafRequest header = new WafRequest("GET", "/x", "/x", "", List.of(new WafHeader("X-A", "a%00b")));
        assertThat(policy.evaluate(header).ruleId()).isEqualTo("PROTO-002");
    }

    @Test
    @DisplayName("DETECT mode lets the request through and reports the rule that matched")
    void detectModeReportsTheMatch() {
        WafDecision decision = WafPolicies.defaultCoreRules(WafMode.DETECT).evaluate(query("id=1 union select 1"));
        assertThat(decision.isAllowed()).isTrue();
        assertThat(decision.isDetected()).isTrue();
        assertThat(decision.ruleId()).isEqualTo("SQLI-101");
        assertThat(decision.category()).isEqualTo(WafCategory.SQL_INJECTION);
        assertThat(WafPolicies.defaultCoreRules(WafMode.DETECT).evaluate(query("id=1")).isDetected()).isFalse();
    }

    @Test
    @DisplayName("The token of a restricted-header decision is the canonical name, not request text")
    void restrictedHeaderTokenIsCanonical() {
        WafRequest req = new WafRequest("GET", "/x", "/x", "", List.of(new WafHeader("X-ORIGINAL-URL", "/admin")));
        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.matchedToken()).isEqualTo("x-original-url");
    }

    @Test
    @DisplayName("A header name is reduced to token characters in a decision description")
    void headerNameInDescriptionIsSanitised() {
        WafRequest req = new WafRequest("GET", "/x", "/x", "",
                List.of(new WafHeader("X-A<script>\r\n", "1 union select 1")));
        WafDecision decision = policy.evaluate(req);
        assertThat(decision.isAllowed()).isFalse();
        assertThat(decision.description()).doesNotContain("<", ">", "\r", "\n");
    }

    @Test
    @DisplayName("A request does not change when the list it was built from changes")
    void requestCopiesItsHeaders() {
        java.util.ArrayList<WafHeader> source = new java.util.ArrayList<>();
        WafRequest req = new WafRequest("GET", "/x", "/x", "", source);
        source.add(new WafHeader("X-A", "1"));
        assertThat(req.headers()).isEmpty();
    }
}
