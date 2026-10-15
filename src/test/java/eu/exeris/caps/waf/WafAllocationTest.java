package eu.exeris.caps.waf;

import eu.exeris.caps.waf.api.WafDecision;
import eu.exeris.caps.waf.api.WafHeader;
import eu.exeris.caps.waf.api.WafPolicies;
import eu.exeris.caps.waf.api.WafPolicy;
import eu.exeris.caps.waf.api.WafRequest;
import eu.exeris.kernel.tck.contract.JfrAllocationMonitor;
import eu.exeris.kernel.tck.contract.JfrAllocationMonitor.Config;
import eu.exeris.kernel.tck.contract.JfrAllocationMonitor.Contract;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Measures the steady-state allocation of {@link WafPolicy#evaluate} with the kernel TCK's
 * {@link JfrAllocationMonitor}: JFR allocation events for {@code eu.exeris.*} types plus the exact
 * per-thread allocated-bytes delta, which the monitor requires to stay below one byte per iteration.
 * The requests are built before the measurement; only {@code evaluate} runs inside it.
 */
@DisplayName("WafPolicy allocation")
class WafAllocationTest {

    private static final WafPolicy POLICY = WafPolicies.defaultCoreRules();

    private static WafRequest request(String rawPath, String rawQuery, WafHeader... headers) {
        String uri = rawQuery.isEmpty() ? rawPath : rawPath + "?" + rawQuery;
        return new WafRequest("GET", uri, rawPath, rawQuery, List.of(headers));
    }

    private static void assertZeroAllocation(String what, WafRequest[] requests, boolean expectAllowed) throws IOException {
        Config config = Config.ofDefaults("WafRules", "WafAllocationTest", Contract.zero());
        long[] sink = new long[1];
        JfrAllocationMonitor.Result result = JfrAllocationMonitor.measure(config, iterations -> {
            long acc = 0;
            for (int i = 0; i < iterations; i++) {
                WafDecision d = POLICY.evaluate(requests[i % requests.length]);
                acc += d.isAllowed() ? 1 : 0;
            }
            sink[0] = acc;
        });
        assertThat(sink[0] > 0).as("workload ran and decisions were %s", expectAllowed ? "allowed" : "refused")
                .isEqualTo(expectAllowed);
        JfrAllocationMonitor.assertContract(config, result, what);
    }

    @Test
    @DisplayName("A clean request with plain values allocates nothing")
    void cleanPlainRequest() throws IOException {
        WafRequest[] requests = {
                request("/api/v1/products", "category=electronics&limit=20",
                        new WafHeader("Host", "api.example.com"),
                        new WafHeader("User-Agent", "Mozilla/5.0"),
                        new WafHeader("Accept", "application/json")),
                request("/", "")
        };
        assertZeroAllocation("evaluate(clean, plain)", requests, true);
    }

    @Test
    @DisplayName("A clean request whose values need percent-decoding, repeatedly, allocates nothing")
    void cleanEncodedRequest() throws IOException {
        WafRequest[] requests = {
                request("/api/v1/search", "q=a+b%20c&name=J%C3%B6rg&n=1%2B1",
                        new WafHeader("Cookie", "a=b%3Dc"),
                        new WafHeader("Referer", "https://example.com/a%2520b")),
                request("/api/v1/été", "q=über+café%25252541")
        };
        assertZeroAllocation("evaluate(clean, percent-encoded)", requests, true);
    }

    @Test
    @DisplayName("A request that matches a rule or violates the protocol allocates nothing either")
    void matchingRequests() throws IOException {
        WafRequest[] requests = {
                request("/api/v1/users", "id=1%20union%20select%201"),
                request("/x", "f=a%2500b"),
                request("/x", "", new WafHeader("X-Original-URL", "/admin")),
                request("/x", "", new WafHeader("X-A", "<script>")),
                request("/x", "a=%25252525252541")
        };
        assertZeroAllocation("evaluate(matching)", requests, false);
    }

    @Test
    @DisplayName("The measurement fails for a workload that allocates, so a pass above is not vacuous")
    void measurementDetectsAllocation() throws IOException {
        Config config = Config.ofDefaults("WafRules", "WafAllocationTest", Contract.zero());
        Object[] sink = new Object[1];
        JfrAllocationMonitor.Result result = JfrAllocationMonitor.measure(config, iterations -> {
            for (int i = 0; i < iterations; i++) {
                sink[0] = new StringBuilder("q=").append(i).toString();
            }
        });
        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> JfrAllocationMonitor.assertContract(config, result, "control"))
                .isInstanceOf(AssertionError.class);
    }
}
