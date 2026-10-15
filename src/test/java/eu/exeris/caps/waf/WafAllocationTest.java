package eu.exeris.caps.waf;

import eu.exeris.caps.waf.api.WafDecision;
import eu.exeris.caps.waf.api.WafHeader;
import eu.exeris.caps.waf.api.WafMode;
import eu.exeris.caps.waf.api.WafPolicies;
import eu.exeris.caps.waf.api.WafPolicy;
import eu.exeris.caps.waf.api.WafRequest;
import eu.exeris.caps.waf.internal.CoreWafRuleSet;
import eu.exeris.caps.waf.internal.DefaultWafPolicy;
import eu.exeris.kernel.community.memory.CommunityMemoryProvider;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import eu.exeris.kernel.spi.memory.MemoryProviderConfig;
import eu.exeris.kernel.tck.contract.JfrAllocationMonitor;
import eu.exeris.kernel.tck.contract.JfrAllocationMonitor.Config;
import eu.exeris.kernel.tck.contract.JfrAllocationMonitor.Contract;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Measures the steady-state allocation of {@link WafPolicy#evaluate} with the kernel TCK's
 * {@link JfrAllocationMonitor} contracts, each evaluation on a new virtual thread as the kernel serves a
 * connection: see {@link VirtualThreadAllocation} for why the TCK's own {@code measure} cannot observe that.
 * The requests are built before the measurement; only {@code evaluate} runs inside it.
 *
 * <p>A request none of whose values contains {@code %} or {@code +} needs no decode room and is measured
 * against {@link Contract#zero()}. A request that does borrows its room once, from the allocator: against an
 * allocator whose borrow allocates nothing it is measured against {@code Contract.zero()} too, which shows the
 * policy adds no allocation of its own, and against the kernel's Community allocator, whose borrow allocates the
 * objects that wrap its pooled memory, against a {@link Contract#bytesPerIteration} budget.
 */
@DisplayName("WafPolicy allocation, one virtual thread per evaluation")
class WafAllocationTest {

    private static final int WARMUP = 5_000;
    private static final int MEASURED = 10_000;

    private static WafRequest request(String rawPath, String rawQuery, WafHeader... headers) {
        String uri = rawQuery.isEmpty() ? rawPath : rawPath + "?" + rawQuery;
        return new WafRequest("GET", uri, rawPath, rawQuery, List.of(headers));
    }

    private static final WafRequest[] PLAIN_CLEAN = {
            request("/api/v1/products", "category=electronics&limit=20",
                    new WafHeader("Host", "api.example.com"),
                    new WafHeader("User-Agent", "Mozilla/5.0"),
                    new WafHeader("Accept", "application/json")),
            request("/", "")
    };

    /** Matches or violates the protocol checks on the value as received, so nothing is decoded. */
    private static final WafRequest[] PLAIN_REFUSED = {
            request("/api/v1/users", "id=1 union select 1"),
            request("/x", "", new WafHeader("X-Original-URL", "/admin")),
            request("/x", "", new WafHeader("X-A", "<script>")),
            request("/x", "q=a\0b")
    };

    private static final WafRequest[] ENCODED_CLEAN = {
            request("/api/v1/search", "q=a+b%20c&name=J%C3%B6rg&n=1%2B1",
                    new WafHeader("Cookie", "a=b%3Dc"),
                    new WafHeader("Referer", "https://example.com/a%2520b")),
            request("/api/v1/été", "q=über+café%25252541")
    };

    private static final WafRequest[] ENCODED_REFUSED = {
            request("/api/v1/users", "id=1%20union%20select%201"),
            request("/x", "f=a%2500b"),
            request("/x", "a=%25252525252541"),
            request("/x", "", new WafHeader("X-A", "%3Cscript%3E"))
    };

    private static final WafRequest[][] ENCODED = {ENCODED_CLEAN, ENCODED_REFUSED};

    private static WafPolicy policy(MemoryAllocator allocator) {
        return new DefaultWafPolicy(WafMode.BLOCK, CoreWafRuleSet.defaultRules(), allocator);
    }

    private static Config config(Contract contract) {
        return new Config("WafRules", "WafAllocationTest", WARMUP, MEASURED, contract);
    }

    /** Evaluates the requests in turn, one per virtual thread, and returns how many were allowed. */
    private static long run(Config config, WafPolicy policy, WafRequest[] requests) throws Exception {
        long[] allowed = new long[1];
        JfrAllocationMonitor.Result result = VirtualThreadAllocation.measure(config, i -> {
            if (policy.evaluate(requests[i % requests.length]).isAllowed()) {
                allowed[0]++;
            }
        });
        JfrAllocationMonitor.assertContract(config, result, "evaluate");
        return allowed[0];
    }

    @Test
    @DisplayName("A clean request whose values need no decoding allocates nothing")
    void cleanPlainRequest() throws Exception {
        long allowed = run(config(Contract.zero()), WafPolicies.defaultCoreRules(), PLAIN_CLEAN);
        assertThat(allowed).isPositive();
    }

    @Test
    @DisplayName("A request refused on the value as received allocates nothing either")
    void refusedPlainRequest() throws Exception {
        long allowed = run(config(Contract.zero()), WafPolicies.defaultCoreRules(), PLAIN_REFUSED);
        assertThat(allowed).isZero();
    }

    @Test
    @DisplayName("Percent-encoded requests allocate nothing of their own when the borrow allocates nothing")
    void encodedRequestsAddNothingToTheBorrow() throws Exception {
        for (WafRequest[] requests : ENCODED) {
            RecyclingAllocator allocator = new RecyclingAllocator(4, 64 * 1_024);
            WafPolicy policy = policy(allocator);
            long allowed = run(config(Contract.zero()), policy, requests);
            assertThat(allowed > 0).isEqualTo(requests == ENCODED_CLEAN);
            assertThat(allocator.borrows()).as("one borrow per evaluation").isEqualTo(WARMUP + MEASURED);
            assertThat(allocator.outstanding()).as("every borrow returned").isZero();
        }
    }

    @Test
    @DisplayName("Percent-encoded requests borrow from the kernel's Community allocator within a byte budget")
    void encodedRequestsAgainstTheCommunityAllocator() throws Exception {
        try (MemoryAllocator community = new CommunityMemoryProvider().createAllocator(MemoryProviderConfig.defaults())) {
            WafPolicy policy = policy(community);
            for (WafRequest[] requests : ENCODED) {
                run(config(Contract.bytesPerIteration(BORROW_BYTES_BUDGET)), policy, requests);
            }
            assertThat(community.stats().allocationCount()).isEqualTo(community.stats().releaseCount());
        }
    }

    /**
     * What one borrow from the Community allocator may allocate, in bytes: the buffer object that wraps the pooled
     * segment, the record that carries the segment back, and the queue node that takes it back.
     */
    private static final double BORROW_BYTES_BUDGET = 160;

    @Test
    @DisplayName("Without an allocator, a request that needs room allocates it, and the measurement says so")
    void withoutAnAllocatorTheRoomIsAllocated() throws Exception {
        WafPolicy policy = WafPolicies.defaultCoreRules();
        Config config = config(Contract.zero());
        JfrAllocationMonitor.Result result = VirtualThreadAllocation.measure(config, i ->
                policy.evaluate(ENCODED_CLEAN[i % ENCODED_CLEAN.length]));
        assertThatThrownBy(() -> JfrAllocationMonitor.assertContract(config, result, "evaluate, no allocator"))
                .isInstanceOf(AssertionError.class);
    }

    @Test
    @DisplayName("Control: a thread-local decode buffer is caught on virtual threads")
    void threadLocalScratchIsCaught() throws Exception {
        ThreadLocal<char[][]> scratch = ThreadLocal.withInitial(() -> new char[][] {new char[512]});
        long[] sink = new long[1];
        Config config = config(Contract.zero());
        JfrAllocationMonitor.Result result = VirtualThreadAllocation.measure(config, i -> {
            char[] buffer = scratch.get()[0];
            buffer[i % buffer.length] = (char) i;
            sink[0] += buffer[0];
        });
        assertThatThrownBy(() -> JfrAllocationMonitor.assertContract(config, result, "thread-local scratch"))
                .isInstanceOf(AssertionError.class);
    }

    @Test
    @DisplayName("Control: the same thread-local buffer passes when every iteration runs on one thread, "
            + "which is the measurement that hid the cost")
    void threadLocalScratchPassesOnOnePlatformThread() throws IOException {
        ThreadLocal<char[][]> scratch = ThreadLocal.withInitial(() -> new char[][] {new char[512]});
        long[] sink = new long[1];
        Config config = config(Contract.zero());
        JfrAllocationMonitor.Result result = JfrAllocationMonitor.measure(config, iterations -> {
            for (int i = 0; i < iterations; i++) {
                char[] buffer = scratch.get()[0];
                buffer[i % buffer.length] = (char) i;
                sink[0] += buffer[0];
            }
        });
        JfrAllocationMonitor.assertContract(config, result, "thread-local scratch, one platform thread");
    }

    @Test
    @DisplayName("Control: the measurement fails for a workload that allocates")
    void measurementDetectsAllocation() throws Exception {
        Object[] sink = new Object[1];
        Config config = config(Contract.zero());
        JfrAllocationMonitor.Result result = VirtualThreadAllocation.measure(config,
                i -> sink[0] = new StringBuilder("q=").append(i).toString());
        assertThatThrownBy(() -> JfrAllocationMonitor.assertContract(config, result, "control"))
                .isInstanceOf(AssertionError.class);
    }

    @Test
    @DisplayName("A decision does not depend on where the room comes from")
    void decisionsAgreeAcrossRoomSources() throws Exception {
        MemoryAllocator community = new CommunityMemoryProvider().createAllocator(MemoryProviderConfig.defaults());
        RecyclingAllocator recycling = new RecyclingAllocator(1, 64 * 1_024);
        WafPolicy none = WafPolicies.defaultCoreRules();
        WafPolicy explicit = policy(recycling);
        WafPolicy pooled = policy(community);
        WafPolicy bound = WafPolicies.defaultCoreRules();
        try (community) {
            for (WafRequest[] requests : new WafRequest[][] {PLAIN_CLEAN, PLAIN_REFUSED, ENCODED_CLEAN, ENCODED_REFUSED}) {
                for (WafRequest request : requests) {
                    WafDecision expected = none.evaluate(request);
                    assertThat(explicit.evaluate(request)).isEqualTo(expected);
                    assertThat(pooled.evaluate(request)).isEqualTo(expected);
                    assertThat(boundEvaluate(recycling, bound, request)).isEqualTo(expected);
                }
            }
            assertThat(recycling.borrows()).isPositive();
            assertThat(recycling.outstanding()).isZero();
        }
    }

    private static WafDecision boundEvaluate(MemoryAllocator allocator, WafPolicy policy, WafRequest request)
            throws Exception {
        return ScopedValue.where(eu.exeris.kernel.spi.context.KernelProviders.MEMORY_ALLOCATOR, allocator)
                .call(() -> policy.evaluate(request));
    }
}
