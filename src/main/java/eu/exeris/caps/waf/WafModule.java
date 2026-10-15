package eu.exeris.caps.waf;

import eu.exeris.caps.waf.api.WafPolicy;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;

/**
 * Capability declaration for {@code exeris-caps-waf-rules}.
 *
 * <p>Provides the {@link WafPolicy} service contract for Layer 7 gateway security inspection.
 *
 * @since 0.1.0
 */
@CapabilityModule
@Provides(service = WafPolicy.class, version = "0.1.0")
public final class WafModule {

    private WafModule() {
        // Declaration carrier only — never constructed.
    }
}
