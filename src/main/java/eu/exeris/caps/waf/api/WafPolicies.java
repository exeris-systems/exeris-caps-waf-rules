package eu.exeris.caps.waf.api;

import eu.exeris.caps.waf.internal.CoreWafRuleSet;
import eu.exeris.caps.waf.internal.DefaultWafPolicy;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory and builder for creating {@link WafPolicy} instances.
 *
 * @since 0.1.0
 */
public final class WafPolicies {

    private WafPolicies() {}

    /**
     * Creates a {@link WafPolicy} with the default Core Rule Set in active blocking mode.
     *
     * @return active WAF policy
     */
    public static WafPolicy defaultCoreRules() {
        return defaultCoreRules(WafMode.BLOCK);
    }

    /**
     * Creates a {@link WafPolicy} with the default Core Rule Set in the specified mode.
     *
     * @param mode enforcement mode
     * @return configured WAF policy
     */
    public static WafPolicy defaultCoreRules(WafMode mode) {
        return new DefaultWafPolicy(mode, CoreWafRuleSet.defaultRules());
    }

    /**
     * Creates a new fluent {@link Builder} to construct a customized WAF policy.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link WafPolicy}.
     */
    public static final class Builder {
        private WafMode mode = WafMode.BLOCK;
        private final List<WafRule> customRules = new ArrayList<>(CoreWafRuleSet.defaultRules());

        public Builder mode(WafMode mode) {
            this.mode = (mode != null) ? mode : WafMode.BLOCK;
            return this;
        }

        public Builder addRule(WafRule rule) {
            if (rule != null) {
                this.customRules.add(rule);
            }
            return this;
        }

        public WafPolicy build() {
            return new DefaultWafPolicy(mode, customRules);
        }
    }
}
