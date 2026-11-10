package eu.exeris.caps.waf;

import eu.exeris.kernel.spi.contract.EntitlementClass;
import eu.exeris.kernel.spi.contract.EntitlementRequirement;
import eu.exeris.kernel.tck.contract.AbstractEntitlementRequirementTck;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.ServiceLoader;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("exeris-caps-waf-rules: EntitlementRequirement")
class WafEntitlementTest extends AbstractEntitlementRequirementTck {

    @Override
    protected Class<? extends EntitlementRequirement> providerClass() {
        return WafEntitlement.class;
    }

    @Test
    @DisplayName("ServiceLoader discovers the provider from the cap's own service registration")
    void serviceLoaderDiscoversTheProvider() {
        List<Class<? extends EntitlementRequirement>> types = ServiceLoader.load(EntitlementRequirement.class)
                .stream()
                .map(ServiceLoader.Provider::type)
                .toList();

        assertThat(types).contains(WafEntitlement.class);
    }

    @Test
    @DisplayName("It requires exactly this cap's own capability identifier")
    void requiresOnlyItsOwnCapability() {
        assertThat(new WafEntitlement().requiredCapabilities()).containsExactly("exeris-caps-waf-rules");
        assertThat(WafEntitlement.CAPABILITY_ID).isEqualTo("exeris-caps-waf-rules");
    }

    @Test
    @DisplayName("It declares the COMMERCIAL entitlement class, stable across calls")
    void entitlementClassIsCommercialAndStable() {
        WafEntitlement entitlement = new WafEntitlement();
        EntitlementClass first = entitlement.entitlementClass();

        assertThat(first).isEqualTo(EntitlementClass.COMMERCIAL);
        assertThat(entitlement.entitlementClass()).isSameAs(first);
        assertThat(new WafEntitlement().entitlementClass()).isEqualTo(EntitlementClass.COMMERCIAL);
    }
}
