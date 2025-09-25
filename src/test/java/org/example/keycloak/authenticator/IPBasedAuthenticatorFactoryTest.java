package org.example.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test suite for IPBasedAuthenticatorFactory
 */
@DisplayName("IPBasedAuthenticatorFactory Tests")
class IPBasedAuthenticatorFactoryTest {

    private IPBasedAuthenticatorFactory factory;
    private KeycloakSession session;
    private KeycloakSessionFactory sessionFactory;
    private Config.Scope configScope;

    @BeforeEach
    void setUp() {
        factory = new IPBasedAuthenticatorFactory();
        session = mock(KeycloakSession.class);
        sessionFactory = mock(KeycloakSessionFactory.class);
        configScope = mock(Config.Scope.class);
    }

    @Nested
    @DisplayName("Factory Metadata Tests")
    class MetadataTests {

        @Test
        @DisplayName("Should return correct provider ID")
        void testGetId() {
            assertEquals("ip-based-authenticator", factory.getId());
        }

        @Test
        @DisplayName("Should return correct display type")
        void testGetDisplayType() {
            assertEquals("IP-Based Conditional Authentication", factory.getDisplayType());
        }

        @Test
        @DisplayName("Should return correct reference category")
        void testGetReferenceCategory() {
            assertEquals("conditional", factory.getReferenceCategory());
        }

        @Test
        @DisplayName("Should be configurable")
        void testIsConfigurable() {
            assertTrue(factory.isConfigurable());
        }

        @Test
        @DisplayName("Should not allow user setup")
        void testIsUserSetupAllowed() {
            assertFalse(factory.isUserSetupAllowed());
        }

        @Test
        @DisplayName("Should provide help text")
        void testGetHelpText() {
            String helpText = factory.getHelpText();
            assertNotNull(helpText);
            assertTrue(helpText.contains("IP address"));
            assertTrue(helpText.contains("authentication flows"));
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should provide all required configuration properties")
        void testGetConfigProperties() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();

            assertNotNull(properties);
            assertEquals(3, properties.size());

            // Verify trusted IPs property
            ProviderConfigProperty trustedIPs = findProperty(properties, "trusted-ips");
            assertNotNull(trustedIPs);
            assertEquals(ProviderConfigProperty.STRING_TYPE, trustedIPs.getType());
            assertEquals("Trusted IP Addresses", trustedIPs.getLabel());
            assertNotNull(trustedIPs.getHelpText());

            // Verify check behind proxy property
            ProviderConfigProperty checkProxy = findProperty(properties, "check-behind-proxy");
            assertNotNull(checkProxy);
            assertEquals(ProviderConfigProperty.BOOLEAN_TYPE, checkProxy.getType());
            assertEquals("Check Behind Proxy", checkProxy.getLabel());
            assertEquals("false", checkProxy.getDefaultValue());

            // Verify proxy header property
            ProviderConfigProperty proxyHeader = findProperty(properties, "proxy-header");
            assertNotNull(proxyHeader);
            assertEquals(ProviderConfigProperty.STRING_TYPE, proxyHeader.getType());
            assertEquals("Proxy Header Name", proxyHeader.getLabel());
            assertEquals("X-Forwarded-For", proxyHeader.getDefaultValue());
        }

        @Test
        @DisplayName("Should have correct help text for trusted IPs")
        void testTrustedIPsHelpText() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();
            ProviderConfigProperty trustedIPs = findProperty(properties, "trusted-ips");

            assertNotNull(trustedIPs.getHelpText());
            assertTrue(trustedIPs.getHelpText().contains("CIDR"));
            assertTrue(trustedIPs.getHelpText().contains("192.168.1.0/24"));
        }

        @Test
        @DisplayName("Should have correct help text for proxy configuration")
        void testProxyConfigurationHelpText() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();

            ProviderConfigProperty checkProxy = findProperty(properties, "check-behind-proxy");
            assertTrue(checkProxy.getHelpText().contains("proxy headers"));

            ProviderConfigProperty proxyHeader = findProperty(properties, "proxy-header");
            assertTrue(proxyHeader.getHelpText().contains("X-Forwarded-For"));
            assertTrue(proxyHeader.getHelpText().contains("X-Real-IP"));
        }
    }

    @Nested
    @DisplayName("Requirement Choices Tests")
    class RequirementTests {

        @Test
        @DisplayName("Should provide correct requirement choices")
        void testGetRequirementChoices() {
            AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();

            assertNotNull(requirements);
            assertEquals(3, requirements.length);

            // Verify all expected requirements are present
            assertTrue(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.REQUIRED));
            assertTrue(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.ALTERNATIVE));
            assertTrue(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.DISABLED));
        }

        @Test
        @DisplayName("Should not include CONDITIONAL requirement")
        void testNoConditionalRequirement() {
            AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();
            assertFalse(containsRequirement(requirements, AuthenticationExecutionModel.Requirement.CONDITIONAL));
        }
    }

    @Nested
    @DisplayName("Authenticator Creation Tests")
    class CreationTests {

        @Test
        @DisplayName("Should create authenticator instance")
        void testCreate() {
            Authenticator authenticator = factory.create(session);

            assertNotNull(authenticator);
            assertInstanceOf(IPBasedAuthenticator.class, authenticator);
        }

        @Test
        @DisplayName("Should create new instance each time")
        void testCreatesNewInstances() {
            Authenticator authenticator1 = factory.create(session);
            Authenticator authenticator2 = factory.create(session);

            assertNotNull(authenticator1);
            assertNotNull(authenticator2);
            assertNotSame(authenticator1, authenticator2);
        }
    }

    @Nested
    @DisplayName("Lifecycle Methods Tests")
    class LifecycleTests {

        @Test
        @DisplayName("Should initialize without errors")
        void testInit() {
            assertDoesNotThrow(() -> factory.init(configScope));
            // Verify no interactions since init does nothing
            verifyNoInteractions(configScope);
        }

        @Test
        @DisplayName("Should post-initialize without errors")
        void testPostInit() {
            assertDoesNotThrow(() -> factory.postInit(sessionFactory));
            // Verify no interactions since postInit does nothing
            verifyNoInteractions(sessionFactory);
        }

        @Test
        @DisplayName("Should close without errors")
        void testClose() {
            assertDoesNotThrow(() -> factory.close());
        }

        @Test
        @DisplayName("Should handle null parameters in lifecycle methods")
        void testLifecycleWithNullParameters() {
            assertDoesNotThrow(() -> factory.init(null));
            assertDoesNotThrow(() -> factory.postInit(null));
        }
    }

    @Nested
    @DisplayName("Property Validation Tests")
    class PropertyValidationTests {

        @Test
        @DisplayName("Should have non-null property names")
        void testPropertyNamesNotNull() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();

            for (ProviderConfigProperty property : properties) {
                assertNotNull(property.getName(), "Property name should not be null");
            }
        }

        @Test
        @DisplayName("Should have non-null property types")
        void testPropertyTypesNotNull() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();

            for (ProviderConfigProperty property : properties) {
                assertNotNull(property.getType(), "Property type should not be null");
            }
        }

        @Test
        @DisplayName("Should have non-null property labels")
        void testPropertyLabelsNotNull() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();

            for (ProviderConfigProperty property : properties) {
                assertNotNull(property.getLabel(), "Property label should not be null");
            }
        }

        @Test
        @DisplayName("Should have valid default values")
        void testDefaultValues() {
            List<ProviderConfigProperty> properties = factory.getConfigProperties();

            ProviderConfigProperty trustedIPs = findProperty(properties, "trusted-ips");
            assertEquals("", trustedIPs.getDefaultValue());

            ProviderConfigProperty checkProxy = findProperty(properties, "check-behind-proxy");
            assertEquals("false", checkProxy.getDefaultValue());

            ProviderConfigProperty proxyHeader = findProperty(properties, "proxy-header");
            assertEquals("X-Forwarded-For", proxyHeader.getDefaultValue());
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle multiple create calls")
        void testMultipleCreates() {
            for (int i = 0; i < 10; i++) {
                Authenticator authenticator = factory.create(session);
                assertNotNull(authenticator);
            }
        }

        @Test
        @DisplayName("Should maintain consistent configuration properties")
        void testConsistentConfigProperties() {
            List<ProviderConfigProperty> properties1 = factory.getConfigProperties();
            List<ProviderConfigProperty> properties2 = factory.getConfigProperties();

            // Should return the same list (not necessarily the same instance)
            assertEquals(properties1.size(), properties2.size());

            for (int i = 0; i < properties1.size(); i++) {
                assertEquals(properties1.get(i).getName(), properties2.get(i).getName());
                assertEquals(properties1.get(i).getType(), properties2.get(i).getType());
            }
        }

        @Test
        @DisplayName("Should have immutable requirement choices")
        void testRequirementChoicesImmutability() {
            AuthenticationExecutionModel.Requirement[] requirements1 = factory.getRequirementChoices();
            AuthenticationExecutionModel.Requirement[] requirements2 = factory.getRequirementChoices();
            // Modify first array
            requirements1[0] = AuthenticationExecutionModel.Requirement.CONDITIONAL;
            // Second array should not be affected
            assertNotEquals(requirements1[0], requirements2[0]);
        }
    }

    private ProviderConfigProperty findProperty(List<ProviderConfigProperty> properties, String name) {
        return properties.stream()
                .filter(p -> name.equals(p.getName()))
                .findFirst()
                .orElse(null);
    }

    private boolean containsRequirement(AuthenticationExecutionModel.Requirement[] requirements,
                                        AuthenticationExecutionModel.Requirement requirement) {
        for (AuthenticationExecutionModel.Requirement req : requirements) {
            if (req == requirement) {
                return true;
            }
        }
        return false;
    }
}