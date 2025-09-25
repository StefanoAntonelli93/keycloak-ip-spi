package org.example.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("IPValidator Tests")
class IPValidatorTest {

    private AuthenticationFlowContext context;
    private AuthenticatorConfigModel configModel;

    @BeforeEach
    void setUp() {
        context = mock(AuthenticationFlowContext.class);
        configModel = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
    }

    @Nested
    @DisplayName("Validator Creation Tests")
    class ValidatorCreationTests {

        @Test
        @DisplayName("Should create validator from valid configuration")
        void testValidatorCreation() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24, 10.0.0.1");
            when(configModel.getConfig()).thenReturn(config);

            Optional<IPValidator> validator = IPValidator.fromContext(context);

            assertTrue(validator.isPresent());
        }

        @Test
        @DisplayName("Should return empty when configuration is missing")
        void testMissingConfiguration() {
            when(context.getAuthenticatorConfig()).thenReturn(null);

            Optional<IPValidator> validator = IPValidator.fromContext(context);

            assertFalse(validator.isPresent());
        }

        @Test
        @DisplayName("Should return empty when trusted IPs is empty")
        void testEmptyTrustedIPs() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "");
            when(configModel.getConfig()).thenReturn(config);

            Optional<IPValidator> validator = IPValidator.fromContext(context);

            assertFalse(validator.isPresent());
        }

        @Test
        @DisplayName("Should return empty when trusted IPs is whitespace only")
        void testWhitespaceOnlyTrustedIPs() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "   ");
            when(configModel.getConfig()).thenReturn(config);

            Optional<IPValidator> validator = IPValidator.fromContext(context);

            assertFalse(validator.isPresent());
        }
    }

    @Nested
    @DisplayName("IP Validation Tests")
    class IPValidationTests {

        @ParameterizedTest
        @DisplayName("Should validate IPs against CIDR ranges")
        @CsvSource({
                "'192.168.1.0/24', '192.168.1.100', true",
                "'192.168.1.0/24', '192.168.1.255', true",
                "'192.168.1.0/24', '192.168.2.1', false",
                "'10.0.0.0/8', '10.255.255.255', true",
                "'10.0.0.0/8', '11.0.0.1', false",
                "'172.16.0.0/12', '172.31.255.255', true",
                "'172.16.0.0/12', '172.32.0.1', false"
        })
        void testCIDRValidation(String trustedRange, String ipToTest, boolean expected) {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", trustedRange);
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();
            boolean result = validator.isTrusted(ipToTest);

            assertEquals(expected, result);
        }

        @Test
        @DisplayName("Should validate exact IP matches")
        void testExactIPMatch() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.1, 10.0.0.1, 8.8.8.8");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            assertTrue(validator.isTrusted("192.168.1.1"));
            assertTrue(validator.isTrusted("10.0.0.1"));
            assertTrue(validator.isTrusted("8.8.8.8"));
            assertFalse(validator.isTrusted("192.168.1.2"));
            assertFalse(validator.isTrusted("8.8.4.4"));
        }

        @Test
        @DisplayName("Should handle mixed exact IPs and CIDR ranges")
        void testMixedPatterns() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.1, 10.0.0.0/8, 8.8.8.8, 172.16.0.0/12");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            // Verify exact matches
            assertTrue(validator.isTrusted("192.168.1.1"));
            assertTrue(validator.isTrusted("8.8.8.8"));

            // Verify CIDR ranges
            assertTrue(validator.isTrusted("10.50.50.50"));
            assertTrue(validator.isTrusted("172.20.1.1"));

            // Verify non-matches
            assertFalse(validator.isTrusted("192.168.1.2"));
            assertFalse(validator.isTrusted("11.0.0.1"));
        }

        @Test
        @DisplayName("Should handle /32 CIDR (single IP)")
        void testSingleIPCIDR() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.1/32");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            assertTrue(validator.isTrusted("192.168.1.1"));
            assertFalse(validator.isTrusted("192.168.1.2"));
        }

        @Test
        @DisplayName("Should handle /0 CIDR (all IPs)")
        void testAllIPsCIDR() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "0.0.0.0/0");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            assertTrue(validator.isTrusted("1.1.1.1"));
            assertTrue(validator.isTrusted("192.168.1.1"));
            assertTrue(validator.isTrusted("255.255.255.255"));
        }
    }

    @Nested
    @DisplayName("Invalid Input Handling Tests")
    class InvalidInputTests {

        @ParameterizedTest
        @DisplayName("Should handle invalid IP formats")
        @ValueSource(strings = {
                "256.1.1.1",
                "1.1.1",
                "1.1.1.1.1",
                "abc.def.ghi.jkl",
                "",
                "192.168.-1.1",
                "not-an-ip"
        })
        void testInvalidIPFormats(String invalidIP) {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();
            boolean result = validator.isTrusted(invalidIP);

            assertFalse(result);
        }

        @Test
        @DisplayName("Should skip invalid patterns in configuration")
        void testInvalidPatternsInConfig() {
            // mix of valid and invalid patterns
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24, invalid-cidr, 10.0.0.1, 256.256.256.256, 172.16.0.0/40");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            // only valid patterns should work
            assertTrue(validator.isTrusted("192.168.1.100"));
            assertTrue(validator.isTrusted("10.0.0.1"));
            assertFalse(validator.isTrusted("256.256.256.256"));
            assertFalse(validator.isTrusted("172.16.0.1")); // Invalid CIDR /40
        }
    }

    @Nested
    @DisplayName("Whitespace Handling Tests")
    class WhitespaceTests {

        @Test
        @DisplayName("Should trim whitespace from configuration")
        void testWhitespaceTrimming() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", " 192.168.1.0/24 , 10.0.0.1 , 172.16.0.0/12 ");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            assertTrue(validator.isTrusted("192.168.1.100"));
            assertTrue(validator.isTrusted("10.0.0.1"));
            assertTrue(validator.isTrusted("172.16.0.100"));
        }

        @Test
        @DisplayName("Should handle tabs and newlines in configuration")
        void testTabsAndNewlines() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24,\t10.0.0.1,\n172.16.0.0/12");
            when(configModel.getConfig()).thenReturn(config);

            IPValidator validator = IPValidator.fromContext(context).orElseThrow();

            assertTrue(validator.isTrusted("192.168.1.100"));
            assertTrue(validator.isTrusted("10.0.0.1"));
            assertTrue(validator.isTrusted("172.16.0.100"));
        }
    }
}