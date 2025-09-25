package org.example.keycloak.authenticator.utils;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;

/**
 * Utility class for creating test fixtures and mock objects
 */
public class TestUtils {

    /**
     * Create a mock AuthenticationFlowContext with basic configuration
     */
    public static AuthenticationFlowContext createMockContext(String trustedIPs, String clientIP) {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticatorConfigModel configModel = mock(AuthenticatorConfigModel.class);

        Map<String, String> config = new HashMap<>();
        config.put("trusted-ips", trustedIPs);

        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(configModel.getConfig()).thenReturn(config);

        var connection = mock(org.keycloak.common.ClientConnection.class);
        when(connection.getRemoteAddr()).thenReturn(clientIP);
        when(context.getConnection()).thenReturn(connection);

        return context;
    }

    /**
     * Test data provider for various IP addresses
     */
    public static class IPTestData {
        public static final String[] PRIVATE_IPS = {
                "192.168.1.1", "192.168.255.255",
                "10.0.0.1", "10.255.255.255",
                "172.16.0.1", "172.31.255.255"
        };

        public static final String[] PUBLIC_IPS = {
                "8.8.8.8", "1.1.1.1",
                "203.0.113.42", "198.51.100.1"
        };

        public static final String[] INVALID_IPS = {
                "256.1.1.1", "1.1.1", "1.1.1.1.1",
                "abc.def.ghi.jkl", "", "not-an-ip"
        };

        public static final String[] CIDR_RANGES = {
                "192.168.1.0/24", "10.0.0.0/8",
                "172.16.0.0/12", "0.0.0.0/0"
        };
    }
}