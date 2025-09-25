package org.example.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for IPBasedAuthenticator
 */
@DisplayName("IPBasedAuthenticator Tests")
class IPBasedAuthenticatorTest {

    private IPBasedAuthenticator authenticator;
    private AuthenticationFlowContext context;
    private AuthenticationSessionModel authSession;
    private AuthenticatorConfigModel configModel;
    private ClientConnection connection;
    private HttpRequest httpRequest;
    private HttpHeaders httpHeaders;

    @BeforeEach
    void setUp() {
        authenticator = new IPBasedAuthenticator();
        context = mock(AuthenticationFlowContext.class);
        authSession = mock(AuthenticationSessionModel.class);
        configModel = mock(AuthenticatorConfigModel.class);
        connection = mock(ClientConnection.class);
        httpRequest = mock(HttpRequest.class);
        httpHeaders = mock(HttpHeaders.class);

        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(context.getConnection()).thenReturn(connection);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getHttpHeaders()).thenReturn(httpHeaders);
    }

    @Nested
    @DisplayName("Trusted IP Authentication Tests")
    class TrustedIPTests {

        @Test
        @DisplayName("Should allow trusted IP with normal flow")
        void testTrustedIPAuthentication() {
            String trustedIP = "192.168.1.100";
            setupContextWithConfig("192.168.1.0/24", trustedIP, false, null);

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
            verify(context, never()).attempted();
        }

        @Test
        @DisplayName("Should handle multiple trusted IP ranges")
        void testMultipleTrustedRanges() {
            String trustedIP = "10.0.0.50";
            setupContextWithConfig("192.168.1.0/24, 10.0.0.0/16, 172.16.0.0/12", trustedIP, false, null);

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }

        @Test
        @DisplayName("Should handle exact IP match")
        void testExactIPMatch() {
            String exactIP = "8.8.8.8";
            setupContextWithConfig("192.168.1.0/24, 8.8.8.8, 1.1.1.1", exactIP, false, null);

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }
    }

    @Nested
    @DisplayName("Untrusted IP Authentication Tests")
    class UntrustedIPTests {

        @Test
        @DisplayName("Should require OTP for untrusted IP")
        void testUntrustedIPAuthentication() {
            String untrustedIP = "203.0.113.42";
            setupContextWithConfig("192.168.1.0/24", untrustedIP, false, null);

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "false");
            verify(authSession).setAuthNote("require-otp", "true");
            verify(context).attempted();
            verify(context, never()).success();
        }

        @ParameterizedTest
        @DisplayName("Should mark various untrusted IPs as requiring OTP")
        @ValueSource(strings = {"8.8.8.8", "1.1.1.1", "203.0.113.1", "198.51.100.1"})
        void testVariousUntrustedIPs(String untrustedIP) {
            setupContextWithConfig("192.168.1.0/24, 10.0.0.0/8", untrustedIP, false, null);

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("require-otp", "true");
            verify(context).attempted();
        }
    }

    @Nested
    @DisplayName("Proxy Configuration Tests")
    class ProxyTests {

        @Test
        @DisplayName("Should extract IP from proxy header when enabled")
        void testProxyHeaderExtraction() {
            String proxyIP = "203.0.113.42";
            String directIP = "10.0.0.1";
            setupContextWithProxy("203.0.113.42", directIP, proxyIP, "X-Forwarded-For", true);

            authenticator.authenticate(context);

            // proxy IP should be used and marked as trusted
            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }

        @Test
        @DisplayName("Should parse multiple IPs from X-Forwarded-For header")
        void testMultipleProxyIPs() {
            String proxyHeader = "203.0.113.42, 198.51.100.1, 10.0.0.1";
            String directIP = "172.16.0.1";
            setupContextWithProxy("203.0.113.42", directIP, proxyHeader, "X-Forwarded-For", true);

            authenticator.authenticate(context);

            // first IP from proxy header should be used
            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }

        @Test
        @DisplayName("Should use custom proxy header when configured")
        void testCustomProxyHeader() {
            String proxyIP = "192.168.1.100";
            String directIP = "10.0.0.1";
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            config.put("check-behind-proxy", "true");
            config.put("proxy-header", "X-Real-IP");

            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn(directIP);

            MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
            headers.putSingle("X-Real-IP", proxyIP);
            when(httpHeaders.getRequestHeaders()).thenReturn(headers);

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }

        @Test
        @DisplayName("Should fall back to direct IP when proxy header is missing")
        void testFallbackToDirectIP() {
            String directIP = "192.168.1.50";
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            config.put("check-behind-proxy", "true");

            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn(directIP);
            when(httpHeaders.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());

            authenticator.authenticate(context);

            // should use direct IP and mark as trusted
            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when no configuration is present")
        void testNoConfiguration() {
            when(context.getAuthenticatorConfig()).thenReturn(null);
            assertThrows(Exception.class, () -> authenticator.authenticate(context));
        }

        @Test
        @DisplayName("Should throw exception when trusted IPs not configured")
        void testMissingTrustedIPs() {
            Map<String, String> config = new HashMap<>();
            // Not setting trusted-ips
            when(configModel.getConfig()).thenReturn(config);
            assertThrows(Exception.class, () -> authenticator.authenticate(context));
        }

        @Test
        @DisplayName("Should throw exception when trusted IPs is empty")
        void testEmptyTrustedIPs() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "");
            when(configModel.getConfig()).thenReturn(config);

            assertThrows(Exception.class, () -> authenticator.authenticate(context));
        }

        @Test
        @DisplayName("Should handle invalid IP addresses gracefully")
        void testInvalidIPAddress() {
            String invalidIP = "999.999.999.999"; // This would fail IPv4 parsing
            setupContextWithConfig("192.168.1.0/24", invalidIP, false, null);

            authenticator.authenticate(context);

            // invalid IP should be treated as untrusted
            verify(authSession).setAuthNote("ip-trusted", "false");
            verify(authSession).setAuthNote("require-otp", "true");
            verify(context).attempted();
        }
    }

    @Nested
    @DisplayName("Authenticator Interface Methods Tests")
    class InterfaceMethodsTests {

        @Test
        @DisplayName("Should handle action method")
        void testActionMethod() {
            authenticator.action(context);
            verify(context).success();
        }

        @Test
        @DisplayName("Should not require user")
        void testRequiresUser() {
            assertFalse(authenticator.requiresUser());
        }

        @Test
        @DisplayName("Should always be configured for user")
        void testConfiguredFor() {
            KeycloakSession session = mock(KeycloakSession.class);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);

            assertTrue(authenticator.configuredFor(session, realm, user));
        }

        @Test
        @DisplayName("Should not set required actions")
        void testSetRequiredActions() {
            KeycloakSession session = mock(KeycloakSession.class);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);

            // Should complete without any actions
            authenticator.setRequiredActions(session, realm, user);
            verifyNoInteractions(session, realm, user);
        }

        @Test
        @DisplayName("Should close without issues")
        void testClose() {
            // Should complete without exceptions
            assertDoesNotThrow(() -> authenticator.close());
        }
    }

    @Nested
    @DisplayName("Complex Scenarios Tests")
    class ComplexScenariosTests {

        @Test
        @DisplayName("Should handle RFC 7239 Forwarded header")
        void testForwardedHeaderRFC7239() {
            // Setup
            String forwardedValue = "for=192.168.1.100, for=10.0.0.1";
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            config.put("check-behind-proxy", "true");
            config.put("proxy-header", "Forwarded");

            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn("10.0.0.1");

            MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
            headers.putSingle("Forwarded", forwardedValue);
            when(httpHeaders.getRequestHeaders()).thenReturn(headers);

            // Execute
            authenticator.authenticate(context);

            // Verify
            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }

        @Test
        @DisplayName("Should handle whitespace in configuration")
        void testWhitespaceInConfiguration() {
            // Setup with extra whitespace
            String trustedIP = "192.168.1.100";
            setupContextWithConfig(" 192.168.1.0/24 , 10.0.0.0/8 , 172.16.0.1 ", trustedIP, false, null);

            // Execute
            authenticator.authenticate(context);

            // Verify
            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(context).success();
        }

        @Test
        @DisplayName("Should verify auth notes are set correctly")
        void testAuthNotesAreSetCorrectly() {
            // Setup
            String trustedIP = "192.168.1.100";
            setupContextWithConfig("192.168.1.0/24", trustedIP, false, null);

            ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

            // Execute
            authenticator.authenticate(context);

            // Capture and verify auth notes
            verify(authSession, times(1)).setAuthNote(keyCaptor.capture(), valueCaptor.capture());

            assertEquals("ip-trusted", keyCaptor.getValue());
            assertEquals("true", valueCaptor.getValue());
        }
    }

    // Helper methods

    private void setupContextWithConfig(String trustedIPs, String clientIP, boolean proxyEnabled, String proxyHeader) {
        Map<String, String> config = new HashMap<>();
        config.put("trusted-ips", trustedIPs);
        config.put("check-behind-proxy", String.valueOf(proxyEnabled));
        if (proxyHeader != null) {
            config.put("proxy-header", proxyHeader);
        }

        when(configModel.getConfig()).thenReturn(config);
        when(connection.getRemoteAddr()).thenReturn(clientIP);

        // Setup empty headers by default
        when(httpHeaders.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());
    }

    private void setupContextWithProxy(String trustedIPs, String directIP, String proxyIP, String headerName, boolean proxyEnabled) {
        Map<String, String> config = new HashMap<>();
        config.put("trusted-ips", trustedIPs);
        config.put("check-behind-proxy", String.valueOf(proxyEnabled));
        config.put("proxy-header", headerName);

        when(configModel.getConfig()).thenReturn(config);
        when(connection.getRemoteAddr()).thenReturn(directIP);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle(headerName, proxyIP);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);
    }
}