package org.example.keycloak.authenticator.integration;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.example.keycloak.authenticator.IPBasedAuthenticator;
import org.example.keycloak.authenticator.IPBasedAuthenticatorFactory;
import org.junit.jupiter.api.*;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

/**
 * These tests verify the complete flow with all components working together
 */
@DisplayName("IP Authenticator Integration Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class IPAuthenticatorIntegrationTest {

    private IPBasedAuthenticatorFactory factory;
    private IPBasedAuthenticator authenticator;

    @Mock
    private KeycloakSession session;
    @Mock
    private AuthenticationFlowContext context;
    @Mock
    private AuthenticationSessionModel authSession;
    @Mock
    private AuthenticatorConfigModel configModel;
    @Mock
    private ClientConnection connection;
    @Mock
    private HttpRequest httpRequest;
    @Mock
    private HttpHeaders httpHeaders;

    private AutoCloseable mocks;

    @BeforeAll
    void setUpAll() {
        factory = new IPBasedAuthenticatorFactory();
    }

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        authenticator = (IPBasedAuthenticator) factory.create(session);

        // Setup common mock behaviors
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(context.getConnection()).thenReturn(connection);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getHttpHeaders()).thenReturn(httpHeaders);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    @Nested
    @DisplayName("End-to-End Flow Tests")
    class EndToEndTests {

        @Test
        @DisplayName("Complete trusted IP flow with proxy")
        void testCompleteTrustedIPFlowWithProxy() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24, 10.0.0.0/8, 203.0.113.42");
            config.put("check-behind-proxy", "true");
            config.put("proxy-header", "X-Forwarded-For");

            when(configModel.getConfig()).thenReturn(config);

            // Simulate proxy header with multiple IPs
            MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
            headers.putSingle("X-Forwarded-For", "203.0.113.42, 198.51.100.1, 10.0.0.1");
            when(httpHeaders.getRequestHeaders()).thenReturn(headers);

            // Direct connection as fallback
            when(connection.getRemoteAddr()).thenReturn("172.16.0.1");

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "true");
            verify(authSession, never()).setAuthNote("require-otp", "true");
            verify(context).success();
            verify(context, never()).attempted();
        }

        @Test
        @DisplayName("Complete untrusted IP flow with OTP requirement")
        void testCompleteUntrustedIPFlowWithOTP() {
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            config.put("check-behind-proxy", "false");

            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn("8.8.8.8");

            authenticator.authenticate(context);

            verify(authSession).setAuthNote("ip-trusted", "false");
            verify(authSession).setAuthNote("require-otp", "true");
            verify(context).attempted();
            verify(context, never()).success();
        }
    }

    @Nested
    @DisplayName("Performance Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should handle concurrent authentication requests")
        @Timeout(value = 10)
        void testConcurrentAuthentications() throws InterruptedException {
            int threadCount = 100;
            ExecutorService executor = Executors.newFixedThreadPool(10);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger failureCount = new AtomicInteger(0);

            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            when(configModel.getConfig()).thenReturn(config);

            // Execute concurrent authentications
            for (int i = 0; i < threadCount; i++) {
                final String ip = "192.168.1." + (i % 256);
                executor.submit(() -> {
                    try {
                        AuthenticationFlowContext localContext = createLocalContext(ip);
                        IPBasedAuthenticator localAuth = new IPBasedAuthenticator();
                        localAuth.authenticate(localContext);
                        successCount.incrementAndGet();
                    } catch (Exception e) {
                        failureCount.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }

            // Wait for completion
            assertTrue(latch.await(10, TimeUnit.SECONDS));
            executor.shutdown();

            assertEquals(threadCount, successCount.get());
            assertEquals(0, failureCount.get());
        }

        @Test
        @DisplayName("Should perform well with large IP lists")
        void testPerformanceWithLargeIPList() {
            // Create a large list of trusted IP ranges
            StringBuilder ipList = new StringBuilder();
            for (int i = 1; i <= 100; i++) {
                if (i > 1) ipList.append(", ");
                ipList.append(String.format("10.%d.0.0/16", i));
            }

            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", ipList.toString());
            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn("10.50.100.100");

            // Measure performance
            long startTime = System.nanoTime();

            for (int i = 0; i < 1000; i++) {
                authenticator.authenticate(context);
            }

            long endTime = System.nanoTime();
            long durationMs = (endTime - startTime) / 1_000_000;

            // Should complete in reasonable time
            assertTrue(durationMs < 1500, "1000 authentications should complete in < 1.5 seconds");

            verify(context, times(1000)).success();
        }
    }

    @Nested
    @DisplayName("Complex Configuration Tests")
    class ComplexConfigurationTests {

        @Test
        @DisplayName("Should handle multiple proxy headers fallback")
        void testMultipleProxyHeadersFallback() {
            // Setup with custom proxy header
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            config.put("check-behind-proxy", "true");
            config.put("proxy-header", "CF-Connecting-IP");

            when(configModel.getConfig()).thenReturn(config);

            // No CF-Connecting-IP header, but X-Forwarded-For exists
            MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
            headers.putSingle("X-Forwarded-For", "8.8.8.8");
            when(httpHeaders.getRequestHeaders()).thenReturn(headers);

            // Should fall back to direct connection
            when(connection.getRemoteAddr()).thenReturn("192.168.1.100");

            // Execute
            authenticator.authenticate(context);

            // Verify - should use direct connection (trusted)
            verify(context).success();
        }

        @Test
        @DisplayName("Should handle IPv6 addresses gracefully")
        void testIPv6Handling() {
            // Setup
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            when(configModel.getConfig()).thenReturn(config);

            // IPv6 address (should fail parsing and be treated as untrusted)
            when(connection.getRemoteAddr()).thenReturn("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

            // Execute
            authenticator.authenticate(context);

            // Verify - IPv6 should be treated as untrusted (not in IPv4 range)
            verify(context).attempted();
            verify(authSession).setAuthNote("require-otp", "true");
        }
    }

    @Nested
    @DisplayName("State Management Tests")
    class StateManagementTests {

        @Test
        @DisplayName("Should not maintain state between authentications")
        void testStatelessAuthentication() {
            // First authentication - trusted IP
            Map<String, String> config = new HashMap<>();
            config.put("trusted-ips", "192.168.1.0/24");
            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn("192.168.1.100");

            authenticator.authenticate(context);
            verify(context).success();

            // Reset mocks
            reset(context, authSession);
            when(context.getAuthenticationSession()).thenReturn(authSession);
            when(context.getAuthenticatorConfig()).thenReturn(configModel);
            when(context.getConnection()).thenReturn(connection);

            // Second authentication - untrusted IP
            when(connection.getRemoteAddr()).thenReturn("8.8.8.8");

            authenticator.authenticate(context);
            verify(context).attempted();

            // Verify independence
            verify(authSession).setAuthNote("require-otp", "true");
        }
    }

    // Helper method for creating isolated contexts
    private AuthenticationFlowContext createLocalContext(String ip) {
        AuthenticationFlowContext localContext = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel localAuthSession = mock(AuthenticationSessionModel.class);
        ClientConnection localConnection = mock(ClientConnection.class);

        when(localContext.getAuthenticationSession()).thenReturn(localAuthSession);
        when(localContext.getAuthenticatorConfig()).thenReturn(configModel);
        when(localContext.getConnection()).thenReturn(localConnection);
        when(localConnection.getRemoteAddr()).thenReturn(ip);

        return localContext;
    }
}
