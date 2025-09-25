package org.example.keycloak.authenticator;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test suite for IPExtractorHelper
 */
@DisplayName("IPExtractorHelper Tests")
class IPExtractorHelperTest {

    private AuthenticationFlowContext context;
    private AuthenticatorConfigModel configModel;
    private ClientConnection connection;
    private HttpRequest httpRequest;
    private HttpHeaders httpHeaders;

    @BeforeEach
    void setUp() {
        context = mock(AuthenticationFlowContext.class);
        configModel = mock(AuthenticatorConfigModel.class);
        connection = mock(ClientConnection.class);
        httpRequest = mock(HttpRequest.class);
        httpHeaders = mock(HttpHeaders.class);

        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(context.getConnection()).thenReturn(connection);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getHttpHeaders()).thenReturn(httpHeaders);
    }

    @Nested
    @DisplayName("Direct Connection Extraction Tests")
    class DirectConnectionTests {

        @Test
        @DisplayName("Should extract IP from direct connection when proxy is disabled")
        void testDirectIPExtraction() {
            String expectedIP = "192.168.1.100";
            Map<String, String> config = new HashMap<>();
            config.put("check-behind-proxy", "false");

            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn(expectedIP);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals(expectedIP, result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.DIRECT_CONNECTION, result.source());
            assertTrue(result.metadata().isEmpty());
        }

        @Test
        @DisplayName("Should use direct IP when proxy is enabled but header is missing")
        void testFallbackToDirect() {
            String directIP = "10.0.0.1";
            Map<String, String> config = new HashMap<>();
            config.put("check-behind-proxy", "true");
            config.put("proxy-header", "X-Forwarded-For");

            when(configModel.getConfig()).thenReturn(config);
            when(connection.getRemoteAddr()).thenReturn(directIP);
            when(httpHeaders.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals(directIP, result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.DIRECT_CONNECTION, result.source());
        }
    }

    @Nested
    @DisplayName("Proxy Header Extraction Tests")
    class ProxyHeaderTests {

        @Test
        @DisplayName("Should extract IP from X-Forwarded-For header")
        void testXForwardedForExtraction() {
            String proxyIP = "203.0.113.42";
            setupProxyContext("X-Forwarded-For", proxyIP);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals(proxyIP, result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.PROXY_HEADER, result.source());
            assertEquals("X-Forwarded-For", result.metadata().orElse(null));
        }

        @ParameterizedTest
        @DisplayName("Should parse various X-Forwarded-For formats")
        @CsvSource({
                "'203.0.113.42', '203.0.113.42'",
                "'203.0.113.42, 198.51.100.1', '203.0.113.42'",
                "'203.0.113.42,198.51.100.1,10.0.0.1', '203.0.113.42'",
                "' 203.0.113.42 ', '203.0.113.42'"
        })
        void testXForwardedForParsing(String headerValue, String expectedIP) {
            setupProxyContext("X-Forwarded-For", headerValue);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals(expectedIP, result.ip());
        }

        @Test
        @DisplayName("Should handle RFC 7239 Forwarded header")
        void testForwardedHeaderRFC7239() {
            String headerValue = "for=192.168.1.100, for=10.0.0.1";
            setupProxyContext("Forwarded", headerValue);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals("192.168.1.100", result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.PROXY_HEADER, result.source());
        }

        @Test
        @DisplayName("Should use custom proxy header when configured")
        void testCustomProxyHeader() {
            String proxyIP = "203.0.113.100";
            setupProxyContext("X-Real-IP", proxyIP);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals(proxyIP, result.ip());
            assertEquals("X-Real-IP", result.metadata().orElse(null));
        }
    }

    @Nested
    @DisplayName("Configuration Handling Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should use default configuration when config is null")
        void testNullConfiguration() {
            when(context.getAuthenticatorConfig()).thenReturn(null);
            when(connection.getRemoteAddr()).thenReturn("192.168.1.1");

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals("192.168.1.1", result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.DIRECT_CONNECTION, result.source());
        }

        @Test
        @DisplayName("Should use default proxy header when not specified")
        void testDefaultProxyHeader() {
            Map<String, String> config = new HashMap<>();
            config.put("check-behind-proxy", "true");

            String proxyIP = "203.0.113.1";
            when(configModel.getConfig()).thenReturn(config);

            MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
            headers.putSingle("X-Forwarded-For", proxyIP);
            when(httpHeaders.getRequestHeaders()).thenReturn(headers);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals(proxyIP, result.ip());
            assertEquals("X-Forwarded-For", result.metadata().orElse(null));
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @ParameterizedTest
        @DisplayName("Should handle empty or blank proxy headers")
        @ValueSource(strings = {"", " ", "  ", "\t", "\n"})
        void testEmptyProxyHeaders(String headerValue) {
            setupProxyContext("X-Forwarded-For", headerValue);
            when(connection.getRemoteAddr()).thenReturn("10.0.0.1");

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals("10.0.0.1", result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.DIRECT_CONNECTION, result.source());
        }

        @Test
        @DisplayName("Should return fallback when no IP sources available")
        void testFallbackResult() {
            when(context.getConnection()).thenReturn(null);
            when(context.getHttpRequest()).thenReturn(null);

            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(context);

            assertEquals("unknown", result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.FALLBACK, result.source());
            assertTrue(result.metadata().isEmpty());
        }

        @Test
        @DisplayName("Should handle null context")
        void testNullContext() {
            IPExtractorHelper.IPExtractionResult result = IPExtractorHelper.extractClientIP(null);

            assertEquals("unknown", result.ip());
            assertEquals(IPExtractorHelper.IPExtractionResult.IPSource.FALLBACK, result.source());
        }
    }

    private void setupProxyContext(String headerName, String headerValue) {
        Map<String, String> config = new HashMap<>();
        config.put("check-behind-proxy", "true");
        config.put("proxy-header", headerName);

        when(configModel.getConfig()).thenReturn(config);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle(headerName, headerValue);
        when(httpHeaders.getRequestHeaders()).thenReturn(headers);

        when(connection.getRemoteAddr()).thenReturn("10.0.0.1");
    }
}