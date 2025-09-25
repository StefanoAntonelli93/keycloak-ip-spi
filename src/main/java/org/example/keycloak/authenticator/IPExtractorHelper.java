package org.example.keycloak.authenticator;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class IPExtractorHelper {

    /**
     * Extract client IP with detailed result
     */
    public static IPExtractionResult extractClientIP(AuthenticationFlowContext context) {
        if (context == null) {
            return IPExtractionResult.fallback();
        }
        ProxyConfig config = extractConfig(context);
        return Stream.<Supplier<Optional<IPExtractionResult>>>of(
                        () -> tryExtractFromProxy(context, config),
                        () -> tryExtractDirect(context)
                )
                .map(Supplier::get)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst()
                .orElseGet(IPExtractionResult::fallback);
    }

    private static ProxyConfig extractConfig(AuthenticationFlowContext context) {
        return Optional.ofNullable(context)
                .map(AuthenticationFlowContext::getAuthenticatorConfig)
                .map(AuthenticatorConfigModel::getConfig)
                .map(ProxyConfig::from)
                .orElse(ProxyConfig.defaults());
    }

    private static Optional<IPExtractionResult> tryExtractFromProxy(
            AuthenticationFlowContext context,
            ProxyConfig config) {

        if (!config.enabled()) {
            return Optional.empty();
        }

        return Optional.ofNullable(context.getHttpRequest())
                .flatMap(req -> extractHeaderValue(req, config.headerName()))
                .map(IPExtractorHelper::parseProxyHeader)
                .map(ip -> IPExtractionResult.fromProxy(ip, config.headerName()));
    }

    private static Optional<String> extractHeaderValue(
            HttpRequest request,
            String headerName) {

        return Optional.ofNullable(request.getHttpHeaders())
                .map(HttpHeaders::getRequestHeaders)
                .map(headers -> headers.getFirst(headerName))
                .filter(value -> !value.isBlank());
    }

    private static String parseProxyHeader(String headerValue) {
        if (headerValue.toLowerCase().startsWith("for=")) {
            // Handle "Forwarded" header format (RFC 7239)
            return headerValue.substring(4).split(",")[0].trim();
        }
        // Standard comma-separated format
        return headerValue.split(",")[0].trim();
    }

    private static Optional<IPExtractionResult> tryExtractDirect(AuthenticationFlowContext context) {
        return Optional.ofNullable(context.getConnection())
                .map(ClientConnection::getRemoteAddr)
                .filter(ip -> !ip.isBlank())
                .map(IPExtractionResult::fromDirect);
    }

    record ProxyConfig(boolean enabled, String headerName) {
        static ProxyConfig from(Map<String, String> config) {
            return new ProxyConfig(
                    Boolean.parseBoolean(config.getOrDefault("check-behind-proxy", "false")),
                    config.getOrDefault("proxy-header", "X-Forwarded-For")
            );
        }

        static ProxyConfig defaults() {
            return new ProxyConfig(false, "X-Forwarded-For");
        }
    }

    /**
     * Result wrapper with metadata
     */
    public record IPExtractionResult(String ip, IPSource source, Optional<String> metadata) {
        enum IPSource {
            PROXY_HEADER("Proxy Header"),
            DIRECT_CONNECTION("Direct Connection"),
            FALLBACK("Fallback");

            IPSource(String description) { }
        }

        static IPExtractionResult fromProxy(String ip, String headerName) {
            return new IPExtractionResult(ip, IPSource.PROXY_HEADER, Optional.of(headerName));
        }

        static IPExtractionResult fromDirect(String ip) {
            return new IPExtractionResult(ip, IPSource.DIRECT_CONNECTION, Optional.empty());
        }

        static IPExtractionResult fallback() {
            return new IPExtractionResult("unknown", IPSource.FALLBACK, Optional.empty());
        }
    }

}
