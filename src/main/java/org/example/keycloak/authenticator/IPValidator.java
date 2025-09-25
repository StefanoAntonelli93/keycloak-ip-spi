package org.example.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

public class IPValidator {

    // Configuration constants
    public static final String CHECK_BEHIND_PROXY = "check-behind-proxy";
    public static final String PROXY_HEADER = "proxy-header";
    public static final String PROVIDER_ID = "ip-based-authenticator";
    public static final String TRUSTED_IPS = "trusted-ips";

    private final Set<IPPattern> trustedPatterns;

    private IPValidator(Set<IPPattern> trustedPatterns) {
        this.trustedPatterns = trustedPatterns;
    }

    /**
     * Create the IP Validator from the auth context, it builds a set of trusted patterns to check against
     * @param context the auth flow context
     * @return an optional with the ip validator if configured or an empty
     */
    public static Optional<IPValidator> fromContext(AuthenticationFlowContext context) {
        return Optional.ofNullable(context)
                .map(AuthenticationFlowContext::getAuthenticatorConfig)
                .map(AuthenticatorConfigModel::getConfig)
                .map(config -> config.get(IPValidator.TRUSTED_IPS))
                .filter(ips -> !ips.trim().isEmpty())
                .map(IPValidator::parse);
    }

    /**
     * Parse configuration string into validator
     */
    private static IPValidator parse(String configuration) {
        Set<IPPattern> patterns = Stream.of(configuration.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(IPPattern::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(HashSet::new, HashSet::add, HashSet::addAll);
        return new IPValidator(patterns);
    }

    /**
     * Check if an ip is trusted against the trusted patterns
     * @param ipAddress the ip addr to check
     * @return if the addr is trusted
     */
    public boolean isTrusted(String ipAddress) {
        return IPv4Address.parse(ipAddress)
                .map(ip -> trustedPatterns.stream().anyMatch(pattern -> pattern.matches(ip)))
                .orElse(false);
    }

    /**
     * Abstract IP pattern matcher
     */
    private interface IPPattern {
        boolean matches(IPv4Address address);

        static Optional<IPPattern> parse(String pattern) {
            if (pattern.contains("/")) {
                return CIDRPattern.parse(pattern).map(Function.identity());
            } else {
                return IPv4Address.parse(pattern)
                        .map(ExactIPPattern::new);
            }
        }
    }

    /**
     * Exact IP match pattern
     */
    private record ExactIPPattern(IPv4Address address) implements IPPattern {

        @Override
        public boolean matches(IPv4Address other) {
            return address.equals(other);
        }
    }

    /**
     * CIDR range pattern
     */
    private record CIDRPattern(long baseAddress, long mask) implements IPPattern {

        static Optional<CIDRPattern> parse(String cidr) {
            var parts = cidr.split("/");
            if (parts.length != 2) {
                return Optional.empty();
            }

            return IPv4Address.parse(parts[0])
                    .flatMap(base -> tryParseInt(parts[1])
                            .filter(prefix -> prefix >= 0 && prefix <= 32)
                            .map(prefix -> new CIDRPattern(
                                    base.value(),
                                    -1L << (32 - prefix)
                            )));
        }

        @Override
        public boolean matches(IPv4Address address) {
            long addr = address.value();
            return (addr & mask) == (baseAddress & mask);
        }

        private static Optional<Integer> tryParseInt(String s) {
            try {
                return Optional.of(Integer.parseInt(s));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
    }

    /**
     * IPv4 representation pattern
     */
    private record IPv4Address(long value) {

        static Optional<IPv4Address> parse(String address) {
            var parts = address.split("\\.");
            if (parts.length != 4) {
                return Optional.empty();
            }
            long result = 0;
            for (String part : parts) {
                try {
                    int octet = Integer.parseInt(part);
                    if (octet < 0 || octet > 255) {
                        return Optional.empty();
                    }
                    // dark bit-shift magic, left shift the result by 8 and then add the octet to the freed space
                    // this is an integer, so a simple sum would break the addr notation
                    result = (result << 8) | octet;
                } catch (NumberFormatException e) {
                    return Optional.empty();
                }
            }
            return Optional.of(new IPv4Address(result));
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof IPv4Address && ((IPv4Address) obj).value == value;
        }

        @Override
        public int hashCode() {
            return Long.hashCode(value);
        }
    }

}