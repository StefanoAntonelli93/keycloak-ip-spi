package org.example.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

import static org.example.keycloak.authenticator.IPValidator.*;

/**
 * Factory for the IP-based authenticator
 */
public class IPBasedAuthenticatorFactory implements AuthenticatorFactory {

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                .name(TRUSTED_IPS)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Trusted IP Addresses")
                .helpText("Comma-separated list of trusted IP addresses or CIDR ranges (e.g., 192.168.1.0/24, 10.0.0.1)")
                .defaultValue("")
                .add()

                .property()
                .name(CHECK_BEHIND_PROXY)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Check Behind Proxy")
                .helpText("If enabled, will check proxy headers for the real client IP")
                .defaultValue("false")
                .add()

                .property()
                .name(PROXY_HEADER)
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Proxy Header Name")
                .helpText("Name of the header containing the real client IP (e.g., X-Forwarded-For, X-Real-IP)")
                .defaultValue("X-Forwarded-For")
                .add()

                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "IP-Based Conditional Authentication";
    }

    @Override
    public String getHelpText() {
        return "Checks the client IP address and routes to different authentication flows based on whether the IP is trusted";
    }

    @Override
    public String getReferenceCategory() {
        return "conditional";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new IPBasedAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to initialize
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to post-initialize
    }

    @Override
    public void close() {
        // Nothing to close
    }
}