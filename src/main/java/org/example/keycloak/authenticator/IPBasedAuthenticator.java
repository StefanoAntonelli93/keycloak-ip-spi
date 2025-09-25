package org.example.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.jboss.logging.Logger;

/**
 * Custom Keycloak Authenticator that checks IP addresses and routes to different authentication flows
 */
public class IPBasedAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(IPBasedAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        IPValidator validator = IPValidator.fromContext(context).orElseThrow();
        String clientIP = IPExtractorHelper.extractClientIP(context).ip();
        logger.infof("Authenticating request from IP: %s", clientIP);
        if (validator.isTrusted(clientIP)) {
            logger.infof("IP %s is trusted, proceeding with normal flow", clientIP);
            // Set a note that can be checked by subsequent authenticators
            context.getAuthenticationSession().setAuthNote("ip-trusted", "true");
            context.success();
        } else {
            logger.infof("IP %s is not trusted, requiring OTP", clientIP);
            // Set a note indicating OTP is required
            context.getAuthenticationSession().setAuthNote("ip-trusted", "false");
            context.getAuthenticationSession().setAuthNote("require-otp", "true");
            // Continue to next authenticator in the flow (which should be OTP)
            context.attempted();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No action needed for this authenticator
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Nothing to close
    }
}