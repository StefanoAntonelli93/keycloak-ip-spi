package org.example.keycloak.authenticator;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Main test suite runner for all IP Authenticator tests
 */
@Suite
@SuiteDisplayName("IP-Based Authenticator Complete Test Suite")
@SelectClasses({
        IPBasedAuthenticatorTest.class,
        IPBasedAuthenticatorFactoryTest.class,
        IPExtractorHelperTest.class,
        IPValidatorTest.class
})
public class IPAuthenticatorTestSuite {
    // This class serves as a test suite runner
    // It will execute all the specified test classes
}
