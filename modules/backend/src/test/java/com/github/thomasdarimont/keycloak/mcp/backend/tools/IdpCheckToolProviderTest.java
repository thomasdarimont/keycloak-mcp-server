package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The outbound side of keycloak_idp_check, without a network. */
class IdpCheckToolProviderTest {

    @Test
    void privateAddressesAreRefusedUnderListed() {
        var check = new IdpCheckToolProvider().restrict(HostAllowList.ANY, PrivateHosts.LISTED);
        var fetch = check.fetch("http://127.0.0.1:1/.well-known/openid-configuration");
        assertFalse(fetch.ok());
        assertTrue(fetch.problem().startsWith("Not fetched:"), fetch.problem());
        assertTrue(fetch.problem().contains("identity provider"), fetch.problem());
    }

    @Test
    void otherSchemesAreNotFetched() {
        var check = new IdpCheckToolProvider();
        assertTrue(check.fetch("file:///etc/passwd").problem().startsWith("Only http and https"));
        assertTrue(check.fetch("ftp://example.com/x").problem().startsWith("Only http and https"));
    }

    @Test
    void literallyAllowedHostsMayBePrivate() {
        var check = new IdpCheckToolProvider().restrict(HostAllowList.of(List.of("127.0.0.1")), PrivateHosts.LISTED);
        var fetch = check.fetch("http://127.0.0.1:1/x");
        assertFalse(fetch.ok());
        assertFalse(fetch.problem().startsWith("Not fetched:"), "tried, the port is closed: " + fetch.problem());
    }

    @Test
    void samlMetadataWithADoctypeIsRejected() {
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>"
                + "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">&e;</EntityDescriptor>";
        assertThrows(Exception.class, () -> IdpCheckToolProvider.parse(xxe.getBytes(StandardCharsets.UTF_8)));
    }
}
