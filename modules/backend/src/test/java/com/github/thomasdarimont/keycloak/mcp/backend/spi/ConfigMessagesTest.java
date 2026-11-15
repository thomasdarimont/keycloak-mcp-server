package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.backend.authzen.AuthZenSettings;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.RateLimitCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.StepUpCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.oauth.ClientAuthenticators;
import com.github.thomasdarimont.keycloak.mcp.backend.policies.PolicySettings;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessageKeys;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessages;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.PiiAuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.DatabaseKeyVault;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.DatabaseKeycloakSystemRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The texts of the specs come from the bundles of the jars that bring them. */
class ConfigMessagesTest {

    private final ConfigMessages messages = new ConfigMessages(getClass().getClassLoader());

    /** Every built-in spec by its message prefix. */
    static Map<String, ConfigSpec> builtInSpecs() {
        Map<String, ConfigSpec> specs = new java.util.LinkedHashMap<>();
        specs.put(ConfigMessageKeys.prefix(AuthorizationEngine.SPI, AuthZenSettings.ID),
                AuthZenSettings.CONFIG_SPEC.plus(ClientAuthenticators.fromClassPath().configSpec()));
        specs.put(ConfigMessageKeys.prefix(Confirmer.SPI, CibaSettings.ID), CibaSettings.CONFIG_SPEC);
        for (String check : List.of("group-scope", "no-escalation", "self-protection")) {
            specs.put(ConfigMessageKeys.prefix(AccessCheck.SPI, check), PolicySettings.spec(check));
        }
        specs.put(ConfigMessageKeys.prefix(AccessCheck.SPI, RateLimitCheck.ID), RateLimitCheck.CONFIG_SPEC);
        specs.put(ConfigMessageKeys.prefix(AccessCheck.SPI, StepUpCheck.ID), StepUpCheck.CONFIG_SPEC);
        specs.put(ConfigMessageKeys.prefix(AuditScrubber.SPI, PiiAuditScrubber.ID), PiiAuditScrubber.CONFIG_SPEC);
        specs.put(ConfigMessageKeys.prefix(AuditListener.SPI, DatabaseAuditListener.ID),
                DatabaseAuditListener.CONFIG_SPEC);
        specs.put(ConfigMessageKeys.prefix(KeyVault.SPI, DatabaseKeyVault.ID), DatabaseKeyVault.CONFIG_SPEC);
        specs.put(ConfigMessageKeys.prefix(KeycloakSystemRepository.SPI, DatabaseKeycloakSystemRepository.ID),
                DatabaseKeycloakSystemRepository.CONFIG_SPEC);
        return specs;
    }

    @Test
    void everyBuiltInSettingAndGroupHasAnEnglishLabel() {
        List<String> missing = new ArrayList<>();
        builtInSpecs().forEach((prefix, spec) -> missing.addAll(messages.missingLabels(prefix, spec)));
        assertEquals(List.of(), missing);
    }

    @Test
    void everyProblemCodeHasAnEnglishMessage() {
        List<String> codes = List.of(ConfigProblem.INVALID_VALUE, ConfigProblem.REQUIRED, ConfigProblem.UNKNOWN_KEY,
                ConfigProblem.VALIDATION_FAILED,
                com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessCheckChain.INVALID_PLACEHOLDER,
                PolicySettings.INVALID_TOOL_ENTRY, AuthZenSettings.NOT_HTTP_URL, AuthZenSettings.HEADER_VALUE_NEEDED,
                AuthZenSettings.CLIENT_CREDENTIALS_INCOMPLETE,
                com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaConfirmer.CALLERS_REQUIRED,
                com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaConfirmer.APPROVAL_STORE_MISSING,
                ClientAuthenticators.UNKNOWN_METHOD,
                com.github.thomasdarimont.keycloak.mcp.backend.oauth.PrivateKeyJwtAuthenticatorFactory.BOTH_KEY_SOURCES,
                com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients.TLS_REGISTRY_MISSING,
                com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients.TLS_UNKNOWN,
                com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients.TLS_NO_TRUST_STORE);
        assertEquals(List.of(), codes.stream().filter(c -> messages.find(Locale.ROOT, c).isEmpty()).toList());
    }

    @Test
    void bundlesOfSeveralJarsAreMerged() {
        assertEquals("Pseudonym key",
                messages.label(Locale.ROOT, "audit-scrubber.pii.", PiiAuditScrubber.PSEUDONYM_KEY), "storage's bundle");
        assertEquals("PDP URL", messages.label(Locale.ROOT, "authorization-engine.authzen.", AuthZenSettings.URL),
                "backend's bundle");
        assertTrue(messages.find(Locale.ROOT, ConfigProblem.REQUIRED).isPresent(), "api's bundle");
    }

    @Test
    void sharedTextsServeSettingsSeveralExtensionsRead() {
        ConfigProperty secret = ConfigProperty.string("client-secret");
        assertEquals("Client secret", messages.label(Locale.ROOT, "authorization-engine.authzen.", secret),
                "AuthZEN has no client-secret text of its own: the shared one");
        assertEquals("Client assertion key",
                messages.label(Locale.ROOT, "authorization-engine.authzen.", ConfigHint.group("assertion-key")));
    }

    @Test
    void aLocaleFallsBackToEnglishAndMissingKeysToNames() {
        assertEquals("PDP URL", messages.label(Locale.GERMANY, "authorization-engine.authzen.", AuthZenSettings.URL));
        assertEquals("nope", messages.label(Locale.ROOT, "tools.acme.", ConfigProperty.string("nope")));
        assertEquals("other", messages.label(Locale.ROOT, "tools.acme.", ConfigHint.group("other")));
        assertEquals("drop", messages.option(Locale.ROOT, "audit-scrubber.pii.", PiiAuditScrubber.MODE, "drop"));
    }

    @Test
    void problemsAreFormattedWithTheirArguments() {
        ConfigProblem p = new ProviderConfig(Confirmer.SPI, CibaSettings.ID, Map.of("enabled", "true"),
                CibaSettings.CONFIG_SPEC)
            .problems()
            .getFirst();
        assertEquals("kc-mcp.spi.confirmer.ciba.client-id is required", messages.message(Locale.ROOT, p));
        ConfigProblem unknown = ConfigProblem.error("acme.unknown", "the English message");
        assertEquals("the English message", messages.message(Locale.ROOT, unknown), "no text: the message");
    }
}
