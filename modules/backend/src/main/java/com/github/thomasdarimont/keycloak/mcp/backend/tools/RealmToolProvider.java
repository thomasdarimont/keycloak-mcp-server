package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.info.FeatureRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.keycloak.representations.info.ThemeInfoRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.FeatureGuidance;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * REALM: server info, realm configuration and realm updates (login options, tokens, SMTP,
 * WebAuthn passwordless).
 */
@AutoService(ToolProvider.class)
public class RealmToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "realm";
    }

    @Override
    public String displayName() {
        return "Realm and server";
    }

    @Override
    public String description() {
        return "Realm configuration and Keycloak server information.";
    }

    @Override
    public int order() {
        return 90;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_server_info").title("Server info")
                    .description("Keycloak version, enabled features and available themes.")
                    .category(Category.REALM)
                    .read()
                    .global()
                    .hot()
                    .synonyms("version", "health", "which keycloak", "features", "about")
                    .handler(this::serverInfo)
                    .api(ApiOperation.unspecified("get", "/admin/serverinfo",
                            "ServerInfoAdminResource is not part of the published OpenAPI document"))
                    .build(),
                tool("keycloak_server_features").title("Server features")
                    .description("Keycloak feature flags with type (default, preview, experimental, deprecated) "
                            + "and enabled status; filter, or check one feature by name.")
                    .category(Category.REALM)
                    .read()
                    .global()
                    .synonyms("feature", "feature flag", "preview features", "is feature enabled",
                            "organizations enabled", "passkeys", "experimental", "deprecated", "enabled features",
                            "capabilities")
                    .schema(schema().string("name", "One feature to check, e.g. organization or passkeys (optional)")
                        .enumeration("type", "Only features of this type", "default", "preview", "experimental",
                                "deprecated", "disabled_by_default")
                        .bool("enabled", "Only enabled (true) or disabled (false) features"))
                    .handler(this::serverFeatures)
                    .api(ApiOperation.unspecified("get", "/admin/serverinfo",
                            "ServerInfoAdminResource is not part of the published OpenAPI document"))
                    .build(),
                tool("keycloak_realm_get_config").title("Get realm configuration")
                    .description("Key realm settings: login options, tokens, flows, SMTP host, password policy.")
                    .category(Category.REALM)
                    .read()
                    .hot()
                    .synonyms("settings", "realm config", "registration enabled", "token lifespan", "smtp",
                            "password policy", "brute force", "ssl required", "default locale")
                    .handler(this::realmConfig)
                    .roles("view-realm")
                    .api(get(R))
                    .build(),
                tool("keycloak_realm_update").title("Update realm settings")
                    .description(
                            "Change realm settings (login options, tokens, events, orgs, SMTP, WebAuthn); read-merge-write.")
                    .category(Category.REALM)
                    .destructive()
                    .idempotent(true)
                    .synonyms("enable registration", "enable events", "enable organizations", "smtp", "mail server",
                            "passwordless", "webauthn policy", "token lifespan", "password policy", "brute force",
                            "remember me", "realm settings")
                    .schema(schema().string("displayName", "Display name")
                        .bool("enabled", "Realm enabled")
                        .bool("registrationAllowed", "Self registration")
                        .bool("registrationEmailAsUsername", "Email as username")
                        .bool("loginWithEmailAllowed", "Login with email")
                        .bool("duplicateEmailsAllowed", "Allow duplicate emails")
                        .bool("resetPasswordAllowed", "Forgot password link")
                        .bool("rememberMe", "Remember me")
                        .bool("verifyEmail", "Require email verification")
                        .bool("editUsernameAllowed", "Users may edit their username")
                        .bool("bruteForceProtected", "Brute force detection")
                        .bool("eventsEnabled", "Save login events")
                        .bool("adminEventsEnabled", "Save admin events")
                        .bool("organizationsEnabled", "Enable organizations")
                        .integer("accessTokenLifespan", "Access token lifespan in seconds")
                        .min(1)
                        .integer("ssoSessionIdleTimeout", "SSO session idle in seconds")
                        .min(1)
                        .integer("ssoSessionMaxLifespan", "SSO session max in seconds")
                        .min(1)
                        .string("passwordPolicy", "Policy string, e.g. length(12) and digits(1)")
                        .string("defaultLocale", "Default locale, e.g. en")
                        .stringMap("smtpServer",
                                "SMTP settings: host, port, from, fromDisplayName, auth, user, "
                                        + "password, starttls, ssl, replyTo")
                        .sensitiveKeys("password")
                        .anyMap("webAuthnPasswordlessPolicy",
                                "Keys: rpEntityName, rpId, signatureAlgorithms "
                                        + "(list), userVerificationRequirement, requireResidentKey, "
                                        + "authenticatorAttachment, attestationConveyancePreference"))
                    .handler(this::realmUpdate)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("manage-realm")
                    .api(put(R).body("RealmRepresentation", "displayName", "enabled", "registrationAllowed",
                            "registrationEmailAsUsername", "loginWithEmailAllowed", "duplicateEmailsAllowed",
                            "resetPasswordAllowed", "rememberMe", "verifyEmail", "editUsernameAllowed",
                            "bruteForceProtected", "eventsEnabled", "adminEventsEnabled", "organizationsEnabled",
                            "accessTokenLifespan", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan", "passwordPolicy",
                            "defaultLocale", "smtpServer", "webAuthnPolicyPasswordlessRpEntityName",
                            "webAuthnPolicyPasswordlessRpId", "webAuthnPolicyPasswordlessSignatureAlgorithms",
                            "webAuthnPolicyPasswordlessUserVerificationRequirement",
                            "webAuthnPolicyPasswordlessRequireResidentKey",
                            "webAuthnPolicyPasswordlessAuthenticatorAttachment",
                            "webAuthnPolicyPasswordlessAttestationConveyancePreference",
                            "webAuthnPolicyPasswordlessCreateTimeout",
                            "webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister",
                            "webAuthnPolicyPasswordlessAcceptableAaguids", "webAuthnPolicyPasswordlessPasskeysEnabled"))
                    .build());
    }

    ToolResult realmUpdate(ToolCall call) {
        RealmRepresentation r = call.kc().realm(call.realm()).toRepresentation();
        List<String> changed = new ArrayList<>();
        if (call.has("displayName")) {
            r.setDisplayName(call.str("displayName"));
            changed.add("displayName");
        }
        if (call.has("enabled")) {
            r.setEnabled(call.bool("enabled"));
            changed.add("enabled");
        }
        if (call.has("registrationAllowed")) {
            r.setRegistrationAllowed(call.bool("registrationAllowed"));
            changed.add("registrationAllowed");
        }
        if (call.has("registrationEmailAsUsername")) {
            r.setRegistrationEmailAsUsername(call.bool("registrationEmailAsUsername"));
            changed.add("registrationEmailAsUsername");
        }
        if (call.has("loginWithEmailAllowed")) {
            r.setLoginWithEmailAllowed(call.bool("loginWithEmailAllowed"));
            changed.add("loginWithEmailAllowed");
        }
        if (call.has("duplicateEmailsAllowed")) {
            r.setDuplicateEmailsAllowed(call.bool("duplicateEmailsAllowed"));
            changed.add("duplicateEmailsAllowed");
        }
        if (call.has("resetPasswordAllowed")) {
            r.setResetPasswordAllowed(call.bool("resetPasswordAllowed"));
            changed.add("resetPasswordAllowed");
        }
        if (call.has("rememberMe")) {
            r.setRememberMe(call.bool("rememberMe"));
            changed.add("rememberMe");
        }
        if (call.has("verifyEmail")) {
            r.setVerifyEmail(call.bool("verifyEmail"));
            changed.add("verifyEmail");
        }
        if (call.has("editUsernameAllowed")) {
            r.setEditUsernameAllowed(call.bool("editUsernameAllowed"));
            changed.add("editUsernameAllowed");
        }
        if (call.has("bruteForceProtected")) {
            r.setBruteForceProtected(call.bool("bruteForceProtected"));
            changed.add("bruteForceProtected");
        }
        if (call.has("eventsEnabled")) {
            r.setEventsEnabled(Boolean.TRUE.equals(call.bool("eventsEnabled")));
            changed.add("eventsEnabled");
        }
        if (call.has("adminEventsEnabled")) {
            r.setAdminEventsEnabled(call.bool("adminEventsEnabled"));
            changed.add("adminEventsEnabled");
        }
        if (call.has("organizationsEnabled")) {
            r.setOrganizationsEnabled(call.bool("organizationsEnabled"));
            changed.add("organizationsEnabled");
        }
        if (call.has("accessTokenLifespan")) {
            r.setAccessTokenLifespan(call.integer("accessTokenLifespan"));
            changed.add("accessTokenLifespan");
        }
        if (call.has("ssoSessionIdleTimeout")) {
            r.setSsoSessionIdleTimeout(call.integer("ssoSessionIdleTimeout"));
            changed.add("ssoSessionIdleTimeout");
        }
        if (call.has("ssoSessionMaxLifespan")) {
            r.setSsoSessionMaxLifespan(call.integer("ssoSessionMaxLifespan"));
            changed.add("ssoSessionMaxLifespan");
        }
        if (call.has("passwordPolicy")) {
            r.setPasswordPolicy(call.str("passwordPolicy"));
            changed.add("passwordPolicy");
        }
        if (call.has("defaultLocale")) {
            r.setDefaultLocale(call.str("defaultLocale"));
            changed.add("defaultLocale");
        }
        if (call.has("smtpServer")) {
            Map<String, String> smtp = r.getSmtpServer() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(r.getSmtpServer());
            smtp.putAll(Objects.requireNonNull(call.stringMap("smtpServer")));
            r.setSmtpServer(smtp);
            changed.add("smtpServer");
        }
        if (call.has("webAuthnPasswordlessPolicy")) {
            applyWebAuthnPasswordless(r, call.args().get("webAuthnPasswordlessPolicy"));
            changed.add("webAuthnPasswordlessPolicy");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one setting.");
        }
        call.kc().save(r, call.realm());
        return ToolResult.done("Realm updated", "realm", r.getRealm(), "changed", changed);
    }

    @SuppressWarnings("unchecked")
    private static void applyWebAuthnPasswordless(RealmRepresentation r, Object policy) {
        Map<String, Object> p = (Map<String, Object>) policy;
        for (Map.Entry<String, Object> e : p.entrySet()) {
            Object v = e.getValue();
            String s = v == null ? null : String.valueOf(v);
            switch (e.getKey()) {
                case "rpEntityName" -> r.setWebAuthnPolicyPasswordlessRpEntityName(s);
                case "rpId" -> r.setWebAuthnPolicyPasswordlessRpId(s);
                case "signatureAlgorithms" -> r.setWebAuthnPolicyPasswordlessSignatureAlgorithms(toList(v));
                case "userVerificationRequirement" -> r.setWebAuthnPolicyPasswordlessUserVerificationRequirement(s);
                case "requireResidentKey" -> r.setWebAuthnPolicyPasswordlessResidentKey(s);
                case "authenticatorAttachment" -> r.setWebAuthnPolicyPasswordlessAuthenticatorAttachment(s);
                case "attestationConveyancePreference" ->
                    r.setWebAuthnPolicyPasswordlessAttestationConveyancePreference(s);
                case "createTimeout" ->
                    r.setWebAuthnPolicyPasswordlessCreateTimeout(s == null ? null : Integer.parseInt(s));
                case "avoidSameAuthenticatorRegister" ->
                    r.setWebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister(Boolean.parseBoolean(s));
                case "acceptableAaguids" -> r.setWebAuthnPolicyPasswordlessAcceptableAaguids(toList(v));
                case "passkeysEnabled" -> r.setWebAuthnPolicyPasswordlessPasskeysEnabled(Boolean.parseBoolean(s));
                default -> throw new ToolException("invalid_arguments",
                        "Unknown webAuthnPasswordlessPolicy key '" + e.getKey() + "'");
            }
        }
    }

    private static List<String> toList(Object v) {
        if (v instanceof List<?> l) {
            return l.stream().map(String::valueOf).toList();
        }
        List<String> out = new ArrayList<>();
        for (String part : String.valueOf(v).split(",")) {
            if (!part.isBlank()) {
                out.add(part.trim());
            }
        }
        return out;
    }

    ToolResult serverInfo(ToolCall call) {
        ServerInfoRepresentation info = call.kc().client().serverInfo().getInfo();
        Map<String, Object> m = new LinkedHashMap<>();
        if (info.getSystemInfo() != null) {
            m.put("version", info.getSystemInfo().getVersion());
            m.put("serverTime", info.getSystemInfo().getServerTime());
            m.put("uptime", info.getSystemInfo().getUptime());
        }
        if (info.getFeatures() != null) {
            m.put("enabledFeatures",
                    info.getFeatures()
                        .stream()
                        .filter(FeatureRepresentation::isEnabled)
                        .map(FeatureRepresentation::getName)
                        .sorted()
                        .toList());
        }
        if (info.getThemes() != null) {
            Map<String, Object> themes = new LinkedHashMap<>();
            info.getThemes()
                .forEach(
                        (type, list) -> themes.put(type, list.stream().map(ThemeInfoRepresentation::getName).toList()));
            m.put("themes", themes);
        }
        return ToolResult.ok(m);
    }

    ToolResult serverFeatures(ToolCall call) {
        ServerInfoRepresentation info = call.kc().client().serverInfo().getInfo();
        String version = info.getSystemInfo() == null ? null : info.getSystemInfo().getVersion();
        List<FeatureRepresentation> all = info.getFeatures() == null ? List.of() : info.getFeatures();
        String name = call.str("name");
        if (name != null && !name.isBlank()) {
            String wanted = normalizeFeature(name);
            FeatureRepresentation f = all.stream()
                .filter(x -> normalizeFeature(x.getName()).equals(wanted)
                        || (x.getLabel() != null && normalizeFeature(x.getLabel()).equals(wanted)))
                .findFirst()
                .orElse(null);
            if (f == null) {
                // "Organizations" or "passkey" resolve when exactly one feature name
                // contains or is contained in them
                List<FeatureRepresentation> similar = all.stream()
                    .filter(x -> normalizeFeature(x.getName()).contains(wanted)
                            || wanted.contains(normalizeFeature(x.getName())))
                    .sorted(Comparator.comparing(FeatureRepresentation::getName))
                    .toList();
                if (similar.size() != 1) {
                    return ToolResult.error("not_found", "No feature named '" + name + "'.", "didYouMean",
                            similar.isEmpty() ? null : similar.stream().map(RealmToolProvider::cliName).toList(),
                            "hint", "Call without a name to list all features.");
                }
                f = similar.getFirst();
            }
            Map<String, Object> m = feature(f);
            Views.put(m, "label", f.getLabel());
            if (f.getDependencies() != null && !f.getDependencies().isEmpty()) {
                m.put("dependencies", f.getDependencies().stream().sorted().toList());
            }
            Views.put(m, "version", version);
            m.put("howToChange",
                    "Set " + FeatureGuidance.envName(cliName(f)) + "=" + (f.isEnabled() ? "disabled" : "enabled")
                            + " (or --feature-" + cliName(f) + "=" + (f.isEnabled() ? "disabled" : "enabled")
                            + ") on every node and restart Keycloak; see " + FeatureGuidance.DOCS + ".");
            m.put(f.isEnabled() ? "howToDisable" : "howToEnable",
                    f.isEnabled() ? FeatureGuidance.howToDisable(cliName(f)) : FeatureGuidance.howToEnable(cliName(f)));
            return ToolResult.ok(m);
        }
        String type = call.str("type");
        Boolean enabled = call.bool("enabled");
        List<Map<String, Object>> items = new ArrayList<>();
        int enabledCount = 0;
        for (FeatureRepresentation f : all.stream()
            .sorted(Comparator.comparing(FeatureRepresentation::getName))
            .toList()) {
            if (f.isEnabled()) {
                enabledCount++;
            }
            if (type != null && (f.getType() == null || !f.getType().name().equalsIgnoreCase(type))) {
                continue;
            }
            if (enabled != null && enabled != f.isEnabled()) {
                continue;
            }
            items.add(feature(f));
        }
        Map<String, Object> m = new LinkedHashMap<>();
        Views.put(m, "version", version);
        m.put("total", all.size());
        m.put("enabled", enabledCount);
        m.put("items", items);
        return ToolResult.ok(m);
    }

    private static Map<String, Object> feature(FeatureRepresentation f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", cliName(f));
        Views.put(m, "type", f.getType() == null ? null : f.getType().name().toLowerCase());
        m.put("enabled", f.isEnabled());
        if (Boolean.TRUE.equals(f.isDeprecated())) {
            m.put("deprecated", true);
        }
        return m;
    }

    /**
     * Keycloak reports {@code TOKEN_EXCHANGE}; the CLI and docs say
     * {@code token-exchange}.
     */
    private static String cliName(FeatureRepresentation f) {
        return f.getName().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    /**
     * {@code Organizations}, {@code organization}, {@code ORGANIZATION} and
     * {@code passkeys-v2} compare alike.
     */
    private static String normalizeFeature(String s) {
        return s.toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    ToolResult realmConfig(ToolCall call) {
        RealmRepresentation r = call.kc().realm(call.realm()).toRepresentation();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("realm", r.getRealm());
        m.put("displayName", r.getDisplayName());
        m.put("enabled", r.isEnabled());
        m.put("sslRequired", r.getSslRequired());
        Map<String, Object> login = new LinkedHashMap<>();
        login.put("registrationAllowed", r.isRegistrationAllowed());
        login.put("registrationEmailAsUsername", r.isRegistrationEmailAsUsername());
        login.put("loginWithEmailAllowed", r.isLoginWithEmailAllowed());
        login.put("duplicateEmailsAllowed", r.isDuplicateEmailsAllowed());
        login.put("resetPasswordAllowed", r.isResetPasswordAllowed());
        login.put("rememberMe", r.isRememberMe());
        login.put("verifyEmail", r.isVerifyEmail());
        login.put("editUsernameAllowed", r.isEditUsernameAllowed());
        login.put("bruteForceProtected", r.isBruteForceProtected());
        m.put("login", login);
        Map<String, Object> tokens = new LinkedHashMap<>();
        tokens.put("accessTokenLifespan", r.getAccessTokenLifespan());
        tokens.put("ssoSessionIdleTimeout", r.getSsoSessionIdleTimeout());
        tokens.put("ssoSessionMaxLifespan", r.getSsoSessionMaxLifespan());
        tokens.put("offlineSessionIdleTimeout", r.getOfflineSessionIdleTimeout());
        tokens.put("accessCodeLifespanUserAction", r.getAccessCodeLifespanUserAction());
        tokens.put("actionTokenGeneratedByAdminLifespan", r.getActionTokenGeneratedByAdminLifespan());
        m.put("tokens", tokens);
        Map<String, Object> flows = new LinkedHashMap<>();
        flows.put("browserFlow", r.getBrowserFlow());
        flows.put("registrationFlow", r.getRegistrationFlow());
        flows.put("directGrantFlow", r.getDirectGrantFlow());
        flows.put("resetCredentialsFlow", r.getResetCredentialsFlow());
        flows.put("clientAuthenticationFlow", r.getClientAuthenticationFlow());
        flows.put("dockerAuthenticationFlow", r.getDockerAuthenticationFlow());
        flows.put("firstBrokerLoginFlow", r.getFirstBrokerLoginFlow());
        m.put("flows", flows);
        m.put("passwordPolicy", r.getPasswordPolicy());
        m.put("otpPolicyType", r.getOtpPolicyType());
        Map<String, Object> passwordless = new LinkedHashMap<>();
        passwordless.put("rpEntityName", r.getWebAuthnPolicyPasswordlessRpEntityName());
        passwordless.put("rpId", r.getWebAuthnPolicyPasswordlessRpId());
        passwordless.put("signatureAlgorithms", r.getWebAuthnPolicyPasswordlessSignatureAlgorithms());
        passwordless.put("userVerificationRequirement", r.getWebAuthnPolicyPasswordlessUserVerificationRequirement());
        passwordless.put("requireResidentKey", r.getWebAuthnPolicyPasswordlessResidentKey());
        passwordless.put("authenticatorAttachment", r.getWebAuthnPolicyPasswordlessAuthenticatorAttachment());
        passwordless.values().removeIf(Objects::isNull);
        m.put("webAuthnPasswordlessPolicy", passwordless);
        m.put("defaultLocale", r.getDefaultLocale());
        m.put("internationalizationEnabled", r.isInternationalizationEnabled());
        m.put("eventsEnabled", r.isEventsEnabled());
        m.put("adminEventsEnabled", r.isAdminEventsEnabled());
        m.put("organizationsEnabled", r.isOrganizationsEnabled());
        if (r.getSmtpServer() != null && !r.getSmtpServer().isEmpty()) {
            Map<String, Object> smtp = new LinkedHashMap<>(r.getSmtpServer());
            smtp.remove("password");
            m.put("smtp", smtp);
        }
        m.values().removeIf(Objects::isNull);
        return ToolResult.ok(m);
    }
}
