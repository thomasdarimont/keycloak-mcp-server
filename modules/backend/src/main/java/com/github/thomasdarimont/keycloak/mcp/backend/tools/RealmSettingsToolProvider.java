package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientPoliciesRepresentation;
import org.keycloak.representations.idm.ClientPolicyRepresentation;
import org.keycloak.representations.idm.ClientProfileRepresentation;
import org.keycloak.representations.idm.ClientProfilesRepresentation;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.keycloak.representations.idm.RealmEventsConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPAttributePermissions;
import org.keycloak.representations.userprofile.config.UPAttributeRequired;
import org.keycloak.representations.userprofile.config.UPConfig;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * REALM settings beyond {@code keycloak_realm_update}: event recording, signing keys, the
 * user profile, client policies and realm-specific translations.
 */
@AutoService(ToolProvider.class)
public class RealmSettingsToolProvider extends AbstractToolProvider {

    /** Keycloak refuses to drop these from the user profile. */
    static final Set<String> BUILT_IN_ATTRIBUTES = Set.of("username", "email");

    static final String WHO = "Who: user (the account itself), admin (administrators)";

    @Override
    public String id() {
        return "realm-settings";
    }

    @Override
    public String displayName() {
        return "Realm settings";
    }

    @Override
    public String description() {
        return "Event recording, signing keys, the user profile, client policies and realm translations.";
    }

    @Override
    public int order() {
        return 92;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_realm_events_config_get").title("Get event settings")
                    .description(
                            "Whether login and admin events are recorded, which types, for how long, and listeners.")
                    .category(Category.EVENTS)
                    .read()
                    .synonyms("event logging", "audit settings", "are events saved", "event listeners",
                            "event retention")
                    .handler(this::eventsConfig)
                    .roles("view-events")
                    .api(get(R + "/events/config"))
                    .build(),
                tool("keycloak_realm_events_config_update").title("Update event settings")
                    .description(
                            "Switch login or admin event recording on or off, set types, expiration and listeners.")
                    .category(Category.EVENTS)
                    .destructive()
                    .synonyms("enable events", "save events", "enable admin events", "event expiration",
                            "add event listener", "audit logging")
                    .schema(schema().bool("eventsEnabled", "Record login events")
                        .integer("eventsExpiration", "Keep login events this many seconds; 0 keeps them forever")
                        .min(0)
                        .stringArray("enabledEventTypes",
                                "Login event types to record, e.g. [\"LOGIN\", \"LOGIN_ERROR\"]")
                        .bool("adminEventsEnabled", "Record admin events")
                        .bool("adminEventsDetailsEnabled", "Include the request body in admin events")
                        .stringArray("eventsListeners",
                                "Event listeners, replacing the list, e.g. [\"jboss-logging\"]"))
                    .handler(this::eventsConfigUpdate)
                    .roles("manage-events")
                    .api(put(R + "/events/config").body("RealmEventsConfigRepresentation", "eventsEnabled",
                            "eventsExpiration", "enabledEventTypes", "adminEventsEnabled", "adminEventsDetailsEnabled",
                            "eventsListeners"))
                    .build(),
                tool("keycloak_realm_keys_list").title("List realm keys")
                    .description("Signing and encryption keys of the realm: kid, algorithm, status, provider, expiry.")
                    .category(Category.REALM)
                    .read()
                    .synonyms("signing key", "kid", "jwks", "rsa key", "certificate expiry", "key rotation",
                            "active key")
                    .schema(schema().bool("activeOnly", "Only active keys (default false)"))
                    .handler(this::keys)
                    .roles("view-realm")
                    .api(get(R + "/keys"))
                    .build(),
                tool("keycloak_user_profile_get").title("Get user profile")
                    .description(
                            "The realm's user profile: attributes with validation, who may view or edit them, required.")
                    .category(Category.USERS)
                    .read()
                    .synonyms("user attributes", "custom attribute", "registration fields", "declarative user profile",
                            "required fields", "unmanaged attributes")
                    .handler(this::userProfile)
                    .roles("view-realm")
                    .api(get(R + "/users/profile"))
                    .build(),
                tool("keycloak_user_profile_attribute_set").title("Add or change a user profile attribute")
                    .description("Declare a user attribute, or change one: label, required, permissions, validations.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("add user attribute", "custom field", "registration field", "make field required",
                            "attribute validation", "phone number field")
                    .schema(schema().string("name", "Attribute name, e.g. phoneNumber")
                        .required()
                        .string("displayName", "Label, e.g. Phone number or ${phoneNumber}")
                        .bool("required", "Required (true) or optional (false)")
                        .stringArray("requiredFor", "Required for whom when required: user, admin (default both)")
                        .stringArray("viewableBy", WHO + "; who may see it")
                        .stringArray("editableBy", WHO + "; who may change it")
                        .bool("multivalued", "More than one value allowed")
                        .string("group", "Attribute group, e.g. user-metadata")
                        .anyMap("validations",
                                "Validators, replacing the old ones, e.g. {\"length\": {\"max\": 30}, "
                                        + "\"pattern\": {\"pattern\": \"^[0-9+ ]+$\"}}")
                        .anyMap("annotations", "Annotations, e.g. {\"inputType\": \"textarea\"}"))
                    .handler(this::attributeSet)
                    .roles("manage-realm")
                    .api(get(R + "/users/profile"), put(R + "/users/profile").body("UPConfig", "attributes"))
                    .build(),
                tool("keycloak_user_profile_attribute_delete").title("Remove a user profile attribute")
                    .description("Drop an attribute from the user profile; values users have stay but are unmanaged.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("remove user attribute", "drop field", "delete custom attribute")
                    .schema(schema().string("name", "Attribute name").required())
                    .handler(this::attributeDelete)
                    .roles("manage-realm")
                    .api(get(R + "/users/profile"), put(R + "/users/profile").body("UPConfig", "attributes"))
                    .build(),
                tool("keycloak_user_profile_unmanaged_set").title("Set unmanaged attribute policy")
                    .description("Whether attributes not declared in the user profile are allowed, and who sees them.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("unmanaged attributes", "allow any attribute", "free form attributes",
                            "legacy attributes")
                    .schema(schema()
                        .enumeration("policy",
                                "DISABLED: not allowed; ENABLED: users and admins; ADMIN_VIEW: admins see them; "
                                        + "ADMIN_EDIT: admins edit them",
                                "DISABLED", "ENABLED", "ADMIN_VIEW", "ADMIN_EDIT")
                        .required())
                    .handler(this::unmanagedSet)
                    .roles("manage-realm")
                    .api(get(R + "/users/profile"),
                            put(R + "/users/profile").body("UPConfig", "unmanagedAttributePolicy"))
                    .build(),
                tool("keycloak_client_policies_get").title("Get client policies")
                    .description(
                            "Client policies (when they apply, enabled) and the profiles of executors they enforce.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("fapi", "oauth 2.1", "security profile", "client policy", "executor", "enforce pkce")
                    .schema(schema().bool("includeGlobal",
                            "Include Keycloak's built-in global profiles (default false)"))
                    .handler(this::clientPolicies)
                    .roles("view-realm")
                    .api(get(R + "/client-policies/policies").queryAs("include-global-policies", "includeGlobal"),
                            get(R + "/client-policies/profiles").queryAs("include-global-profiles", "includeGlobal"))
                    .build(),
                tool("keycloak_client_policy_set_enabled").title("Enable or disable a client policy")
                    .description("Switch one client policy on or off by name.")
                    .category(Category.CLIENTS)
                    .write()
                    .idempotent(true)
                    .synonyms("enable fapi", "turn on client policy", "disable client policy")
                    .schema(schema().string("name", "Client policy name")
                        .required()
                        .bool("enabled", "On or off")
                        .required())
                    .handler(this::clientPolicySetEnabled)
                    .roles("manage-realm")
                    .api(get(R + "/client-policies/policies").fixedQuery("include-global-policies"),
                            put(R + "/client-policies/policies").body("ClientPoliciesRepresentation", "policies"))
                    .build(),
                tool("keycloak_localization_locales_list").title("List realm locales")
                    .description("Languages the realm offers and which of them have realm-specific translations.")
                    .category(Category.REALM)
                    .read()
                    .synonyms("languages", "internationalization", "i18n", "translations", "supported locales")
                    .handler(this::locales)
                    .roles("view-realm")
                    .api(get(R + "/localization"))
                    .build(),
                tool("keycloak_localization_texts_get").title("Get realm translations")
                    .description("Realm-specific texts of one locale, e.g. overridden login page messages.")
                    .category(Category.REALM)
                    .read()
                    .synonyms("translations", "message bundle", "login page text", "custom messages", "i18n")
                    .schema(schema().string("locale", "Locale, e.g. en or de")
                        .required()
                        .string("search", "Filter by (partial) key or text"))
                    .handler(this::texts)
                    .roles("view-realm")
                    .api(get(R + "/localization/{locale}").path("locale", "locale"))
                    .build(),
                tool("keycloak_localization_texts_set").title("Set realm translations")
                    .description("Add or change realm-specific texts of one locale, e.g. a login page message.")
                    .category(Category.REALM)
                    .write()
                    .idempotent(true)
                    .synonyms("translate", "change login text", "override message", "custom message", "i18n")
                    .schema(schema().string("locale", "Locale, e.g. en or de")
                        .required()
                        .stringMap("texts", "Key to text, e.g. {\"loginTitle\": \"Sign in to ACME\"}")
                        .required())
                    .handler(this::textsSet)
                    .roles("manage-realm")
                    .api(post(R + "/localization/{locale}").path("locale", "locale"))
                    .build(),
                tool("keycloak_localization_text_delete").title("Delete a realm translation")
                    .description("Remove one realm-specific text, so the theme's default applies again.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("remove translation", "reset message", "restore default text")
                    .schema(schema().string("locale", "Locale, e.g. en")
                        .required()
                        .string("message", "Message key, e.g. loginTitle")
                        .required())
                    .handler(this::textDelete)
                    .roles("manage-realm")
                    .api(delete(R + "/localization/{locale}/{key}").path("locale", "locale").path("key", "message"))
                    .build());
    }

    // ---- events --------------------------------------------------------------------

    static Map<String, Object> view(RealmEventsConfigRepresentation c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("eventsEnabled", c.isEventsEnabled());
        Views.put(m, "eventsExpiration", c.getEventsExpiration());
        Views.put(m, "enabledEventTypes", sorted(c.getEnabledEventTypes()));
        m.put("adminEventsEnabled", Boolean.TRUE.equals(c.isAdminEventsEnabled()));
        m.put("adminEventsDetailsEnabled", Boolean.TRUE.equals(c.isAdminEventsDetailsEnabled()));
        Views.put(m, "eventsListeners", sorted(c.getEventsListeners()));
        return m;
    }

    private static List<String> sorted(List<String> values) {
        return values == null ? null : values.stream().sorted().toList();
    }

    ToolResult eventsConfig(ToolCall call) {
        return ToolResult.ok(view(call.kc().realm(call.realm()).getRealmEventsConfig()));
    }

    ToolResult eventsConfigUpdate(ToolCall call) {
        RealmResource realm = call.kc().realm(call.realm());
        RealmEventsConfigRepresentation c = realm.getRealmEventsConfig();
        List<String> changed = new ArrayList<>();
        if (call.has("eventsEnabled")) {
            c.setEventsEnabled(call.bool("eventsEnabled"));
            changed.add("eventsEnabled");
        }
        if (call.has("eventsExpiration")) {
            long seconds = call.longValue("eventsExpiration");
            c.setEventsExpiration(seconds == 0 ? null : seconds);
            changed.add("eventsExpiration");
        }
        if (call.has("enabledEventTypes")) {
            c.setEnabledEventTypes(call.strings("enabledEventTypes"));
            changed.add("enabledEventTypes");
        }
        if (call.has("adminEventsEnabled")) {
            c.setAdminEventsEnabled(call.bool("adminEventsEnabled"));
            changed.add("adminEventsEnabled");
        }
        if (call.has("adminEventsDetailsEnabled")) {
            c.setAdminEventsDetailsEnabled(call.bool("adminEventsDetailsEnabled"));
            changed.add("adminEventsDetailsEnabled");
        }
        if (call.has("eventsListeners")) {
            c.setEventsListeners(call.strings("eventsListeners"));
            changed.add("eventsListeners");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one setting.");
        }
        realm.updateRealmEventsConfig(c);
        return ToolResult.done("Event settings updated", "changed", changed, "now", view(realm.getRealmEventsConfig()));
    }

    // ---- keys ----------------------------------------------------------------------

    ToolResult keys(ToolCall call) {
        KeysMetadataRepresentation keys = call.kc().realm(call.realm()).keys().getKeyMetadata();
        boolean activeOnly = call.bool("activeOnly", false);
        List<Map<String, Object>> items = new ArrayList<>();
        for (KeysMetadataRepresentation.KeyMetadataRepresentation k : keys.getKeys()) {
            if (activeOnly && !"ACTIVE".equals(k.getStatus())) {
                continue;
            }
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("kid", k.getKid());
            v.put("algorithm", k.getAlgorithm());
            v.put("type", k.getType());
            Views.put(v, "use", k.getUse() == null ? null : k.getUse().name().toLowerCase(Locale.ROOT));
            v.put("status", k.getStatus());
            v.put("priority", k.getProviderPriority());
            v.put("providerId", k.getProviderId());
            Views.put(v, "validTo", Views.iso(k.getValidTo()));
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        Views.put(page, "activeBy", keys.getActive());
        return ToolResult.ok(page);
    }

    // ---- user profile --------------------------------------------------------------

    static Map<String, Object> view(UPAttribute a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", a.getName());
        Views.put(m, "displayName", a.getDisplayName());
        if (a.getRequired() != null) {
            Map<String, Object> r = new LinkedHashMap<>();
            Views.put(r, "roles", a.getRequired().getRoles());
            Views.put(r, "scopes", a.getRequired().getScopes());
            m.put("required", r.isEmpty() ? "always" : r);
        }
        if (a.getPermissions() != null) {
            Views.put(m, "viewableBy", a.getPermissions().getView());
            Views.put(m, "editableBy", a.getPermissions().getEdit());
        }
        if (a.isMultivalued()) {
            m.put("multivalued", true);
        }
        Views.put(m, "group", a.getGroup());
        if (a.getValidations() != null && !a.getValidations().isEmpty()) {
            m.put("validations", a.getValidations());
        }
        if (a.getAnnotations() != null && !a.getAnnotations().isEmpty()) {
            m.put("annotations", a.getAnnotations());
        }
        return m;
    }

    ToolResult userProfile(ToolCall call) {
        UPConfig config = call.kc().realm(call.realm()).users().userProfile().getConfiguration();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("unmanagedAttributePolicy", config.getUnmanagedAttributePolicy() == null ? "DISABLED"
                : config.getUnmanagedAttributePolicy().name());
        m.put("attributes", Views.list(config.getAttributes(), RealmSettingsToolProvider::view));
        if (config.getGroups() != null && !config.getGroups().isEmpty()) {
            m.put("groups", config.getGroups().stream().map(g -> g.getName()).toList());
        }
        return ToolResult.ok(m);
    }

    /** The values of a {@code user}/{@code admin} list, checked. */
    private static Set<String> who(ToolCall call, String arg) {
        Set<String> out = new LinkedHashSet<>();
        for (String s : Objects.requireNonNull(call.strings(arg))) {
            String v = s.trim().toLowerCase(Locale.ROOT);
            if (!v.equals("user") && !v.equals("admin")) {
                throw new ToolException("invalid_arguments",
                        arg + ": only user and admin are allowed, not '" + s + "'");
            }
            out.add(v);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> anyMap(ToolCall call, String arg) {
        Object v = call.args().get(arg);
        if (!(v instanceof Map<?, ?> m)) {
            throw new ToolException("invalid_arguments", arg + " must be an object");
        }
        return new LinkedHashMap<>((Map<String, Object>) m);
    }

    ToolResult attributeSet(ToolCall call) {
        var profile = call.kc().realm(call.realm()).users().userProfile();
        UPConfig config = profile.getConfiguration();
        String name = call.str("name");
        UPAttribute a = config.getAttribute(name);
        boolean created = a == null;
        if (created) {
            a = new UPAttribute(name);
            a.setDisplayName(call.str("displayName", name));
            UPAttributePermissions p = new UPAttributePermissions();
            p.setView(Set.of("admin", "user"));
            p.setEdit(Set.of("admin", "user"));
            a.setPermissions(p);
        }
        if (call.has("displayName")) {
            a.setDisplayName(call.str("displayName"));
        }
        if (call.has("required") || call.has("requiredFor")) {
            if (call.has("required") && !call.bool("required")) {
                a.setRequired(null);
            }
            else {
                UPAttributeRequired r = new UPAttributeRequired();
                r.setRoles(call.has("requiredFor") ? who(call, "requiredFor") : Set.of("admin", "user"));
                a.setRequired(r);
            }
        }
        if (call.has("viewableBy") || call.has("editableBy")) {
            UPAttributePermissions p = a.getPermissions() == null ? new UPAttributePermissions() : a.getPermissions();
            if (call.has("viewableBy")) {
                p.setView(who(call, "viewableBy"));
            }
            if (call.has("editableBy")) {
                p.setEdit(who(call, "editableBy"));
            }
            a.setPermissions(p);
        }
        if (call.has("multivalued")) {
            a.setMultivalued(call.bool("multivalued"));
        }
        if (call.has("group")) {
            String group = call.str("group");
            a.setGroup(group == null || group.isBlank() ? null : group);
        }
        if (call.has("validations")) {
            Map<String, Map<String, Object>> validations = new LinkedHashMap<>();
            anyMap(call, "validations").forEach((k, v) -> validations.put(k,
                    v instanceof Map<?, ?> m ? new LinkedHashMap<>(castMap(m)) : new LinkedHashMap<>()));
            a.setValidations(validations);
        }
        if (call.has("annotations")) {
            a.setAnnotations(anyMap(call, "annotations"));
        }
        config.addOrReplaceAttribute(a);
        call.kc().save(config, call.realm(), "users", "profile");
        return ToolResult.done(created ? "Attribute added to the user profile" : "Attribute updated", "attribute",
                view(profile.getConfiguration().getAttribute(name)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> m) {
        return (Map<String, Object>) m;
    }

    ToolResult attributeDelete(ToolCall call) {
        String name = call.str("name");
        if (BUILT_IN_ATTRIBUTES.contains(name)) {
            return ToolResult.error("invalid_arguments", "'" + name + "' is built in and cannot be removed.");
        }
        var profile = call.kc().realm(call.realm()).users().userProfile();
        UPConfig config = profile.getConfiguration();
        if (!config.removeAttribute(name)) {
            throw ToolException.notFound("User profile attribute", name);
        }
        call.kc().save(config, call.realm(), "users", "profile");
        return ToolResult.done("Attribute removed from the user profile", "name", name);
    }

    ToolResult unmanagedSet(ToolCall call) {
        var profile = call.kc().realm(call.realm()).users().userProfile();
        UPConfig config = profile.getConfiguration();
        String policy = call.str("policy").toUpperCase(Locale.ROOT);
        config.setUnmanagedAttributePolicy(
                "DISABLED".equals(policy) ? null : UPConfig.UnmanagedAttributePolicy.valueOf(policy));
        call.kc().save(config, call.realm(), "users", "profile");
        return ToolResult.done("Unmanaged attribute policy set", "policy", policy);
    }

    // ---- client policies -----------------------------------------------------------

    ToolResult clientPolicies(ToolCall call) {
        RealmResource realm = call.kc().realm(call.realm());
        boolean global = call.bool("includeGlobal", false);
        ClientPoliciesRepresentation policies = realm.clientPoliciesPoliciesResource().getPolicies(global);
        ClientProfilesRepresentation profiles = realm.clientPoliciesProfilesResource().getProfiles(global);
        List<Map<String, Object>> ps = new ArrayList<>();
        for (ClientPolicyRepresentation p : list(policies.getPolicies(), policies.getGlobalPolicies())) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("name", p.getName());
            Views.put(v, "description", p.getDescription());
            v.put("enabled", Boolean.TRUE.equals(p.isEnabled()));
            if (p.getConditions() != null) {
                v.put("conditions", p.getConditions().stream().map(c -> c.getConditionProviderId()).toList());
            }
            Views.put(v, "profiles", p.getProfiles());
            ps.add(v);
        }
        List<Map<String, Object>> prs = new ArrayList<>();
        for (ClientProfileRepresentation p : list(profiles.getProfiles(), profiles.getGlobalProfiles())) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("name", p.getName());
            Views.put(v, "description", p.getDescription());
            if (p.getExecutors() != null) {
                v.put("executors", p.getExecutors().stream().map(e -> e.getExecutorProviderId()).toList());
            }
            prs.add(v);
        }
        return ToolResult.ok(Map.of("policies", ps, "profiles", prs));
    }

    private static <T> List<T> list(List<T> own, List<T> global) {
        List<T> out = new ArrayList<>();
        if (own != null) {
            out.addAll(own);
        }
        if (global != null) {
            out.addAll(global);
        }
        return out;
    }

    ToolResult clientPolicySetEnabled(ToolCall call) {
        var resource = call.kc().realm(call.realm()).clientPoliciesPoliciesResource();
        ClientPoliciesRepresentation policies = resource.getPolicies(false);
        String name = call.str("name");
        ClientPolicyRepresentation policy = policies.getPolicies() == null ? null
                : policies.getPolicies().stream().filter(p -> name.equals(p.getName())).findFirst().orElse(null);
        if (policy == null) {
            throw ToolException.notFound("Client policy", name);
        }
        policy.setEnabled(call.bool("enabled"));
        // the realm's own policies only: global ones are read-only
        policies.setGlobalPolicies(null);
        resource.updatePolicies(policies);
        return ToolResult.done(call.bool("enabled") ? "Client policy enabled" : "Client policy disabled", "name", name);
    }

    // ---- localization --------------------------------------------------------------

    ToolResult locales(ToolCall call) {
        RealmResource realm = call.kc().realm(call.realm());
        RealmRepresentation r = realm.toRepresentation();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("internationalizationEnabled", Boolean.TRUE.equals(r.isInternationalizationEnabled()));
        Views.put(m, "supportedLocales",
                r.getSupportedLocales() == null ? null : new ArrayList<>(r.getSupportedLocales()));
        Views.put(m, "defaultLocale", r.getDefaultLocale());
        m.put("withRealmTexts", realm.localization().getRealmSpecificLocales());
        return ToolResult.ok(m);
    }

    ToolResult texts(ToolCall call) {
        Map<String, String> all = call.kc()
            .realm(call.realm())
            .localization()
            .getRealmLocalizationTexts(call.str("locale"));
        String needle = call.has("search") ? call.str("search").toLowerCase(Locale.ROOT) : null;
        Map<String, String> texts = new TreeMap<>();
        all.forEach((k, v) -> {
            if (needle == null || k.toLowerCase(Locale.ROOT).contains(needle)
                    || (v != null && v.toLowerCase(Locale.ROOT).contains(needle))) {
                texts.put(k, v);
            }
        });
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("locale", call.str("locale"));
        m.put("count", texts.size());
        if (texts.size() > call.maxItems()) {
            Map<String, String> first = new TreeMap<>();
            texts.entrySet().stream().limit(call.maxItems()).forEach(e -> first.put(e.getKey(), e.getValue()));
            m.put("texts", first);
            m.put("more", true);
        }
        else {
            m.put("texts", texts);
        }
        return ToolResult.ok(m);
    }

    ToolResult textsSet(ToolCall call) {
        Map<String, String> texts = Objects.requireNonNull(call.stringMap("texts"));
        if (texts.isEmpty()) {
            return ToolResult.error("invalid_arguments", "texts is empty: pass at least one key and text.");
        }
        call.kc().realm(call.realm()).localization().createOrUpdateRealmLocalizationTexts(call.str("locale"), texts);
        return ToolResult.done("Translations saved", "locale", call.str("locale"), "keys",
                new ArrayList<>(new java.util.TreeSet<>(texts.keySet())));
    }

    ToolResult textDelete(ToolCall call) {
        try {
            call.kc()
                .realm(call.realm())
                .localization()
                .deleteRealmLocalizationText(call.str("locale"), call.str("message"));
        }
        catch (jakarta.ws.rs.NotFoundException e) {
            throw ToolException.notFound("Translation", call.str("locale") + "/" + call.str("message"));
        }
        return ToolResult.done("Translation deleted", "locale", call.str("locale"), "message", call.str("message"));
    }
}
