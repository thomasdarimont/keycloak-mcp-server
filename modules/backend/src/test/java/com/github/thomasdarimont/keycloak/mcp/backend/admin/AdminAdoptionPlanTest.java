package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** What an adoption stores, decided from the system and Keycloak's realm list alone. */
class AdminAdoptionPlanTest {

    static final List<AdminAdoption.KeycloakRealm> LISTED = List.of(realm("acme", "id-acme", "ACME Corp."),
            realm("beta", "id-beta", null), realm("master", "id-master", "Keycloak"));

    static AdminAdoption.KeycloakRealm realm(String name, String id, String displayName) {
        return new AdminAdoption.KeycloakRealm(name, id, Optional.ofNullable(displayName), Optional.of(true));
    }

    static KeycloakSystem.Builder system() {
        return KeycloakSystem.builder("prod", "https://sso.example.com")
            .grantType(GrantType.CLIENT_CREDENTIALS)
            .clientAuth(ClientAuth.PRIVATE_KEY_JWT)
            .clientId("keycloak-mcp-server")
            .authRealm("master");
    }

    static AdminAdoption.Request request(List<String> realms, boolean all, boolean restrict, String preset) {
        return new AdminAdoption.Request(realms, all, restrict, Optional.ofNullable(preset));
    }

    @Test
    void aSelectionOnAnUnrestrictedSystemOnlyStoresSettings() {
        AdminAdoption.Plan plan = AdminAdoption.plan(system().build(), LISTED,
                request(List.of("acme"), false, false, null));
        assertEquals(Optional.empty(), plan.allowedRealms(), "every realm stays reachable");
        assertEquals(List.of(), plan.unreachable());
        assertEquals(List.of("acme"), plan.created().stream().map(RealmSettings::name).toList());

        plan = AdminAdoption.plan(system().build(), LISTED, request(List.of("acme", "beta"), false, true, "read-only"));
        assertEquals(Optional.of(Set.of("acme", "beta")), plan.allowedRealms());
        assertEquals(List.of("master"), plan.unreachable());
        assertEquals(List.of("acme", "beta"), plan.created().stream().map(RealmSettings::name).toList());
        RealmSettings acme = plan.created().getFirst();
        assertEquals(Optional.of("id-acme"), acme.realmId());
        assertEquals(Optional.of("ACME Corp."), acme.displayName());
        assertEquals(Optional.of("read-only"), acme.preset());
        assertEquals(Optional.empty(), plan.created().get(1).displayName());
    }

    /**
     * Every realm adopted, one realm's settings deleted, that realm adopted again: the
     * others keep their access, with or without a restriction.
     */
    @Test
    void readoptingARealmKeepsTheOthersReachable() {
        List<AdminAdoption.KeycloakRealm> listed = List.of(realm("alpha", "id-alpha", null),
                realm("beta", "id-beta", null), realm("gamma", "id-gamma", null), realm("master", "id-master", null));
        KeycloakSystem.Builder everyRealm = system();
        for (String name : List.of("alpha", "gamma", "master")) {
            // beta's settings were deleted; the system has no allowlist
            everyRealm.realm(new RealmSettings(name, Optional.of("id-" + name), Optional.empty(), Optional.empty(),
                    Optional.empty(), AccessSettings.NONE, ToolSettings.NONE));
        }
        KeycloakSystem system = everyRealm.build();

        AdminAdoption.Plan plan = AdminAdoption.plan(system, listed, request(List.of("beta"), false, false, null));
        assertEquals(Optional.empty(), plan.allowedRealms(), "no restriction asked for: every realm stays reachable");
        assertEquals(List.of("beta"), plan.created().stream().map(RealmSettings::name).toList());
        assertEquals(List.of(), plan.unreachable());

        AdminAdoption.Plan restricted = AdminAdoption.plan(system, listed, request(List.of("beta"), false, true, null));
        assertEquals(Optional.of(Set.of("alpha", "beta", "gamma", "master")), restricted.allowedRealms(),
                "the realms adopted before stay on the allowlist");
        assertEquals(List.of(), restricted.unreachable());

        // a realm never adopted is what a restriction leaves out
        KeycloakSystem withoutGamma = system.toBuilder()
            .realms(system.realms().values().stream().filter(r -> !r.name().equals("gamma")).toList())
            .build();
        AdminAdoption.Plan leavesGamma = AdminAdoption.plan(withoutGamma, listed,
                request(List.of("beta"), false, true, null));
        assertEquals(Optional.of(Set.of("alpha", "beta", "master")), leavesGamma.allowedRealms());
        assertEquals(List.of("gamma"), leavesGamma.unreachable());
    }

    @Test
    void aSelectionExtendsAnAllowlist() {
        KeycloakSystem restricted = system().allowedRealms(List.of("master")).build();
        AdminAdoption.Plan plan = AdminAdoption.plan(restricted, LISTED, request(List.of("beta"), false, false, null));
        assertEquals(Optional.of(Set.of("master", "beta")), plan.allowedRealms());
        // a realm already on the list changes nothing there
        AdminAdoption.Plan again = AdminAdoption.plan(restricted, LISTED,
                request(List.of("master"), false, false, null));
        assertEquals(Optional.empty(), again.allowedRealms());
    }

    @Test
    void allRealmsClearsTheAllowlistAndAdoptsEveryListedRealm() {
        KeycloakSystem restricted = system().allowedRealms(List.of("master")).build();
        AdminAdoption.Plan plan = AdminAdoption.plan(restricted, LISTED, request(List.of(), true, false, null));
        assertEquals(Optional.of(Set.of()), plan.allowedRealms());
        assertEquals(3, plan.created().size());
        assertEquals(Optional.empty(),
                AdminAdoption.plan(system().build(), LISTED, request(List.of(), true, false, null)).allowedRealms());
    }

    @Test
    void existingSettingsKeepTheirsAndGainTheRealmId() {
        RealmSettings own = new RealmSettings("acme", Optional.empty(), Optional.of("ACME (prod)"),
                Optional.of("owned by the platform team"), Optional.of("support"), AccessSettings.NONE,
                ToolSettings.NONE);
        RealmSettings complete = new RealmSettings("beta", Optional.of("id-beta"), Optional.empty(), Optional.empty(),
                Optional.of("support"), AccessSettings.NONE, ToolSettings.NONE);
        KeycloakSystem s = system().allowedRealms(List.of("acme", "beta")).realm(own).realm(complete).build();
        AdminAdoption.Plan plan = AdminAdoption.plan(s, LISTED,
                request(List.of("acme", "beta"), false, false, "read-only"));
        assertTrue(plan.created().isEmpty());
        assertEquals(List.of("beta"), plan.unchanged());
        RealmSettings acme = plan.updated().getFirst();
        assertEquals(Optional.of("id-acme"), acme.realmId());
        assertEquals(Optional.of("ACME (prod)"), acme.displayName(), "the own label stays");
        assertEquals(Optional.of("support"), acme.preset(), "the request's preset is for new realms");
        assertEquals(Optional.of("owned by the platform team"), acme.description());
    }

    @Test
    void onlyRealmsKeycloakListsCanBeAdopted() {
        AdminException unknown = assertThrows(AdminException.class, () -> AdminAdoption.plan(system().build(), LISTED,
                request(List.of("acme", "gone"), false, true, null)));
        assertEquals("unknown_keycloak_realm", unknown.code());
        assertTrue(unknown.getMessage().contains("gone"), unknown.getMessage());
        AdminException none = assertThrows(AdminException.class,
                () -> AdminAdoption.plan(system().build(), LISTED, request(List.of(), false, true, null)));
        assertEquals("no_realms", none.code());
    }

    @Test
    void theListingMarksAdoptedRenamedAndUnlistedRealms() {
        RealmSettings renamed = new RealmSettings("acme-old", Optional.of("id-acme"), Optional.empty(),
                Optional.empty(), Optional.empty(), AccessSettings.NONE, ToolSettings.NONE);
        RealmSettings beta = new RealmSettings("beta", Optional.of("id-beta"), Optional.empty(), Optional.empty(),
                Optional.of("support"), AccessSettings.NONE, ToolSettings.NONE);
        KeycloakSystem s = system().allowedRealms(List.of("beta", "acme-old", "deleted"))
            .realm(renamed)
            .realm(beta)
            .build();
        Map<String, Object> out = AdminAdoption.represent(s, LISTED);
        assertEquals(true, out.get("restricted"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> realms = (List<Map<String, Object>>) out.get("realms");
        Map<String, Map<String, Object>> byName = new LinkedHashMap<>();
        realms.forEach(r -> byName.put((String) r.get("name"), r));
        assertEquals("acme-old", byName.get("acme").get("renamedFrom"));
        assertEquals(false, byName.get("acme").get("allowed"));
        assertEquals(true, byName.get("beta").get("adopted"));
        assertEquals(true, byName.get("beta").get("allowed"));
        assertFalse(byName.get("master").containsKey("renamedFrom"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> notListed = (List<Map<String, Object>>) out.get("notListed");
        assertEquals(List.of("acme-old", "deleted"), notListed.stream().map(r -> r.get("name")).toList());
        assertEquals("id-acme", notListed.getFirst().get("realmId"));
    }

    @Test
    void unadoptingLeavesTheAllowlistButNeverEmptiesIt() {
        KeycloakSystem restricted = system().allowedRealms(List.of("acme", "beta")).build();
        assertEquals(Optional.of(Set.of("beta")), AdminAdoption.unadoptPlan(restricted, "acme", List.of(), false));
        KeycloakSystem one = system().allowedRealms(List.of("acme")).build();
        assertEquals("last_realm",
                assertThrows(AdminException.class, () -> AdminAdoption.unadoptPlan(one, "acme", List.of(), false))
                    .code());
        assertEquals("not_adopted", assertThrows(AdminException.class,
                () -> AdminAdoption.unadoptPlan(restricted, "gamma", List.of(), false))
            .code());
        // settings of a realm off the allowlist: only they go
        RealmSettings stale = new RealmSettings("gamma", Optional.of("id-gamma"), Optional.empty(), Optional.empty(),
                Optional.empty(), AccessSettings.NONE, ToolSettings.NONE);
        assertEquals(Optional.empty(), AdminAdoption.unadoptPlan(
                system().allowedRealms(List.of("acme", "beta")).realm(stale).build(), "gamma", List.of(), false));
        KeycloakSystem byDefault = system().allowedRealms(List.of("acme", "beta")).defaultRealm("acme").build();
        assertEquals("default_realm",
                assertThrows(AdminException.class, () -> AdminAdoption.unadoptPlan(byDefault, "acme", List.of(), false))
                    .code());
    }

    @Test
    void unadoptingFromEveryRealmNeedsRestrict() {
        KeycloakSystem every = system().build();
        List<String> listed = List.of("acme", "beta", "master");
        assertEquals("would_restrict",
                assertThrows(AdminException.class, () -> AdminAdoption.unadoptPlan(every, "acme", listed, false))
                    .code());
        assertEquals(Optional.of(Set.of("beta", "master")), AdminAdoption.unadoptPlan(every, "acme", listed, true));
        assertEquals("last_realm", assertThrows(AdminException.class,
                () -> AdminAdoption.unadoptPlan(every, "acme", List.of("acme"), true))
            .code());
        assertEquals("not_adopted",
                assertThrows(AdminException.class, () -> AdminAdoption.unadoptPlan(every, "gone", listed, true))
                    .code());
    }

    @Test
    void anIssuerIsTheAuthRealmsIssuer() {
        AdminSystems.checkIssuer(system().build());
        AdminSystems.checkIssuer(system().issuer("https://sso.example.com/realms/master").build());
        AdminSystems.checkIssuer(system().issuer("https://sso.example.com/auth/realms/master/").build());
        AdminException base = assertThrows(AdminException.class,
                () -> AdminSystems.checkIssuer(system().issuer("http://localhost:8095").build()));
        assertEquals("invalid_issuer", base.code());
        assertTrue(base.getMessage().contains("http://localhost:8095/realms/master"), base.getMessage());
        assertThrows(AdminException.class,
                () -> AdminSystems.checkIssuer(system().issuer("https://sso.example.com/realms/acme").build()));
    }

    @Test
    void theScriptGrantsAndScopesEveryRole() {
        Map<String, List<String>> grants = new LinkedHashMap<>();
        grants.put(null, List.of("admin"));
        grants.put("acme-realm", List.of("view-realm", "view-users"));
        String script = AdminAdoption.script(system().build(), "keycloak-mcp-server",
                Map.of("clientId", "keycloak-mcp-server"), grants);
        assertTrue(script.contains("--uusername \"$SA\" --rolename \"$ROLE\""), script);
        assertTrue(script.contains("scope-mappings/realm"), script);
        assertTrue(script.contains("--cclientid 'acme-realm'"), script);
        assertTrue(script.contains("scope-mappings/clients/$RCID"), script);
        assertTrue(script.contains("SA='service-account-keycloak-mcp-server'"), script);
        assertEquals("'it'\\''s'", AdminAdoption.shell("it's"));
    }

    /** The Windows variant: the same grants, PowerShell syntax, kcadm.bat. */
    @Test
    void thePowerShellScriptGrantsAndScopesEveryRole() {
        Map<String, List<String>> grants = new LinkedHashMap<>();
        grants.put(null, List.of("admin"));
        grants.put("acme-realm", List.of("view-realm", "view-users"));
        String script = AdminAdoption.powershellScript(system().build(), "keycloak-mcp-server",
                Map.of("clientId", "keycloak-mcp-server", "description", "it's $HOME"), grants);
        assertTrue(script.contains("$Kcadm = if ($env:KCADM) { $env:KCADM } else { 'kcadm.bat' }"), script);
        assertTrue(script.contains("$SA = 'service-account-keycloak-mcp-server'"), script);
        assertTrue(script.contains("foreach ($Role in @('admin'))"), script);
        assertTrue(script.contains("foreach ($Role in @('view-realm', 'view-users'))"), script);
        assertTrue(script.contains("--cclientid 'acme-realm' --rolename $Role"), script);
        assertTrue(script.contains("-q 'clientId=acme-realm'"), script);
        assertTrue(script.contains("scope-mappings/clients/$Rcid"), script);
        // unquoted, PowerShell would pass id,name as an array
        assertTrue(script.contains("--fields 'id,name'"), script);
        assertTrue(script.contains("$LASTEXITCODE -ne 0"), "native exit codes are checked: " + script);
        // the JSON in a literal here-string, $HOME stays as it is; on stdin as UTF-8
        assertTrue(script.contains("$clientJson = @'\n{") && script.contains("\"it's $HOME\"")
                && script.contains("\n'@\n$clientJson | Invoke-Kcadm create clients -r $Realm -f -"), script);
        assertTrue(script.contains("$OutputEncoding = New-Object System.Text.UTF8Encoding $false"), script);
        assertTrue(script.contains("$KcadmImage = if ($null -ne $env:KCADM_IMAGE) { $env:KCADM_IMAGE } else { '' }"),
                "installed by default: " + script);
        assertFalse(script.contains("#!/usr/bin/env bash") || script.contains("sed "), script);
        assertEquals("'it''s'", AdminAdoption.powershell("it's"));
    }

    /** kcadm from the Keycloak image: the system's version, KCADM_IMAGE overrides it. */
    @Test
    void theScriptsCanRunKcadmFromTheKeycloakImage() {
        KeycloakSystem versioned = system().version("26.8.2").build();
        assertEquals(Optional.of("quay.io/keycloak/keycloak:26.8.2"), AdminAdoption.kcadmImage(versioned, "docker"));
        assertEquals(Optional.of("quay.io/keycloak/keycloak:latest"),
                AdminAdoption.kcadmImage(system().build(), "Docker"));
        assertEquals(Optional.empty(), AdminAdoption.kcadmImage(versioned, null));
        assertEquals("invalid_kcadm",
                assertThrows(AdminException.class, () -> AdminAdoption.kcadmImage(versioned, "podman")).code());

        Map<String, List<String>> grants = Map.of("realm-management", List.of("realm-admin"));
        Optional<String> image = AdminAdoption.kcadmImage(versioned, "docker");
        String bash = AdminAdoption.script(versioned, "kc-mcp", Map.of("clientId", "kc-mcp"), grants, image);
        assertTrue(bash.contains("KCADM_IMAGE=\"${KCADM_IMAGE-quay.io/keycloak/keycloak:26.8.2}\""), bash);
        assertTrue(bash.contains("--entrypoint /opt/keycloak/bin/kcadm.sh \"$KCADM_IMAGE\" \"$@\""), bash);
        // the login per system, apart from an existing ~/.keycloak
        assertTrue(bash.contains("KCADM_CONFIG_DIR=\"${KCADM_CONFIG_DIR:-$HOME/.kc-mcp/kcadm/prod}\""), bash);
        assertTrue(bash.contains("-v \"$KCADM_CONFIG_DIR:/opt/keycloak/.keycloak:z\""), bash);
        assertFalse(bash.contains("$HOME/.keycloak:"), bash);
        assertEquals(".kc-mcp/kcadm/a_b", AdminAdoption.kcadmConfigDir(system().name("a/b").build()));
        assertTrue(bash.contains("#     quay.io/keycloak/keycloak:26.8.2 config credentials --server"), bash);
        assertFalse(bash.contains("\"$KCADM\""), "every call goes through the kcadm function: " + bash);

        String ps = AdminAdoption.powershellScript(versioned, "kc-mcp", Map.of("clientId", "kc-mcp"), grants, image);
        assertTrue(ps.contains("else { 'quay.io/keycloak/keycloak:26.8.2' }"), ps);
        assertTrue(ps.contains("else { Join-Path $HOME '.kc-mcp/kcadm/prod' }"), ps);
        assertTrue(ps.contains("$input | docker run --rm -i \"--net=$network\" -e HOME=/opt/keycloak"), ps);
    }
}
