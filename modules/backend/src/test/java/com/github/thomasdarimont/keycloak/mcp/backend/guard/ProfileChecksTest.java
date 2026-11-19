package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget;
import com.github.thomasdarimont.keycloak.mcp.config.InstanceRole;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.github.thomasdarimont.keycloak.mcp.config.SecurityProfile;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProfileChecksTest {

    private static ProfileChecks.Settings settings(SecurityProfile profile, boolean oidc, boolean audience,
            boolean hosts, boolean adminEnabled, boolean adminIssuer, boolean adminAudience, boolean newSystems) {
        return new ProfileChecks.Settings(profile, oidc, audience, hosts, adminEnabled, adminIssuer, adminAudience,
                newSystems);
    }

    private static ProfileChecks.Settings instance(SecurityProfile profile, InstanceRole role, boolean mcp,
            boolean admin, boolean ui) {
        return new ProfileChecks.Settings(profile, false, false, true, admin, true, true, true, role, mcp, ui);
    }

    @Test
    void switchesAgainstTheInstanceRoleConflict() {
        assertEquals(List.of(),
                ProfileChecks.roleConflicts(instance(SecurityProfile.LOCAL, InstanceRole.MCP, true, false, false)));
        assertEquals(2, ProfileChecks.roleConflicts(instance(SecurityProfile.LOCAL, InstanceRole.MCP, true, true, true))
            .size());
        List<String> admin = ProfileChecks
            .roleConflicts(instance(SecurityProfile.LOCAL, InstanceRole.ADMIN, true, true, false));
        assertEquals(1, admin.size(), admin.toString());
        assertTrue(admin.getFirst().startsWith("kc-mcp.mcp.enabled=true"), admin.getFirst());
        assertEquals(List.of(),
                ProfileChecks.roleConflicts(instance(SecurityProfile.LOCAL, InstanceRole.ALL, true, true, true)));
    }

    @Test
    void aSharedAdminInstanceNeedsNoCallerAuthentication() {
        assertTrue(ProfileChecks.problems(instance(SecurityProfile.SHARED, InstanceRole.ADMIN, false, true, true))
            .isEmpty());
        List<String> mcp = ProfileChecks
            .problems(instance(SecurityProfile.SHARED, InstanceRole.MCP, true, false, false));
        assertEquals(2, mcp.size(), "an MCP instance still does: " + mcp);
        assertTrue(ProfileChecks.warnings(instance(SecurityProfile.LOCAL, InstanceRole.ADMIN, false, true, true))
            .isEmpty(), "no warning about an anonymous MCP endpoint that does not exist");
    }

    @Test
    void sharedRefusesThePasswordGrant() {
        ProfileChecks.Settings complete = settings(SecurityProfile.SHARED, true, true, true, false, false, false,
                false);
        assertTrue(ProfileChecks.problems(complete).isEmpty(), "complete without password grant");
        ProfileChecks.Settings password = new ProfileChecks.Settings(SecurityProfile.SHARED, true, true, true, false,
                false, false, false, InstanceRole.ALL, true, false, List.of("default", "prod"));
        List<String> p = ProfileChecks.problems(password);
        assertEquals(1, p.size(), p.toString());
        assertTrue(p.getFirst().contains("grant-type=client_credentials for default, prod"), p.getFirst());
        ProfileChecks.Settings local = new ProfileChecks.Settings(SecurityProfile.LOCAL, true, true, true, false, false,
                false, false, InstanceRole.ALL, true, false, List.of("default"));
        assertTrue(ProfileChecks.problems(local).isEmpty(), "local allows it");
    }

    @Test
    void localNeverFails() {
        assertTrue(ProfileChecks.problems(settings(SecurityProfile.LOCAL, false, false, false, true, true, false, true))
            .isEmpty());
    }

    @Test
    void localWarnsAboutOpenRegistrationWithoutHostList() {
        List<String> w = ProfileChecks
            .warnings(settings(SecurityProfile.LOCAL, true, true, false, true, true, true, true));
        assertEquals(1, w.size(), w.toString());
        assertTrue(w.getFirst().contains("kc-mcp.allowed-hosts"), w.getFirst());
        assertTrue(ProfileChecks.warnings(settings(SecurityProfile.LOCAL, true, true, false, true, true, true, false))
            .isEmpty(), "closed registration");
        assertTrue(ProfileChecks.warnings(settings(SecurityProfile.LOCAL, true, true, true, true, true, true, true))
            .isEmpty(), "hosts listed");
    }

    @Test
    void sharedListsEveryMissingSetting() {
        List<String> p = ProfileChecks
            .problems(settings(SecurityProfile.SHARED, false, false, false, true, true, false, true));
        assertEquals(4, p.size(), p.toString());
        assertTrue(p.getFirst().contains("kc-mcp.mcp.oauth.enabled"));
        assertTrue(p.get(1).contains("kc-mcp.mcp.oauth.audience"));
        assertTrue(p.get(2).contains("kc-mcp.allowed-hosts"));
        assertTrue(p.get(3).contains("kc-mcp.admin.oauth.audience"));
    }

    @Test
    void sharedPassesWhenConfigured() {
        assertTrue(ProfileChecks.problems(settings(SecurityProfile.SHARED, true, true, true, true, true, true, true))
            .isEmpty());
        assertTrue(ProfileChecks.problems(settings(SecurityProfile.SHARED, true, true, true, false, false, false, true))
            .isEmpty(), "admin API off: no admin audience needed");
        assertTrue(ProfileChecks.problems(settings(SecurityProfile.SHARED, true, true, true, true, false, false, true))
            .isEmpty(), "admin API with a static token only: no issuer, no audience needed");
        assertTrue(ProfileChecks.warnings(settings(SecurityProfile.SHARED, true, true, true, true, true, true, true))
            .isEmpty());
    }

    @Test
    void profileParsesAliases() {
        assertEquals(SecurityProfile.SHARED, SecurityProfile.parse("prod"));
        assertEquals(SecurityProfile.LOCAL, SecurityProfile.parse(" Local "));
        assertEquals(ConfirmFallback.DENY, ConfirmFallback.parse("elicitation-only"));
        assertEquals(ExplicitTarget.WRITE, ExplicitTarget.parse("mutations"));
    }

    private static ProfileCheck check(String id, List<String> problems, List<String> warnings, boolean fail) {
        return new ProfileCheck() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public List<String> problems(ProfileCheckContext ctx) {
                if (fail) {
                    throw new IllegalStateException("boom");
                }
                return ctx.shared() ? problems : List.of();
            }

            @Override
            public List<String> warnings(ProfileCheckContext ctx) {
                return warnings;
            }
        };
    }

    private static Function<String, ProfileCheckContext> contexts(SecurityProfile profile) {
        return id -> new ProfileCheckContext(profile, true, null, new ProviderConfig(id, Map.of()), null);
    }

    @Test
    void extensionChecksJoinTheBuiltInOnesTaggedWithTheirId() {
        var s = settings(SecurityProfile.SHARED, false, true, true, false, false, false, true);
        var findings = ProfileChecks.run(s,
                List.of(check("acme", List.of("the ticket URL must be https"), List.of("w1"), false),
                        check("quiet", List.of(), List.of(), false)),
                contexts(SecurityProfile.SHARED));
        assertEquals(List.of("kc-mcp.security-profile=shared needs authenticated callers: kc-mcp.mcp.oauth.enabled=true"
                + " (env KC_MCP_MCP_OAUTH_ENABLED) with kc-mcp.mcp.oauth.issuer pointing at the realm that"
                + " issues the caller tokens", "[acme] the ticket URL must be https"), findings.problems());
        assertEquals(List.of("[acme] w1"), findings.warnings());
    }

    @Test
    void aFailingCheckStopsASharedServerAndOnlyWarnsALocalOne() {
        var ok = settings(SecurityProfile.SHARED, true, true, true, false, false, false, true);
        var shared = ProfileChecks.run(ok, List.of(check("flaky", List.of(), List.of(), true)),
                contexts(SecurityProfile.SHARED));
        assertEquals(1, shared.problems().size());
        assertTrue(shared.problems().getFirst().startsWith("[flaky] the check failed"), shared.problems().toString());

        var local = ProfileChecks.run(settings(SecurityProfile.LOCAL, true, true, true, false, false, false, true),
                List.of(check("flaky", List.of(), List.of(), true)), contexts(SecurityProfile.LOCAL));
        assertTrue(local.problems().isEmpty());
        assertTrue(local.warnings().stream().anyMatch(w -> w.startsWith("[flaky] the check failed")),
                local.warnings().toString());
    }
}
