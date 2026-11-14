package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.config.InstanceRole;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.github.thomasdarimont.keycloak.mcp.config.SecurityProfile;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.StartupEvent;

/**
 * Enforces what {@code kc-mcp.security-profile=shared} promises: callers of the MCP
 * endpoint authenticate against an audience (skipped on an instance without the
 * endpoint), outbound hosts are listed, the admin API's tokens carry an audience, no
 * system signs in with a person's password (the password grant). Every violation is
 * collected and startup fails with the whole list (the storage encryption is checked by
 * the storage module). Profile {@code local} only warns where a setting leaves a door
 * open that the admin API could walk through. In every profile, a switch set against
 * {@code kc-mcp.instance-role} stops the start. Extensions add their own checks
 * ({@link ProfileCheck}); their problems join the list, tagged with the check's id.
 */
@ApplicationScoped
public class ProfileChecks {

    private static final Logger LOG = Logger.getLogger(ProfileChecks.class);

    @Inject
    McpServerConfig config;
    @Inject
    CallerAuth callers;
    @Inject
    DefaultKeycloakSystems systems;
    @Inject
    ExtensionRegistry extensions;

    void onStart(@Observes StartupEvent event) {
        ValidationRun.guard(this::runStartupChecks);
    }

    private void runStartupChecks() {
        Optional<String> audience = ConfigProvider.getConfig()
            .getOptionalValue("quarkus.oidc.token.audience", String.class)
            .filter(v -> !v.isBlank());
        Settings s = new Settings(config.securityProfile(), callers.oidcEnabled(), audience.isPresent(),
                !systems.allowedHosts().unrestricted(), config.admin().enabled(), config.admin().issuer().isPresent(),
                config.admin().audience().filter(v -> !v.isBlank()).isPresent(), config.admin().allowNewSystems(),
                config.instanceRole(), config.mcp().enabled(), config.ui().enabled(), systems.passwordGrantSystems());
        List<ProfileCheck> checks = extensions.extensions(ProfileCheck.class);
        for (ProfileCheck c : checks) {
            LOG.infof("Profile check '%s' registered (%s)", c.id(), c.getClass().getName());
        }
        Findings findings = run(s, checks,
                id -> new ProfileCheckContext(config.securityProfile(), callers.required(), config,
                        ProviderConfig.forExtension(ProfileCheck.SPI, id, config),
                        name -> ConfigProvider.getConfig().getOptionalValue(name, String.class)));
        List<String> conflicts = roleConflicts(s);
        if (!conflicts.isEmpty()) {
            throw new IllegalStateException(
                    "kc-mcp.instance-role=" + s.role().id() + " contradicts: " + String.join("; ", conflicts));
        }
        if (s.role() != InstanceRole.ALL) {
            LOG.infof("Instance role %s: MCP endpoint %s, admin API %s, management UI %s", s.role().id(),
                    onOff(s.mcpEnabled()), onOff(s.adminEnabled()), onOff(s.uiEnabled()));
        }
        if (!findings.problems().isEmpty()) {
            throw new IllegalStateException("Startup checks of profile " + config.securityProfile().name().toLowerCase()
                    + " failed: " + String.join("; ", findings.problems()));
        }
        for (String w : findings.warnings()) {
            LOG.warn(w);
        }
        String host = ConfigProvider.getConfig().getOptionalValue("quarkus.http.host", String.class).orElse("");
        if (s.mcpEnabled() && !callers.required() && !isLoopback(host)) {
            LOG.warnf("The MCP endpoint is anonymous and listens on %s: everyone who reaches this address administers"
                    + " Keycloak with the server's credentials. Bind to 127.0.0.1 (quarkus.http.host), or require"
                    + " callers (kc-mcp.require-caller / kc-mcp.security-profile=shared).",
                    host.isEmpty() ? "all interfaces" : host);
        }
        LOG.infof(
                "Profile %s: callers %s, confirm-fallback %s, explicit-target %s, outbound hosts %s,"
                        + " dynamic-private-hosts %s, audit-on-failure %s",
                config.securityProfile().name().toLowerCase(), callers.required() ? "required" : "optional",
                config.effectiveConfirmFallback().name().toLowerCase(),
                config.effectiveExplicitTarget().name().toLowerCase(),
                s.hostsRestricted() ? systems.allowedHosts().patterns() : "unrestricted",
                config.effectiveDynamicPrivateHosts().name().toLowerCase(),
                config.effectiveAuditOnFailure().name().toLowerCase().replace('_', '-'));
    }

    private static String onOff(boolean on) {
        return on ? "on" : "off";
    }

    /**
     * Switches set against the instance role, in every profile: the role is what the
     * operator meant, a switch that contradicts it is a mistake in one of the two.
     */
    public static List<String> roleConflicts(Settings s) {
        List<String> out = new ArrayList<>();
        if (!s.role().servesMcp() && s.mcpEnabled()) {
            out.add("kc-mcp.mcp.enabled=true (an admin instance serves no MCP endpoint)");
        }
        if (!s.role().servesAdmin() && s.adminEnabled()) {
            out.add("kc-mcp.admin.enabled=true (an mcp instance serves no admin API)");
        }
        if (!s.role().servesAdmin() && s.uiEnabled()) {
            out.add("kc-mcp.ui.enabled=true (an mcp instance serves no management UI)");
        }
        return out;
    }

    /** Whether a listen address only reaches this machine. */
    static boolean isLoopback(String host) {
        return switch (host.trim().toLowerCase(Locale.ROOT)) {
            case "localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1" -> true;
            default -> host.trim().startsWith("127.");
        };
    }

    /** Problems (stop the start) and warnings (logged) of all checks. */
    public record Findings(List<String> problems, List<String> warnings) {
    }

    /**
     * The built-in checks, then the extensions' in order: problems and warnings of each
     * extension are tagged {@code [id]}. A check that throws is a problem in profile
     * {@code shared} and a warning in {@code local}.
     */
    public static Findings run(Settings s, List<ProfileCheck> checks, Function<String, ProfileCheckContext> contexts) {
        List<String> problems = new ArrayList<>(
                problems(s).stream().map(p -> "kc-mcp.security-profile=shared needs " + p).toList());
        List<String> warnings = new ArrayList<>(warnings(s));
        for (ProfileCheck c : checks) {
            ProfileCheckContext ctx = contexts.apply(c.id());
            try {
                for (String p : nonNull(c.problems(ctx))) {
                    problems.add("[" + c.id() + "] " + p);
                }
                for (String w : nonNull(c.warnings(ctx))) {
                    warnings.add("[" + c.id() + "] " + w);
                }
            }
            catch (RuntimeException e) {
                String msg = "[" + c.id() + "] the check failed: " + e;
                if (s.profile().shared()) {
                    problems.add(msg);
                }
                else {
                    warnings.add(msg);
                }
            }
        }
        return new Findings(List.copyOf(problems), List.copyOf(warnings));
    }

    private static List<String> nonNull(List<String> l) {
        return l == null ? List.of() : l.stream().filter(v -> v != null && !v.isBlank()).toList();
    }

    /** The settings the checks look at, so they can be run without a container. */
    public record Settings(SecurityProfile profile, boolean oidcEnabled, boolean callerAudience,
            boolean hostsRestricted, boolean adminEnabled, boolean adminIssuer, boolean adminAudience,
            boolean adminAllowsNewSystems, InstanceRole role, boolean mcpEnabled, boolean uiEnabled,
            List<String> passwordGrantSystems) {

        public Settings {
            passwordGrantSystems = List.copyOf(passwordGrantSystems);
        }

        /** Without systems on the password grant. */
        public Settings(SecurityProfile profile, boolean oidcEnabled, boolean callerAudience, boolean hostsRestricted,
                boolean adminEnabled, boolean adminIssuer, boolean adminAudience, boolean adminAllowsNewSystems,
                InstanceRole role, boolean mcpEnabled, boolean uiEnabled) {
            this(profile, oidcEnabled, callerAudience, hostsRestricted, adminEnabled, adminIssuer, adminAudience,
                    adminAllowsNewSystems, role, mcpEnabled, uiEnabled, List.of());
        }

        /** An instance of role {@code all} with the MCP endpoint on and the UI off. */
        public Settings(SecurityProfile profile, boolean oidcEnabled, boolean callerAudience, boolean hostsRestricted,
                boolean adminEnabled, boolean adminIssuer, boolean adminAudience, boolean adminAllowsNewSystems) {
            this(profile, oidcEnabled, callerAudience, hostsRestricted, adminEnabled, adminIssuer, adminAudience,
                    adminAllowsNewSystems, InstanceRole.ALL, true, false, List.of());
        }
    }

    /** What {@code shared} refuses to start without; empty for {@code local}. */
    public static List<String> problems(Settings s) {
        List<String> problems = new ArrayList<>();
        if (!s.profile().shared()) {
            return problems;
        }
        // without the MCP endpoint (instance role admin) there are no callers to
        // authenticate
        if (s.mcpEnabled() && !s.oidcEnabled()) {
            problems.add("authenticated callers: quarkus.oidc.tenant-enabled=true (env QUARKUS_OIDC_TENANT_ENABLED)"
                    + " with quarkus.oidc.auth-server-url pointing at the realm that issues the caller tokens");
        }
        if (s.mcpEnabled() && !s.callerAudience()) {
            problems.add("an audience on the caller tokens: quarkus.oidc.token.audience (env"
                    + " QUARKUS_OIDC_TOKEN_AUDIENCE), so that tokens issued for other services are refused");
        }
        if (!s.hostsRestricted()) {
            problems.add("the Keycloak hosts the server may talk to: kc-mcp.allowed-hosts (env KC_MCP_ALLOWED_HOSTS),"
                    + " e.g. *.example.com,sso.internal:8443");
        }
        if (s.adminEnabled() && s.adminIssuer() && !s.adminAudience()) {
            problems.add("an audience on the admin API tokens: kc-mcp.admin.audience (env KC_MCP_ADMIN_AUDIENCE)");
        }
        // a person's password stands in for every caller, and the Keycloak audit names
        // that person for everything the server does
        if (!s.passwordGrantSystems().isEmpty()) {
            problems.add("a service client instead of the password grant: kc-mcp.systems.<name>.grant-type="
                    + "client_credentials for " + String.join(", ", s.passwordGrantSystems()));
        }
        return problems;
    }

    /** Doors left open in {@code local} that are worth a line in the log. */
    public static List<String> warnings(Settings s) {
        List<String> warnings = new ArrayList<>();
        if (s.profile().shared()) {
            return warnings;
        }
        if (s.adminEnabled() && s.adminAllowsNewSystems() && !s.hostsRestricted()) {
            warnings.add("The admin API registers new Keycloak systems and kc-mcp.allowed-hosts is unset: a registered"
                    + " URL may point anywhere the server can reach (set kc-mcp.allowed-hosts, or"
                    + " kc-mcp.admin.allow-new-systems=false)");
        }
        if (s.mcpEnabled() && !s.oidcEnabled()) {
            warnings.add("Profile local: the MCP endpoint is anonymous and every call runs with the server's own"
                    + " credentials; for a server other people reach set kc-mcp.security-profile=shared");
        }
        return warnings;
    }
}
