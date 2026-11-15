package com.github.thomasdarimont.keycloak.mcp.access;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;

/**
 * Additional access predicate, evaluated per call after the static policy, realm
 * allow-list and role checks and before confirmation. Attach to one tool with
 * {@code ToolSpec.builder(...).access(check)} or contribute globally from
 * {@link ToolProvider#accessChecks(ToolProviderContext)}, as a CDI bean, or on its own
 * via the ServiceLoader ({@code @AutoService(AccessCheck.class)}). Checks run on the
 * handler's virtual thread and may call Keycloak; only the {@code tools/list} filter must
 * not block.
 */
@FunctionalInterface
public interface AccessCheck extends Extension {

    Decision check(Context context);

    /**
     * Whether the check runs where neither the server's {@code default} nor a system's or
     * realm's entry says otherwise. Default: yes; a check that only makes sense where it
     * is asked for (the group scope) answers no.
     */
    default boolean enabledByDefault() {
        return true;
    }

    /**
     * @param tool the tool about to run
     * @param system Keycloak system name ({@code null} in single-system unit tests)
     * @param realm resolved target realm ({@code null} for global tools)
     * @param args validated arguments
     * @param roles what the token behind this call can do: the server's own, or the
     * caller's under delegation
     * @param caller who is acting through the connection
     * @param keycloak the admin client the call will run with (the caller's own under
     * delegation); {@code null} in unit tests
     * @param attributes scratch space of this one evaluation, fresh per call: a check
     * that looks something up, a directory say, keeps it here so the other checks of the
     * same call reuse it instead of asking Keycloak again
     * @param settings this check's effective settings for the call: the server's
     * {@code kc-mcp.spi.access-check.<id>.*} with the system's and the realm's
     * {@code access.<id>} entries over them, without {@code enabled} and {@code order};
     * empty for checks attached to a tool
     */
    record Context(ToolSpec tool, String system, String realm, Map<String, Object> args, GrantedRoles roles,
            Caller caller, KeycloakAdmin keycloak, Map<String, Object> attributes, ProviderConfig settings) {

        public Context {
            settings = settings == null ? new ProviderConfig(AccessCheckSpi.NAME, "", Map.of()) : settings;
        }

        public Context(ToolSpec tool, String system, String realm, Map<String, Object> args, GrantedRoles roles,
                Caller caller, KeycloakAdmin keycloak, Map<String, Object> attributes) {
            this(tool, system, realm, args, roles, caller, keycloak, attributes, null);
        }

        public Context(ToolSpec tool, String system, String realm, Map<String, Object> args, GrantedRoles roles,
                Caller caller, KeycloakAdmin keycloak) {
            this(tool, system, realm, args, roles, caller, keycloak, new ConcurrentHashMap<>());
        }

        /**
         * The same call as another check sees it: its own settings, the shared
         * attributes.
         */
        public Context forCheck(ProviderConfig checkSettings) {
            return new Context(tool, system, realm, args, roles, caller, keycloak, attributes, checkSettings);
        }

        public Context(ToolSpec tool, String system, String realm, Map<String, Object> args, GrantedRoles roles,
                Caller caller) {
            this(tool, system, realm, args, roles, caller, null);
        }

        public Context(ToolSpec tool, String realm, Map<String, Object> args, GrantedRoles roles, Caller caller) {
            this(tool, null, realm, args, roles, caller, null);
        }

        public String arg(String name) {
            Object v = args.get(name);
            return v == null ? null : String.valueOf(v);
        }
    }

    /**
     * {@code allowed}, a denial with an error code (defaults to {@code access_denied})
     * and a message, or {@code confirmation}: allowed provided the human confirms this
     * very call themselves. The server then runs the call through its confirmers as if
     * the tool were destructive, with the model's {@code confirm: true} not counting, so
     * only a client with elicitation or a confirmer that asks the human (CIBA) lets it
     * through; {@code code} and {@code message} say why.
     */
    record Decision(boolean allowed, String code, String message, boolean confirmation) {

        public static final Decision ALLOW = new Decision(true, null, null, false);

        public Decision(boolean allowed, String code, String message) {
            this(allowed, code, message, false);
        }

        public static Decision allow() {
            return ALLOW;
        }

        public static Decision deny(String message) {
            return new Decision(false, "access_denied", message);
        }

        public static Decision deny(String code, String message) {
            return new Decision(false, code, message);
        }

        /** Allowed once the human confirms it themselves; see {@link #confirmation()}. */
        public static Decision confirm(String code, String message) {
            return new Decision(true, code, message, true);
        }
    }
}
