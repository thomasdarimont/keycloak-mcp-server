package com.github.thomasdarimont.keycloak.mcp.access;

import java.util.Map;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * A client of an outside policy service that decides about tool calls: the built-in
 * {@code authzen} (OpenID AuthZEN), or a vendor's engine from an extension. Settings
 * {@code kc-mcp.spi.authorization-engine.<id>.*}; register with
 * {@code @AutoService(AuthorizationEngine.class)} or as a CDI bean.
 * <p>
 * Engines do not decide <em>whether</em> a call is theirs: the server's access check
 * {@code authorization} does, from the system's (and realm's)
 * {@link KeycloakSystem#authorization(String) authorization} block. It calls
 * {@link #decide} for every engine the block names, or for every engine when it names
 * none, as long as the block's switch, else {@link #evaluatesByDefault()}, says the call
 * is evaluated. It denies calls that need an engine the server does not have, and calls
 * whose engine throws. A denial of any engine refuses the call.
 * <p>
 * The engine's {@link #id()} names its block in a system's authorization
 * ({@code "authorization": {"<id>": {...}}}); {@link Request#settings()} hands it the
 * effective settings, the system's with the realm's over them, for the engine to put over
 * its own defaults.
 */
public interface AuthorizationEngine extends Extension {

    /**
     * Whether calls of systems whose block has no switch are evaluated by this engine.
     * Default: no; governance is switched on per system or realm.
     */
    default boolean evaluatesByDefault() {
        return false;
    }

    /**
     * The decision about one call: {@link AccessCheck.Decision#allow()},
     * {@link AccessCheck.Decision#deny}, or {@link AccessCheck.Decision#confirm} for a
     * call the human has to confirm themselves. Runs on the handler's virtual thread and
     * may call the policy service. An exception denies the call.
     */
    AccessCheck.Decision decide(Request request);

    /**
     * Checks this engine's settings of a system, its own and its realms', before the
     * admin API stores it, without calling anyone. Default: nothing to check.
     *
     * @param systemKey whether the system will have a signing key of its own (configured,
     * in the vault, or created by it on first use), for engines that sign with it
     * @throws IllegalArgumentException with what is wrong, shown to the caller
     */
    default void validate(KeycloakSystem system, boolean systemKey) {
    }

    /**
     * @param context the call, as access checks see it
     * @param system the system it targets, its secret references resolved; empty in tests
     * without systems
     * @param authorization the effective authorization block of the call (the system's
     * with the realm's over it)
     * @param settings this engine's part of it, by kebab-case key; empty when the block
     * does not name the engine
     */
    record Request(AccessCheck.Context context, Optional<KeycloakSystem> system, AuthorizationSettings authorization,
            Map<String, String> settings) {

        public Request {
            system = system == null ? Optional.empty() : system;
            authorization = authorization == null ? AuthorizationSettings.NONE : authorization;
            settings = settings == null ? Map.of() : Map.copyOf(settings);
        }

        /** The realm the call targets, {@code null} for a global tool. */
        public String realm() {
            return context.realm();
        }

        /** The name of the system the call targets. */
        public String systemName() {
            return context.system();
        }
    }
}
