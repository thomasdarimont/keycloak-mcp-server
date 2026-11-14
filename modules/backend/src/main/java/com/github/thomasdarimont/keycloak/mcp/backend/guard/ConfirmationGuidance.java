package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ModelConfirmation;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;

/**
 * What the model is told about confirming destructive tools, per session and caller
 * ({@code kc-mcp.model-confirmation}, {@code kc-mcp.model-confirmation-trusted-roles}):
 * the text goes into {@code search_tools} hits of destructive tools, {@code whoami} and
 * the {@code confirmation_required} answers. Guidance only, the confirmers decide.
 */
@ApplicationScoped
public class ConfirmationGuidance {

    public enum Mode {
        /**
         * Ask the user once after {@code confirmation_required}, then
         * {@code confirm: true}.
         */
        ASK,
        /** The caller is trusted: {@code confirm: true} right away. */
        TRUSTED,
        /**
         * The server asks (client elicitation, the user's device) or refuses; never the
         * model.
         */
        SERVER
    }

    static final String ASK_TEXT = "Destructive tools answer confirmation_required first: ask the user once, then"
            + " call again with the same arguments plus confirm: true. Do not ask before the first call.";
    static final String TRUSTED_TEXT = "The caller is an administrator: call destructive tools with confirm: true"
            + " right away, without asking the user first.";
    static final String SERVER_TEXT = "Confirmation is not your job: the server asks the user itself (through this"
            + " client, or on their device) or refuses. Call destructive tools right away without asking the user"
            + " first and relay the answer; confirm: true is not needed and not accepted as a substitute.";

    private final ModelConfirmation setting;
    private final ConfirmFallback fallback;
    private final boolean confirmerAsksTheHuman;
    private final Set<String> trustedRoles;

    @Inject
    public ConfirmationGuidance(McpServerConfig config, ConfirmerChain chain) {
        this(config.modelConfirmation(), config.effectiveConfirmFallback(),
                chain.confirmers().stream().anyMatch(Confirmer::asksTheHuman),
                Set.copyOf(config.modelConfirmationTrustedRoles().orElse(List.of())));
    }

    public ConfirmationGuidance(ModelConfirmation setting, ConfirmFallback fallback, boolean confirmerAsksTheHuman,
            Set<String> trustedRoles) {
        this.setting = setting == null ? ModelConfirmation.AUTO : setting;
        this.fallback = fallback == null ? ConfirmFallback.FLAG : fallback;
        this.confirmerAsksTheHuman = confirmerAsksTheHuman;
        this.trustedRoles = trustedRoles == null ? Set.of() : Set.copyOf(trustedRoles);
    }

    /** The guidance of a server without any of the switches: the model asks. */
    public static ConfirmationGuidance standalone() {
        return new ConfirmationGuidance(ModelConfirmation.ASK, ConfirmFallback.FLAG, false, Set.of());
    }

    public Mode mode(TransportContext ctx) {
        boolean trusted = ctx != null && !ctx.caller().isAnonymous()
                && trustedRoles.stream().anyMatch(ctx.caller()::hasRole);
        boolean clientAsks = ctx != null && ElicitationPrompter.of(ctx.elicitation(), Duration.ZERO).available();
        return switch (setting) {
            case ASK -> trusted ? Mode.TRUSTED : Mode.ASK;
            case SERVER -> Mode.SERVER;
            case AUTO -> confirmerAsksTheHuman || !fallback.acceptsFlag() || clientAsks ? Mode.SERVER
                    : trusted ? Mode.TRUSTED : Mode.ASK;
        };
    }

    public String howTo(Mode mode) {
        return switch (mode) {
            case ASK -> ASK_TEXT;
            case TRUSTED -> TRUSTED_TEXT;
            case SERVER -> SERVER_TEXT;
        };
    }

    public String howTo(TransportContext ctx) {
        return howTo(mode(ctx));
    }

    /** For {@code whoami}. */
    public Map<String, Object> json(TransportContext ctx) {
        Mode mode = mode(ctx);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", mode.name().toLowerCase());
        out.put("howTo", howTo(mode));
        return out;
    }
}
