package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.List;
import java.util.function.LongSupplier;
import jakarta.enterprise.context.ApplicationScoped;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigValueException;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * Step-up authentication (RFC 9470): the tools it concerns run only when the caller's own
 * token says they authenticated strongly enough ({@code acr}) and recently enough
 * ({@code auth_time} within {@code max-age}). A passkey, a second factor or a fresh login
 * is a matter of the authentication flow the realm maps to the {@code acr} value.
 * <p>
 * Off unless the server ({@code kc-mcp.spi.access-check.step-up.default=on}), a system or
 * a realm asks for it. The check reads the token the caller presented to this server:
 * Keycloak's token exchange does not carry the {@code acr} over, so the token the admin
 * call runs with says nothing about it. A call without a caller token cannot pass.
 * <p>
 * A call that falls short is refused with {@code insufficient_user_authentication} and
 * the {@code acr_values} and {@code max_age} to sign in again with, or, with
 * {@code on-missing=confirm}, handed to the human, whose own confirmation lets it
 * through; the model's {@code confirm: true} does not.
 */
@ApplicationScoped
public class StepUpCheck implements AccessCheck {

    public static final String ID = "step-up";

    /** RFC 9470's error code, the denial's. */
    public static final String INSUFFICIENT = "insufficient_user_authentication";

    public static final ConfigProperty ACR = ConfigProperty.list("acr");

    public static final ConfigProperty MAX_AGE = ConfigProperty.duration("max-age");

    public static final ConfigProperty LEVELS = ConfigProperty.list("levels").withDefault("destructive");

    public static final ConfigProperty TOOLS = ConfigProperty.list("tools");

    public static final ConfigProperty ON_MISSING = ConfigProperty.choice("on-missing", "deny", "confirm")
        .withDefault("deny");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec.of(ACR, MAX_AGE, LEVELS, TOOLS, ON_MISSING);

    private final LongSupplier clock;

    public StepUpCheck() {
        this(System::currentTimeMillis);
    }

    /** For tests: a clock in epoch milliseconds. */
    StepUpCheck(LongSupplier clock) {
        this.clock = clock;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Step-up authentication";
    }

    @Override
    public String description() {
        return "Runs sensitive tools only for callers who authenticated strongly and recently enough.";
    }

    /**
     * After the checks that say whether the caller may do this at all, before the rate
     * limit: a call refused here is not counted.
     */
    @Override
    public int order() {
        return 2500;
    }

    @Override
    public boolean enabledByDefault() {
        return false;
    }

    @Override
    public ConfigSpec configSpec() {
        return CONFIG_SPEC;
    }

    @Override
    public List<ConfigProblem> validate(ProviderConfig config) {
        try {
            Requirement.from(config);
            return List.of();
        }
        catch (ConfigValueException e) {
            return List.of(e.problem());
        }
    }

    @Override
    public Decision check(Context ctx) {
        Requirement required;
        try {
            required = Requirement.from(ctx.settings());
        }
        catch (IllegalArgumentException e) {
            return Decision.deny("access_check_failed",
                    "The settings of the access check '" + ID + "' for this system are invalid: " + e.getMessage());
        }
        if (!required.scope().contains(ctx.tool())) {
            return Decision.allow();
        }
        if (required.nothing()) {
            // switched on without saying what to ask for: refuse rather than run without
            return Decision.deny("access_check_failed", "The access check '" + ID + "' is on for " + ctx.tool().name()
                    + " but names neither an acr nor a max-age, so nothing can satisfy it. An administrator has to"
                    + " set one. Do not retry.");
        }
        String shortfall = required.shortfall(ctx.caller(), clock.getAsLong());
        if (shortfall == null) {
            return Decision.allow();
        }
        String why = ctx.tool().name() + " requires " + required.describe() + "; " + shortfall + ".";
        if (required.confirm()) {
            return Decision.confirm(INSUFFICIENT, why + " So this call needs the user's own confirmation.");
        }
        return Decision.deny(INSUFFICIENT,
                why + " Nothing was changed. Tell the user to sign in again in their MCP client with "
                        + required.challenge() + ", then call again. Do not retry before that.");
    }

    /**
     * @param acr the accepted {@code acr} values, any of them; empty when only the age of
     * the login matters
     * @param maxAge how old the login may be, or {@code null} when only the {@code acr}
     * matters
     * @param scope the tools the requirement applies to
     * @param confirm a caller falling short is handed to the human instead of refused
     */
    record Requirement(List<String> acr, Duration maxAge, ToolScope scope, boolean confirm) {

        static Requirement from(ProviderConfig config) {
            Duration maxAge = config.readDuration(MAX_AGE);
            if (maxAge != null && (maxAge.isZero() || maxAge.isNegative())) {
                throw ToolScope.invalid(config, MAX_AGE, config.raw(MAX_AGE).orElse(String.valueOf(maxAge)),
                        "a duration above zero, such as 5m");
            }
            List<String> acr = config.readList(ACR).stream().map(String::trim).filter(v -> !v.isEmpty()).toList();
            return new Requirement(acr, maxAge, ToolScope.from(config, LEVELS, TOOLS),
                    "confirm".equals(config.readChoice(ON_MISSING)));
        }

        boolean nothing() {
            return acr.isEmpty() && maxAge == null;
        }

        /**
         * What the caller's token lacks, as a clause for the message, or {@code null}
         * when it satisfies the requirement.
         */
        String shortfall(Caller caller, long nowMillis) {
            if (caller == null || caller.isAnonymous() || caller.claims().isEmpty()) {
                return "the call carries no token of a signed-in user";
            }
            if (!acr.isEmpty()) {
                Object claim = caller.claim("acr");
                if (claim == null) {
                    return "the caller's token has no acr claim";
                }
                if (!acr.contains(String.valueOf(claim))) {
                    return "the caller's token has acr '" + claim + "'";
                }
            }
            if (maxAge != null) {
                Long authTime = epochSeconds(caller.claim("auth_time"));
                if (authTime == null) {
                    return "the caller's token has no auth_time claim";
                }
                long ageSeconds = nowMillis / 1000 - authTime;
                if (ageSeconds > maxAge.toSeconds()) {
                    return "the caller signed in " + ago(ageSeconds) + " ago";
                }
            }
            return null;
        }

        /** "a login with acr 'x' or 'y' that is at most 5 min old". */
        String describe() {
            StringBuilder out = new StringBuilder("a login");
            if (!acr.isEmpty()) {
                out.append(" with acr ").append(String.join(" or ", acr.stream().map(v -> "'" + v + "'").toList()));
            }
            if (maxAge != null) {
                out.append(" that is at most ").append(RateLimitCheck.describe(maxAge)).append(" old");
            }
            return out.toString();
        }

        /** The RFC 9470 parameters of the authorization request that satisfies it. */
        String challenge() {
            StringBuilder out = new StringBuilder();
            if (!acr.isEmpty()) {
                out.append("acr_values=").append(String.join(" ", acr));
            }
            if (maxAge != null) {
                out.append(out.isEmpty() ? "" : " and ").append("max_age=").append(maxAge.toSeconds());
            }
            return out.toString();
        }

        private static String ago(long seconds) {
            if (seconds >= 7200) {
                return seconds / 3600 + " h";
            }
            return seconds >= 120 ? seconds / 60 + " min" : seconds + " s";
        }

        private static Long epochSeconds(Object claim) {
            if (claim instanceof Number n) {
                return n.longValue();
            }
            if (claim instanceof String s) {
                try {
                    return Long.parseLong(s.trim());
                }
                catch (NumberFormatException e) {
                    return null;
                }
            }
            return null;
        }
    }
}
