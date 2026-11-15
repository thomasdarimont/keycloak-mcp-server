package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.List;
import java.util.function.LongSupplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigValueException;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.state.StateScope;

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

    /**
     * {@code browser}: a refused caller gets a link to a login this server runs itself.
     */
    public static final ConfigProperty LOGIN = ConfigProperty.choice("login", "off", "browser", "device")
        .withDefault("off");

    public static final ConfigProperty LOGIN_CLIENT_ID = ConfigProperty.string("login-client-id");

    public static final ConfigProperty LOGIN_CLIENT_SECRET = ConfigProperty.string("login-client-secret")
        .asConfidential();

    public static final ConfigProperty LOGIN_ISSUER = ConfigProperty.string("login-issuer").withDefault("caller");

    public static final ConfigProperty LOGIN_SCOPE = ConfigProperty.string("login-scope").withDefault("openid");

    public static final ConfigProperty LOGIN_TIMEOUT = ConfigProperty.duration("login-timeout").withDefault("5m");

    public static final ConfigProperty LOGIN_VALIDITY = ConfigProperty.duration("login-validity").withDefault("1h");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec
        .of(ACR, MAX_AGE, LEVELS, TOOLS, ON_MISSING, LOGIN, LOGIN_CLIENT_ID, LOGIN_CLIENT_SECRET, LOGIN_ISSUER,
                LOGIN_SCOPE, LOGIN_TIMEOUT, LOGIN_VALIDITY)
        .withHints(
                ConfigHint.group("requirement", ACR.name(), MAX_AGE.name(), LEVELS.name(), TOOLS.name(),
                        ON_MISSING.name()),
                ConfigHint.group("login", LOGIN.name(), LOGIN_CLIENT_ID.name(), LOGIN_CLIENT_SECRET.name(),
                        LOGIN_ISSUER.name(), LOGIN_SCOPE.name(), LOGIN_TIMEOUT.name(), LOGIN_VALIDITY.name()),
                ConfigHint.when(LOGIN_CLIENT_ID.name()).is(LOGIN.name(), "browser", "device"),
                ConfigHint.when(LOGIN_CLIENT_SECRET.name()).is(LOGIN.name(), "browser", "device"),
                ConfigHint.when(LOGIN_ISSUER.name()).is(LOGIN.name(), "browser", "device"),
                ConfigHint.when(LOGIN_SCOPE.name()).is(LOGIN.name(), "browser", "device"),
                ConfigHint.when(LOGIN_TIMEOUT.name()).is(LOGIN.name(), "browser", "device"),
                ConfigHint.when(LOGIN_VALIDITY.name()).is(LOGIN.name(), "browser", "device"));

    private static final Logger LOG = Logger.getLogger(StepUpCheck.class);

    private static final String AFTERWARDS = "Call again with the same arguments once the user says they are done,"
            + " not before.";

    private final LongSupplier clock;
    private final StepUpLogins logins;

    @Inject
    public StepUpCheck(StepUpLogins logins) {
        this(System::currentTimeMillis, logins);
    }

    /** For tests: a clock in epoch milliseconds. */
    StepUpCheck(LongSupplier clock, StepUpLogins logins) {
        this.clock = clock;
        this.logins = logins;
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
        long now = clock.getAsLong();
        String shortfall = required.shortfall(ctx.caller(), now);
        if (shortfall == null) {
            return Decision.allow();
        }
        String why = ctx.tool().name() + " requires " + required.describe() + "; " + shortfall + ".";
        if (required.confirm()) {
            return Decision.confirm(INSUFFICIENT, why + " So this call needs the user's own confirmation.");
        }
        StepUpLogins.LoginClient client = required.login(ctx.caller());
        if (client != null) {
            Caller caller = ctx.caller();
            // state belongs to a system; a call without one (a single-system unit test)
            // is the default system's
            StepUpLogins.Request request = new StepUpLogins.Request(client,
                    StateScope.of(ctx.system() == null ? "default" : ctx.system(), ctx.realm()), caller.subject(),
                    caller.claim("sid") == null ? null : String.valueOf(caller.claim("sid")), caller.name(),
                    required.acr(), required.maxAge(),
                    ctx.tool().name() + (ctx.system() == null ? "" : " on system '" + ctx.system() + "'"));
            try {
                StepUpLogins.Grant grant = logins.grant(request);
                if (grant != null && required.shortfall(grant.acr(), grant.authTime(), now) == null) {
                    return Decision.allow();
                }
                return required.login().device() ? device(request, why, now) : browser(request, why);
            }
            catch (RuntimeException e) {
                // a login that cannot be started or whose state cannot be kept proves
                // nothing: refuse
                LOG.errorf(e, "Step-up login failed, so %s is refused: %s", ctx.tool().name(), e.getMessage());
                return Decision.deny("access_check_failed",
                        "This server cannot run its step-up login, so it refuses " + ctx.tool().name()
                                + "; nothing was changed. An administrator has to fix it (the server log names the"
                                + " problem). Do not retry.");
            }
        }
        return Decision.deny(INSUFFICIENT,
                why + " Nothing was changed. Tell the user to sign in again in their MCP client with "
                        + required.challenge() + ", then call again. Do not retry before that.");
    }

    private Decision browser(StepUpLogins.Request request, String why) {
        StepUpLogins.Ticket ticket = logins.ticket(request);
        return Decision.deny(INSUFFICIENT,
                why + " Nothing was changed. Show the user this link and ask them to open it in their browser and"
                        + " sign in there: " + logins.link(ticket) + " (valid for "
                        + RateLimitCheck.describe(request.client().timeout()) + "). " + AFTERWARDS);
    }

    private Decision device(StepUpLogins.Request request, String why, long now) {
        StepUpLogins.DeviceStep step = logins.device(request);
        return switch (step.status()) {
            case GRANTED -> Decision.allow();
            case STARTED, PENDING -> Decision.deny(INSUFFICIENT, why + " Nothing was changed. "
                    + (step.status() == StepUpLogins.DeviceStatus.PENDING
                            ? "The user has not completed the sign-in yet. Show them this link again"
                            : "Show the user this link")
                    + " and ask them to open it in their browser and sign in there: " + step.link()
                    + (step.userCode() == null ? "" : " (the page shows or asks for the code " + step.userCode() + ")")
                    + ", valid for another "
                    + RateLimitCheck.describe(Duration.ofSeconds(Math.max(60, (step.expiresAt() - now) / 60_000 * 60)))
                    + ". " + AFTERWARDS);
            case REFUSED -> Decision.deny(INSUFFICIENT, why + " " + step.detail()
                    + " Tell the user; calling again with the same arguments starts a new sign-in.");
        };
    }

    /**
     * @param acr the accepted {@code acr} values, any of them; empty when only the age of
     * the login matters
     * @param maxAge how old the login may be, or {@code null} when only the {@code acr}
     * matters
     * @param scope the tools the requirement applies to
     * @param confirm a caller falling short is handed to the human instead of refused
     */
    record Requirement(List<String> acr, Duration maxAge, ToolScope scope, boolean confirm, LoginSettings login) {

        static Requirement from(ProviderConfig config) {
            Duration maxAge = config.readDuration(MAX_AGE);
            if (maxAge != null && (maxAge.isZero() || maxAge.isNegative())) {
                throw ToolScope.invalid(config, MAX_AGE, config.raw(MAX_AGE).orElse(String.valueOf(maxAge)),
                        "a duration above zero, such as 5m");
            }
            List<String> acr = config.readList(ACR).stream().map(String::trim).filter(v -> !v.isEmpty()).toList();
            return new Requirement(acr, maxAge, ToolScope.from(config, LEVELS, TOOLS),
                    "confirm".equals(config.readChoice(ON_MISSING)), LoginSettings.from(config));
        }

        /**
         * The client of this server's own login for a caller, or {@code null} when the
         * login is off or the caller's token names no subject and issuer to bind it to.
         */
        StepUpLogins.LoginClient login(Caller caller) {
            if (login == null || caller == null || caller.subject() == null
                    || !(caller.claim("iss") instanceof String issuer) || issuer.isBlank()) {
                return null;
            }
            return new StepUpLogins.LoginClient(login.issuer() == null ? issuer : login.issuer(), issuer,
                    login.clientId(), login.scope(), login.timeout(), login.validity());
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
            return shortfall(caller.claim("acr"), epochSeconds(caller.claim("auth_time")), nowMillis);
        }

        /**
         * The same for an {@code acr} and an {@code auth_time} (epoch seconds), either
         * possibly missing.
         */
        String shortfall(Object claim, Long authTime, long nowMillis) {
            if (!acr.isEmpty()) {
                if (claim == null) {
                    return "the caller's token has no acr claim";
                }
                if (!acr.contains(String.valueOf(claim))) {
                    return "the caller's token has acr '" + claim + "'";
                }
            }
            if (maxAge != null) {
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

    /**
     * The settings of this server's own login ({@code login=browser} or {@code device}).
     * The client's secret is not among them: the login reads it from the server's
     * settings, so it is never part of the state of a login.
     *
     * @param device the device login instead of the browser one
     * @param issuer the URL the server reaches the provider at, or {@code null} for the
     * issuer of the caller's token
     */
    record LoginSettings(boolean device, String issuer, String clientId, String scope, Duration timeout,
            Duration validity) {

        /** {@code null} when the login is off. */
        static LoginSettings from(ProviderConfig config) {
            String mode = config.readChoice(LOGIN);
            if ("off".equals(mode)) {
                return null;
            }
            String clientId = config.readString(LOGIN_CLIENT_ID);
            if (clientId == null || clientId.isBlank()) {
                throw ToolScope.invalid(config, LOGIN_CLIENT_ID, "",
                        "the client this server signs users in with when login is browser or device");
            }
            Duration timeout = positive(config, LOGIN_TIMEOUT);
            Duration validity = positive(config, LOGIN_VALIDITY);
            String issuer = config.readString(LOGIN_ISSUER);
            return new LoginSettings("device".equals(mode),
                    issuer == null || "caller".equalsIgnoreCase(issuer.trim()) ? null : issuer.trim(), clientId.trim(),
                    config.readString(LOGIN_SCOPE), timeout, validity);
        }

        private static Duration positive(ProviderConfig config, ConfigProperty property) {
            Duration d = config.readDuration(property);
            if (d == null || d.isZero() || d.isNegative()) {
                throw ToolScope.invalid(config, property, config.raw(property).orElse(String.valueOf(d)),
                        "a duration above zero, such as 5m");
            }
            return d;
        }
    }
}
