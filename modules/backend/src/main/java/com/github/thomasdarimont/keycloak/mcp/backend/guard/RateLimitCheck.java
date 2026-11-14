package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStore;
import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStoreMisconfiguredException;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigValueException;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * A brake on runaway callers: at most {@code max} counted calls per caller and Keycloak
 * system within a sliding {@code window}. Which calls count is a matter of their level
 * ({@code levels}) or, when given, their name ({@code tools}). A call over the limit is
 * refused ({@code rate_limited}) or, with {@code on-limit=confirm}, handed to the human,
 * whose own confirmation lets it through; the model's {@code confirm: true} does not.
 * <p>
 * Off unless the server ({@code kc-mcp.spi.access-check.rate-limit.default=on}), a system
 * or a realm asks for it. It runs after the other checks, so only calls they admit are
 * counted; a call over the limit is not counted, so a caller that keeps trying does not
 * lock itself out for longer.
 * <p>
 * The calls are counted in the {@link RateLimitStore}: the database's when the storage is
 * on, so the limit holds for all instances on it together, else this instance's memory.
 * While the store fails the check counts in memory, per instance; a store that is set up
 * wrongly (no grants, no table) refuses the counted calls instead. Callers without an
 * identity (an endpoint without authentication) share one count per system.
 */
@ApplicationScoped
public class RateLimitCheck implements AccessCheck {

    public static final String ID = "rate-limit";

    public static final ConfigProperty MAX = ConfigProperty.integer("max").withDefault("30");

    public static final ConfigProperty WINDOW = ConfigProperty.duration("window").withDefault("10m");

    public static final ConfigProperty LEVELS = ConfigProperty.list("levels").withDefault("write,destructive");

    public static final ConfigProperty TOOLS = ConfigProperty.list("tools");

    public static final ConfigProperty ON_LIMIT = ConfigProperty.choice("on-limit", "deny", "confirm")
        .withDefault("deny");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec.of(MAX, WINDOW, LEVELS, TOOLS, ON_LIMIT);

    private static final Logger LOG = Logger.getLogger(RateLimitCheck.class);

    private static final long WARN_EVERY_MILLIS = Duration.ofMinutes(1).toMillis();

    private final LongSupplier clock;
    private final Supplier<RateLimitStore> selected;
    private volatile RateLimitStore store;

    /** Counts while the selected store cannot: this instance alone, but not nothing. */
    private final InMemoryRateLimitStore local = new InMemoryRateLimitStore();
    private final AtomicLong lastWarned = new AtomicLong();

    @Inject
    public RateLimitCheck(Instance<DefaultExtensionRegistry> registry) {
        // looked up on first use: the registry lists this check among the others
        this(System::currentTimeMillis, () -> registry.isResolvable()
                ? registry.get().extensions(RateLimitStore.class).stream().findFirst().orElse(null) : null);
    }

    /** For tests: a clock in epoch milliseconds and a fixed store. */
    RateLimitCheck(LongSupplier clock, RateLimitStore store) {
        this(clock, () -> store);
    }

    private RateLimitCheck(LongSupplier clock, Supplier<RateLimitStore> selected) {
        this.clock = clock;
        this.selected = selected;
    }

    /**
     * The store the calls are counted in: the selected one, else this instance's memory.
     */
    RateLimitStore store() {
        RateLimitStore s = store;
        if (s == null) {
            s = selected.get();
            if (s == null) {
                s = local;
            }
            store = s;
        }
        return s;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Rate limit";
    }

    @Override
    public String description() {
        return "Limits how many calls a caller may make on a system within a time window.";
    }

    /** After the other checks: only calls they admit are counted. */
    @Override
    public int order() {
        return 3000;
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
            Limit.from(config);
            return List.of();
        }
        catch (ConfigValueException e) {
            return List.of(e.problem());
        }
    }

    @Override
    public Decision check(Context ctx) {
        Limit limit;
        try {
            limit = Limit.from(ctx.settings());
        }
        catch (IllegalArgumentException e) {
            // a limit that does not parse limits nothing: refuse rather than run without
            return Decision.deny("access_check_failed",
                    "The settings of the access check '" + ID + "' for this system are invalid: " + e.getMessage());
        }
        if (!limit.counts(ctx.tool())) {
            return Decision.allow();
        }
        long now = clock.getAsLong();
        long retryAfter;
        try {
            retryAfter = admit(key(ctx.caller(), ctx.system()), now, limit);
        }
        catch (RateLimitStoreMisconfiguredException e) {
            if (warnNow(now)) {
                LOG.errorf("Rate limit store '%s' cannot count, so calls under the rate limit are refused: %s",
                        store().id(), e.getMessage());
            }
            return Decision.deny("access_check_failed",
                    "This server cannot count calls for its rate limit, so it refuses " + ctx.tool().name()
                            + "; nothing was changed. An administrator has to fix the rate limit store (the server"
                            + " log names the problem). Do not retry.");
        }
        if (retryAfter == 0) {
            return Decision.allow();
        }
        String reached = "The limit of " + limit.max() + " " + limit.what() + " calls within "
                + describe(limit.window()) + (ctx.system() == null ? "" : " on system '" + ctx.system() + "'")
                + " is reached";
        if (limit.confirm()) {
            return Decision.confirm("rate_limited", reached + ", so this call needs the user's own confirmation.");
        }
        return Decision.deny("rate_limited",
                reached + ". Stop and tell the user; do not retry right away. The next such call is possible in about "
                        + describe(Duration.ofSeconds(Math.max(1, (retryAfter + 999) / 1000))) + ".");
    }

    /**
     * Counts the call if the limit has room for it, in the store or, while that fails, in
     * this instance's memory: a database that is away loosens the limit to one per
     * instance instead of lifting it or stopping every counted call. A store that is set
     * up wrongly is not bridged.
     *
     * @return {@code 0} when the call was counted, otherwise the milliseconds until the
     * oldest call in the window leaves it
     * @throws RateLimitStoreMisconfiguredException when the store cannot count until
     * someone fixes it
     */
    private long admit(String key, long now, Limit limit) {
        RateLimitStore counted = store();
        try {
            return counted.admit(key, now, limit.max(), limit.window().toMillis());
        }
        catch (RateLimitStoreMisconfiguredException e) {
            throw e; // will not pass: refuse rather than count somewhere else
        }
        catch (RuntimeException e) {
            if (warnNow(now)) {
                LOG.warnf(e, "Rate limit store '%s' failed, counting in this instance's memory meanwhile: %s",
                        counted.id(), e.getMessage());
            }
            return local.admit(key, now, limit.max(), limit.window().toMillis());
        }
    }

    /** Whether a store failure is logged now: at most once a minute. */
    private boolean warnNow(long now) {
        long last = lastWarned.get();
        return now - last >= WARN_EVERY_MILLIS && lastWarned.compareAndSet(last, now);
    }

    private static String key(Caller caller, String system) {
        String who = caller == null || caller.isAnonymous() ? "anonymous"
                : "user:" + caller.realm() + "/" + caller.subject();
        return who + "@" + (system == null ? "" : system);
    }

    static String describe(Duration d) {
        long s = d.toSeconds();
        if (s % 3600 == 0) {
            return s / 3600 + " h";
        }
        return s % 60 == 0 ? s / 60 + " min" : s + " s";
    }

    /**
     * @param tools the tools that count, by full or short name; when empty the
     * {@code levels} decide
     * @param confirm over the limit the human is asked instead of the call being refused
     */
    record Limit(int max, Duration window, Set<ToolLevel> levels, Set<String> tools, boolean confirm) {

        static Limit from(ProviderConfig config) {
            int max = config.readInt(MAX);
            if (max < 1) {
                throw invalid(config, MAX, String.valueOf(max), "a whole number from 1");
            }
            Duration window = config.readDuration(WINDOW);
            if (window.isZero() || window.isNegative() || window.toMillis() > RateLimitStore.MAX_WINDOW_MILLIS) {
                throw invalid(config, WINDOW, config.raw(WINDOW).orElse(String.valueOf(window)),
                        "a duration of at most 24h, such as 10m or 1h");
            }
            Set<ToolLevel> levels = EnumSet.noneOf(ToolLevel.class);
            for (String level : config.readList(LEVELS)) {
                try {
                    levels.add(ToolLevel.valueOf(level.trim().toUpperCase(Locale.ROOT)));
                }
                catch (IllegalArgumentException e) {
                    throw invalid(config, LEVELS, level, "read, write or destructive, comma separated");
                }
            }
            Set<String> tools = config.readList(TOOLS)
                .stream()
                .map(AccessPolicy::shortName)
                .collect(Collectors.toUnmodifiableSet());
            return new Limit(max, window, levels, tools, "confirm".equals(config.readChoice(ON_LIMIT)));
        }

        boolean counts(ToolSpec tool) {
            return tools.isEmpty() ? levels.contains(tool.level())
                    : tools.contains(AccessPolicy.shortName(tool.name()));
        }

        /** What is counted, for the message: "write or destructive", "listed". */
        String what() {
            return !tools.isEmpty() ? "listed"
                    : levels.stream().map(l -> l.name().toLowerCase(Locale.ROOT)).collect(Collectors.joining(" or "));
        }

        private static ConfigValueException invalid(ProviderConfig config, ConfigProperty property, String value,
                String expected) {
            String key = config.key(property.name());
            return new ConfigValueException(ConfigProblem
                .error(ConfigProblem.INVALID_VALUE, key + " must be " + expected + ", not '" + value + "'",
                        property.name())
                .withArg("key", key)
                .withArg("name", property.name())
                .withArg("type", property.type().name())
                .withArg("expected", expected)
                .withArg("value", value));
        }
    }
}
