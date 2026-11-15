package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheckSpi;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.CheckSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * Which global access checks run for a call, in which order, with which settings. Per
 * check the server's entry ({@code kc-mcp.spi.access-check.<id>.*}: {@code default}
 * whether it runs where nothing says otherwise, {@code order}, its settings) with the
 * system's and the realm's {@code access.<id>} entry over it; a check the operator
 * {@code locked} keeps the server's entry. The checks run that are switched on, lowest
 * {@code order} first, then by id. Entries for checks the server does not have are
 * {@link Plan#missing()}: the calls they would govern are refused.
 */
public final class AccessCheckChain {

    private static final Logger LOG = Logger.getLogger(AccessCheckChain.class);

    /**
     * Problem code: a setting with a placeholder that does not exist or a brace without
     * end; args {@code key}, {@code error}.
     */
    public static final String INVALID_PLACEHOLDER = "access-check.invalid-placeholder";

    /** Server settings that are about the check's place, not passed to it. */
    static final Set<String> META = Set.of("enabled", "default", "order", "locked", "required", "provider");

    /**
     * In a step's settings: present when the system or realm switched the check on (or
     * off) itself.
     */
    public static final String ENABLED = "enabled";

    /**
     * One check to run, with its effective settings, placeholders resolved.
     *
     * @param error why the settings cannot be used (a placeholder without a value); empty
     * when they can: a step with an error refuses the call
     */
    public record Step(AccessCheck check, ProviderConfig settings, int order, Optional<String> error) {

        public Step(AccessCheck check, ProviderConfig settings, int order) {
            this(check, settings, order, Optional.empty());
        }
    }

    /**
     * @param steps the checks to run, in order
     * @param missing ids the block switches on (or leaves on) that the server has no
     * check for
     */
    public record Plan(List<Step> steps, Set<String> missing) {
    }

    private record Known(AccessCheck check, CheckSettings server, boolean locked) {
    }

    private final Map<String, Known> known = new LinkedHashMap<>();

    /**
     * @param checks the global checks the server has (installed, switched on, supported)
     * @param serverConfig the server's settings of a check, by id
     */
    public AccessCheckChain(List<AccessCheck> checks, Function<String, ProviderConfig> serverConfig) {
        for (AccessCheck c : checks) {
            String id = ProviderConfig.configId(c.id());
            if (known.containsKey(id)) {
                continue;
            }
            ProviderConfig cfg = serverConfig == null ? new ProviderConfig(AccessCheckSpi.NAME, id, Map.of())
                    : serverConfig.apply(id);
            if (!cfg.getBoolean("enabled", true)) {
                // removed from the server, whoever contributed it
                continue;
            }
            List<ConfigProblem> errors = report(c, cfg.withSpec(c.configSpec()), cfg.keys());
            if (!errors.isEmpty()) {
                throw new IllegalStateException(
                        "Access check '" + c.id() + "' is misconfigured: " + ConfigProblem.describe(errors));
            }
            known.put(id, new Known(c, server(c, cfg), cfg.getBoolean("locked", false)));
        }
    }

    /**
     * {@link #problems}, logging the warnings about keys among {@code written}.
     *
     * @return the errors
     */
    private static List<ConfigProblem> report(AccessCheck check, ProviderConfig settings, Set<String> written) {
        List<ConfigProblem> problems = problems(check, settings);
        problems.stream()
            .filter(p -> !p.isError() && p.properties().stream().anyMatch(written::contains))
            .forEach(p -> LOG.warnf("Access check '%s': %s", check.id(), p.message()));
        return ConfigProblem.errors(problems);
    }

    /**
     * What is wrong with a check's settings, placeholders filled with sample values
     * (their real values are known per call only): the spec's checks, then the check's
     * own rules. Nothing when the check declares nothing.
     *
     * @param settings the check's settings with its spec
     */
    public static List<ConfigProblem> problems(AccessCheck check, ProviderConfig settings) {
        if (settings.spec().isEmpty()) {
            return List.of();
        }
        Placeholders sample = new Placeholders(null, "x", r -> Optional.of("x"));
        Map<String, String> resolved = new LinkedHashMap<>();
        List<ConfigProblem> problems = new ArrayList<>();
        settings.asMap().forEach((k, v) -> {
            try {
                resolved.put(k, sample.resolve(v));
            }
            catch (IllegalArgumentException e) {
                // the message repeats the value: not for a confidential or undeclared one
                ConfigProperty declared = settings.declared().get(k);
                String error = declared != null && !declared.confidential() ? e.getMessage()
                        : "a placeholder is malformed or unknown";
                problems.add(ConfigProblem.error(INVALID_PLACEHOLDER, settings.key(k) + ": " + error, k)
                    .withArg("key", settings.key(k))
                    .withArg("error", error));
            }
        });
        problems.addAll(settings.withValues(resolved).problems(check));
        return problems;
    }

    private static CheckSettings server(AccessCheck c, ProviderConfig cfg) {
        String where = ProviderConfig.PREFIX + AccessCheckSpi.NAME + "." + ProviderConfig.configId(c.id()) + ".";
        String mode = cfg.get("default", c.enabledByDefault() ? "on" : "off").trim().toLowerCase(Locale.ROOT);
        boolean on = switch (mode) {
            case "on", "true" -> true;
            case "off", "false" -> false;
            default -> throw new IllegalStateException(where + "default must be on or off, not '" + mode + "'");
        };
        int order;
        try {
            order = cfg.get("order").map(v -> Integer.parseInt(v.trim())).orElse(c.order());
        }
        catch (NumberFormatException e) {
            throw new IllegalStateException(where + "order must be a whole number", e);
        }
        Map<String, String> settings = new LinkedHashMap<>();
        cfg.asMap().forEach((k, v) -> {
            if (!META.contains(k)) {
                settings.put(k, v);
            }
        });
        return new CheckSettings(Optional.of(on), Optional.of(order), settings);
    }

    /** The ids of the checks the server has. */
    public Set<String> ids() {
        return new TreeSet<>(known.keySet());
    }

    public boolean locked(String id) {
        Known k = known.get(ProviderConfig.configId(id));
        return k != null && k.locked();
    }

    /**
     * The plan of a call into a realm of a system ({@code system} {@code null}: the
     * server's settings alone).
     */
    public Plan plan(KeycloakSystem system, String realm) {
        return plan(system, realm, r -> Optional.empty());
    }

    /**
     * @param realmIds Keycloak's id of a realm, for {@code {realm.id}} when the realm's
     * settings do not hold it; asked only when a setting needs it
     */
    public Plan plan(KeycloakSystem system, String realm, Function<String, Optional<String>> realmIds) {
        Placeholders values = new Placeholders(system, realm, realmIds);
        AccessSettings block = system == null ? AccessSettings.NONE : system.access(realm);
        List<Step> steps = new ArrayList<>();
        for (Map.Entry<String, Known> e : known.entrySet()) {
            Known k = e.getValue();
            CheckSettings own = k.locked() ? CheckSettings.NONE : block.check(e.getKey());
            CheckSettings effective = k.server().overlay(own);
            if (!effective.enabled().orElse(true)) {
                continue;
            }
            Map<String, String> settings = new LinkedHashMap<>(effective.settings());
            // a system or realm that switched the check on says so, for checks that tell
            // "asked for here" from "on by the server's default" (the authorization
            // check)
            own.enabled().ifPresent(on -> settings.put(ENABLED, String.valueOf(on)));
            Optional<String> error = Optional.empty();
            try {
                settings.replaceAll((key, value) -> values.resolve(value));
            }
            catch (IllegalArgumentException ex) {
                error = Optional.of("access." + e.getKey() + ": " + ex.getMessage());
            }
            steps.add(new Step(k.check(),
                    new ProviderConfig(AccessCheckSpi.NAME, e.getKey(), settings, k.check().configSpec()),
                    effective.order().orElse(k.check().order()), error));
        }
        steps.sort(Comparator.comparingInt(Step::order).thenComparing(s -> ProviderConfig.configId(s.check().id())));
        Set<String> missing = new TreeSet<>();
        block.checks().forEach((id, entry) -> {
            if (!known.containsKey(id) && entry.enabled().orElse(true)) {
                missing.add(id);
            }
        });
        return new Plan(List.copyOf(steps), missing);
    }

    /**
     * What a block may not ask for: an entry for a check the server does not have, or for
     * one the operator locked.
     *
     * @param where the block's path, for the message
     * @throws IllegalArgumentException with what is wrong
     */
    public void validate(AccessSettings block, String where) {
        for (Map.Entry<String, CheckSettings> e : block.checks().entrySet()) {
            if (!known.containsKey(e.getKey())) {
                if (e.getValue().enabled().orElse(true)) {
                    throw new IllegalArgumentException(where + e.getKey() + ": this server has no access check '"
                            + e.getKey() + "'; it has " + ids());
                }
            }
            else if (known.get(e.getKey()).locked()) {
                throw new IllegalArgumentException(where + e.getKey() + ": the access check '" + e.getKey()
                        + "' is locked by the server (" + ProviderConfig.PREFIX + AccessCheckSpi.NAME + "." + e.getKey()
                        + ".locked=true); systems and realms cannot change it");
            }
            else {
                Known k = known.get(e.getKey());
                // the block over the server's settings: a value may need another to make
                // sense, and the block names only what differs
                ProviderConfig effective = new ProviderConfig(AccessCheckSpi.NAME, e.getKey(),
                        k.server().overlay(e.getValue()).settings(), k.check().configSpec())
                    .describedAs(where + e.getKey() + ".");
                List<ConfigProblem> errors = report(k.check(), effective, e.getValue().settings().keySet());
                if (!errors.isEmpty()) {
                    throw new IllegalArgumentException(ConfigProblem.describe(errors));
                }
            }
        }
    }

    /**
     * The placeholders of settings: {@code {realm.name}}, {@code {realm.id}},
     * {@code {realm.displayName}}, {@code {system.name}}, and {@code {realm}} and
     * {@code {system}} for the names; {@code {{} is a literal brace. A global tool has no
     * realm: {@code _} stands for its name and id. In a setting that is a URL the values
     * are percent-encoded, so that a name cannot leave its place in the URL. A
     * placeholder without a value, or an unknown one, makes the setting unusable.
     */
    static final class Placeholders {

        private final KeycloakSystem system;
        private final String realm;
        private final Function<String, Optional<String>> realmIds;
        private Optional<String> realmId;

        Placeholders(KeycloakSystem system, String realm, Function<String, Optional<String>> realmIds) {
            this.system = system;
            this.realm = realm;
            this.realmIds = realmIds;
        }

        String resolve(String value) {
            if (value.indexOf('{') < 0) {
                return value;
            }
            boolean url = value.startsWith("http://") || value.startsWith("https://");
            StringBuilder out = new StringBuilder();
            int i = 0;
            while (i < value.length()) {
                char c = value.charAt(i);
                if (c == '{' && i + 1 < value.length() && value.charAt(i + 1) == '{') {
                    out.append('{');
                    i += 2;
                    continue;
                }
                if (c != '{') {
                    out.append(c);
                    i++;
                    continue;
                }
                int end = value.indexOf('}', i);
                if (end < 0) {
                    throw new IllegalArgumentException(
                            "'" + value + "' has a '{' without '}' (a literal brace is '{{')");
                }
                String name = value.substring(i + 1, end).trim();
                String v = value(name);
                out.append(
                        url ? java.net.URLEncoder.encode(v, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20")
                                : v);
                i = end + 1;
            }
            return out.toString();
        }

        private String value(String name) {
            return switch (name) {
                case "realm", "realm.name" -> realm == null ? "_" : realm;
                case "realm.id" -> realm == null ? "_" : realmId().orElseThrow(() -> new IllegalArgumentException(
                        "{realm.id}: Keycloak's id of realm '" + realm + "' is not known"));
                case "realm.displayName", "realm.display-name" ->
                    realmSettings().flatMap(RealmSettings::displayName).orElse(realm == null ? "_" : realm);
                case "system", "system.name" -> system == null ? "_" : system.name();
                default ->
                    throw new IllegalArgumentException("{" + name + "} is not a placeholder; known: {realm.name},"
                            + " {realm.id}, {realm.displayName}, {system.name}");
            };
        }

        private Optional<RealmSettings> realmSettings() {
            return system == null || realm == null ? Optional.empty() : Optional.ofNullable(system.realms().get(realm));
        }

        private Optional<String> realmId() {
            if (realmId == null) {
                realmId = realmSettings().flatMap(RealmSettings::realmId).or(() -> realmIds.apply(realm));
            }
            return realmId;
        }
    }
}
