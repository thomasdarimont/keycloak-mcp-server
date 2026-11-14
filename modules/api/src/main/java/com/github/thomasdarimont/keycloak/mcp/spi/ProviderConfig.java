package com.github.thomasdarimont.keycloak.mcp.spi;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy;
import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStore;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenRequestCustomizer;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKeyGenerator;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

/**
 * Read-only view on {@code kc-mcp.spi.<spi>.<id>.*}. Keys are relative and
 * single-segment, e.g. {@code get("page-size")} reads
 * {@code kc-mcp.spi.<spi>.<id>.page-size} / {@code KC_MCP_SPI_<SPI>_<ID>_PAGE_SIZE}. The
 * id is used in kebab-case, as Keycloak does with its provider ids:
 * {@code acmeTicketChecker} is configured as
 * {@code kc-mcp.spi.access-check.acme-ticket-checker.*} /
 * {@code KC_MCP_SPI_ACCESS_CHECK_ACME_TICKET_CHECKER_*}; see {@link #configId(String)}.
 * <p>
 * Settings the extension declares ({@link Extension#configSpec()}) are best read with
 * {@link #readString(ConfigProperty)}, {@link #readInt(ConfigProperty)} and their
 * siblings, which apply the declared default and parse by the declared type;
 * {@link #problems()} checks the settings against the spec, {@link #problems(Extension)}
 * with the extension's own rules. {@link #toString()} shows only declared,
 * non-confidential values.
 */
public final class ProviderConfig {

    public static final String PREFIX = "kc-mcp.spi.";

    private static final Pattern CAMEL = Pattern.compile("([a-z0-9])([A-Z])");
    private static final Pattern ACRONYM = Pattern.compile("([A-Z]+)([A-Z][a-z])");
    private static final Pattern SEPARATORS = Pattern.compile("[^a-z0-9]+");

    /** The names of the extension points, the first segment after {@link #PREFIX}. */
    public static final Set<String> SPIS = Set.of(ToolProvider.SPI, PromptProvider.SPI, Confirmer.SPI, AccessCheck.SPI,
            AuthorizationEngine.SPI, AuthZenRequestCustomizer.SPI, CallerIssuerPolicy.SPI, AuditListener.SPI,
            AuditScrubber.SPI, ProfileCheck.SPI, PendingApprovalStore.SPI, RateLimitStore.SPI,
            KeycloakSystemRepository.SPI, KeyVault.SPI, SigningKeyGenerator.SPI, UserSessionStore.SPI);

    /**
     * Settings every extension has, handled by the server: {@code enabled} and
     * {@code required}.
     */
    public static final Set<String> RESERVED_KEYS = Set.of("enabled", "required");

    /**
     * Settings the server handles for every access check besides {@link #RESERVED_KEYS}:
     * {@code default}, {@code order}, {@code locked}.
     */
    public static final Set<String> ACCESS_CHECK_KEYS = Set.of("default", "order", "locked");

    /** The extension points served by exactly one extension. */
    public static final Set<String> SINGLE_PROVIDER_SPIS = Set.of(KeyVault.SPI, SigningKeyGenerator.SPI,
            UserSessionStore.SPI, PendingApprovalStore.SPI, RateLimitStore.SPI);

    private final String spi;
    private final String providerId;
    private final Map<String, String> values;
    private final ConfigSpec spec;
    private final Map<String, ConfigProperty> declared;
    /**
     * Where the settings are written, for messages; {@code null}:
     * {@link #providerPrefix()}.
     */
    private final String shownPrefix;

    /** Settings of an extension point's extension. */
    public ProviderConfig(String spi, String providerId, Map<String, String> values) {
        this(spi, providerId, values, ConfigSpec.EMPTY);
    }

    /** Settings of an extension point's extension, with the extension's spec. */
    public ProviderConfig(String spi, String providerId, Map<String, String> values, ConfigSpec spec) {
        this(spi, providerId, values, spec, null);
    }

    /** Settings of an extension point's extension, with these declared properties. */
    public ProviderConfig(String spi, String providerId, Map<String, String> values, List<ConfigProperty> declared) {
        this(spi, providerId, values, ConfigSpec.of(declared), null);
    }

    private ProviderConfig(String spi, String providerId, Map<String, String> values, ConfigSpec spec,
            String shownPrefix) {
        this.shownPrefix = shownPrefix;
        this.spi = spi;
        this.providerId = configId(providerId);
        this.values = values == null ? Map.of() : Map.copyOf(values);
        this.spec = spec == null ? ConfigSpec.EMPTY : spec;
        Map<String, ConfigProperty> byName = new LinkedHashMap<>();
        this.spec.properties().forEach(p -> byName.put(p.name(), p));
        this.declared = Collections.unmodifiableMap(byName);
    }

    /** Settings with a spec, without an extension point, for tests. */
    public ProviderConfig(String providerId, Map<String, String> values, ConfigSpec spec) {
        this(null, providerId, values, spec);
    }

    /** Settings with declared properties, without an extension point, for tests. */
    public ProviderConfig(String providerId, Map<String, String> values, List<ConfigProperty> declared) {
        this(null, providerId, values, declared);
    }

    /** Settings without an extension point, for tests of an extension's own logic. */
    public ProviderConfig(String providerId, Map<String, String> values) {
        this(null, providerId, values);
    }

    /** The settings of an extension. */
    public static ProviderConfig forExtension(Extension extension, McpServerConfig config) {
        return forExtension(extension.spiName(), extension.id(), extension.configSpec(), config);
    }

    /** The settings of an extension, with the process environment. */
    public static ProviderConfig forExtension(String spi, String extensionId, McpServerConfig config) {
        return forExtension(spi, extensionId, ConfigSpec.EMPTY, config);
    }

    /** The settings of an extension with this spec, with the process environment. */
    public static ProviderConfig forExtension(String spi, String extensionId, ConfigSpec declared,
            McpServerConfig config) {
        Map<String, Map<String, Map<String, String>>> spis = new LinkedHashMap<>();
        config.spi().forEach((name, settings) -> spis.put(name, settings.extensions()));
        return forExtension(spi, extensionId, spis, System.getenv(), declared);
    }

    /**
     * The id named by {@code kc-mcp.spi.<spi>.provider} /
     * {@code KC_MCP_SPI_<SPI>_PROVIDER}; a system property (the command line) comes
     * first, as everywhere in the configuration.
     */
    public static Optional<String> selectedProvider(String spi, McpServerConfig config, Map<String, String> env) {
        return Optional.ofNullable(System.getProperty(PREFIX + spi + ".provider"))
            .or(() -> Optional.ofNullable(env.get(providerVariable(spi))))
            .or(() -> Optional.ofNullable(config.spi().get(spi)).flatMap(McpServerConfig.Spi::provider))
            .filter(v -> !v.isBlank())
            .map(String::trim);
    }

    /** {@code KC_MCP_SPI_<SPI>_PROVIDER} */
    public static String providerVariable(String spi) {
        return new ProviderConfig(null, spi, Map.of()).envPrefix() + "PROVIDER";
    }

    /**
     * The settings of an extension: the {@code kc-mcp.spi} entry under the extension
     * point and the kebab-case id (else the id as written), with environment variables
     * {@code KC_MCP_SPI_<SPI>_<ID>_<KEY>} on top. The variables are read here because the
     * config mapping cannot tell {@code AUTH_FLOWS} from {@code AUTH.FLOWS} in a map key;
     * with extension point and id known, the remainder is the key ({@code _} ->
     * {@code -}, lowercase). System properties, which is what the command line sets, go
     * above the variables, as everywhere in the configuration.
     * @param env the environment to read the variables from
     */
    public static ProviderConfig forExtension(String spi, String extensionId,
            Map<String, Map<String, Map<String, String>>> spis, Map<String, String> env) {
        return forExtension(spi, extensionId, spis, env, ConfigSpec.EMPTY);
    }

    /**
     * {@link #forExtension(String, String, Map, Map)} for an extension with this spec: a
     * variable whose remainder matches a declared name apart from case and separators
     * gets that name, so {@code _PAGE_SIZE} reads {@code page-size} and {@code _PDP_URL}
     * reads {@code pdp.url} when that is what is declared.
     */
    public static ProviderConfig forExtension(String spi, String extensionId,
            Map<String, Map<String, Map<String, String>>> spis, Map<String, String> env, ConfigSpec declared) {
        Map<String, String> declaredByVariable = new LinkedHashMap<>();
        for (ConfigProperty p : declared == null ? List.<ConfigProperty>of() : declared.properties()) {
            declaredByVariable.put(variableForm(p.name()), p.name());
        }
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Map<String, String>> ofSpi = spis == null ? null : spis.get(spi);
        if (ofSpi != null) {
            Map<String, String> entry = ofSpi.get(configId(extensionId));
            if (entry == null) {
                entry = ofSpi.get(extensionId);
            }
            if (entry != null) {
                values.putAll(entry);
            }
        }
        String prefix = new ProviderConfig(spi, extensionId, Map.of()).envPrefix();
        if (env != null) {
            for (Map.Entry<String, String> e : env.entrySet()) {
                if (e.getKey().startsWith(prefix) && e.getKey().length() > prefix.length()) {
                    String rest = e.getKey().substring(prefix.length());
                    String key = declaredByVariable.getOrDefault(variableForm(rest),
                            rest.toLowerCase(Locale.ROOT).replace('_', '-'));
                    values.put(key, e.getValue());
                }
            }
        }
        putSystemProperties(values, PREFIX + spi + "." + extensionId + ".");
        putSystemProperties(values, PREFIX + spi + "." + configId(extensionId) + ".");
        return new ProviderConfig(spi, extensionId, values, declared);
    }

    /** A key as an environment variable can write it: lowercase letters and digits. */
    private static String variableForm(String key) {
        return key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static void putSystemProperties(Map<String, String> values, String prefix) {
        for (String name : System.getProperties().stringPropertyNames()) {
            if (name.startsWith(prefix) && name.length() > prefix.length()) {
                values.put(name.substring(prefix.length()), System.getProperty(name));
            }
        }
    }

    /**
     * The id as it appears in configuration keys: camelCase split at the humps, every run
     * of other separators ({@code .}, {@code _}, {@code $}, blanks) a single {@code -},
     * all lowercase. {@code acmeTicketChecker} and {@code acme_ticket_checker} both give
     * {@code acme-ticket-checker}; the class-name default id
     * {@code com.acme.TicketChecker} gives {@code com-acme-ticket-checker}.
     */
    public static String configId(String id) {
        String s = ACRONYM.matcher(id.trim()).replaceAll("$1-$2");
        s = CAMEL.matcher(s).replaceAll("$1-$2").toLowerCase(Locale.ROOT);
        s = SEPARATORS.matcher(s).replaceAll("-");
        return s.replaceAll("^-+|-+$", "");
    }

    /** {@code kc-mcp.spi.<spi>.<config id>.} */
    public String providerPrefix() {
        return PREFIX + (spi == null ? "" : spi + ".") + providerId + ".";
    }

    /** {@code KC_MCP_SPI_<SPI>_<CONFIG_ID>_} */
    public String envPrefix() {
        return providerPrefix().toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_');
    }

    public Optional<String> get(String key) {
        return Optional.ofNullable(values.get(key)).filter(v -> !v.isBlank());
    }

    public String get(String key, String defaultValue) {
        return get(key).orElse(defaultValue);
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        return get(key).map(v -> v.trim().equalsIgnoreCase("true")).orElse(defaultValue);
    }

    public int getInt(String key, int defaultValue) {
        return get(key).map(v -> Integer.parseInt(v.trim())).orElse(defaultValue);
    }

    /** The extension's spec; {@link ConfigSpec#EMPTY} when it declares nothing. */
    public ConfigSpec spec() {
        return spec;
    }

    /** The properties the extension declares, by name, in declaration order. */
    public Map<String, ConfigProperty> declared() {
        return declared;
    }

    /**
     * The full key of a setting, as messages name it:
     * {@code kc-mcp.spi.<spi>.<id>.<name>}, or under the prefix of {@link #describedAs}.
     */
    public String key(String name) {
        return (shownPrefix != null ? shownPrefix : providerPrefix()) + name;
    }

    /**
     * These settings with messages naming them under another prefix, where they were
     * written: {@code kc-mcp.systems.<name>.authorization.authzen.} for a system's
     * settings merged over the server's.
     */
    public ProviderConfig describedAs(String prefix) {
        return new ProviderConfig(spi, providerId, values, spec, prefix);
    }

    /** The setting as written, else the declared default. */
    public Optional<String> raw(ConfigProperty property) {
        return get(property.name()).or(() -> Optional.ofNullable(property.defaultValue()));
    }

    /** Whether the setting is written (not blank); a default does not count. */
    public boolean isSet(ConfigProperty property) {
        return get(property.name()).isPresent();
    }

    /**
     * Any type, as written (trimmed for every type but STRING), {@code null} if absent.
     */
    public String readString(ConfigProperty property) {
        return raw(property).map(v -> property.type() == ConfigProperty.Type.STRING ? v : v.trim()).orElse(null);
    }

    public boolean readBoolean(ConfigProperty property) {
        return (Boolean) parsed(property, ConfigProperty.Type.BOOLEAN);
    }

    public int readInt(ConfigProperty property) {
        long v = readLong(property);
        if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
            throw new ConfigValueException(ConfigProblem
                .error(ConfigProblem.INVALID_VALUE,
                        key(property.name()) + " is out of range: " + property.display(v + ""), property.name())
                .withArg("key", key(property.name()))
                .withArg("name", property.name())
                .withArg("type", property.type().name())
                .withArg("expected", "a whole number from " + Integer.MIN_VALUE + " to " + Integer.MAX_VALUE)
                .withArg("value", property.confidential() ? null : v + ""));
        }
        return (int) v;
    }

    public long readLong(ConfigProperty property) {
        return (Long) parsed(property, ConfigProperty.Type.INT);
    }

    /** A NUMBER, or an INT as a double. */
    public double readNumber(ConfigProperty property) {
        Object v = parsed(property, ConfigProperty.Type.NUMBER, ConfigProperty.Type.INT);
        return ((Number) v).doubleValue();
    }

    /** {@code null} if absent and without default. */
    public Duration readDuration(ConfigProperty property) {
        return (Duration) optionalParsed(property, ConfigProperty.Type.DURATION);
    }

    /** {@code null} if absent and without default. */
    public URI readUrl(ConfigProperty property) {
        return (URI) optionalParsed(property, ConfigProperty.Type.URL);
    }

    /** Empty if absent and without default. */
    @SuppressWarnings("unchecked")
    public List<String> readList(ConfigProperty property) {
        Object v = optionalParsed(property, ConfigProperty.Type.LIST);
        return v == null ? List.of() : (List<String>) v;
    }

    /** The option as declared, {@code null} if absent and without default. */
    public String readChoice(ConfigProperty property) {
        return (String) optionalParsed(property, ConfigProperty.Type.CHOICE);
    }

    /**
     * The constant whose name matches the chosen option, case-insensitive and with
     * {@code -} for {@code _}; {@code null} if absent and without default.
     */
    public <E extends Enum<E>> E readEnum(ConfigProperty property, Class<E> type) {
        String option = readChoice(property);
        if (option == null) {
            return null;
        }
        String name = option.replace('-', '_');
        for (E e : type.getEnumConstants()) {
            if (e.name().equalsIgnoreCase(name)) {
                return e;
            }
        }
        throw new IllegalStateException(
                "Option '" + option + "' of " + key(property.name()) + " has no constant in " + type.getName());
    }

    /**
     * {@code JsonObject}, {@code JsonArray}, a scalar or {@code null}; {@code null} also
     * if absent and without default.
     */
    public Object readJson(ConfigProperty property) {
        return optionalParsed(property, ConfigProperty.Type.JSON);
    }

    private Object parsed(ConfigProperty property, ConfigProperty.Type... types) {
        Object v = optionalParsed(property, types);
        if (v == null) {
            throw new IllegalStateException(key(property.name()) + " has no value and no default");
        }
        return v;
    }

    private Object optionalParsed(ConfigProperty property, ConfigProperty.Type... types) {
        if (!List.of(types).contains(property.type())) {
            throw new IllegalStateException(
                    key(property.name()) + " is declared as " + property.type() + ", not read as " + List.of(types));
        }
        return raw(property).map(v -> property.parse(v, key(property.name()))).orElse(null);
    }

    /**
     * What is wrong with the settings as declared: errors for a malformed value and for a
     * missing required one (required while its {@link ConfigHint.AppliesWhen conditions}
     * hold), warnings for keys the extension does not declare. Empty when the extension
     * declares nothing; confidential values are not repeated.
     */
    public List<ConfigProblem> problems() {
        List<ConfigProblem> problems = new ArrayList<>();
        for (ConfigProperty p : declared.values()) {
            Optional<String> v = raw(p);
            if (v.isEmpty()) {
                List<ConfigHint.AppliesWhen> conditions = spec.conditions(p.name());
                if (p.required() && conditions.stream().allMatch(c -> c.holds(this))) {
                    String when = conditions.isEmpty() ? null
                            : String.join(" and ", conditions.stream().map(ConfigHint.AppliesWhen::describe).toList());
                    problems.add(ConfigProblem
                        .error(ConfigProblem.REQUIRED,
                                key(p.name()) + " is required" + (when == null ? "" : " when " + when), p.name())
                        .withArg("key", key(p.name()))
                        .withArg("name", p.name())
                        .withArg("conditions", when));
                }
                continue;
            }
            try {
                p.parse(v.get(), key(p.name()));
            }
            catch (ConfigValueException e) {
                problems.add(e.problem());
            }
        }
        for (String k : unknownKeys()) {
            problems
                .add(ConfigProblem
                    .warning(ConfigProblem.UNKNOWN_KEY,
                            key(k) + " is not a setting of this extension and is ignored; it reads "
                                    + declared.keySet(),
                            k)
                    .withArg("key", key(k))
                    .withArg("known", String.join(",", declared.keySet())));
        }
        return problems;
    }

    /**
     * {@link #problems()}, then, if there are no errors among them, the extension's own
     * rules ({@link Extension#validate}); one that throws counts as an error
     * ({@link ConfigValueException}: its problem; else
     * {@link ConfigProblem#VALIDATION_FAILED}).
     */
    public List<ConfigProblem> problems(Extension extension) {
        List<ConfigProblem> problems = new ArrayList<>(problems());
        if (ConfigProblem.errors(problems).isEmpty()) {
            try {
                problems.addAll(extension.validate(this));
            }
            catch (ConfigValueException e) {
                problems.add(e.problem());
            }
            catch (RuntimeException e) {
                problems.add(ConfigProblem.error(ConfigProblem.VALIDATION_FAILED, String.valueOf(e.getMessage()))
                    .withArg("error", String.valueOf(e.getMessage())));
            }
        }
        return problems;
    }

    /**
     * The settings that are written but not declared, minus the {@link #reserved} ones;
     * empty when the extension declares nothing, as then nothing can be told apart.
     */
    public Set<String> unknownKeys() {
        if (declared.isEmpty()) {
            return Set.of();
        }
        return values.keySet()
            .stream()
            .filter(k -> !declared.containsKey(k) && !reserved(k))
            .collect(Collectors.toCollection(TreeSet::new));
    }

    /**
     * The settings as they may be shown, by key: declared values as written, confidential
     * ones {@link ConfigProperty#MASK masked}, undeclared ones masked as well, since
     * nothing says they are harmless.
     */
    public Map<String, String> display() {
        Map<String, String> shown = new TreeMap<>();
        values.forEach((k, v) -> {
            ConfigProperty p = declared.get(k);
            shown.put(k, p != null ? p.display(v) : reserved(k) ? v : ConfigProperty.MASK);
        });
        return shown;
    }

    /**
     * Whether the server handles the key itself: {@link #RESERVED_KEYS}, and
     * {@link #ACCESS_CHECK_KEYS} under {@code access-check}.
     */
    public boolean reserved(String key) {
        return RESERVED_KEYS.contains(key) || (AccessCheck.SPI.equals(spi) && ACCESS_CHECK_KEYS.contains(key));
    }

    /** These settings with other values, the same declaration. */
    public ProviderConfig withValues(Map<String, String> other) {
        return new ProviderConfig(spi, providerId, other, spec, shownPrefix);
    }

    /** These settings checked against another spec. */
    public ProviderConfig withSpec(ConfigSpec other) {
        return new ProviderConfig(spi, providerId, values, other, shownPrefix);
    }

    /** {@code kc-mcp.spi.<spi>.<id>.{key=value, ...}} with {@link #display()}. */
    @Override
    public String toString() {
        return providerPrefix() + display();
    }

    public Set<String> keys() {
        return new TreeSet<>(values.keySet());
    }

    public Map<String, String> asMap() {
        return values;
    }
}
