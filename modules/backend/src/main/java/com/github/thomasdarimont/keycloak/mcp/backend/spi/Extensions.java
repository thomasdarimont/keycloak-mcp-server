package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheckSpi;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;
import com.github.thomasdarimont.keycloak.mcp.spi.Spis;

import io.quarkus.runtime.ShutdownEvent;

/**
 * Finds the implementations of an extension point ({@code ToolProvider},
 * {@code PromptProvider}, {@code AccessCheck}, {@code Confirmer}, {@code AuditListener}):
 * ServiceLoader entries on the class path and in the jars of the providers directory
 * ({@code kc-mcp.providers-dir}, like Keycloak's {@code providers/}), then CDI beans. A
 * class seen on both paths counts once.
 * <p>
 * The providers directory is read once at startup; a relative path is resolved against
 * the directory of the application jar ({@code quarkus-run.jar}) when the server runs
 * packaged, otherwise against the working directory. Jars found there are loaded by a
 * class loader whose parent is the application, so they see the api and the server
 * classes but are not visible to CDI: extensions in those jars register through
 * {@code META-INF/services}. JVM mode only.
 */
@ApplicationScoped
public class Extensions {

    private static final Logger LOG = Logger.getLogger(Extensions.class);

    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private static final String REQUIRED = "required";

    private final Map<Class<?>, List<?>> discovered = new ConcurrentHashMap<>();
    private final Map<Extension, Boolean> admitted = new ConcurrentHashMap<>();
    private final List<Extension> toClose = new CopyOnWriteArrayList<>();
    private final Map<String, Extension> selected = new ConcurrentHashMap<>();
    private final List<Extension> madeByServer = new CopyOnWriteArrayList<>();
    private final Path dir;
    private final List<Path> jars;
    private final ClassLoader loader;
    private final URLClassLoader owned;
    private final Instance<Object> cdi;
    /**
     * The extension points the class path and the providers directory declare, by name.
     */
    private final List<Spi> spis;

    @Inject
    public Extensions(McpServerConfig config, @Any Instance<Object> cdi) {
        this(resolve(config.providersDir()), contextLoader(), cdi);
    }

    /**
     * @param dir providers directory, {@code null} for none
     * @param parent class loader for the service lookup and the parent of the jar loader
     * @param cdi {@code @Any Instance<Object>} for the bean lookup, {@code null} for none
     */
    public Extensions(Path dir, ClassLoader parent, Instance<Object> cdi) {
        this.dir = dir;
        this.cdi = cdi;
        this.jars = listJars(dir);
        if (jars.isEmpty()) {
            this.owned = null;
            this.loader = parent;
            if (dir != null) {
                LOG.debugf("No extension jars in %s", dir);
            }
        }
        else {
            this.owned = new URLClassLoader("kc-mcp-providers", urls(jars), parent);
            this.loader = owned;
            LOG.infof("Extensions directory %s: %s", dir, jars.stream().map(p -> p.getFileName().toString()).toList());
        }
        this.spis = Spis.load(loader);
    }

    /** Every extension point, the server's own and those of extension jars, by name. */
    public List<Spi> spis() {
        return spis;
    }

    /**
     * The extension point whose extensions implement this interface, if one is declared.
     */
    public Optional<Spi> spi(Class<?> extensionType) {
        return spis.stream().filter(s -> s.extensionType() == extensionType).findFirst();
    }

    /** Class path only, no providers directory and no CDI: tests and embedding. */
    public static Extensions classpath() {
        return new Extensions(null, contextLoader(), null);
    }

    /**
     * The implementations of {@code spi}, ServiceLoader entries first (class path, then
     * providers directory), then CDI beans; each class once. Found once per extension
     * point, so every caller gets the same instances.
     */
    @SuppressWarnings("unchecked")
    public <T> List<T> discover(Class<T> spi) {
        List<?> known = discovered.get(spi);
        if (known != null) {
            return (List<T>) known;
        }
        // not computeIfAbsent: creating a CDI bean may discover another extension point
        List<T> found = find(spi);
        List<?> raced = discovered.putIfAbsent(spi, found);
        return raced != null ? (List<T>) raced : found;
    }

    private <T> List<T> find(Class<T> spi) {
        Map<String, T> byClass = new LinkedHashMap<>();
        for (T t : ServiceLoader.load(spi, loader)) {
            byClass.putIfAbsent(t.getClass().getName(), t);
        }
        if (cdi != null) {
            for (Instance.Handle<T> h : cdi.select(spi).handles()) {
                byClass.computeIfAbsent(h.getBean().getBeanClass().getName(), k -> h.get());
            }
        }
        for (T t : byClass.values()) {
            if (t instanceof Extension e) {
                // also the check that the class serves this extension point and no other
                seen.add(key(Spis.of(e.getClass(), spis).name(), e.id()));
            }
        }
        return List.copyOf(byClass.values());
    }

    /**
     * The ids ({@code kc-mcp.spi.<spi>.<id>} form) of every extension discovered so far,
     * of any extension point.
     */
    public Set<String> seen() {
        return Set.copyOf(seen);
    }

    /**
     * The ids that {@code kc-mcp.spi.<spi>.<id>.required=true} names but no discovered
     * extension has: a required security control whose jar is missing must stop the
     * start, not be skipped because there is nothing to check.
     */
    public static List<String> missingRequired(McpServerConfig config, Set<String> seen) {
        return missingRequired(config, seen, System.getenv());
    }

    /**
     * @param env the environment: {@code KC_MCP_SPI_<SPI>_<ID>_REQUIRED} also names
     * extensions that appear nowhere else, and overrides a file's value; a system
     * property (the command line) overrides both
     */
    public static List<String> missingRequired(McpServerConfig config, Set<String> seen, Map<String, String> env) {
        return missingRequired(config, seen, env, Spis.onClassPath());
    }

    /**
     * @param spis the extension points, to tell extension point and id apart in a
     * variable's name
     */
    public static List<String> missingRequired(McpServerConfig config, Set<String> seen, Map<String, String> env,
            List<Spi> spis) {
        Map<String, Boolean> required = new TreeMap<>();
        config.spi().forEach((spi, spiSettings) -> spiSettings.extensions().forEach((id, settings) -> {
            if (settings.containsKey(REQUIRED)) {
                required.put(key(spi, id), Boolean.parseBoolean(settings.get(REQUIRED).trim()));
            }
        }));
        env.forEach((name, value) -> requiredVariable(name, spis)
            .ifPresent(extension -> required.put(extension, Boolean.parseBoolean(value.trim()))));
        System.getProperties()
            .stringPropertyNames()
            .forEach(name -> requiredProperty(name).ifPresent(
                    extension -> required.put(extension, Boolean.parseBoolean(System.getProperty(name).trim()))));
        return required.entrySet()
            .stream()
            .filter(e -> e.getValue() && !seen.contains(e.getKey()))
            .map(Map.Entry::getKey)
            .toList();
    }

    /** {@code <spi>.<id>} of a {@code kc-mcp.spi.<spi>.<id>.required} system property. */
    private static Optional<String> requiredProperty(String name) {
        String suffix = "." + REQUIRED;
        if (!name.startsWith(ProviderConfig.PREFIX) || !name.endsWith(suffix)) {
            return Optional.empty();
        }
        String path = name.substring(ProviderConfig.PREFIX.length(), name.length() - suffix.length());
        int dot = path.indexOf('.');
        return dot <= 0 || dot == path.length() - 1 ? Optional.empty()
                : Optional.of(key(path.substring(0, dot), path.substring(dot + 1)));
    }

    /**
     * {@code <spi>.<id>} of a {@code KC_MCP_SPI_<SPI>_<ID>_REQUIRED} variable. With an
     * unknown extension point the whole remainder is the id: it cannot be installed, and
     * a required control must not be skipped because of a typo.
     */
    private static Optional<String> requiredVariable(String name, List<Spi> spis) {
        String suffix = "_REQUIRED";
        String root = "KC_MCP_SPI_";
        if (!name.startsWith(root) || !name.endsWith(suffix) || name.length() <= root.length() + suffix.length()) {
            return Optional.empty();
        }
        String path = name.substring(root.length(), name.length() - suffix.length());
        // the longest name first: of 'audit' and 'audit-listener' the more specific one
        // (Spis.load refuses such a pair, a list given by hand may hold one)
        for (String spi : spis.stream()
            .map(Spi::name)
            .sorted(Comparator.comparingInt(String::length).reversed())
            .toList()) {
            String prefix = spi.toUpperCase(Locale.ROOT).replace('-', '_') + "_";
            if (path.startsWith(prefix) && path.length() > prefix.length()) {
                return Optional.of(key(spi, path.substring(prefix.length()).replace('_', '-')));
            }
        }
        return Optional.of(path.toLowerCase(Locale.ROOT).replace('_', '-'));
    }

    private static String key(String spi, String id) {
        return spi + "." + ProviderConfig.configId(id);
    }

    /**
     * The class loader the extensions come from: the application's, with the jars of the
     * providers directory when there are any.
     */
    public ClassLoader classLoader() {
        return loader;
    }

    /** The providers directory, {@code null} when none is configured. */
    public Path dir() {
        return dir;
    }

    /** The extension jars loaded from the providers directory. */
    public List<Path> jars() {
        return jars;
    }

    /**
     * {@link #usable}, decided once per extension; one that takes part is closed at
     * shutdown.
     */
    public boolean admit(Extension e, String kind, McpServerConfig config) {
        Boolean decided = admitted.get(e);
        if (decided != null) {
            return decided;
        }
        boolean usable = usable(e, kind, config);
        if (admitted.putIfAbsent(e, usable) == null && usable) {
            toClose.add(e);
        }
        return usable;
    }

    /**
     * The extension serving an extension point that has exactly one: the one
     * {@code kc-mcp.spi.<spi>.provider} names, which must be found and usable, else the
     * usable candidate with the lowest order, the built-ins last. The candidates not
     * chosen are neither configured nor closed.
     *
     * @param builtIns candidates the server makes itself rather than discovers
     * @throws IllegalStateException when the named provider cannot serve
     */
    public <T extends Extension> Optional<T> select(Class<T> type, String spi, String kind, McpServerConfig config,
            List<? extends T> builtIns) {
        return select(discover(type), builtIns, spi, kind, config);
    }

    /** {@link #select(Class, String, String, McpServerConfig, List)} among these. */
    public <T extends Extension> Optional<T> select(List<T> discoveredCandidates, List<? extends T> builtIns,
            String spi, String kind, McpServerConfig config) {
        List<T> candidates = new ArrayList<>(discoveredCandidates);
        candidates.sort(Comparator.comparingInt(Extension::order).thenComparing(Extension::id));
        candidates.addAll(builtIns);
        builtIns.forEach(b -> {
            seen.add(key(spi, b.id()));
            madeByServer.add(b);
        });
        Optional<String> wanted = ProviderConfig.selectedProvider(spi, config, System.getenv());
        if (wanted.isEmpty()) {
            Optional<T> first = candidates.stream().filter(c -> admit(c, kind, config)).findFirst();
            first.ifPresent(c -> selected.put(spi, c));
            return first;
        }
        String id = ProviderConfig.configId(wanted.get());
        T chosen = candidates.stream()
            .filter(c -> ProviderConfig.configId(c.id()).equals(id))
            .findFirst()
            .orElseThrow(
                    () -> new IllegalStateException(ProviderConfig.PREFIX + spi + ".provider names '" + wanted.get()
                            + "', which is not installed; found " + candidates.stream().map(Extension::id).toList()));
        if (!admit(chosen, kind, config)) {
            throw new IllegalStateException(ProviderConfig.PREFIX + spi + ".provider names '" + wanted.get()
                    + "', which is switched off or not supported with the current configuration");
        }
        selected.put(spi, chosen);
        return Optional.of(chosen);
    }

    /**
     * One extension as the {@code providers} command shows it.
     *
     * @param status {@code active} or {@code selected} when it takes part;
     * {@code disabled}, {@code not supported} or {@code not selected} when it does not;
     * {@code available} when nothing has asked for it yet, which happens where an
     * extension is picked on first use
     * @param origin {@code built-in}, or the jar of the providers directory
     */
    public record ProviderStatus(String spi, String id, String status, String origin, String className) {
    }

    /**
     * Every extension found so far, each {@code <spi>.<id>} once, by extension point,
     * then order and id.
     */
    public List<Extension> all() {
        Map<String, Extension> all = new LinkedHashMap<>();
        Stream.concat(discovered.values().stream().flatMap(List::stream), madeByServer.stream())
            .filter(Extension.class::isInstance)
            .map(Extension.class::cast)
            .forEach(e -> all.putIfAbsent(key(Spis.of(e).name(), e.id()), e));
        return all.values()
            .stream()
            .sorted(Comparator.comparing((Extension e) -> Spis.of(e).name())
                .thenComparingInt(Extension::order)
                .thenComparing(Extension::id))
            .toList();
    }

    /** Every extension found so far, by extension point, then order and id. */
    public List<ProviderStatus> report(McpServerConfig config) {
        return all().stream().map(e -> describe(e, config)).toList();
    }

    /** One extension as the {@code providers} command shows it. */
    public ProviderStatus describe(Extension e, McpServerConfig config) {
        return new ProviderStatus(Spis.of(e).name(), ProviderConfig.configId(e.id()), status(e, config), origin(e),
                e.getClass().getName());
    }

    private String status(Extension e, McpServerConfig config) {
        if (!ProviderConfig.forExtension(e, config).getBoolean("enabled", true)) {
            return "disabled";
        }
        Boolean decided = admitted.get(e);
        Spi spi = Spis.of(e.getClass(), spis);
        if (spi.singleProvider()) {
            Extension chosen = selected.get(spi.name());
            if (chosen == e) {
                return "selected";
            }
            if (Boolean.FALSE.equals(decided)) {
                return "not supported";
            }
            return chosen != null ? "not selected" : "available";
        }
        if (decided == null) {
            return "available";
        }
        return decided ? "active" : "not supported";
    }

    private String origin(Extension e) {
        if (owned == null || e.getClass().getClassLoader() != owned) {
            return "built-in";
        }
        return Path.of(e.getClass().getProtectionDomain().getCodeSource().getLocation().getPath())
            .getFileName()
            .toString();
    }

    /**
     * {@code kc-mcp.spi.<spi>.provider} settings that select nothing: on an extension
     * point where every extension runs, or on one that does not exist.
     */
    public static List<String> misplacedProviders(McpServerConfig config, Map<String, String> env) {
        return misplacedProviders(config, env, Spis.onClassPath());
    }

    /** @param spis the extension points that exist */
    public static List<String> misplacedProviders(McpServerConfig config, Map<String, String> env, List<Spi> spis) {
        List<String> misplaced = new ArrayList<>();
        Set<String> single = spis.stream().filter(Spi::singleProvider).map(Spi::name).collect(Collectors.toSet());
        Set<String> names = new TreeSet<>(spis.stream().map(Spi::name).toList());
        names.addAll(config.spi().keySet());
        for (String spi : names) {
            if (!single.contains(spi) && ProviderConfig.selectedProvider(spi, config, env).isPresent()) {
                misplaced.add(ProviderConfig.PREFIX + spi + ".provider");
            }
        }
        return misplaced;
    }

    /** On the shutdown event, while the extensions' CDI beans are still alive. */
    void onShutdown(@Observes ShutdownEvent event) {
        closeExtensions();
    }

    /** Closes what was admitted, last admitted first; each once. */
    void closeExtensions() {
        List<Extension> closing = new ArrayList<>(toClose);
        toClose.clear();
        Collections.reverse(closing);
        for (Extension e : closing) {
            try {
                e.close();
            }
            catch (RuntimeException ex) {
                LOG.warnf(ex, "Extension '%s' failed to close", e.id());
            }
        }
    }

    @PreDestroy
    void close() {
        if (owned != null) {
            try {
                owned.close();
            }
            catch (IOException e) {
                LOG.debugf(e, "Closing the extension class loader failed");
            }
        }
    }

    /**
     * A relative directory is resolved against the application home: the directory of the
     * jar when the class path is a single jar ({@code java -jar quarkus-run.jar}), else
     * the working directory.
     */
    public static Path resolve(String configured) {
        Path p = Path.of(configured.trim());
        if (p.isAbsolute()) {
            return p;
        }
        return appHome().resolve(p).toAbsolutePath().normalize();
    }

    static Path appHome() {
        String cp = System.getProperty("java.class.path", "");
        if (!cp.isBlank() && !cp.contains(File.pathSeparator) && cp.endsWith(".jar")) {
            Path parent = Path.of(cp).toAbsolutePath().getParent();
            if (parent != null) {
                return parent;
            }
        }
        return Path.of("").toAbsolutePath();
    }

    private static List<Path> listJars(Path dir) {
        if (dir == null || !Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".jar") && Files.isRegularFile(p))
                .sorted()
                .toList();
        }
        catch (IOException e) {
            LOG.warnf(e, "Cannot read the extensions directory %s", dir);
            return List.of();
        }
    }

    private static URL[] urls(List<Path> jars) {
        List<URL> urls = new ArrayList<>();
        for (Path jar : jars) {
            try {
                urls.add(jar.toUri().toURL());
            }
            catch (MalformedURLException e) {
                throw new IllegalStateException(e);
            }
        }
        return urls.toArray(URL[]::new);
    }

    private static ClassLoader contextLoader() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return cl != null ? cl : Extensions.class.getClassLoader();
    }

    /**
     * Whether a found extension takes part: not switched off with
     * {@code kc-mcp.spi.<spi>.<id>.enabled=false}, then {@link Extension#configure} with
     * its settings, and {@link Extension#isSupported} with the current configuration.
     * Every place that picks extensions asks here, so the rules and the log lines are the
     * same for all extension points.
     * <p>
     * Settings the extension declares ({@link Extension#configSpec()}) are checked first,
     * then its own rules ({@link Extension#validate}): warnings (unknown keys) are
     * logged, errors (a malformed or missing required value) stop the start whatever the
     * profile, as a typo must not quietly switch a control off.
     * <p>
     * Fail closed where it matters: an extension marked
     * {@code kc-mcp.spi.<spi>.<id>.required=true} that is switched off or unsupported
     * stops the start, and so does an {@code isSupported} that throws in profile
     * {@code shared}; elsewhere both are logged and the extension is left out.
     *
     * @param kind the extension point, for the log ({@code Confirmer}, {@code KeyVault},
     * ...)
     * @throws IllegalStateException when a required extension cannot take part
     */
    public static boolean usable(Extension e, String kind, McpServerConfig config) {
        ProviderConfig settings = ProviderConfig.forExtension(e, config);
        boolean required = settings.getBoolean("required", false);
        if (!settings.getBoolean("enabled", true)) {
            if (required) {
                throw new IllegalStateException(kind + " '" + e.id() + "' is required (" + settings.providerPrefix()
                        + "required=true) but switched off (" + settings.providerPrefix() + "enabled=false)");
            }
            LOG.infof("%s '%s' disabled by configuration", kind, e.id());
            return false;
        }
        // an access check's settings may hold placeholders and are merged with the
        // systems' and realms': the access check chain checks them
        if (!AccessCheckSpi.NAME.equals(Spis.of(e).name())) {
            List<ConfigProblem> problems = settings.problems(e);
            problems.stream()
                .filter(p -> !p.isError())
                .forEach(p -> LOG.warnf("%s '%s': %s", kind, e.id(), p.message()));
            List<ConfigProblem> errors = ConfigProblem.errors(problems);
            if (!errors.isEmpty()) {
                throw new IllegalStateException(
                        kind + " '" + e.id() + "' is misconfigured: " + ConfigProblem.describe(errors));
            }
        }
        boolean supported;
        try {
            e.configure(settings);
            supported = e.isSupported(config, settings);
        }
        catch (RuntimeException ex) {
            if (required || config.securityProfile().shared()) {
                throw new IllegalStateException(kind + " '" + e.id()
                        + "' could not be configured or cannot tell whether it works with this" + " configuration ("
                        + ex + "); " + (required ? "it is required" : "profile shared") + " does not start without it",
                        ex);
            }
            LOG.warnf(ex, "%s '%s' left out: configure or isSupported failed: %s", kind, e.id(), ex.getMessage());
            return false;
        }
        if (!supported) {
            if (required) {
                throw new IllegalStateException(kind + " '" + e.id() + "' is required (" + settings.providerPrefix()
                        + "required=true) but not supported with the current configuration");
            }
            LOG.infof("%s '%s' left out: not supported with the current configuration", kind, e.id());
        }
        return supported;
    }
}
