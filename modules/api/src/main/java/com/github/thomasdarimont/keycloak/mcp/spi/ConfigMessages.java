package com.github.thomasdarimont.keycloak.mcp.spi;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;

/**
 * The texts of configuration specs and problems: the message bundles
 * {@code META-INF/kc-mcp/messages.properties} (English) and
 * {@code META-INF/kc-mcp/messages_<lang>.properties} / {@code _<lang>_<COUNTRY>} of every
 * jar on a class loader, the server's own and the extensions' (the providers directory
 * included), merged: an extension brings the texts of its settings in its own jar. Files
 * are UTF-8.
 * <p>
 * Keys are those of {@link ConfigMessageKeys}. A setting's text that its extension does
 * not have falls back to {@code config.<name>...}: the shared texts of settings that
 * several extensions read ({@code client-secret}, the {@code jwt-*} keys of the client
 * authentication methods). A key no bundle has is logged once and replaced by the
 * setting's name, the group's id, the option or the problem's English message.
 * <p>
 * Messages take named arguments: {@code {key} must be {expected}} with
 * {@link ConfigProblem#args()}; an argument the message names but the problem lacks stays
 * as written.
 */
public final class ConfigMessages {

    /** The bundles' base name on the class path. */
    public static final String BUNDLE = "META-INF/kc-mcp/messages";

    private static final Logger LOG = Logger.getLogger(ConfigMessages.class);
    private static final Pattern ARG = Pattern.compile("\\{([A-Za-z0-9_.-]+)}");

    private final ClassLoader loader;
    /** Merged texts by bundle suffix ({@code ""}, {@code _de}, {@code _de_CH}). */
    private final Map<String, Map<String, String>> bySuffix = new ConcurrentHashMap<>();
    private final Set<String> reported = ConcurrentHashMap.newKeySet();

    public ConfigMessages(ClassLoader loader) {
        this.loader = loader != null ? loader : ConfigMessages.class.getClassLoader();
    }

    /** The text of a key in this locale or a more general one, else the English one. */
    public Optional<String> find(Locale locale, String key) {
        for (String suffix : suffixes(locale)) {
            String v = texts(suffix).get(key);
            if (v != null) {
                return Optional.of(v);
            }
        }
        return Optional.empty();
    }

    /**
     * {@link #find} with the arguments filled in; {@code fallback} when no bundle has the
     * key.
     */
    public String format(Locale locale, String key, Map<String, String> args, String fallback) {
        return find(locale, key).map(t -> fill(t, args)).orElseGet(() -> {
            missing(key);
            return fallback;
        });
    }

    /**
     * An extension's name: the bundles' text, else what the extension itself says
     * ({@link Extension#displayName()}). The texts of an extension are never shared ones,
     * and a bundle without them is no fault: the extension's own text is the English one.
     */
    public String displayName(Locale locale, Extension extension) {
        return own(locale, ConfigMessageKeys.displayName(ConfigMessageKeys.prefix(extension)), extension.displayName())
            .orElseGet(extension::id);
    }

    /**
     * An extension's description, like {@link #displayName}; empty when there is none.
     */
    public Optional<String> description(Locale locale, Extension extension) {
        return own(locale, ConfigMessageKeys.description(ConfigMessageKeys.prefix(extension)), extension.description());
    }

    /** An extension's help, like {@link #displayName}; empty when there is none. */
    public Optional<String> helpText(Locale locale, Extension extension) {
        return own(locale, ConfigMessageKeys.helpText(ConfigMessageKeys.prefix(extension)), extension.helpText());
    }

    private Optional<String> own(Locale locale, String key, String fromExtension) {
        return find(locale, key).or(() -> Optional.ofNullable(fromExtension).filter(t -> !t.isBlank()));
    }

    /** A setting's label: its own, the shared one, else its name. */
    public String label(Locale locale, String prefix, ConfigProperty property) {
        return text(locale, prefix, ConfigMessageKeys.label(prefix, property)).orElseGet(() -> {
            missing(ConfigMessageKeys.label(prefix, property));
            return property.name();
        });
    }

    /** A setting's description: its own or the shared one; empty when there is none. */
    public Optional<String> description(Locale locale, String prefix, ConfigProperty property) {
        return text(locale, prefix, ConfigMessageKeys.description(prefix, property));
    }

    /** The text of an option of a choice; the option itself when there is none. */
    public String option(Locale locale, String prefix, ConfigProperty property, String option) {
        return text(locale, prefix, ConfigMessageKeys.option(prefix, property, option)).orElse(option);
    }

    /** A group's title: its own, the shared one, else its id. */
    public String label(Locale locale, String prefix, ConfigHint.Group group) {
        return text(locale, prefix, ConfigMessageKeys.label(prefix, group)).orElseGet(() -> {
            missing(ConfigMessageKeys.label(prefix, group));
            return group.id();
        });
    }

    public Optional<String> description(Locale locale, String prefix, ConfigHint.Group group) {
        return text(locale, prefix, ConfigMessageKeys.description(prefix, group));
    }

    /**
     * A problem in this locale: its code's message with its args, else its English
     * message.
     */
    public String message(Locale locale, ConfigProblem problem) {
        return format(locale, problem.code(), problem.args(), problem.message());
    }

    /**
     * The keys of a spec that no English bundle has: every setting's and group's label (a
     * description and an option's text are optional). For tests that keep the bundles
     * complete.
     */
    public List<String> missingLabels(String prefix, ConfigSpec spec) {
        List<String> missing = new ArrayList<>();
        for (ConfigProperty p : spec.properties()) {
            String key = ConfigMessageKeys.label(prefix, p);
            if (text(Locale.ROOT, prefix, key).isEmpty()) {
                missing.add(key);
            }
        }
        for (ConfigHint h : spec.hints()) {
            if (h instanceof ConfigHint.Group g) {
                String key = ConfigMessageKeys.label(prefix, g);
                if (text(Locale.ROOT, prefix, key).isEmpty()) {
                    missing.add(key);
                }
            }
        }
        return missing;
    }

    /** The extension's own text, else the shared one. */
    private Optional<String> text(Locale locale, String prefix, String key) {
        return find(locale, key).or(() -> find(locale, ConfigMessageKeys.shared(prefix, key)));
    }

    private void missing(String key) {
        if (reported.add(key)) {
            LOG.warnf("No text for '%s' in the message bundles %s*.properties", key, BUNDLE);
        }
    }

    static String fill(String text, Map<String, String> args) {
        if (args == null || args.isEmpty() || text.indexOf('{') < 0) {
            return text;
        }
        Matcher m = ARG.matcher(text);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String v = args.get(m.group(1));
            m.appendReplacement(out, Matcher.quoteReplacement(v != null ? v : m.group()));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static List<String> suffixes(Locale locale) {
        List<String> out = new ArrayList<>();
        if (locale != null && !locale.getLanguage().isEmpty()) {
            if (!locale.getCountry().isEmpty()) {
                out.add("_" + locale.getLanguage() + "_" + locale.getCountry());
            }
            out.add("_" + locale.getLanguage());
        }
        out.add("");
        return out;
    }

    private Map<String, String> texts(String suffix) {
        return bySuffix.computeIfAbsent(suffix, this::load);
    }

    /** Every jar's file of this suffix; a key the first file has wins. */
    private Map<String, String> load(String suffix) {
        Map<String, String> merged = new LinkedHashMap<>();
        String name = BUNDLE + suffix + ".properties";
        try {
            Enumeration<URL> files = loader.getResources(name);
            while (files.hasMoreElements()) {
                URL url = files.nextElement();
                Properties p = new Properties();
                try (InputStream in = url.openStream();
                        Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                    p.load(reader);
                }
                for (String key : p.stringPropertyNames()) {
                    String before = merged.putIfAbsent(key, p.getProperty(key));
                    if (before != null && !before.equals(p.getProperty(key))) {
                        LOG.debugf("Message '%s' of %s is ignored: an earlier bundle has it", key, url);
                    }
                }
            }
        }
        catch (IOException e) {
            LOG.warnf(e, "Cannot read the message bundles %s", name);
        }
        return Map.copyOf(merged);
    }
}
