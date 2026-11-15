package com.github.thomasdarimont.keycloak.mcp.spi;

/**
 * The message keys a UI translates an extension's spec with, derived from the extension
 * point, the extension's id ({@link ProviderConfig#configId}) and the names in the spec,
 * so declarations need not repeat them. The texts are in the message bundles
 * ({@link ConfigMessages}), English in {@code META-INF/kc-mcp/messages.properties} of the
 * jar that brings the extension.
 * <ul>
 * <li>an extension point: {@code <spi>.display-name} and {@code <spi>.description}
 * ({@code access-check.display-name})</li>
 * <li>the extension itself: {@code <spi>.<id>.display-name},
 * {@code <spi>.<id>.description} and {@code <spi>.<id>.help-text}
 * ({@code access-check.step-up.help-text}), the texts of {@link Extension#displayName()},
 * {@link Extension#description()} and {@link Extension#helpText()}</li>
 * <li>a setting: {@code <spi>.<id>.<name>.label}, {@code <spi>.<id>.<name>.description}
 * ({@code audit-scrubber.pii.mode.label})</li>
 * <li>an option of a choice: {@code <spi>.<id>.<name>.option.<option>}
 * ({@code audit-scrubber.pii.mode.option.pseudonymize})</li>
 * <li>a group: {@code <spi>.<id>.group.<group>.label},
 * {@code <spi>.<id>.group.<group>.description}</li>
 * <li>a problem: its {@link ConfigProblem#code()}</li>
 * </ul>
 * Settings that several extensions read have shared texts under {@code config.} instead
 * of the extension's prefix ({@link #shared}): {@code config.client-secret.label}.
 */
public final class ConfigMessageKeys {

    private ConfigMessageKeys() {
    }

    /** {@code <spi>.<id>.} */
    public static String prefix(String spi, String extensionId) {
        return spi + "." + ProviderConfig.configId(extensionId) + ".";
    }

    public static String prefix(Extension extension) {
        return prefix(extension.spiName(), extension.id());
    }

    /** The shared form of a key: {@code config.} instead of the extension's prefix. */
    public static String shared(String prefix, String key) {
        return key.startsWith(prefix) ? SHARED + key.substring(prefix.length()) : key;
    }

    /** The prefix of the shared texts. */
    public static final String SHARED = "config.";

    /** The name of an extension point, for people. */
    public static String extensionPoint(String spi) {
        return spi + ".display-name";
    }

    /** What an extension point is for, in a sentence or two. */
    public static String extensionPointDescription(String spi) {
        return spi + ".description";
    }

    /** The extension's name ({@link Extension#displayName()}). */
    public static String displayName(String prefix) {
        return prefix + "display-name";
    }

    /** The extension's description ({@link Extension#description()}). */
    public static String description(String prefix) {
        return prefix + "description";
    }

    /** The extension's help text ({@link Extension#helpText()}). */
    public static String helpText(String prefix) {
        return prefix + "help-text";
    }

    public static String label(String prefix, ConfigProperty property) {
        return prefix + property.name() + ".label";
    }

    public static String description(String prefix, ConfigProperty property) {
        return prefix + property.name() + ".description";
    }

    public static String option(String prefix, ConfigProperty property, String option) {
        return prefix + property.name() + ".option." + option;
    }

    public static String label(String prefix, ConfigHint.Group group) {
        return prefix + "group." + group.id() + ".label";
    }

    public static String description(String prefix, ConfigHint.Group group) {
        return prefix + "group." + group.id() + ".description";
    }
}
