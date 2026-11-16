package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * The extension points ({@link Spi}) a class loader knows, and the one an extension
 * belongs to.
 */
public final class Spis {

    /** The extension point of an extension class, found once per class. */
    private static final ClassValue<Spi> OF = new ClassValue<>() {
        @Override
        protected Spi computeValue(Class<?> type) {
            ClassLoader loader = type.getClassLoader();
            return of(type, load(loader != null ? loader : Spis.class.getClassLoader()));
        }
    };

    private Spis() {
    }

    /**
     * Every extension point this class loader finds, by name: the server's own and those
     * of the jars it sees.
     *
     * @throws IllegalStateException when two share a name or an interface, or when one's
     * name continues another's ({@code audit} and {@code audit-listener}): an environment
     * variable such as {@code KC_MCP_SPI_AUDIT_LISTENER_DB_REQUIRED} would then name an
     * extension of either
     */
    public static List<Spi> load(ClassLoader loader) {
        Map<String, Spi> byName = new LinkedHashMap<>();
        Map<Class<?>, Spi> byType = new LinkedHashMap<>();
        Map<String, Spi> byClass = new LinkedHashMap<>();
        for (Spi spi : ServiceLoader.load(Spi.class, loader)) {
            // a jar seen twice (class path and providers directory) declares it twice
            if (byClass.putIfAbsent(spi.getClass().getName(), spi) != null) {
                continue;
            }
            String name = spi.name();
            Class<? extends Extension> type = spi.extensionType();
            if (name == null || name.isBlank() || type == null) {
                throw new IllegalStateException(
                        "The extension point " + spi.getClass().getName() + " has no name or no extension type");
            }
            Spi sameName = byName.putIfAbsent(name, spi);
            if (sameName != null) {
                throw new IllegalStateException("Two extension points are named '" + name + "': "
                        + sameName.getClass().getName() + " and " + spi.getClass().getName());
            }
            Spi sameType = byType.putIfAbsent(type, spi);
            if (sameType != null) {
                throw new IllegalStateException("Two extension points share the interface " + type.getName() + ": '"
                        + sameType.name() + "' and '" + name + "'");
            }
        }
        List<Spi> all = new ArrayList<>(byName.values());
        all.sort(Comparator.comparing(Spi::name));
        for (Spi shorter : all) {
            for (Spi longer : all) {
                if (longer.name().startsWith(shorter.name() + "-")) {
                    throw new IllegalStateException("The extension point '" + longer.name() + "' ("
                            + longer.getClass().getName() + ") continues the name of '" + shorter.name() + "' ("
                            + shorter.getClass().getName() + "): their environment variables could not be told"
                            + " apart, rename one");
                }
            }
        }
        return List.copyOf(all);
    }

    /**
     * The extension points on the class path of the calling thread, else of the server.
     */
    public static List<Spi> onClassPath() {
        ClassLoader context = Thread.currentThread().getContextClassLoader();
        return load(context != null ? context : Spis.class.getClassLoader());
    }

    /**
     * The extension point an extension class belongs to: the one whose
     * {@link Spi#extensionType()} it implements.
     *
     * @throws IllegalStateException when it implements none, or those of several: one
     * class serves one extension point
     */
    public static Spi of(Class<? extends Extension> extensionClass) {
        return OF.get(extensionClass);
    }

    /** The extension point of this extension ({@link #of(Class)} of its class). */
    public static Spi of(Extension extension) {
        return of(extension.getClass());
    }

    /** As {@link #of(Class)}, among these extension points. */
    public static Spi of(Class<?> extensionClass, List<Spi> spis) {
        List<Spi> matching = spis.stream().filter(s -> s.extensionType().isAssignableFrom(extensionClass)).toList();
        if (matching.size() == 1) {
            return matching.getFirst();
        }
        if (matching.isEmpty()) {
            throw new IllegalStateException(extensionClass.getName() + " implements the interface of no extension"
                    + " point: declare one (" + Spi.class.getName() + ")");
        }
        throw new IllegalStateException(extensionClass.getName() + " implements the interfaces of several extension"
                + " points, " + matching.stream().map(Spi::name).toList() + ": a class serves one extension point,"
                + " split it");
    }
}
