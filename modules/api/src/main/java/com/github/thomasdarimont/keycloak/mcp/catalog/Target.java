package com.github.thomasdarimont.keycloak.mcp.catalog;

/**
 * What an argument of a tool refers to: a tool that changes or deletes something declares
 * its targets ({@link ToolSpec.Builder#targets}), so that whoever is asked to confirm the
 * call is shown what it acts on. The arguments come from the model; a user, client, group
 * or organization is therefore looked up in Keycloak before anyone is asked, and shown by
 * the name Keycloak has for it, whether the model passed that name or an id. An argument
 * that is a name already ({@link Kind#NAMED}: a role, an alias, a mapper) is shown as
 * given.
 *
 * @param arg the argument's name
 * @param kind what the value identifies
 * @param label what the confirmation calls it when a call has several targets
 */
public record Target(String arg, Kind kind, String label) {

    /** How a target's value is turned into what the confirmation shows. */
    public enum Kind {

        /** A user by id, username or email: shown by username. */
        USER,
        /** A client by internal id or client id: shown by client id. */
        CLIENT,
        /** A group by id, path or name: shown by path. */
        GROUP,
        /** An organization by id, alias or name: shown by name. */
        ORGANIZATION,
        /** A name or an id nothing is looked up for: shown as given. */
        NAMED

    }

    public static Target user(String arg) {
        return new Target(arg, Kind.USER, "user");
    }

    public static Target client(String arg) {
        return new Target(arg, Kind.CLIENT, "client");
    }

    public static Target group(String arg) {
        return new Target(arg, Kind.GROUP, "group");
    }

    public static Target organization(String arg) {
        return new Target(arg, Kind.ORGANIZATION, "organization");
    }

    /** An argument shown as given, under this label. */
    public static Target named(String arg, String label) {
        return new Target(arg, Kind.NAMED, label);
    }

    /** An argument shown as given, under its own name. */
    public static Target named(String arg) {
        return new Target(arg, Kind.NAMED, arg);
    }
}
