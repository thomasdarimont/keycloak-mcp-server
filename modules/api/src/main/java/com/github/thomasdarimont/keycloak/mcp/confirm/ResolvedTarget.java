package com.github.thomasdarimont.keycloak.mcp.confirm;

/**
 * A target of the call a {@link Confirmer} decides on, as the server found it in Keycloak
 * before asking: what to show the human instead of the argument the model sent.
 *
 * @param label what it is: user, client, group, role, ...
 * @param name what Keycloak calls it (a username, a client id, a group path); the
 * argument as given for targets nothing is looked up for
 * @param id its id in Keycloak, or {@code null} when none was looked up
 * @param verified whether {@code name} comes from Keycloak; {@code false}: it is the
 * argument as the model sent it
 */
public record ResolvedTarget(String label, String name, String id, boolean verified) {

    /** {@code user carol}: for a confirmation that lists several targets. */
    public String labelled() {
        return label + " " + name;
    }
}
