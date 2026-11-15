package com.github.thomasdarimont.keycloak.mcp.state;

/**
 * What an entry of the {@link StateStore} belongs to: the Keycloak system it was created
 * for and, when that happened for one of its realms, the realm. State goes with what it
 * belongs to: removing a system removes its entries, removing a realm those of the realm.
 *
 * @param system the system's name
 * @param realm the realm, or {@code null} for state of the system as a whole
 */
public record StateScope(String system, String realm) {

    public StateScope {
        if (system == null || system.isBlank()) {
            throw new IllegalArgumentException("State belongs to a Keycloak system: its name is required");
        }
        realm = realm == null || realm.isBlank() ? null : realm;
    }

    public static StateScope of(String system) {
        return new StateScope(system, null);
    }

    public static StateScope of(String system, String realm) {
        return new StateScope(system, realm);
    }
}
