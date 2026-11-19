package com.github.thomasdarimont.keycloak.mcp.spi;

/**
 * An {@link Extension} that has something to say about how it runs: which table or
 * endpoint it works with, how many entries it holds, whether something is not as it
 * should be. The server collects it in its server info (the admin API's
 * {@code GET /api/admin/server-info}, the management UI), next to the extension's name
 * and status. Not an extension point of its own: implement it on the extension.
 * <p>
 * Asked only of extensions that take part (active or selected), after
 * {@link Extension#configure}, on a request thread and each time the server info is read:
 * answer from what the extension already knows, without calling a remote system. The
 * texts are shown as they are, so no secrets, and state rather than settings: those are
 * in the extension's configuration.
 */
public interface ServerInfoContributor {

    /** Adds this extension's operational facts and warnings to {@code info}. */
    void contributeServerInfo(ServerInfo info);
}
