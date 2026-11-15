package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * A startup check of the deployment, next to the built-in ones of
 * {@code kc-mcp.security-profile}: an extension states what its own feature needs to be
 * safe, say an audit file outside {@code /tmp}, a ticket system URL over HTTPS, or a
 * setting that must not be left at its default on a shared server. Register with
 * {@code @AutoService(ProfileCheck.class)} or as a CDI bean;
 * {@code kc-mcp.spi.<spi>.<id>.enabled=false} switches one off.
 * <p>
 * The server runs every check at startup, after its own. All {@link #problems} of all
 * checks are reported together, each tagged with the check's id, and stop the start; a
 * check decides itself in which profiles a finding is a problem (typically only in
 * {@link SecurityProfile#SHARED}) and returns {@link #warnings} for the rest. A check
 * that throws stops the start in profile {@code shared} and is logged in {@code local}.
 */
public interface ProfileCheck extends Extension {

    /** What prevents a safe start; empty when nothing does. */
    List<String> problems(ProfileCheckContext context);

    /** What is worth a line in the log but no reason to stop. */
    default List<String> warnings(ProfileCheckContext context) {
        return List.of();
    }
}
