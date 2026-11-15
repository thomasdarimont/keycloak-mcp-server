package com.github.thomasdarimont.keycloak.mcp.authzen;

import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Adjusts the evaluation the built-in {@code authzen} engine sends, before it is sent:
 * further context (a ticket id, a tenant attribute), other resource types, a subject from
 * a directory. Customizers run in {@link #order()}, each on the result of the one before;
 * one that throws refuses the call. Register with
 * {@code @AutoService(AuthZenRequestCustomizer.class)} or as a CDI bean; settings
 * {@code kc-mcp.spi.authzen-customizer.<id>.*}.
 * <p>
 * The subject is the caller from the token: a customizer that replaces it takes the
 * responsibility for who the PDP believes is acting.
 */
@FunctionalInterface
public interface AuthZenRequestCustomizer extends Extension {

    /**
     * @param evaluation what is about to be sent
     * @param request the call, its system and the effective {@code authzen} settings (a
     * customizer's own keys may be among them)
     * @return what to send instead; {@code evaluation} itself to change nothing
     */
    AuthZenEvaluation customize(AuthZenEvaluation evaluation, AuthorizationEngine.Request request);
}
