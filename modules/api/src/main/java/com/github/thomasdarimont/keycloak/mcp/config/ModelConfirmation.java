package com.github.thomasdarimont.keycloak.mcp.config;

import java.util.Locale;

/**
 * What the model is told about confirming destructive tools
 * ({@code kc-mcp.confirm.model}): whether it should ask the user itself or leave that to
 * the server. The server enforces its confirmation either way; this only shapes the
 * guidance in the instructions, {@code search_tools} hits, {@code whoami} and the
 * {@code confirmation_required} answers, so that a model does not ask "shall I really?"
 * when the user's device or the MCP client is going to ask anyway.
 */
public enum ModelConfirmation {
    /**
     * The model asks the user once after the server answered
     * {@code confirmation_required}, then calls again with {@code confirm: true}. Callers
     * holding one of {@code kc-mcp.confirm.model-trusted-roles} are told to pass
     * {@code confirm: true} right away.
     */
    ASK,
    /**
     * Confirmation is the server's: elicitation through the client, the CIBA confirmer,
     * or a refusal ({@code confirm-fallback=deny}). The model calls the tool right away
     * and relays the answer.
     */
    SERVER,
    /**
     * Default: {@link #SERVER} when a confirmer obtains the human's decision itself
     * (CIBA), when the client supports elicitation, or when {@code confirm: true} is not
     * accepted anyway; else {@link #ASK}.
     */
    AUTO;

    public static ModelConfirmation parse(String value) {
        String v = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (v) {
            case "ASK", "MODEL" -> ASK;
            case "SERVER", "NONE", "NEVER" -> SERVER;
            case "AUTO" -> AUTO;
            default -> throw new IllegalArgumentException(
                    "Unknown model-confirmation '" + value + "', expected ask, server or auto");
        };
    }

    public static class Converter implements org.eclipse.microprofile.config.spi.Converter<ModelConfirmation> {
        @Override
        public ModelConfirmation convert(String value) {
            return parse(value);
        }
    }
}
