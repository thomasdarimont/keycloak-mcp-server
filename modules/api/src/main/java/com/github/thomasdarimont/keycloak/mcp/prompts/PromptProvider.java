package com.github.thomasdarimont.keycloak.mcp.prompts;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;

/**
 * Contributes {@link PromptSpec}s, the task recipes a user can pick in their MCP client.
 * Discovered like {@link ToolProvider}s: {@code @AutoService(PromptProvider.class)} (jars
 * in {@code providers/} included) or a CDI bean;
 * {@code kc-mcp.spi.<spi>.<id>.enabled=false} switches a provider off. Prompts whose
 * tools are all disabled on this server are not registered.
 */
public interface PromptProvider extends Extension {

    /** Unique, stable id such as {@code prompts} or {@code acme-recipes}. */
    @Override
    String id();

    List<PromptSpec> prompts(ExtensionContext context);

}
