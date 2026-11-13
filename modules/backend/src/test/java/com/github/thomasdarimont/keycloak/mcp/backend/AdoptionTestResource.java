package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.testcontainers.DockerClientFactory;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.ExecCreateCmdResponse;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.ContainerPort;
import com.github.dockerjava.api.model.Frame;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonObject;

/**
 * The {@link SharedKeycloak} with no static system: systems come through the admin API
 * (static token) into an in-memory database, as for a control plane adopting a Keycloak.
 * Helpers talk to that Keycloak as its admin, over HTTP and with {@code kcadm.sh} inside
 * its container.
 */
public class AdoptionTestResource implements QuarkusTestResourceLifecycleManager {

    public static final String TOKEN = "adoption-test-token";

    @Override
    public Map<String, String> start() {
        SharedKeycloak.base();
        return Map.ofEntries(Map.entry("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-adoption;DB_CLOSE_DELAY=-1"),
                Map.entry("kc-mcp.storage.secret-key", "test-passphrase"), Map.entry("kc-mcp.dynamic-systems", "true"),
                Map.entry("kc-mcp.static-systems", "false"), Map.entry("kc-mcp.dynamic-private-hosts", "allow"),
                Map.entry("kc-mcp.startup-check", "off"), Map.entry("kc-mcp.admin.enabled", "true"),
                Map.entry("kc-mcp.admin.token", TOKEN), Map.entry("kc-mcp.tool-exposure", "direct"));
    }

    @Override
    public void stop() {
    }

    /** An admin token of the master realm (admin-cli). */
    static String adminToken() {
        HttpResponse<String> r = send(HttpRequest
            .newBuilder(URI.create(SharedKeycloak.base() + "/realms/master/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers
                .ofString("grant_type=password&client_id=admin-cli&username=admin&password=admin"))
            .build());
        return new JsonObject(r.body()).getString("access_token");
    }

    /** An Admin API call as master's admin; the response, whatever its status. */
    static HttpResponse<String> keycloak(String method, String path, String json) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(SharedKeycloak.base() + path))
            .header("Authorization", "Bearer " + adminToken())
            .header("Content-Type", "application/json");
        b.method(method,
                json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json));
        return send(b.build());
    }

    private static HttpResponse<String> send(HttpRequest request) {
        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /**
     * Runs a bash script in the shared Keycloak's container, after logging
     * {@code kcadm.sh} in as master's admin; {@code KCADM} names the tool.
     *
     * @return exit code and output
     */
    static Map.Entry<Integer, String> kcadm(String script) {
        DockerClient docker = DockerClientFactory.instance().client();
        int port = URI.create(SharedKeycloak.base()).getPort();
        Container container = docker.listContainersCmd()
            .exec()
            .stream()
            .filter(c -> c.getPorts() != null && java.util.Arrays.stream(c.getPorts())
                .map(ContainerPort::getPublicPort)
                .anyMatch(p -> p != null && p == port))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no container publishes port " + port));
        String encoded = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_8));
        String command = "set -e; echo " + encoded + " | base64 -d > /tmp/setup.sh;"
                + " /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master"
                + " --user admin --password admin --config /tmp/kcadm.config;"
                + " printf '#!/bin/bash\\nexec /opt/keycloak/bin/kcadm.sh \"$@\" --config /tmp/kcadm.config\\n'"
                + " > /tmp/kcadm; chmod +x /tmp/kcadm; KCADM=/tmp/kcadm bash /tmp/setup.sh";
        ExecCreateCmdResponse exec = docker.execCreateCmd(container.getId())
            .withCmd("bash", "-c", command)
            .withAttachStdout(true)
            .withAttachStderr(true)
            .exec();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            docker.execStartCmd(exec.getId()).exec(new ResultCallback.Adapter<Frame>() {
                @Override
                public void onNext(Frame frame) {
                    out.writeBytes(frame.getPayload());
                }
            }).awaitCompletion(2, TimeUnit.MINUTES);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        Long code = docker.inspectExecCmd(exec.getId()).exec().getExitCodeLong();
        return Map.entry(code == null ? -1 : code.intValue(), out.toString(StandardCharsets.UTF_8));
    }
}
