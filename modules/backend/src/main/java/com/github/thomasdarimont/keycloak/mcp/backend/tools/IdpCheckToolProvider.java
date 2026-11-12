package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAddressCheck;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * IDP: checks what Keycloak cannot tell by itself, whether an identity provider's
 * published metadata (OIDC discovery and JWKS, SAML descriptor) is reachable and agrees
 * with what the realm has configured.
 * <p>
 * The fetch goes out from this server, to a URL an administrator or a model configured:
 * the same private address rule as for systems registered at runtime applies
 * ({@code kc-mcp.dynamic-private-hosts}, {@code listed} in the shared profile, where only
 * a host {@code kc-mcp.allowed-hosts} names literally may be private); only http(s), no
 * redirects, short timeouts, at most {@value #MAX_BYTES} bytes, and XML without DTDs or
 * external entities. The result is the comparison, never the fetched document.
 */
@AutoService(ToolProvider.class)
public class IdpCheckToolProvider extends AbstractToolProvider {

    static final int MAX_BYTES = 1 << 20;
    static final Duration TIMEOUT = Duration.ofSeconds(5);
    static final int WARN_DAYS = 30;

    static final String GOOGLE_DISCOVERY = "https://accounts.google.com/.well-known/openid-configuration";

    /**
     * The OIDC settings of a Keycloak IdP and the discovery fields they correspond to.
     */
    static final Map<String, String> OIDC_FIELDS = orderedMap("issuer", "issuer", "authorizationUrl",
            "authorization_endpoint", "tokenUrl", "token_endpoint", "userInfoUrl", "userinfo_endpoint", "logoutUrl",
            "end_session_endpoint", "jwksUrl", "jwks_uri");

    private volatile HostAllowList allowedHosts = HostAllowList.ANY;
    private volatile PrivateHosts privateHosts = PrivateHosts.ALLOW;

    /**
     * The outbound rule, for tests; {@link #tools} takes it from the server's settings.
     */
    IdpCheckToolProvider restrict(HostAllowList allowed, PrivateHosts setting) {
        this.allowedHosts = allowed;
        this.privateHosts = setting;
        return this;
    }

    @Override
    public String id() {
        return "idp-check";
    }

    @Override
    public String displayName() {
        return "Identity provider checks";
    }

    @Override
    public String description() {
        return "Fetches an identity provider's OIDC or SAML metadata and compares it with the realm's settings.";
    }

    @Override
    public int order() {
        return 51;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        if (context != null && context.serverConfig() != null) {
            allowedHosts = HostAllowList.of(context.serverConfig().allowedHosts().orElse(List.of()));
            privateHosts = context.serverConfig().effectiveDynamicPrivateHosts();
        }
        return List.of(tool("keycloak_idp_check").title("Check identity provider metadata")
            .description(
                    "Fetch an IdP's OIDC discovery/JWKS or SAML metadata; compare with the settings, report key expiry.")
            .category(Category.IDP)
            .read()
            .synonyms("test idp", "idp connection", "sso broken", "discovery document", "saml metadata",
                    "certificate expiry", "jwks", "well-known")
            .schema(schema().string("alias", "Identity provider alias, e.g. corp-sso").required())
            .handler(this::check)
            .roles("view-identity-providers")
            .api(get(R + "/identity-provider/instances/{alias}").path("alias", "alias"))
            .build());
    }

    ToolResult check(ToolCall call) {
        IdentityProviderRepresentation idp = IdpToolProvider.find(call, call.str("alias"));
        Map<String, String> config = idp.getConfig() == null ? Map.of() : idp.getConfig();
        String provider = idp.getProviderId();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alias", idp.getAlias());
        m.put("providerId", provider);
        switch (provider) {
            case "oidc", "keycloak-oidc" -> {
                String url = present(config.get("metadataDescriptorUrl")) ? config.get("metadataDescriptorUrl")
                        : present(config.get("issuer"))
                                ? stripSlash(config.get("issuer")) + "/.well-known/openid-configuration" : null;
                if (url == null) {
                    return ToolResult.error("not_checkable", "'" + idp.getAlias()
                            + "' has no issuer or discovery URL configured, so there is nothing to fetch; set issuer"
                            + " with keycloak_idp_update.");
                }
                oidc(m, url, config, true);
            }
            case "google" -> oidc(m, GOOGLE_DISCOVERY, config, false);
            case "saml" -> {
                String url = config.get("metadataDescriptorUrl");
                if (!present(url)) {
                    return ToolResult.error("not_checkable", "'" + idp.getAlias() + "' has no metadata URL"
                            + " (metadataDescriptorUrl) configured; set it with keycloak_idp_update to check it.");
                }
                saml(m, url, config);
            }
            default -> {
                return ToolResult.error("not_checkable", "Providers of type '" + provider
                        + "' publish no metadata this tool can read; it checks oidc, keycloak-oidc, google and saml.");
            }
        }
        return ToolResult.ok(m);
    }

    // ---- OIDC ----------------------------------------------------------------------

    private void oidc(Map<String, Object> m, String url, Map<String, String> config, boolean compare) {
        m.put("discoveryUrl", url);
        Fetch discovery = fetch(url);
        m.put("reachable", discovery.ok());
        if (!discovery.ok()) {
            m.put("ok", false);
            m.put("error", discovery.problem());
            return;
        }
        JsonObject doc;
        try {
            doc = new JsonObject(discovery.text());
        }
        catch (RuntimeException e) {
            m.put("ok", false);
            m.put("error", "The discovery document is not JSON.");
            return;
        }
        List<Map<String, Object>> mismatches = new ArrayList<>();
        List<String> matches = new ArrayList<>();
        if (compare) {
            OIDC_FIELDS.forEach((setting, field) -> {
                String configured = config.get(setting);
                String published = doc.getString(field);
                if (!present(configured)) {
                    return;
                }
                if (stripSlash(configured).equals(published == null ? null : stripSlash(published))) {
                    matches.add(setting);
                }
                else {
                    Map<String, Object> d = new LinkedHashMap<>();
                    d.put("setting", setting);
                    d.put("configured", configured);
                    d.put("published", published);
                    mismatches.add(d);
                }
            });
        }
        m.put("matches", matches);
        m.put("mismatches", mismatches);
        List<String> warnings = new ArrayList<>();
        if (compare && !"true".equals(config.get("validateSignature"))) {
            warnings.add("validateSignature is off: Keycloak does not check the signature of the IdP's tokens.");
        }
        String jwksUrl = compare && "true".equals(config.get("useJwksUrl")) && present(config.get("jwksUrl"))
                ? config.get("jwksUrl") : doc.getString("jwks_uri");
        if (present(jwksUrl)) {
            Fetch jwks = fetch(jwksUrl);
            Map<String, Object> keys = new LinkedHashMap<>();
            keys.put("url", jwksUrl);
            keys.put("reachable", jwks.ok());
            if (jwks.ok()) {
                try {
                    JsonArray list = new JsonObject(jwks.text()).getJsonArray("keys", new JsonArray());
                    List<Map<String, Object>> items = new ArrayList<>();
                    for (Object o : list) {
                        JsonObject k = (JsonObject) o;
                        Map<String, Object> v = new LinkedHashMap<>();
                        putIf(v, "kid", k.getString("kid"));
                        putIf(v, "kty", k.getString("kty"));
                        putIf(v, "alg", k.getString("alg"));
                        putIf(v, "use", k.getString("use"));
                        items.add(v);
                    }
                    keys.put("keys", items);
                    if (items.isEmpty()) {
                        warnings.add("The JWKS has no keys: no token of the IdP can be verified.");
                    }
                }
                catch (RuntimeException e) {
                    keys.put("error", "The JWKS is not JSON.");
                }
            }
            else {
                keys.put("error", jwks.problem());
                warnings.add("The JWKS cannot be fetched: Keycloak cannot verify the IdP's tokens with it.");
            }
            m.put("jwks", keys);
        }
        if (!warnings.isEmpty()) {
            m.put("warnings", warnings);
        }
        m.put("ok", mismatches.isEmpty() && !Boolean.FALSE.equals(m.get("reachable"))
                && warnings.stream().noneMatch(w -> w.startsWith("The JWKS")));
    }

    // ---- SAML ----------------------------------------------------------------------

    static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    static final String DS = "http://www.w3.org/2000/09/xmldsig#";

    private void saml(Map<String, Object> m, String url, Map<String, String> config) {
        m.put("metadataUrl", url);
        Fetch fetched = fetch(url);
        m.put("reachable", fetched.ok());
        if (!fetched.ok()) {
            m.put("ok", false);
            m.put("error", fetched.problem());
            return;
        }
        Document doc;
        try {
            doc = parse(fetched.body());
        }
        catch (Exception e) {
            m.put("ok", false);
            m.put("error", "The metadata is not readable XML: " + e.getMessage());
            return;
        }
        Element root = doc.getDocumentElement();
        Element entity = "EntityDescriptor".equals(root.getLocalName()) ? root
                : first(root.getElementsByTagNameNS(MD, "EntityDescriptor"));
        NodeList idps = root.getElementsByTagNameNS(MD, "IDPSSODescriptor");
        if (entity == null || idps.getLength() == 0) {
            m.put("ok", false);
            m.put("error", "The document has no SAML IdP descriptor (IDPSSODescriptor).");
            return;
        }
        Element idp = (Element) idps.item(0);
        List<Map<String, Object>> mismatches = new ArrayList<>();
        List<String> matches = new ArrayList<>();
        compare("idpEntityId", config.get("idpEntityId"), List.of(entity.getAttribute("entityID")), matches,
                mismatches);
        compare("singleSignOnServiceUrl", config.get("singleSignOnServiceUrl"), locations(idp, "SingleSignOnService"),
                matches, mismatches);
        compare("singleLogoutServiceUrl", config.get("singleLogoutServiceUrl"), locations(idp, "SingleLogoutService"),
                matches, mismatches);
        List<String> warnings = new ArrayList<>();
        List<Map<String, Object>> certificates = new ArrayList<>();
        List<String> published = new ArrayList<>();
        NodeList keyDescriptors = idp.getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int i = 0; i < keyDescriptors.getLength(); i++) {
            Element kd = (Element) keyDescriptors.item(i);
            String use = kd.getAttribute("use");
            if (!use.isEmpty() && !"signing".equals(use)) {
                continue;
            }
            NodeList certs = kd.getElementsByTagNameNS(DS, "X509Certificate");
            for (int j = 0; j < certs.getLength(); j++) {
                String b64 = certs.item(j).getTextContent().replaceAll("\\s", "");
                published.add(b64);
                certificates.add(certificate(b64, warnings));
            }
        }
        m.put("signingCertificates", certificates);
        String configured = config.get("signingCertificate");
        if (present(configured)) {
            List<String> ours = List.of(configured.replaceAll("\\s", "").split(","));
            if (ours.stream().anyMatch(published::contains)) {
                matches.add("signingCertificate");
            }
            else {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("setting", "signingCertificate");
                d.put("configured", "a certificate the metadata does not publish");
                d.put("published", certificates.size() + " signing certificate(s)");
                mismatches.add(d);
            }
        }
        if ("true".equals(config.get("validateSignature")) && published.isEmpty()) {
            warnings.add("validateSignature is on, but the metadata publishes no signing certificate.");
        }
        else if (!"true".equals(config.get("validateSignature"))) {
            warnings.add("validateSignature is off: Keycloak does not check the signature of the IdP's responses.");
        }
        m.put("matches", matches);
        m.put("mismatches", mismatches);
        if (!warnings.isEmpty()) {
            m.put("warnings", warnings);
        }
        m.put("ok",
                mismatches.isEmpty() && certificates.stream().noneMatch(c -> Boolean.TRUE.equals(c.get("expired"))));
    }

    private static List<String> locations(Element idp, String service) {
        List<String> out = new ArrayList<>();
        NodeList nodes = idp.getElementsByTagNameNS(MD, service);
        for (int i = 0; i < nodes.getLength(); i++) {
            out.add(((Element) nodes.item(i)).getAttribute("Location"));
        }
        return out;
    }

    private static void compare(String setting, String configured, List<String> published, List<String> matches,
            List<Map<String, Object>> mismatches) {
        if (!present(configured)) {
            return;
        }
        if (published.contains(configured)) {
            matches.add(setting);
            return;
        }
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("setting", setting);
        d.put("configured", configured);
        d.put("published", published.size() == 1 ? published.getFirst() : published);
        mismatches.add(d);
    }

    static Map<String, Object> certificate(String b64, List<String> warnings) {
        Map<String, Object> v = new LinkedHashMap<>();
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(b64)));
            Instant notAfter = cert.getNotAfter().toInstant();
            long days = Duration.between(Instant.now(), notAfter).toDays();
            v.put("subject", cert.getSubjectX500Principal().getName());
            v.put("notAfter", notAfter.toString());
            v.put("daysLeft", days);
            if (notAfter.isBefore(Instant.now())) {
                v.put("expired", true);
                warnings.add("A signing certificate expired on " + notAfter + ".");
            }
            else if (days < WARN_DAYS) {
                warnings.add("A signing certificate expires in " + days + " days.");
            }
        }
        catch (Exception e) {
            v.put("error", "not a readable X.509 certificate");
        }
        return v;
    }

    /** XML without DTDs, external entities or XInclude. */
    static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }

    private static Element first(NodeList nodes) {
        return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
    }

    // ---- fetching ------------------------------------------------------------------

    /** A fetched document, or why there is none. */
    record Fetch(byte[] body, String problem) {

        boolean ok() {
            return problem == null;
        }

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    Fetch fetch(String url) {
        URI uri;
        try {
            uri = URI.create(url.trim());
        }
        catch (IllegalArgumentException e) {
            return new Fetch(null, "Not a valid URL: " + url);
        }
        if (!Set.of("http", "https").contains(String.valueOf(uri.getScheme()).toLowerCase())) {
            return new Fetch(null, "Only http and https URLs are fetched, not " + url);
        }
        Optional<String> refused = HostAddressCheck.refuse(url, allowedHosts, privateHosts);
        if (refused.isPresent()) {
            return new Fetch(null, "Not fetched: " + refused.get()
                .replace("a system registered at runtime", "a URL from an identity provider's settings"));
        }
        try (HttpClient client = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()) {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(TIMEOUT)
                    .header("Accept", "application/json, application/samlmetadata+xml, application/xml")
                    .GET()
                    .build();
            try {
                HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
                try (InputStream in = response.body()) {
                    int status = response.statusCode();
                    if (status >= 300 && status < 400) {
                        return new Fetch(null,
                                "HTTP " + status + " redirect to " + response.headers().firstValue("Location").orElse("?")
                                + "; redirects are not followed," + " configure the final URL");
                    }
                    if (status != 200) {
                        return new Fetch(null, "HTTP " + status + " from " + url);
                    }
                    byte[] body = in.readNBytes(MAX_BYTES + 1);
                    if (body.length > MAX_BYTES) {
                        return new Fetch(null, "The document is larger than " + MAX_BYTES + " bytes.");
                    }
                    return new Fetch(body, null);
                }
            } catch (IOException e) {
                return new Fetch(null, "Cannot reach " + uri.getHost() + ": " + e.getClass().getSimpleName()
                                       + (e.getMessage() == null ? "" : " (" + e.getMessage() + ")"));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new Fetch(null, "Interrupted while fetching " + url);
            }
        }
    }

    // ---- helpers -------------------------------------------------------------------

    private static boolean present(String v) {
        return v != null && !v.isBlank();
    }

    private static String stripSlash(String v) {
        return v.endsWith("/") ? v.substring(0, v.length() - 1) : v;
    }

    private static void putIf(Map<String, Object> m, String key, Object value) {
        if (value != null) {
            m.put(key, value);
        }
    }

    private static Map<String, String> orderedMap(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }
}
