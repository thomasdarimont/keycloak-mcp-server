package com.github.thomasdarimont.keycloak.mcp.config;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithConverter;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithParentName;

/**
 * Server configuration. Every property maps to an env variable with the {@code KC_MCP_}
 * prefix, e.g. {@code kc-mcp.systems.default.url} -> {@code KC_MCP_SYSTEMS_DEFAULT_URL}.
 */
@ConfigMapping(prefix = "kc-mcp")
public interface McpServerConfig {

    /**
     * Security profile: {@code local} (default, one person's machine) or {@code shared}
     * (a server others reach over the network). The profile sets the defaults of
     * {@link #requireCaller()}, {@link #confirmFallback()} and {@link #explicitTarget()}
     * and, as {@code shared}, refuses to start without caller authentication with an
     * audience (where the instance serves the MCP endpoint, {@link #instanceRole()}),
     * {@link #allowedHosts()}, an admin API audience and an encrypted storage.
     */
    @WithDefault("local")
    @WithConverter(SecurityProfile.Converter.class)
    SecurityProfile securityProfile();

    /**
     * What this instance serves: {@code all} (default), {@code mcp} (the MCP endpoint
     * only) or {@code admin} (the admin API and the management UI only). Sets the
     * defaults of {@code kc-mcp.mcp.enabled}, {@code kc-mcp.admin.enabled} and
     * {@code kc-mcp.ui.enabled}; one of them set against the role stops the start.
     */
    @WithDefault("all")
    @WithConverter(InstanceRole.Converter.class)
    InstanceRole instanceRole();

    /**
     * The Keycloak systems, one block each: {@code kc-mcp.systems.<name>.url} and the
     * other {@link SystemSettings}; a system exists exactly when its {@code url} is set.
     * Every setting a system leaves out comes from {@link #systemDefaults()}, then from
     * the built-in default. With several systems the tools gain a {@code system}
     * argument. Environment form: {@code KC_MCP_SYSTEMS_DEFAULT_URL} (names from the
     * environment are lower-case letters and digits).
     */
    Map<String, SystemSettings> systems();

    /**
     * Settings shared by every system that does not set its own:
     * {@code kc-mcp.system-defaults.client-id}, {@code .grant-type}, {@code .auth-realm},
     * {@code .allowed-realms} and the rest of {@link SystemSettings}; {@code url} has no
     * meaning here and is refused.
     */
    SystemSettings systemDefaults();

    /**
     * System used when the {@code system} argument is omitted: the one named here, else
     * the only system, else the one called {@code default}.
     */
    Optional<String> defaultSystem();

    /**
     * For whom the explanation is worded when a tool cannot run on this server:
     * {@code admins} (configuration details and {@code howToFix}), {@code users} (plain:
     * not available here, an administrator can change it) or {@code auto} (by the
     * caller's roles in delegation mode, else admins). Unrelated to the OAuth audience.
     */
    @WithDefault("auto")
    @WithConverter(Explanations.Converter.class)
    Explanations explanations();

    /**
     * Optional prefix for every tool name, e.g. {@code prod_} ->
     * {@code prod_keycloak_user_search}.
     */
    Optional<String> toolPrefix();

    /** Key settings for {@link ClientAuth#PRIVATE_KEY_JWT}. */
    Jwt jwt();

    /**
     * Whether registered {@code KeycloakSystemRepository}s may add systems at runtime.
     * Off by default: a repository found on the class path is then listed in the log but
     * not asked, so an extension cannot point the server at a Keycloak it was not
     * configured for. Each repository can additionally be switched with
     * {@code kc-mcp.spi.<spi>.<id>.enabled}.
     */
    @WithDefault("false")
    boolean dynamicSystems();

    /**
     * JSON file the built-in file repository reads ({@code {"systems": [...]}}), re-read
     * when it changes; needs {@code kc-mcp.dynamic-systems=true}. A relative path is
     * resolved like {@code kc-mcp.providers-dir}.
     */
    Optional<String> systemsFile();

    /**
     * Whether the top-level / {@code kc-mcp.systems.*} settings define systems.
     * {@code false} for deployments whose systems come from sources only; then at least
     * one source must be registered and enabled.
     */
    @WithDefault("true")
    boolean staticSystems();

    /**
     * Where the static configuration ranks among the system repositories (lower is asked
     * first; registered repositories default to 0). The default puts the static
     * configuration first, so a repository cannot redefine a configured system; raise it
     * above the repositories' order to let them take precedence.
     */
    @WithDefault("-1000")
    int staticSystemsOrder();

    /**
     * Directory of the built-in
     * {@link com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault}: one PEM file per
     * system with the {@code private_key_jwt} key generated for it, used when no
     * {@code kc-mcp.jwt.key-file} / {@code keystore-file} is configured. A relative path
     * is resolved like {@code kc-mcp.providers-dir}.
     */
    @WithDefault("data/keys")
    String keysDir();

    /**
     * {@code off} (default): admin calls use the server's own credentials;
     * {@code forward}: the caller's access token is forwarded to the Admin API, so
     * Keycloak enforces the user's own roles; {@code exchange}: the caller's token is
     * exchanged for a delegated token whose actor is the server's own client (Keycloak
     * 26.8 token exchange delegation, needs the caller's consent and the client's
     * {@code delegate} permission). Both require the MCP endpoint to authenticate callers
     * ({@code quarkus.oidc.tenant-enabled=true}); {@code forward} makes the server
     * credentials optional, {@code exchange} needs a confidential client with a service
     * account.
     */
    @WithDefault("off")
    @WithConverter(DelegationMode.Converter.class)
    DelegationMode delegation();

    /**
     * Scope requested with every token the server obtains for the Admin API and
     * advertised to MCP clients in the protected resource metadata: Keycloak 26.8.2 and
     * later only accept Admin API tokens that carry the audience the built-in
     * {@code kc-admin-api} client scope adds. Older servers ignore an unknown scope; a
     * server that answers {@code invalid_scope} is asked again without it. Blank: never
     * request a scope.
     */
    @WithDefault("kc-admin-api")
    String adminApiScope();

    /**
     * Rejects MCP requests whose {@code Host} or {@code Origin} is not a localhost value
     * ({@code localhost}, {@code 127.0.0.1}, {@code ::1}, any port) or one of
     * {@link #dnsRebindingAllowedHosts()}: a web page on the same machine would otherwise
     * reach the anonymous endpoint through a DNS name that resolves to 127.0.0.1 (DNS
     * rebinding). {@code auto} (default) protects while the endpoint is anonymous
     * ({@code quarkus.oidc.tenant-enabled=false} and no required caller) and stands down
     * once callers authenticate; {@code on} and {@code off} decide outright. Only the MCP
     * endpoint is covered, JWKS and admin routes are not.
     */
    @WithDefault("auto")
    String dnsRebindingProtection();

    /**
     * {@code host} or {@code host:port} values accepted besides localhost, for an
     * anonymous server reached by name or through a proxy ({@code mcp.internal:8081}).
     */
    Optional<List<String>> dnsRebindingAllowedHosts();

    /**
     * Refuse unauthenticated MCP requests with a 401 challenge even when the server acts
     * with its own credentials (the caller then only matters for policies and the audit
     * log). Implied by {@code delegation=forward}.
     */
    @WithDefault("false")
    boolean requireCaller();

    /** Effective value: {@link #requireCaller()}, or always in profile {@code shared}. */
    default boolean callerRequired() {
        return requireCaller() || securityProfile().shared();
    }

    /**
     * What confirms a DESTRUCTIVE tool when the client has no elicitation: {@code flag}
     * ({@code confirm: true} in the arguments) or {@code deny} (refused until a client
     * with elicitation or another {@code Confirmer} confirms). Default: {@code flag} in
     * profile {@code local}, {@code deny} in {@code shared}.
     */
    @WithConverter(ConfirmFallback.Converter.class)
    Optional<ConfirmFallback> confirmFallback();

    /**
     * What the model is told about confirming destructive tools: {@code ask} (ask the
     * user once after {@code confirmation_required}, then {@code confirm: true}),
     * {@code server} (the server asks, through the client or the user's device: call
     * right away) or {@code auto} (default: {@code server} when a confirmer asks the
     * human itself, the client supports elicitation or {@code confirm: true} is not
     * accepted; else {@code ask}). Guidance only; the server enforces its confirmation
     * either way.
     */
    @WithDefault("auto")
    @WithConverter(ModelConfirmation.Converter.class)
    ModelConfirmation modelConfirmation();

    /**
     * Callers holding one of these roles ({@code realm:<role>} or
     * {@code <client>.<role>}, as in the policies) are assumed to know what they do: in
     * {@code ask} mode the model is told to pass {@code confirm: true} right away instead
     * of asking them first. Does not apply where the server asks itself.
     */
    Optional<List<String>> modelConfirmationTrustedRoles();

    /** Effective value of {@link #confirmFallback()}, by profile when unset. */
    default ConfirmFallback effectiveConfirmFallback() {
        return confirmFallback().orElse(securityProfile().shared() ? ConfirmFallback.DENY : ConfirmFallback.FLAG);
    }

    /**
     * Which tools must name {@code system} (when several exist) and {@code realm} instead
     * of taking the defaults: {@code off}, {@code destructive} or {@code write}. A
     * system-specific endpoint counts as explicit. Default: {@code off} in profile
     * {@code local}, {@code destructive} in {@code shared}.
     */
    @WithConverter(ExplicitTarget.Converter.class)
    Optional<ExplicitTarget> explicitTarget();

    /** Effective value of {@link #explicitTarget()}, by profile when unset. */
    default ExplicitTarget effectiveExplicitTarget() {
        return explicitTarget().orElse(securityProfile().shared() ? ExplicitTarget.DESTRUCTIVE : ExplicitTarget.OFF);
    }

    /**
     * Whether systems registered at runtime (admin API, repositories) may point at
     * private, loopback or link-local addresses: {@code allow}, or {@code listed} (only
     * hosts that {@link #allowedHosts()} names literally, without a wildcard). Static
     * systems are not checked. Default: {@code allow} in profile {@code local},
     * {@code listed} in {@code shared}.
     */
    @WithConverter(PrivateHosts.Converter.class)
    Optional<PrivateHosts> dynamicPrivateHosts();

    /** Effective value of {@link #dynamicPrivateHosts()}, by profile when unset. */
    default PrivateHosts effectiveDynamicPrivateHosts() {
        return dynamicPrivateHosts().orElse(securityProfile().shared() ? PrivateHosts.LISTED : PrivateHosts.ALLOW);
    }

    /**
     * Hosts the server may talk to: every configured Keycloak URL (top level and per
     * system) must match one of these patterns, checked at startup. Pattern
     * {@code [scheme://]host[:port]} with {@code *} wildcards, e.g.
     * {@code *.example.com}, {@code https://sso-*.corp.example.org},
     * {@code localhost:8080}. Empty = no restriction.
     */
    Optional<List<String>> allowedHosts();

    /** Hide and refuse every WRITE / DESTRUCTIVE tool. */
    @WithDefault("false")
    boolean readOnly();

    /** Only these tools exist on this server (csv of tool names). Empty = all. */
    Optional<List<String>> allowedTools();

    /**
     * These tools never exist on this server (csv). Wins over {@link #allowedTools()}.
     */
    Optional<List<String>> deniedTools();

    /**
     * Only tools of these categories exist (csv, e.g. {@code users,groups}). Empty = all.
     */
    Optional<List<String>> allowedCategories();

    /**
     * What happens to the tools {@link #allowedTools()} does not name: {@code allow},
     * {@code read} (only if they read: new write and destructive tools wait until listed)
     * or {@code deny}. Unset: {@code deny} with an allow-list, {@code allow} without.
     */
    @WithConverter(UnlistedTools.Converter.class)
    Optional<UnlistedTools> unlistedTools();

    /**
     * These tools need confirmation, as destructive ones do (csv). Systems, realms and
     * presets can add their own ({@code tools.confirm}).
     */
    Optional<List<String>> confirmTools();

    /**
     * Every tool that changes Keycloak needs confirmation, not only the destructive ones.
     */
    @WithDefault("false")
    boolean confirmWrites();

    /**
     * Hide and refuse tools whose realm-management roles the server's own token does not
     * hold.
     */
    @WithDefault("true")
    boolean roleFilter();

    /**
     * Startup check that every allowed realm is reachable with the credentials: off, warn
     * or fail.
     */
    @WithDefault("warn")
    String startupCheck();

    /** Which tools show up in {@code tools/list}. */
    @WithDefault("hybrid")
    @WithConverter(ExposureMode.Converter.class)
    ExposureMode toolExposure();

    /** Tools exposed directly in hybrid / progressive mode. */
    @WithDefault("keycloak_user_search,keycloak_user_get,keycloak_realm_get_config,keycloak_server_info")
    List<String> hotTools();

    /** Default number of hits returned by {@code search_tools}. */
    @WithDefault("5")
    int searchLimitDefault();

    /** Upper bound for the {@code max} pagination argument of list tools. */
    @WithDefault("100")
    int resultMaxItems();

    /**
     * Also return every tool result as MCP {@code structuredContent} (the JSON object
     * next to the text block), so clients can render it without parsing text.
     */
    @WithDefault("true")
    boolean structuredContent();

    /**
     * Per tool-provider settings: {@code kc-mcp.spi.<spi>.<id>.<key>=value} (env
     * {@code KC_MCP_SPI_<SPI>_<ID>_<KEY>}). {@code enabled=false} switches a provider
     * off.
     */
    Map<String, Spi> spi();

    /** The settings of one extension point, {@code kc-mcp.spi.<spi>.*}. */
    interface Spi {
        /**
         * Which extension serves an extension point that has exactly one: its id. Without
         * it the lowest {@code order()} wins.
         */
        Optional<String> provider();

        /** Per extension: {@code kc-mcp.spi.<spi>.<id>.<key>}. */
        @WithParentName
        Map<String, Map<String, String>> extensions();
    }

    /**
     * Presets every system can reference: {@code extends} and {@code <check>.<key>} per
     * preset name ({@link com.github.thomasdarimont.keycloak.mcp.keycloak.Preset}).
     */
    Map<String, Map<String, String>> presets();

    /** Elicitation / confirmation prompt timeout in seconds. */
    @WithDefault("120")
    int confirmTimeoutSeconds();

    /**
     * Directory with extension jars ({@code ToolProvider}, {@code PromptProvider},
     * {@code AccessCheck}, {@code Confirmer}, {@code AuditListener} implementations
     * registered through {@code META-INF/services}), like Keycloak's {@code providers/}.
     * A relative path is resolved against the directory of the application jar when the
     * server runs packaged, else the working directory. A missing directory loads
     * nothing. JVM mode only.
     */
    @WithDefault("providers")
    String providersDir();

    /**
     * Directory with prompts as plain text files: every {@code .md} file in it is one
     * prompt, a header that declares it followed by the recipe with placeholders
     * ({@code docs/tools.md}). Resolved like {@code kc-mcp.providers-dir}; a missing
     * directory loads nothing. Read once at startup, after the prompts of the extensions,
     * so a file here replaces a prompt of the same name from anywhere else.
     */
    @WithDefault("prompts")
    String promptsDir();

    /**
     * Whether a prompt may replace an earlier one of the same name: an extension's a
     * built-in one, a file of the prompts directory any other. Each replacement is logged
     * at startup. {@code false}: a name used twice stops the start.
     */
    @WithDefault("true")
    boolean promptOverrides();

    /**
     * Properties files read at startup, comma separated: the distribution's
     * {@code conf/kcmcp.conf} and the files its scripts pass with {@code --config}. They
     * rank above the server's defaults and below the environment and system properties; a
     * missing file stops the start (the backend's {@code ConfigFilesSourceFactory} loads
     * them).
     */
    Optional<String> configFiles();

    /**
     * Development mode, what {@code bin/kcmcp.sh start-dev} sets: when no system is
     * configured, the system {@code default} at {@code http://localhost:8080} (the
     * Keycloak of the examples) is assumed; the backend's
     * {@code DevModeInterceptorFactory} supplies it. Nothing else changes: the security
     * profile and the startup check are set separately.
     */
    @WithDefault("false")
    boolean devMode();

    /**
     * The MCP endpoint itself ({@code kc-mcp.mcp.*}). Off on an instance that serves only
     * the admin API or the management UI next to the MCP-facing ones, all on one
     * database: the endpoint and its entries answer a plain 404, everything else stays.
     */
    Mcp mcp();

    interface Mcp {
        @WithDefault("true")
        boolean enabled();
    }

    /**
     * The admin API ({@code kc-mcp.admin.*}, {@code /admin/systems}): registers systems
     * in the first mutable {@code KeycloakSystemRepository} (the database storage), with
     * their {@code private_key_jwt} keys created in the {@code KeyVault}. Callers present
     * either the static {@link Admin#token()} or an access token of the trusted
     * {@link Admin#issuer()} that carries {@link Admin#role()}.
     */
    Admin admin();

    /**
     * The management UI ({@code kc-mcp.ui.*}, served at {@code /ui} with its BFF under
     * {@code /bff}): the server acts as an OIDC relying party (authorization code flow
     * with PKCE) and keeps the tokens of a browser session in a {@code UserSessionStore},
     * the browser only holds an opaque session id in an HttpOnly, Secure cookie.
     */
    Ui ui();

    /**
     * The server's OpenTelemetry metrics ({@code kc-mcp.metrics.*}); export is Quarkus'
     * {@code quarkus.otel.*}.
     */
    Metrics metrics();

    /**
     * Additional trusted certificates for outbound TLS: PEM files, unencrypted PKCS12
     * files, directories of them. Read by the truststore interceptor before the server
     * starts; declared here so the option is known.
     */
    Optional<List<String>> truststorePaths();

    /**
     * The address clients use, {@code scheme://host[:port]}: fixes the links the server
     * hands out instead of taking them from each request's headers.
     */
    Optional<String> hostname();

    /** PEM server certificate or chain; see {@code HttpsInterceptorFactory}. */
    Optional<String> httpsCertificateFile();

    /** PEM private key of the server certificate. */
    Optional<String> httpsCertificateKeyFile();

    /** Password of an encrypted PEM (PKCS#8) key. */
    Optional<String> httpsCertificateKeyFilePassword();

    /** PKCS12 or JKS key store with the server certificate. */
    Optional<String> httpsKeyStoreFile();

    /** Password of the key store. */
    Optional<String> httpsKeyStorePassword();

    /** Type of the key store; by default from the file's extension. */
    Optional<String> httpsKeyStoreType();

    /** The HTTPS port. */
    Optional<Integer> httpsPort();

    /** TLS protocols to enable. */
    Optional<List<String>> httpsProtocols();

    /** TLS cipher suites to enable. */
    Optional<List<String>> httpsCipherSuites();

    /** How often certificate files are reloaded, {@code -1} never. */
    Optional<String> httpsCertificatesReloadPeriod();

    /** Whether the plain HTTP listener stays on. */
    Optional<Boolean> httpEnabled();

    /**
     * Outbound HTTP of the server's own clients ({@code kc-mcp.http.*}): the Keycloak
     * admin client (read timeout; its connect timeout is the client's built-in 15 s), the
     * CIBA confirmer and the UI's calls to its identity providers, each overridable.
     */
    Http http();

    interface Http {
        /** Time to establish a connection ({@code 10s}, {@code 500ms}, {@code PT10S}). */
        @WithDefault("10s")
        @WithConverter(Durations.DurationConverter.class)
        Duration connectTimeout();

        /**
         * Time to wait for an answer. Generous by default: admin calls such as a
         * directory sync or a partial export can take a while.
         */
        @WithDefault("60s")
        @WithConverter(Durations.DurationConverter.class)
        Duration readTimeout();
    }

    interface Metrics {
        /**
         * Add the {@code realm} attribute to the tool call metrics. Off by default: a
         * multi-tenant server can have thousands of realms, one series each.
         */
        @WithDefault("false")
        boolean includeRealm();
    }

    interface Admin {
        /** Off by default; on needs a {@link #token()} or an {@link #issuer()}. */
        @WithDefault("false")
        boolean enabled();

        /**
         * Static bearer token admin requests may carry (automation without an OAuth
         * client).
         */
        Optional<String> token();

        /**
         * OAuth authorization server whose access tokens the admin API accepts, as the
         * realm URL ({@code https://sso.example.com/realms/master}); its discovery
         * document and keys are fetched from there.
         */
        Optional<String> issuer();

        /** Audience such a token must carry; unset accepts any. */
        Optional<String> audience();

        /**
         * Role such a token must carry, in the server's notation: {@code realm:<role>}
         * for a realm role, {@code <client>.<role>} for a client role. The default is the
         * {@code admin} realm role of a Keycloak master realm.
         */
        @WithDefault("realm:admin")
        String role();

        /**
         * Whether the admin API registers systems it does not know yet. {@code false}
         * freezes the set of systems: {@code PUT}/{@code POST} for a new alias answers
         * 403 {@code registration_closed}, while known systems can still be updated and
         * removed, keys rotated, secrets and storage managed.
         */
        @WithDefault("true")
        boolean allowNewSystems();

        /**
         * Whether the admin API's OpenAPI document ({@code /q/openapi}) and Swagger UI
         * are served; {@code false} answers 404 for both. The document carries no secrets
         * and is served whether the API itself is on or not, so a server that should not
         * even describe the API switches it off here.
         */
        @WithDefault("true")
        boolean openapi();
    }

    interface Ui {
        /**
         * Off by default. On needs a {@code UserSessionStore} (the database storage); the
         * identity providers are contacted on the first login.
         */
        @WithDefault("false")
        boolean enabled();

        /**
         * Identity provider the UI's users log in at when no {@link #idps()} are
         * configured, as the realm URL ({@code https://sso.example.com/realms/master}).
         * Defaults to {@code kc-mcp.admin.issuer}, else
         * {@code <url>/realms/<auth-realm>}.
         */
        Optional<String> issuer();

        /**
         * The OIDC client the server logs users in with at that provider: a public client
         * (PKCE S256) unless {@link #clientSecret()} is set; standard flow, redirect URI
         * {@code <server>/bff/login}, post logout redirect URI {@code <server>/ui/*}.
         */
        @WithDefault("keycloak-mcp-ui")
        String clientId();

        /** Set for a confidential client; unset keeps the client public. */
        Optional<String> clientSecret();

        /**
         * How long after its ID token expired a browser session is still renewed with the
         * refresh token before the user has to sign in again: the provider's SSO idle
         * timeout (Keycloak's default is 30 minutes). Per provider in
         * {@link IdpSettings#sessionAgeExtension()}.
         */
        @WithDefault("PT30M")
        Duration sessionAgeExtension();

        /**
         * Named identity providers ({@code kc-mcp.ui.idps.<alias>.issuer} etc.) when the
         * UI offers more than one way to sign in: each becomes a login choice
         * ({@code /bff/login?idp=<alias>}) and its own OIDC tenant; a session remembers
         * the alias it came from. Without any, the top-level issuer and client form the
         * single provider {@code default}.
         */
        Map<String, IdpSettings> idps();

        /**
         * Named TLS configuration ({@code quarkus.tls.<name>.*}) the server's own calls
         * to the identity providers use (discovery, keys, session checks), for providers
         * behind a private CA. Unset: the JVM's default trust. Quarkus' OIDC login has
         * its own ({@code quarkus.oidc.tls.tls-configuration-name}).
         */
        Optional<String> tlsConfigurationName();

        /**
         * Connect timeout of those calls; falls back to
         * {@code kc-mcp.http.connect-timeout}.
         */
        @WithConverter(Durations.DurationConverter.class)
        Optional<Duration> connectTimeout();

        /**
         * Read timeout of those calls; falls back to {@code kc-mcp.http.read-timeout}.
         */
        @WithConverter(Durations.DurationConverter.class)
        Optional<Duration> readTimeout();

        /**
         * Optional read-only role for the management UI (same notation as
         * {@link Admin#role()}: {@code realm:<role>} or {@code <client>.<role>}). Holders
         * may call safe {@code /bff/api/*} methods and see the UI; writes still need
         * {@link Admin#role()}. Unset: only the admin role opens the API (unchanged from
         * before).
         */
        Optional<String> viewerRole();

        /**
         * Where the management UI links the trace of an audit event to: the URL of a
         * tracing or logging system with {@code {traceId}} (and optionally
         * {@code {spanId}}) in it, e.g.
         * {@code https://jaeger.example.com/trace/{traceId}} or a Grafana Explore link
         * that searches Loki for the id. Unset, the ids are shown without a link. Events
         * carry a trace only while tracing is on
         * ({@code quarkus.otel.sdk.disabled=false}).
         */
        Optional<String> traceUrl();
    }

    /** One identity provider of the management UI. */
    interface IdpSettings {
        /** Realm URL of the provider; required. */
        String issuer();

        /** Falls back to {@link Ui#clientId()}. */
        Optional<String> clientId();

        /**
         * Falls back to {@link Ui#clientSecret()} when neither is set the client is
         * public.
         */
        Optional<String> clientSecret();

        /** What the sign-in button says; defaults to the alias. */
        Optional<String> displayName();

        /** Falls back to {@link Ui#sessionAgeExtension()}. */
        Optional<Duration> sessionAgeExtension();

        /**
         * {@code true} keeps the provider off the login page (a tenant's provider on a
         * shared server); its users sign in through {@code /bff/login?idp=<alias>}, and
         * the UI names it once they are signed in. As Keycloak's own identity provider
         * setting of that name.
         */
        Optional<Boolean> hideOnLoginPage();
    }

    /**
     * One Keycloak system, or the shared defaults
     * ({@link McpServerConfig#systemDefaults()}).
     */
    interface SystemSettings {
        /**
         * Base URL, context path included; set only per system, it is what makes a system
         * exist.
         */
        Optional<String> url();

        @WithConverter(GrantType.Converter.class)
        Optional<GrantType> grantType();

        @WithConverter(ClientAuth.Converter.class)
        Optional<ClientAuth> clientAuth();

        Optional<String> authRealm();

        Optional<String> clientId();

        Optional<String> clientSecret();

        Optional<String> username();

        Optional<String> password();

        Optional<String> defaultRealm();

        Optional<List<String>> allowedRealms();

        /**
         * Issuers besides this system's own Keycloak whose caller tokens the server may
         * hand to it: a realm's issuer URL ({@code https://sso.example/realms/demo}) for
         * that realm alone, a Keycloak's base URL ({@code https://sso.example}) for every
         * realm of it (see {@code CallerIssuerPolicy}). This is the server's side only:
         * whether the target Keycloak accepts such a token is decided there, by its
         * identity provider and JWT authorization grant settings; an entry Keycloak does
         * not honour moves the refusal from this server to Keycloak. Empty by default: a
         * token stays with the Keycloak that issued it.
         */
        Optional<List<String>> trustedIssuers();

        /**
         * Keycloak version of this system ({@code 26.8.2}), for the version checks of the
         * tools. Wins over the version the admin server info reports (a difference is
         * logged) and stands in when the server info is not readable; unset, the reported
         * version applies, and without either the version checks are off.
         */
        Optional<String> version();

        /**
         * Issuer of this system's auth realm as Keycloak states it
         * ({@code https://sso.example.com/realms/master}), for a {@link #url()} that is
         * internal and differs from Keycloak's public hostname. It is the {@code aud} of
         * the {@code private_key_jwt} client assertions, and the public base URL of this
         * Keycloak is derived from it. Unset, {@code <url>/realms/<auth-realm>} applies.
         */
        Optional<String> issuer();

        /**
         * The access checks that govern this system's tool calls, per check id
         * ({@link com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings}):
         * {@code enabled}, {@code order} and the check's settings over
         * {@code kc-mcp.spi.access-check.<id>.*}; ignored in
         * {@code kc-mcp.system-defaults}.
         */
        Map<String, Map<String, String>> access();

        /** The preset the system's {@link #access()} goes over. */
        Optional<String> preset();

        /**
         * Tool restrictions of this system over the server's, which they can only tighten
         * ({@link com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings}):
         * {@code read-only}, {@code allowed}, {@code denied}, {@code categories}; ignored
         * in {@code kc-mcp.system-defaults}.
         */
        Map<String, String> tools();

        /**
         * The system's own presets: {@code extends} and {@code <check>.<key>} per preset
         * name; ignored in {@code kc-mcp.system-defaults}.
         */
        Map<String, Map<String, String>> presets();

        /**
         * Settings of single realms of this system, on top of the system's
         * ({@link com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings});
         * ignored in {@code kc-mcp.system-defaults}.
         */
        Map<String, RealmConfig> realms();
    }

    /** One realm of a system: {@code kc-mcp.systems.<name>.realms.<realm>.*}. */
    interface RealmConfig {
        /** Keycloak's internal id of the realm, which stays when it is renamed. */
        Optional<String> realmId();

        /** A name for people. */
        Optional<String> displayName();

        /** Free text for people: what the realm is, who owns it. */
        Optional<String> description();

        /** Over the system's {@link SystemSettings#access()}, check by check. */
        Map<String, Map<String, String>> access();

        /** The preset the realm's {@link #access()} goes over. */
        Optional<String> preset();

        /** Over the system's {@link SystemSettings#tools()}. */
        Map<String, String> tools();
    }

    interface Jwt {
        /**
         * Path to a PEM file with the client's private key (PKCS#8,
         * {@code BEGIN PRIVATE KEY}).
         */
        Optional<String> keyFile();

        /** Alternatively: a PKCS12/JKS keystore holding the private key. */
        Optional<String> keystoreFile();

        Optional<String> keystorePassword();

        @WithDefault("PKCS12")
        String keystoreType();

        Optional<String> keyAlias();

        /** Password of the key entry; defaults to the keystore password. */
        Optional<String> keyPassword();

        /**
         * Public key / certificate PEM to publish in the JWKS; derived from the private
         * key when unset.
         */
        Optional<String> publicKeyFile();

        /**
         * {@code kid} in the JWS header and the JWKS; defaults to the RFC 7638 thumbprint
         * of the public key.
         */
        Optional<String> keyId();

        /**
         * Serve the public key as a JWK Set so Keycloak can fetch it via the client's
         * "JWKS URL" setting.
         */
        @WithDefault("true")
        boolean jwksEnabled();

        /** HTTP path of the JWK Set. */
        @WithDefault("/.well-known/jwks.json")
        String jwksPath();

        /**
         * RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384 or PS512. Also decides
         * what kind of key the vault generates for a system (RSA, or EC on the matching
         * curve).
         */
        @WithDefault("RS256")
        String algorithm();

        /** Modulus bits of generated RSA keys (2048 or more). */
        @WithDefault("2048")
        int keySize();

        /** Lifetime of each client assertion in seconds. */
        @WithDefault("60")
        int assertionLifespan();
    }
}
