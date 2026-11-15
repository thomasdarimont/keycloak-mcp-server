package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.time.Duration;
import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmerSpi;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * {@code kc-mcp.spi.confirmer.ciba.*}: the OpenID Connect CIBA client the server asks the
 * OpenID provider to authenticate the caller with before a destructive tool runs. Only
 * the standard flow is used (discovery, {@code backchannel_authentication_endpoint},
 * {@code login_hint}, {@code binding_message}, poll mode at the token endpoint), so any
 * CIBA-capable provider works; Keycloak is the one the tests run against.
 *
 * @param enabled off by default
 * @param issuer issuer URL of the CIBA client, or {@code caller} for the issuer of the
 * caller's token (the default; the auth realm when the token has no issuer)
 * @param tokenIssuer the {@code iss} the provider's tokens carry when it differs from the
 * URL the server reaches the provider at (a container reaching Keycloak as
 * {@code http://keycloak:8080} while the tokens say {@code http://localhost:8098}); the
 * approval's ID token is verified against it. Unset: the same as the issuer
 * @param clientId the confidential client registered for CIBA
 * @param clientSecret its secret
 * @param clientAuth {@code client_secret_basic} (default) or {@code client_secret_post}
 * @param scope requested scope, {@code openid} by default
 * @param acrValues optional {@code acr_values}, e.g. to demand a second factor on the
 * device
 * @param loginHint {@code username} (the caller's name) or the name of a token claim
 * ({@code email}, {@code sub}) the provider resolves the user by (Keycloak: the realm's
 * CIBA "authentication requested user hint")
 * @param bindingMessage whether to send one; providers limit its length and characters,
 * the server keeps to Keycloak's rule (50 characters, no spaces)
 * @param bindingMessagePrefix start of the binding message shown on the device, followed
 * by a hash of the operation
 * @param requestedExpiry whether to ask for {@code requested_expiry} = the timeout
 * @param timeoutSeconds how long to wait for the approval; capped by the provider's
 * {@code expires_in}
 * @param when {@code always}, or {@code without-elicitation} to let a client that can ask
 * the human itself do so
 * @param flow {@code two-step} (default): the tool answers {@code confirmation_required}
 * right after filing the request, with the number the device asks for, and the next call
 * with the same arguments collects the approval; {@code blocking}: the call waits for the
 * device (no number matching possible, the chat shows nothing while waiting)
 * @param numberMatching two-step only: a two-digit number travels to the device as the
 * additional request parameter {@code code} and is shown to the model; the device asks
 * the user for it, so a request the user did not trigger cannot be approved (as Entra
 * ID's number matching)
 * @param extraParameters send {@code requester} (the MCP client's name) and
 * {@code operation} as additional request parameters for the device to show; providers
 * ignore parameters they do not know (Keycloak forwards up to five)
 * @param connectTimeout connect timeout of the calls to the provider; {@code null} for
 * {@code kc-mcp.http.connect-timeout}
 * @param readTimeout read timeout of those calls; {@code null} for
 * {@code kc-mcp.http.read-timeout}
 * @param tlsConfigurationName named TLS configuration ({@code quarkus.tls.<name>.*}) for
 * the calls to the provider, e.g. a trust store for a private CA; {@code null} for the
 * JVM's default trust
 * @param pollWaitSeconds two-step only: how long the collecting call waits for the device
 * before answering "still waiting"
 */
public record CibaSettings(boolean enabled, String issuer, String tokenIssuer, String clientId, String clientSecret,
        ClientAuth clientAuth, String scope, String acrValues, String loginHint, boolean bindingMessage,
        String bindingMessagePrefix, boolean requestedExpiry, int timeoutSeconds, When when, Flow flow,
        boolean numberMatching, boolean extraParameters, int pollWaitSeconds, String tlsConfigurationName,
        Duration connectTimeout, Duration readTimeout) {

    public enum Flow {
        TWO_STEP, BLOCKING
    }

    public enum ClientAuth {
        BASIC, POST
    }

    public static final String ID = "ciba";

    public enum When {
        ALWAYS, WITHOUT_ELICITATION
    }

    public static final ConfigProperty ISSUER = ConfigProperty.string("issuer").withDefault("caller");
    public static final ConfigProperty TOKEN_ISSUER = ConfigProperty.string("token-issuer");
    public static final ConfigProperty CLIENT_ID = ConfigProperty.string("client-id").asRequired();
    public static final ConfigProperty CLIENT_SECRET = ConfigProperty.string("client-secret")
        .asConfidential()
        .asRequired();
    public static final ConfigProperty CLIENT_AUTH = ConfigProperty
        .choice("client-auth", "client_secret_basic", "client_secret_post")
        .withAliases("basic", "client_secret_basic", "client-secret-basic", "client_secret_basic", "post",
                "client_secret_post", "client-secret-post", "client_secret_post")
        .withDefault("client_secret_basic");
    public static final ConfigProperty SCOPE = ConfigProperty.string("scope").withDefault("openid");
    public static final ConfigProperty ACR_VALUES = ConfigProperty.string("acr-values");
    public static final ConfigProperty LOGIN_HINT = ConfigProperty.string("login-hint").withDefault("username");
    public static final ConfigProperty BINDING_MESSAGE = ConfigProperty.bool("binding-message").withDefault("true");
    public static final ConfigProperty BINDING_MESSAGE_PREFIX = ConfigProperty.string("binding-message-prefix")
        .withDefault("kc-mcp");
    public static final ConfigProperty REQUESTED_EXPIRY = ConfigProperty.bool("requested-expiry").withDefault("false");
    public static final ConfigProperty TIMEOUT_SECONDS = ConfigProperty.integer("timeout-seconds");
    public static final ConfigProperty WHEN = ConfigProperty.choice("when", When.class)
        .withAliases("without_elicitation", "without-elicitation", "no-elicitation", "without-elicitation",
                "no_elicitation", "without-elicitation", "fallback", "without-elicitation")
        .withDefault("always");
    public static final ConfigProperty FLOW = ConfigProperty.choice("flow", Flow.class)
        .withAliases("two_step", "two-step", "2-step", "two-step", "2_step", "two-step", "async", "two-step", "wait",
                "blocking", "sync", "blocking")
        .withDefault("two-step");
    public static final ConfigProperty NUMBER_MATCHING = ConfigProperty.bool("number-matching").withDefault("true");
    public static final ConfigProperty EXTRA_PARAMETERS = ConfigProperty.bool("extra-parameters").withDefault("true");
    public static final ConfigProperty POLL_WAIT_SECONDS = ConfigProperty.integer("poll-wait-seconds").withDefault("5");
    public static final ConfigProperty TLS_CONFIGURATION_NAME = ConfigProperty.string("tls-configuration-name");
    public static final ConfigProperty CONNECT_TIMEOUT = ConfigProperty.duration("connect-timeout");
    public static final ConfigProperty READ_TIMEOUT = ConfigProperty.duration("read-timeout");

    /**
     * The client is required once CIBA is switched on ({@code enabled=true}): a
     * confidential client with the CIBA grant.
     */
    public static final ConfigSpec CONFIG_SPEC = ConfigSpec
        .of(ISSUER, TOKEN_ISSUER, CLIENT_ID, CLIENT_SECRET, CLIENT_AUTH, SCOPE, ACR_VALUES, LOGIN_HINT, BINDING_MESSAGE,
                BINDING_MESSAGE_PREFIX, REQUESTED_EXPIRY, TIMEOUT_SECONDS, WHEN, FLOW, NUMBER_MATCHING,
                EXTRA_PARAMETERS, POLL_WAIT_SECONDS, TLS_CONFIGURATION_NAME, CONNECT_TIMEOUT, READ_TIMEOUT)
        .withHints(
                ConfigHint.group("provider", ISSUER.name(), TOKEN_ISSUER.name(), TLS_CONFIGURATION_NAME.name(),
                        CONNECT_TIMEOUT.name(), READ_TIMEOUT.name()),
                ConfigHint.group("client", CLIENT_ID.name(), CLIENT_SECRET.name(), CLIENT_AUTH.name(), SCOPE.name()),
                ConfigHint.group("request", LOGIN_HINT.name(), ACR_VALUES.name(), BINDING_MESSAGE.name(),
                        BINDING_MESSAGE_PREFIX.name(), REQUESTED_EXPIRY.name(), EXTRA_PARAMETERS.name()),
                ConfigHint.group("approval", WHEN.name(), FLOW.name(), NUMBER_MATCHING.name(), TIMEOUT_SECONDS.name(),
                        POLL_WAIT_SECONDS.name()),
                ConfigHint.when(CLIENT_ID.name()).is("enabled", "true"),
                ConfigHint.when(CLIENT_SECRET.name()).is("enabled", "true"),
                ConfigHint.when(BINDING_MESSAGE_PREFIX.name()).is(BINDING_MESSAGE.name(), "true"),
                ConfigHint.when(NUMBER_MATCHING.name()).is(FLOW.name(), "two-step"),
                ConfigHint.when(POLL_WAIT_SECONDS.name()).is(FLOW.name(), "two-step"));

    public static CibaSettings from(McpServerConfig server) {
        return from(ProviderConfig.forExtension(ConfirmerSpi.NAME, ID, CONFIG_SPEC, server),
                server.confirmTimeoutSeconds());
    }

    public static CibaSettings from(ProviderConfig settings, int defaultTimeout) {
        ProviderConfig config = settings.withSpec(CONFIG_SPEC)
            .describedAs(ProviderConfig.PREFIX + ConfirmerSpi.NAME + "." + ID + ".");
        List<ConfigProblem> errors = ConfigProblem.errors(config.problems());
        if (!errors.isEmpty()) {
            boolean client = errors.stream()
                .anyMatch(p -> p.properties().contains(CLIENT_ID.name())
                        || p.properties().contains(CLIENT_SECRET.name()));
            throw new IllegalStateException(ConfigProblem.describe(errors)
                    + (client ? " (a confidential Keycloak client with the CIBA grant enabled)" : ""));
        }
        boolean enabled = config.getBoolean("enabled", false);
        String clientId = config.readString(CLIENT_ID);
        String secret = config.readString(CLIENT_SECRET);
        ClientAuth clientAuth = "client_secret_post".equals(config.readChoice(CLIENT_AUTH)) ? ClientAuth.POST
                : ClientAuth.BASIC;
        return new CibaSettings(enabled, config.readString(ISSUER), config.readString(TOKEN_ISSUER), clientId, secret,
                clientAuth, config.readString(SCOPE), config.readString(ACR_VALUES), config.readString(LOGIN_HINT),
                config.readBoolean(BINDING_MESSAGE), config.readString(BINDING_MESSAGE_PREFIX),
                config.readBoolean(REQUESTED_EXPIRY),
                config.isSet(TIMEOUT_SECONDS) ? config.readInt(TIMEOUT_SECONDS) : defaultTimeout,
                config.readEnum(WHEN, When.class), config.readEnum(FLOW, Flow.class),
                config.readBoolean(NUMBER_MATCHING), config.readBoolean(EXTRA_PARAMETERS),
                config.readInt(POLL_WAIT_SECONDS), config.readString(TLS_CONFIGURATION_NAME),
                config.readDuration(CONNECT_TIMEOUT), config.readDuration(READ_TIMEOUT));
    }

    /** Whether the issuer comes from the caller's token. */
    public boolean issuerFromCaller() {
        return "caller".equalsIgnoreCase(issuer);
    }
}
