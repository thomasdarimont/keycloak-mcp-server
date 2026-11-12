# Extending

[keycloak-mcp-server](../README.md) › documentation

The extension SPI of the `api` module: tools, prompts, access checks, confirmers, profile checks, audit listeners and scrubbers, system repositories and key vaults; how extension jars are loaded. Worked example: `examples/extensions/`.

Depend on `com.github.thomasdarimont.keycloak:keycloak-mcp-server-api` (module `api`; Keycloak admin client and Vert.x
JSON, no Quarkus; automatic module `com.github.thomasdarimont.keycloak.mcp.api`). Packages under
`com.github.thomasdarimont.keycloak.mcp`:

- `spi`: `Extension`, `ExtensionRegistry`, `ExtensionContext`, `ProviderConfig`
- `tools`: `ToolProvider`, `ToolProviderContext`, `AbstractToolProvider`
- `prompts`: `PromptProvider`
- `access`: `AccessCheck`, `Caller`, `GrantedRoles`, `RoleRef`, `Delegation`
- `confirm`: `Confirmer`, `ConfirmationRequest`, `Decision`, `Prompter`
- `audit`: `AuditListener`, `AuditEvent`, `AuditScrubber`
- `catalog`: `ToolSpec`, `ToolCall`, `ToolResult`, `InputSchema`, `Category`, `ToolLevel`, prompt descriptions
- `keycloak`: `KeycloakAdmin`, `KeycloakSystems`, `KeycloakSystemRepository`, `KeyVault`, `SigningKeyGenerator`,
  capabilities, host allow list, `Views`
- `config`: server configuration interface, `SecurityProfile`, `ProfileCheck`

```java
public class AcmeToolProvider implements ToolProvider {
    public String id() { return "acme"; }
    public String displayName() { return "ACME tools"; }
    public String description() { return "Company specific helpers."; }

    public List<ToolSpec> tools(ToolProviderContext ctx) {
        KeycloakAdmin kc = ctx.keycloak();                 // shared admin client + lookup helpers
        String greeting = ctx.config().get("greeting", "hi"); // kc-mcp.spi.tools.acme.greeting
        return List.of(ToolSpec.builder("keycloak_acme_ping")
                .title("ACME ping").description("Says hello.")
                .category(Category.REALM).read().global()
                .synonyms("acme", "ping")
                .schema(InputSchema.builder().string("name", "Who to greet"))
                .handler(call -> ToolResult.ok(Map.of("greeting", greeting, "name", call.str("name", "world"))))
                .build());
    }
}
```

- Register: `@AutoService(ToolProvider.class)` (generates `META-INF/services/...tools.ToolProvider`), a hand-written
  services file, or a CDI bean.
- Secrets: `InputSchema.builder().string("pin", "...").sensitive()` for an argument, `.stringMap("config", "...")
  .sensitiveKeys("clientSecret")` for keys of a map, `ToolSpec.builder(...).sensitiveResult()` for a result that is a
  secret; `catalog.Sensitive` tells listeners and confirmers what to hide.
- A read tool is held to it: while it runs, the admin client refuses every Admin API request but `GET`, `HEAD` and
  `OPTIONS`, and the call fails as `read_only_violation`. A tool that changes anything, or reads through a `POST`,
  declares `.write()` ([Read tools only read](security.md#read-tools-only-read)).
- Renaming a tool: `.formerly("old_name")`. Deny-lists naming the old name keep denying it, allow-lists have to name
  the new one, and calls by the old name answer with the new name. A former name may not be any tool's name
  ([New, removed and renamed tools](security.md#new-removed-and-renamed-tools)).
- Every tool declares its level, `.read()`, `.write()` or `.destructive()`; `build()` refuses a tool without one, so a
  forgotten call cannot slip past the read-only filter or the confirmation. The level is in every `search_tools` hit
  (`level`) and in the MCP tool annotations (`readOnlyHint`, `destructiveHint`).
- Cost on a large realm: `.cost(ToolCost.PER_ITEM, "one call per client")` for a tool whose requests grow with
  the realm, `ToolCost.HEAVY` for long-running work in Keycloak; `LIGHT` is the default. The model sees `cost` and
  `costNote` in `search_tools` hits and the note at the end of a directly listed tool's description. The note says
  why in a few words, at most 80 characters.
- Provider tools get search, exposure modes, validation, realm checks, confirmation, audit.
- Built-in areas (`users`, `groups`, `roles`, `clients`, `idp`, `orgs`, `federation`, `auth-flows`, `events`, `realm`)
  use the same SPI; `kc-mcp.spi.<spi>.<id>.enabled=false` switches one off.
- Settings: `kc-mcp.spi.<spi>.<id>.<key>`, environment `KC_MCP_SPI_<SPI>_<ID>_<KEY>`. An id is unique within its
  extension point, so the same id under two extension points has separate settings. `<spi>` is `tools`, `prompts`,
  `access-check`, `authorization-engine`, `authzen-customizer`, `confirmer`, `issuer-policy`, `profile-check`, `audit-listener`, `audit-scrubber`, `approval-store`,
  `system-repository`, `key-vault`, `key-generator` or `session-store`.
- Choosing a provider: `key-vault`, `key-generator`, `session-store` and `approval-store` are served by exactly one
  extension, the others run all of theirs. `kc-mcp.spi.key-vault.provider=db`
  (`KC_MCP_SPI_KEY_VAULT_PROVIDER`) names it; if that one is missing, switched off or unsupported the server does not
  start. Without it the usable extension with the lowest `order()` serves, then the built-in (key vault `file`,
  key generator `default`). Candidates not chosen are neither configured nor closed. On an extension point
  that runs all of its extensions, `provider` stops the start.
- `Extension` base: `id()` (config key, kebab-case; default from class name, `com.acme.TicketChecker` →
  `com-acme-ticket-checker`), `displayName()`, `description()`, `order()` (lower first).
- `configure(config)` (default nothing): hands every extension its `kc-mcp.spi.<spi>.<id>.*` settings, from files,
  environment and command line, at startup after the `enabled` switch and before `isSupported`. Keep them in fields;
  a constructor cannot see them. Only the settings are passed, the Keycloak systems do not exist yet; tool providers
  also get `init(ctx)` with the full context. A failing `configure` counts like a failing `isSupported`.
- `configSpec()` (default `ConfigSpec.EMPTY`, nothing checked): how the extension is configured, like Keycloak's
  `ProviderConfigProperty` list: its settings (`ConfigProperty`) and how they belong together (`ConfigHint`).
  - Properties: types `STRING`, `BOOLEAN`, `INT`, `NUMBER`, `DURATION` (`30`, `500ms`, `30s`, `5m`, `2h`, `1d`,
    `PT30S`), `URL` (absolute, with host), `LIST` (comma separated), `CHOICE` (one of `options`, plus
    `withAliases(...)`) and `JSON`; default (as written in the configuration), `asConfidential()` (masked in logs,
    error messages and `ProviderConfig.toString()`) and `asRequired()`. No texts: those are in the message bundles.
  - Hints: `ConfigHint.group("client", ...)` (a kebab-case id) for sections in a UI, and `ConfigHint.when("header-value").is("auth", "header")` (or
    `.isSet("keystore-file")`) for a setting that only matters under a condition, which may also be `enabled`.
    Advisory, except that a required setting with conditions is required only while they hold.
  - Texts: in `META-INF/kc-mcp/messages.properties` (English, UTF-8) and `META-INF/kc-mcp/messages_<lang>.properties` of the
    extension's jar, by keys derived from the spec (`ConfigMessageKeys`): `<spi>.<id>.<name>.label` and
    `.description`, `<spi>.<id>.<name>.option.<option>`, `<spi>.<id>.group.<group>.label` and `.description`
    (`audit-scrubber.pii.mode.label`). The labels are needed, descriptions and option texts are optional. A text the
    extension lacks falls back to `config.<name>...`, the shared texts of settings several extensions read
    (`config.client-secret.label`); a key no bundle has shows as the name and is logged once. `ConfigMessages` merges
    the bundles of every jar, the providers directory included, and resolves them per locale; `missingLabels(prefix,
    spec)` lets a test keep the bundle complete. The admin API serves an extension's spec, values (confidential ones
    masked) and problems with these texts at `GET /admin/extensions/<spi>/<id>` ([Keycloak systems](systems.md)).
  - `spec.plus(other)` combines specs; the AuthZEN engine adds the client authentication methods' to its own (a
    `ClientAuthenticatorFactory` has `configSpec()` and `validate` too).
  - Read declared settings with `config.readString(P)`, `readBoolean`, `readInt`, `readLong`, `readNumber`,
    `readDuration`, `readUrl`, `readList`, `readChoice`, `readEnum(P, Mode.class)` or `readJson`, which apply the
    default; a reader of the wrong type throws. `KC_MCP_SPI_<SPI>_<ID>_<KEY>` variables map to the declared name
    (`_PDP_URL` → `pdp.url`). `enabled` and `required` are the server's and not declared, nor are `default`, `order`
    and `locked` of an access check.
- `validate(config)` (default none): the extension's own rules between its settings, the ones a spec cannot say
  (settings that exclude each other, one of several, a value that must suit another), as `ConfigProblem`s: severity
  `ERROR` or `WARNING`; a `code`, the key of its text in the bundles (`acme.endpoint-needed`; the server's own are
  `config.invalid-value`, `config.required`, `config.unknown-key`, `config.validation-failed`), with named `args`
  (`key`, the full key, and what the code describes; never a confidential value) for its `{name}` placeholders
  (`acme.endpoint-needed={key}=confirm needs an endpoint`); an English `message` for logs and exceptions naming the
  full key (`config.key(name)`); the settings concerned. Asked once the values pass the spec's
  checks; a `ConfigValueException` thrown while reading keeps its problem.
- Before `configure` the server checks the settings against the spec, then `validate`: warnings (unknown keys
  among them) are logged, errors stop the start in every profile. Access checks are checked by the access check chain
  instead: the server's settings at startup, a system's, realm's or preset's `access.<id>` block (over the server's)
  when it is loaded or saved, placeholders such as `{realm}` filled with sample values first.
  ```java
  public enum Mode {
      KEEP, PSEUDONYMIZE, DROP // options keep, pseudonymize, drop; readEnum maps them back
  }

  private Mode mode;
  private List<String> targets;

  public static final ConfigProperty MODE = ConfigProperty.choice("mode", Mode.class).withDefault("keep");
  public static final ConfigProperty TARGETS = ConfigProperty.list("targets").withDefault("db");
  public static final ConfigProperty KEY = ConfigProperty.string("pseudonym-key").asConfidential();
  public static final ConfigSpec SPEC = ConfigSpec.of(MODE, TARGETS, KEY)
      .withHints(
          // sections of a generic settings form, in this order
          ConfigHint.group("scrubbing", MODE.name(), TARGETS.name()),
          ConfigHint.group("pseudonyms", KEY.name()),
          // shown only while mode=pseudonymize
          ConfigHint.when(KEY.name()).is(MODE.name(), "pseudonymize"));

  @Override public ConfigSpec configSpec() { return SPEC; }
  @Override public void configure(ProviderConfig config) {
      mode = config.readEnum(MODE, Mode.class);
      targets = config.readList(TARGETS);
  }
  ```
  ```properties
  # src/main/resources/META-INF/kc-mcp/messages.properties
  audit-scrubber.pii.mode.label=Mode
  audit-scrubber.pii.mode.description=What happens to personal data.
  audit-scrubber.pii.mode.option.pseudonymize=Pseudonymize (keyed hash)
  audit-scrubber.pii.targets.label=Listeners
  audit-scrubber.pii.pseudonym-key.label=Pseudonym key
  audit-scrubber.pii.group.scrubbing.label=Scrubbing
  audit-scrubber.pii.group.scrubbing.description=What happens to personal data, and where.
  audit-scrubber.pii.group.pseudonyms.label=Pseudonyms
  ```
- `isSupported(serverConfig, config)` (default `true`): asked once at startup after `kc-mcp.spi.<spi>.<id>.enabled`; an
  extension that needs a setting, a feature or a capability answers `false` when it is missing and is left out as if
  it were not installed (logged, not fatal; an exception counts as `false`). Applies to every extension point: tools,
  prompts, access checks, confirmers, audit listeners and scrubbers, profile checks, system repositories, key vaults,
  key generators, session and approval stores. Fail closed: `kc-mcp.spi.<spi>.<id>.required=true` makes a missing,
  switched-off or unsupported extension stop the start (mark security controls such as an `AccessCheck` or a `Confirmer` this way),
  and an `isSupported` that throws stops a server in profile `shared`. Extension points are resolved at startup, so
  these rules apply before the first call. To refuse the start for other reasons, contribute a `ProfileCheck`. Built in:
  the CIBA confirmer is supported only with `kc-mcp.spi.confirmer.ciba.enabled=true`, the metrics audit listener only
  with the OpenTelemetry SDK on.
- `close()` (default nothing): once at shutdown for every extension that took part, last admitted first; a failure is
  logged and the others still close. Release connections, file handles and threads here.
- Lifecycle: one instance per server, shared by all requests, so an extension must be thread-safe. Each extension
  point is discovered once. `configure` and `isSupported` run once at startup, and settings need a restart to change.
- `ExtensionRegistry` (`extensions(Confirmer.class)`, `extension(ToolProvider.class, "users")`, `context(id)`):
  discovery, dedup by id, enabled switch, order. CDI bean, injectable.
- Global `AccessCheck`: `@AutoService(AccessCheck.class)`, CDI bean, or `ToolProvider.accessChecks(...)`. Give it a
  short `id()`: it names the check's entry in systems' and realms' `access` blocks. Read the effective settings of the
  call from `context.settings()` (the server's `kc-mcp.spi.access-check.<id>.*` with the system's and realm's entry
  over them) to follow systems and realms ([Access checks](access-checks.md)).

## Extension jars: `providers/`

- `kc-mcp.providers-dir` (`KC_MCP_PROVIDERS_DIR`), default `providers`. Every `ToolProvider`, `PromptProvider`,
  `AccessCheck`, `Confirmer`, `AuditListener`, `ProfileCheck` in the jars' `META-INF/services` joins the class path ones.
- Relative path: next to `quarkus-run.jar` when packaged (`target/quarkus-app/providers/`, created by the build), else
  the working directory (dev: `./providers`).
- Loaded by a class loader over the application: sees api and server classes, no CDI, no native image. CDI needed:
  Maven dependency instead.
- Docker image: `/deployments/providers` (`docker-compose.yml` has the volume line).
- Prompts without code: `.md` files under `META-INF/kc-mcp/prompts/` of a jar in the directory are registered as
  prompts ([Prompts as text files](tools.md#prompts-as-text-files)); a jar may hold nothing else. Jars on the class
  path are not searched, only those of the providers directory.

```shell
./mvnw package -DskipTests
cp acme-tools.jar modules/backend/target/quarkus-app/providers/
java -jar modules/backend/target/quarkus-app/quarkus-run.jar start      # log: Extensions directory .../providers: [acme-tools.jar]
```

In a distribution, `bin/kcmcp.sh providers` lists every extension with its status (`active`, `selected`, `disabled`,
`not supported`, `not selected`, or `available` where one is picked on first use) and the jar it came from.

## Confirmers

- `Confirmer` (`@AutoService` or CDI bean, by `order()`) gets tool, realm, arguments, `confirm` flag, caller, a
  `Prompter` for elicitation.
- Returns `confirmed()`, `declined(message)`, `confirmationRequired(message)`, `abstain()`. First non-abstention wins;
  the built-in confirmer (elicitation, else `confirm` flag) runs last.

```java
@AutoService(Confirmer.class)
public class TicketConfirmer implements Confirmer {
    public Decision confirm(ConfirmationRequest r) {
        if (!r.tool().name().equals("keycloak_user_delete")) return Decision.abstain();
        String ticket = String.valueOf(r.args().get("ticket"));
        return tickets.isOpen(ticket) ? Decision.confirmed()
                : Decision.declined("User deletion needs an open change ticket (pass ticket=...).");
    }
}
```

## Built-in: CIBA confirmation

The built-in confirmer that has the caller approve each destructive tool on their own device through OpenID Connect
CIBA has a page of its own: [CIBA confirmation](ciba-confirmation.md). `examples/ciba-confirm` runs it.

## Authorization engines

An `AuthorizationEngine` (package `access`) is a client of an outside policy service: the built-in `authzen`, or a
vendor's. Register with `@AutoService(AuthorizationEngine.class)` or as a CDI bean; settings
`kc-mcp.spi.authorization-engine.<id>.*`. The engine decides about a call, not whether the call is its to decide: the
server's access check `authorization` does that from the system's and realm's `authorization` block, denies calls
that need an engine the server does not have, and denies calls whose engine throws
([External authorization](authzen.md)).

```java
@AutoService(AuthorizationEngine.class)
public class AcmeOpaEngine implements AuthorizationEngine {
    public String id() { return "acme-opa"; }                     // "authorization": {"acme-opa": {...}}
    public AccessCheck.Decision decide(Request r) {
        String endpoint = r.settings().getOrDefault("endpoint", defaultEndpoint); // the block's, realm's over system's
        boolean allowed = opa.allows(endpoint, r.context().caller(), r.context().tool().name(), r.context().args());
        return allowed ? AccessCheck.Decision.allow() : AccessCheck.Decision.deny("policy_denied", "OPA says no.");
    }
    public void validate(KeycloakSystem system, boolean systemKey) { /* refuse bad settings before they are stored */ }
}
```

- `Request`: the call's `AccessCheck.Context`, the system it targets, the effective `authorization` block and the
  engine's part of it (`settings()`, kebab-case keys).
- `evaluatesByDefault()` (default `false`): whether systems whose block has no switch are evaluated by this engine.
- `validate`: the admin API calls it before storing a system or realm; throw `IllegalArgumentException` with what is
  wrong. URL-valued settings, `-file` settings and `vault:` references are checked by the server for every engine.
- A setting whose name ends like a secret (`...secret`, `...password`, `...token`, `...key`) is masked and may be a
  `vault:` reference, resolved before the engine sees it.

## AuthZEN for extensions

The `api` module holds the AuthZEN protocol model (package `authzen`), so that extensions need not repeat it:

- `AuthZenEvaluation.of(context, sendArgs, now)`: the evaluation request of a tool call, exactly as the built-in engine
  sends it (subject from the token, the tool as action, the resource from the operation's path, the masked
  arguments); `toJson()` is the request body. Immutable: `withSubject`, `withResource`, `withContextValue` and so on
  give changed copies. `AuthZenMapping` holds the single steps, `AuthZenMapping.subject(caller)` say.
- `AuthZenAnswer.parse(json)`: decision, context, `reason()`, `confirmationRequired()`, and every further top-level
  field in `attributes()`.

With them an extension can talk AuthZEN its own way (a vendor SDK, another transport, a cache) as its own
`AuthorizationEngine`. To keep the built-in engine and only adjust what it sends, contribute an
`AuthZenRequestCustomizer` instead: it gets the evaluation and the call, and returns the evaluation to send.

```java
@AutoService(AuthZenRequestCustomizer.class)
public class TicketContext implements AuthZenRequestCustomizer {
    public AuthZenEvaluation customize(AuthZenEvaluation evaluation, AuthorizationEngine.Request request) {
        Object ticket = request.context().args().get("ticket");
        return ticket == null ? evaluation : evaluation.withContextValue("ticket", ticket);
    }
}
```

Customizers run in `order()`, each on the result of the one before; settings `kc-mcp.spi.authzen-customizer.<id>.*`. One
that throws refuses the call, `on-error=allow` notwithstanding: a request the customizers could not finish is never
sent. A customizer that replaces the subject takes over the responsibility for who the PDP believes is acting.

## Client authenticators

Where the server fetches tokens from an authorization server other than Keycloak's admin login (today: the AuthZEN
engine with `auth=client-credentials`), the client authentication is pluggable. A `ClientAuthenticatorFactory`
(package `oauth`) serves one `token_endpoint_auth_method` by its `id()`; the component names it in its settings
(`client-auth=<id>`) and the factory gets the client id, the token endpoint, the component's settings and, where there
is one, a signer with the Keycloak system's key. The `ClientAuthenticator` it makes adds form parameters or headers to
each `TokenRequest`. Built in: `client_secret_basic`, `client_secret_post`, `private_key_jwt`. Register with
`@AutoService(ClientAuthenticatorFactory.class)`, from the class path or `providers/`, or as a CDI bean; an
extension's factory with a built-in id replaces the built-in one. A factory that throws `IllegalStateException` on
incomplete settings stops the start.

```java
@AutoService(ClientAuthenticatorFactory.class)
public class VendorKeyAuthenticatorFactory implements ClientAuthenticatorFactory {
    public String id() { return "vendor_api_key"; }
    public ClientAuthenticator create(Context ctx) {
        String key = ctx.require(id(), "vendor-key");          // kc-mcp.spi.authorization-engine.authzen.vendor-key
        return request -> request.param("client_id", ctx.clientId()).header("X-Vendor-Key", key);
    }
}
```

## Caller issuer policies

In delegation mode a caller's token is used at the Keycloak system a call targets. The built-in rule lets it reach
the Keycloak that issued it (any realm of it, compared by the issuer's base), plus the
`kc-mcp.systems.<name>.trusted-issuers`: an entry with a realm path (`https://sso.example/realms/demo`) is that one
issuer, an entry without (`https://sso.example`) every realm of that Keycloak. Everything else answers
`caller_foreign_system`. A `CallerIssuerPolicy` (`@AutoService` or CDI bean, by `order()`) decides
before that rule: `ALLOW`, `DENY`, or `ABSTAIN` to leave it to the next one; the built-in rule runs last and never
abstains. A policy that throws counts as a denial.

```java
@AutoService(CallerIssuerPolicy.class)
public class FederationPolicy implements CallerIssuerPolicy {
    public Decision decide(String issuer, KeycloakSystem system) {
        return federation.trusts(system.name(), issuer) ? Decision.ALLOW : Decision.ABSTAIN;
    }
}
```

A policy decides what the server may send, nothing more: allowing a foreign issuer does not make the target Keycloak
accept its tokens. That is configured in Keycloak, where 26.5 introduced the JWT authorization grant (RFC 7523,
preview) for exactly this, an identity provider that lets a client present the external token as `assertion` and get
a local one, as the standard replacement for the external-to-internal token exchange
(<https://www.keycloak.org/2026/01/jwt-authorization-grant>). The server does not perform that grant yet: in mode
`forward` an allowed foreign token is sent as it is, and Keycloak refuses it unless configured to take it.

## Profile checks

`ProfileCheck` (`@AutoService` or CDI bean) adds to the startup checks of `kc-mcp.security-profile`: an extension states what
its own feature needs to be safe (an audit file outside `/tmp`, a ticket system over HTTPS, a setting that must not keep
its default on a shared server). `problems(ctx)` stop the start, reported together with the built-in ones and tagged
`[id]`; `warnings(ctx)` are logged. The check decides per profile (`ctx.shared()`), and gets its own settings
(`ctx.config()`, `kc-mcp.spi.<spi>.<id>.*`), any property (`ctx.property("quarkus.http.host")`) and whether callers are
required. A check that throws stops a shared server and is logged on a local one. Example:
`examples/extensions/.../AuditFileProfileCheck.java`.

```java
@AutoService(ProfileCheck.class)
public class TicketUrlCheck implements ProfileCheck {
    public List<String> problems(ProfileCheckContext ctx) {
        String url = ctx.config().get("url", "");
        return ctx.shared() && !url.startsWith("https://")
                ? List.of("kc-mcp.spi." + id() + ".url must be https on a shared server") : List.of();
    }
}
```

## Audit listeners and scrubbers

- `AuditListener.onToolCall` once per finished call, any outcome. Built-in: console line (`console`). Synchronous on the
  handler's virtual thread; offload slow sinks. Exceptions logged, never change the result.
- Password-like arguments arrive as `***`. Personal data does not: that is `AuditScrubber` (`@AutoService` or CDI bean,
  by `order()`). `scrub(event, listener)` runs per listener: treat all sinks alike, or target one by id (`db`,
  `console`). Derive with `mapArgs`, `withMessage`, `withCaller`; return `null` to skip. Default `NoOpAuditScrubber`.

```java
@AutoService(AuditListener.class)
public class SiemAuditListener implements AuditListener {
    public void onToolCall(AuditEvent e) {
        if (!e.succeeded() || e.level() != ToolLevel.READ) {
            siem.send(e.tool(), e.realm(), e.caller().name(), e.outcome(), e.args());
        }
    }
}

@AutoService(AuditScrubber.class)
public class NoEmailScrubber implements AuditScrubber {        // no e-mail addresses in any audit sink
    public AuditEvent scrub(AuditEvent e, AuditListener target) {
        return e.mapArgs(k -> k.equals("email"), v -> "***");
    }
}
```
