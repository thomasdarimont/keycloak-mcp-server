package com.github.thomasdarimont.keycloak.mcp.backend.prompts;

import java.util.List;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext;
import com.google.auto.service.AutoService;

/**
 * Recipes for recurring admin tasks. Each names the tools it needs; the registrar appends
 * their catalog entries, so even a small model can run the task without searching.
 */
@AutoService(PromptProvider.class)
public class BuiltinPrompts implements PromptProvider {

    @Override
    public String id() {
        return "built-in";
    }

    /**
     * Before every other provider, so that a prompt of the same name from any of them
     * replaces a built-in one.
     */
    @Override
    public int order() {
        return -1000;
    }

    @Override
    public List<PromptSpec> prompts(ExtensionContext context) {
        // the shared default realm, when the systems have one; a system's own default
        // fills in at the call
        String realmHint = context.serverConfig()
            .systemDefaults()
            .defaultRealm()
            .map(r -> "Realm (default " + r + ")")
            .orElse("Realm the user lives in");
        return List.of(onboardUser(realmHint), loginTroubleshoot(realmHint), redirectLoopTroubleshoot(realmHint),
                slowLoginTroubleshoot(realmHint));
    }

    static PromptSpec onboardUser(String realmHint) {
        return PromptSpec.builder("keycloak_onboard_user")
            .title("Onboard a new user")
            .description("Create a user, add them to groups and send the account setup email; verifies each step.")
            .argument("realm", realmHint)
            .required("username", "Username of the new account")
            .required("email", "Email address; the setup email goes there")
            .argument("firstName", "First name")
            .argument("lastName", "Last name")
            .argument("groups", "Groups to join, comma separated paths such as /staff/devs")
            .argument("actions", "Required actions for the setup email, comma separated", "UPDATE_PASSWORD")
            .tools("keycloak_user_search", "keycloak_user_create", "keycloak_group_member_add",
                    "keycloak_user_send_action_email", "keycloak_user_get", "keycloak_user_groups_list")
            .handler(BuiltinPrompts::renderOnboard)
            .build();
    }

    static String renderOnboard(Map<String, String> a) {
        String where = a.containsKey("realm") ? " in realm " + a.get("realm") : "";
        String names = (a.containsKey("firstName") ? ", first name " + a.get("firstName") : "")
                + (a.containsKey("lastName") ? ", last name " + a.get("lastName") : "");
        String groups = a.getOrDefault("groups", "").isBlank() ? "3. No groups were requested; skip group membership."
                : ("3. Add the user to the groups %s (one call per group, by path). "
                        + "A missing group is an error to report, not to create.")
                    .formatted(a.get("groups"));
        return """
                Onboard the user %s (%s)%s. Follow the steps in order and verify each.

                1. Make sure the account does not exist yet: search by username and by email. \
                If either exists, stop and report it; do not create a duplicate.
                2. Create the user: username, email%s, enabled. Do not set a password; the user chooses one \
                through the email.
                %s
                4. Send the account setup email with the required actions %s. Keycloak needs working SMTP \
                for this; report the error if sending fails.
                5. Verify: read the user back (enabled, email, required actions) and list their groups.
                6. Summarize for the admin: user id, groups, and that the setup email was sent to %s.

                If a step is refused as forbidden, call whoami and tell the admin which role is missing; do not retry.
                """.formatted(a.get("username"), a.get("email"), where, names, groups, a.get("actions"),
                a.get("email"));
    }

    static PromptSpec loginTroubleshoot(String realmHint) {
        return PromptSpec.builder("keycloak_login_troubleshoot")
            .title("Why can't a user log in?")
            .description("Read-only investigation of a user's login problems: account state, failed login events, "
                    + "realm and client settings; ends with the likely cause and a proposed fix.")
            .argument("realm", realmHint)
            .required("username", "Username, email or id of the affected user")
            .argument("client", "clientId of the application the user tries to log in to")
            .tools("keycloak_user_get", "keycloak_events_login", "keycloak_user_brute_force_get",
                    "keycloak_user_sessions_list", "keycloak_realm_get_config", "keycloak_client_get",
                    "keycloak_client_evaluate_scopes", "keycloak_user_send_action_email")
            .handler(BuiltinPrompts::renderTroubleshoot)
            .build();
    }

    static String renderTroubleshoot(Map<String, String> a) {
        String where = a.containsKey("realm") ? " in realm " + a.get("realm") : "";
        String client = a.get("client");
        String target = client == null ? "" : " to the client " + client;
        String step5 = client == null
                ? "5. If the admin names an application later, read that client (enabled, flows, redirect URIs)."
                : ("5. Read the client %s: enabled, standard flow enabled, redirect URIs, then evaluate its scopes "
                        + "to see the roles and claims the user would get.")
                    .formatted(client);
        return """
                Find out why the user %s cannot log in%s%s. Investigate read-only; propose changes, but apply \
                none without the admin's go-ahead.

                1. Read the user: enabled? email verified? pending required actions? federated (LDAP) account? \
                A disabled account or a pending required action explains most cases.
                2. Read the user's recent login events and look at the error codes of the failures: \
                invalid_user_credentials (wrong password), user_disabled, user_temporarily_disabled \
                (brute force lockout), invalid_client_credentials, expired_code, and so on. For a lockout, read the \
                user's lockout status: the login page reports a locked account as a wrong password, so the user \
                cannot tell the two apart.
                3. Read the realm configuration: brute force protection and its lockout settings, \
                login with email, email verification, and which browser flow is bound.
                4. List the user's sessions: an active session means the credentials work and the problem is elsewhere.
                %s
                6. Report: the most likely cause, the evidence for it, and the fix. Typical fixes: enable the user, \
                clear or complete the required action, send a password reset email, wait out or lift the \
                brute force lockout, correct the client's redirect URI. Ask before changing anything.
                """.formatted(a.get("username"), where, target, step5);
    }

    static PromptSpec redirectLoopTroubleshoot(String realmHint) {
        return PromptSpec.builder("keycloak_redirect_loop_troubleshoot")
            .title("What causes this redirect loop?")
            .description("Read-only investigation of a login that bounces between an application and Keycloak: "
                    + "classifies the loop by its login events, then checks the client, recent changes and the "
                    + "realm; ends with the cause and whether the fix is in Keycloak or in the application.")
            .argument("realm", realmHint)
            .required("client", "clientId of the application that loops")
            .argument("username", "Username, email or id of an affected user")
            .tools("keycloak_events_login", "keycloak_client_get", "keycloak_events_admin", "keycloak_realm_get_config",
                    "keycloak_user_get", "keycloak_user_sessions_list")
            .handler(BuiltinPrompts::renderRedirectLoop)
            .build();
    }

    static String renderRedirectLoop(Map<String, String> a) {
        String where = a.containsKey("realm") ? " in realm " + a.get("realm") : "";
        String user = a.get("username");
        String who = user == null ? "" : " for the user " + user;
        String step5 = user == null
                ? "5. If the admin names an affected user later, read that user and their sessions as well."
                : ("5. Read the user %s: a required action that cannot be completed sends them round again. List "
                        + "their sessions: a new session per round means the session is lost between the rounds, "
                        + "one session reused means single sign-on works and the loop is behind Keycloak.")
                    .formatted(user);
        return """
                Find out what causes the redirect loop between the application %s and Keycloak%s%s. Investigate \
                read-only; propose changes, but apply none without the admin's go-ahead.

                1. Read the recent login events of the client %s (max 30, newest first) and name the pattern. \
                The pattern decides where the cause is:
                   a. LOGIN and CODE_TO_TOKEN_ERROR take turns: Keycloak logs the user in, the application fails \
                to redeem the code and starts over. The error says why: invalid_client_credentials (wrong client \
                secret or authentication method), invalid_code (code redeemed twice, or by another instance), \
                a PKCE or redirect_uri mismatch.
                   b. LOGIN and CODE_TO_TOKEN repeat without an error: Keycloak is done every time. The application \
                rejects the tokens (issuer, audience, clock) or loses its own session (cookie not stored, no sticky \
                sessions). The fix is in the application or the proxy in front of it.
                   c. LOGIN_ERROR repeats: the error names the cause, e.g. invalid_redirect_uri, client_disabled, \
                cookie_not_found, expired_code, login_required (the application asks with prompt=none).
                   d. No events in the period: the requests never finish a login. Check that events are saved \
                (the tool result says so), then suspect the reverse proxy: http and https redirecting to each \
                other, forwarded headers, hostname.
                2. Read the client: enabled, standard flow, redirect URIs, root and base URL, web origins, \
                client authenticator, PKCE setting. Compare them with the redirect_uri in the events.
                3. Read the admin events of resource type CLIENT from the day the loop began: a changed client \
                or a regenerated secret shortly before the first failure is the usual trigger. Quote time and who.
                4. Read the realm configuration: sslRequired, the session lifetimes (a session that ends at once \
                loops), the browser flow.
                %s
                6. Report: the pattern with the event times and error codes as evidence, the cause, the fix, and \
                whether it belongs in Keycloak or in the application. If the events do not decide it, say what \
                to look at next (application log, proxy configuration, browser network trace) instead of guessing.
                """.formatted(a.get("client"), who, where, a.get("client"), step5);
    }

    static PromptSpec slowLoginTroubleshoot(String realmHint) {
        return PromptSpec.builder("keycloak_slow_login_troubleshoot")
            .title("Why is the login so slow?")
            .description("Read-only search for what makes logins slow: password hashing, user federation, identity "
                    + "providers, the browser flow and event listeners; ends with ranked candidates and what to "
                    + "measure.")
            .argument("realm", realmHint)
            .argument("username", "Username, email or id of a user whose login is slow")
            .argument("client", "clientId of the application, if only its logins are slow")
            .tools("keycloak_realm_get_config", "keycloak_user_get", "keycloak_user_credentials_list",
                    "keycloak_federation_list", "keycloak_idp_list", "keycloak_auth_flow_executions_list",
                    "keycloak_realm_events_config_get", "keycloak_events_login")
            .handler(BuiltinPrompts::renderSlowLogin)
            .build();
    }

    static String renderSlowLogin(Map<String, String> a) {
        String where = a.containsKey("realm") ? " in realm " + a.get("realm") : "";
        String user = a.get("username");
        String client = a.get("client");
        String scope = (user == null ? "" : " for the user " + user)
                + (client == null ? "" : " at the client " + client);
        String step2 = user == null
                ? "2. Without a user to look at, skip the credentials; ask the admin for one slow account if the "
                        + "realm settings explain nothing."
                : ("2. Read the user %s and list their credentials. The password's hash shows what a login pays: "
                        + "algorithm and iterations as stored. A federated user (federationLink) is checked "
                        + "against LDAP on every login.")
                    .formatted(user);
        String events = client == null ? "the realm" : "the client " + client;
        return """
                Find out why the login is slow%s%s. Keycloak's Admin API reports configuration, not timings: \
                look for settings that cost time, rank them, and say what to measure. Investigate read-only; \
                propose changes, but apply none without the admin's go-ahead.

                1. Read the realm configuration and look at passwordPolicy. hashIterations in the millions, or \
                a costly hashAlgorithm, makes every password check take seconds, for every user. For comparison, \
                Keycloak's defaults: argon2 with 5 iterations, pbkdf2-sha512 with 210000, pbkdf2-sha256 with 600000.
                %s
                3. List the user federation providers. A provider is asked for every user Keycloak does not \
                find locally; an LDAP server that is slow or unreachable holds each such login until its \
                timeout. Note connection URL, priority and whether users are imported.
                4. List the identity providers: a login through one is as fast as that provider, and its first \
                login runs an extra flow.
                5. List the executions of the bound browser flow (its name is in the realm configuration): \
                custom or script authenticators and steps that call other systems are candidates.
                6. Read the events configuration: every listed event listener runs during the login; anything \
                beyond jboss-logging is a candidate, an email listener sends mail.
                7. Read the recent login events of %s. Many LOGIN_ERROR events from few addresses mean the \
                server is busy hashing passwords for an attack. A long gap between a LOGIN and its CODE_TO_TOKEN \
                is time spent in the application, not in Keycloak.
                8. Report: the candidates in order of likelihood, each with the setting found as evidence, and \
                the fix. Say what you could not see and where to measure it: Keycloak's metrics and access log, \
                the database, the LDAP server, the browser's network timing.
                """.formatted(scope, where, step2, events);
    }

}
