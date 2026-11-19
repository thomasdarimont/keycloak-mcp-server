import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * The user's "device" in the CIBA flow: the authentication entity of Keycloak's HTTP authentication channel, and
 * an OpenID Connect relying party so that only the user a request is meant for can decide it.
 * <ul>
 * <li>Keycloak POSTs every CIBA authentication request to {@code /auth} (bearer token + JSON with
 * {@code login_hint}, {@code binding_message}, {@code scope} and the additional parameters {@code code},
 * {@code requester}, {@code operation}); the request is kept pending for that user and answered with 201.</li>
 * <li>A user signs in at {@code /login} (authorization code flow with PKCE, public client {@code ciba-approver});
 * the identity comes from the provider's {@code userinfo} endpoint, the browser holds an HttpOnly session cookie.
 * {@code /logout} ends the local session and the provider's (RP-initiated logout with {@code id_token_hint}).
 * The page at {@code /} lists the requests whose {@code login_hint} is the signed-in user's username or email,
 * asks for the number the MCP server showed in the chat (number matching), and posts
 * {@code {"status": "SUCCEED" | "CANCELLED"}} with Keycloak's bearer token to the callback endpoint.</li>
 * <li>Scripts use the same API with {@code Authorization: Bearer <access token>} of that user instead of the
 * cookie: {@code GET /pending}, {@code POST /approve/{id|latest}?code=NN}, {@code POST /decline/{id|latest}},
 * {@code POST /decline-all} (every pending request of the user), {@code POST /history/clear} (their decided
 * list).</li>
 * </ul>
 * Plain JDK, run with {@code java Approver.java}. Environment: PORT (8095), PUBLIC_URL (http://localhost:8095),
 * KC_URL (how this app reaches Keycloak, http://keycloak:8080), KC_PUBLIC_URL (how the browser reaches it,
 * http://localhost:8098), KC_REALM (demo), CLIENT_ID (ciba-approver), REQUEST_TTL_SECONDS (120: the realm's CIBA
 * {@code expires_in}; a request older than that has expired at Keycloak and is dropped).
 */
public class Approver {

    record Request(long id, Instant at, String loginHint, String bindingMessage, String scope, String code,
            String requester, String operation, String bearer) {
        boolean belongsTo(User u) {
            return loginHint != null
                    && (loginHint.equalsIgnoreCase(u.username()) || loginHint.equalsIgnoreCase(u.email()));
        }

        boolean expired() {
            return at.plusSeconds(ttlSeconds).isBefore(Instant.now());
        }
    }

    record User(String username, String email, String name) {
    }

    record Session(User user, String idToken) {
    }

    record Login(String verifier, Instant at) {
    }

    record Decision(long id, Instant at, String by, String text) {
    }

    /** Colours a decision in the list: approved green, declined red, anything else (expired, failed) plain. */
    static String outcomeClass(Decision d) {
        return d.text().startsWith("approved:") ? "approved" : d.text().startsWith("declined:") ? "declined" : "other";
    }

    /** Newest first, as a list on a phone. */
    static final Comparator<Request> NEWEST_FIRST = Comparator.comparingLong(Request::id).reversed();

    static final Map<Long, Request> PENDING = new ConcurrentSkipListMap<>();
    static final Map<Long, Decision> DECIDED = new ConcurrentSkipListMap<>();
    static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();
    static final Map<String, Login> LOGINS = new ConcurrentHashMap<>();
    static final AtomicLong IDS = new AtomicLong();
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final SecureRandom RANDOM = new SecureRandom();
    static final String COOKIE = "approver_session";
    static String publicUrl;
    static String kcUrl;
    static String kcPublicUrl;
    static String realm;
    static String clientId;
    static long ttlSeconds;

    static final String STYLE = """
            <!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
            <title>Approver</title>
            <style>
              :root { --bg: #f3f4f6; --card: #fff; --text: #111827; --muted: #6b7280; --line: #e5e7eb;
                      --accent: #2563eb; --accent-text: #fff; --danger: #b91c1c; --chip: #eef2ff; --chip-text: #3730a3 }
              @media (prefers-color-scheme: dark) {
                :root { --bg: #111827; --card: #1f2937; --text: #f9fafb; --muted: #9ca3af; --line: #374151;
                        --accent: #3b82f6; --danger: #f87171; --chip: #312e81; --chip-text: #c7d2fe }
              }
              * { box-sizing: border-box }
              body { margin: 0; background: var(--bg); color: var(--text);
                     font: 15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif }
              main { max-width: 32em; margin: 0 auto; padding: 1.25em 1em 3em }
              header { display: flex; justify-content: space-between; align-items: center; gap: 1em;
                       padding: .9em 1em; background: var(--card); border-bottom: 1px solid var(--line) }
              header h1 { font-size: 1.1em; margin: 0 }
              header .who { color: var(--muted); font-size: .9em } header a { color: var(--accent) }
              h2 { font-size: .85em; text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
                   margin: 2em 0 .5em }
              p.lead { color: var(--muted); margin: 0 0 1em }
              .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 1em 1.1em;
                      margin: .8em 0; box-shadow: 0 1px 2px rgba(0,0,0,.05) }
              .card .meta { display: flex; justify-content: space-between; gap: 1em; color: var(--muted);
                            font-size: .85em; margin-bottom: .35em }
              .card .op { font-size: 1.1em; font-weight: 600; margin: 0 0 .5em }
              .num { font-weight: 600; color: var(--text); margin-right: .5em }
              .toolbar { display: flex; justify-content: space-between; align-items: baseline; gap: 1em }
              .toolbar form { margin: 0 } .toolbar button { font-size: .85em; padding: .3em .8em }
              .chip { display: inline-block; font: .85em ui-monospace, SFMono-Regular, Menlo, monospace;
                      background: var(--chip); color: var(--chip-text); border-radius: 999px; padding: .15em .7em }
              .actions { display: flex; align-items: center; gap: .6em; flex-wrap: wrap; margin-top: 1em }
              .actions form { display: flex; align-items: center; gap: .6em; margin: 0 }
              label { color: var(--muted); font-size: .9em }
              input { font: 1.3em ui-monospace, SFMono-Regular, Menlo, monospace; width: 3.2em; text-align: center;
                      letter-spacing: .15em; padding: .25em; border: 1px solid var(--line); border-radius: 8px;
                      background: var(--bg); color: var(--text) }
              button { font: inherit; font-weight: 600; padding: .5em 1.1em; border-radius: 8px; cursor: pointer;
                       border: 1px solid var(--accent); background: var(--accent); color: var(--accent-text) }
              button.secondary { background: transparent; color: var(--danger); border-color: var(--line) }
              button.wide { width: 100%; padding: .7em }
              .empty { color: var(--muted); text-align: center; padding: 2.5em 0 }
              .error { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; border-radius: 8px;
                       padding: .6em .9em; margin: 0 0 1em }
              @media (prefers-color-scheme: dark) { .error { background: #450a0a; color: #fecaca; border-color: #7f1d1d } }
              ul.history { list-style: none; padding: 0; margin: 0 }
              ul.history li { padding: .6em .8em; margin-bottom: .4em; border-radius: 8px; font-size: .92em;
                              border: 1px solid var(--line); border-left-width: 4px }
              ul.history li.approved { background: #f0fdf4; border-color: #bbf7d0; border-left-color: #16a34a }
              ul.history li.declined { background: #fef2f2; border-color: #fecaca; border-left-color: #dc2626 }
              @media (prefers-color-scheme: dark) {
                ul.history li.approved { background: #052e16; border-color: #14532d; border-left-color: #22c55e }
                ul.history li.declined { background: #450a0a; border-color: #7f1d1d; border-left-color: #ef4444 }
              }
              ul.history li time { color: var(--muted); margin-right: .5em }
            </style>
            <script>
              // the server sends instants; the browser shows them in the user's own time zone
              addEventListener('DOMContentLoaded', () => document.querySelectorAll('time').forEach(
                  t => t.textContent = new Date(t.dateTime).toLocaleString([], { dateStyle: 'short', timeStyle: 'medium' })));
              // reload only when the number of pending requests changes (a new one arrived, one was decided elsewhere)
              addEventListener('DOMContentLoaded', () => {
                const shown = document.querySelectorAll('.card').length;
                setInterval(async () => {
                  const r = await fetch('/pending', { headers: { accept: 'application/json' } });
                  if (r.status === 401) { location.reload(); return; }
                  if (r.ok && (await r.json()).length !== shown) { location.reload(); }
                }, 3000);
              });
            </script>
            """;

    static final String SIGNED_OUT = """
            %s
            <header><h1>Your device</h1></header>
            <main>
              %s
              <p class=lead>This is where the approval requests of the MCP server arrive. Sign in to see the
              requests meant for you.</p>
              <form method=get action=/login><button class=wide>Sign in with Keycloak</button></form>
            </main>
            """;

    static final String HEADER = """
            %s
            <header>
              <h1>Your device</h1>
              <span class=who>%s <span class=muted>(%s)</span> &middot; <a href=/logout>sign out</a></span>
            </header>
            <main>
              %s
              <p class=lead>Requests Keycloak delivered for you, newest first. Each one names who asked, and what
              for. To approve, enter the number the chat shows: a request you did not trigger has a number you do
              not know.</p>
            """;

    static final String REQUEST = """
            <div class=card>
              <div class=meta><span><span class=num>#%d</span>%s</span><time datetime="%s">%s</time></div>
              <p class=op>%s</p>
              <span class=chip>%s</span>
              <div class=actions>
                <form method=post action=/approve/%d>%s<button>Approve</button></form>
                <form method=post action=/decline/%d><button class=secondary>Decline</button></form>
              </div>
            </div>
            """;

    static final String NUMBER_FIELD = """
            <label>number from the chat <input name=code inputmode=numeric maxlength=2 autofocus required></label>""";

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(env("PORT", "8095"));
        publicUrl = env("PUBLIC_URL", "http://localhost:" + port);
        kcUrl = env("KC_URL", "http://keycloak:8080");
        kcPublicUrl = env("KC_PUBLIC_URL", "http://localhost:8098");
        realm = env("KC_REALM", "demo");
        clientId = env("CLIENT_ID", "ciba-approver");
        ttlSeconds = Long.parseLong(env("REQUEST_TTL_SECONDS", "120"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/auth", Approver::auth);
        server.createContext("/login", Approver::login);
        server.createContext("/callback", Approver::callback);
        server.createContext("/logout", Approver::logout);
        server.createContext("/pending", Approver::pending);
        server.createContext("/approve/", x -> decide(x, "SUCCEED"));
        server.createContext("/decline/", x -> decide(x, "CANCELLED"));
        server.createContext("/decline-all", Approver::declineAll);
        server.createContext("/history/clear", Approver::clearHistory);
        server.createContext("/", Approver::page);
        server.start();
        System.out.printf("Approver listening on :%d as %s; logins at %s/realms/%s (client %s), callbacks to %s%n",
                port, publicUrl, kcPublicUrl, realm, clientId, oidc(kcUrl, "ext/ciba/auth/callback"));
    }

    static String oidc(String base, String endpoint) {
        return base + "/realms/" + realm + "/protocol/openid-connect/" + endpoint;
    }

    // --- Keycloak's authentication channel -------------------------------------------------------------------

    static void auth(HttpExchange x) throws IOException {
        if (!"POST".equals(x.getRequestMethod())) {
            x.sendResponseHeaders(405, -1);
            x.close();
            return;
        }
        String bearer = x.getRequestHeaders().getFirst("Authorization");
        String body = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        // Keycloak flattens the additional request parameters into the JSON next to login_hint; other
        // providers may nest them
        String extra = object(body, "additional_parameters");
        Request r = new Request(IDS.incrementAndGet(), Instant.now(), field(body, "login_hint"),
                field(body, "binding_message"), field(body, "scope"), first(field(body, "code"), field(extra, "code")),
                first(field(body, "requester"), field(extra, "requester")),
                first(field(body, "operation"), field(extra, "operation")), bearer);
        PENDING.put(r.id(), r);
        System.out.printf("[%d] request for %s: %s from %s, binding message %s%s%n", r.id(), r.loginHint(),
                r.operation(), r.requester(), r.bindingMessage(),
                r.code() == null ? "" : ", expects the number " + r.code());
        x.sendResponseHeaders(201, -1); // Keycloak expects 201 Created
        x.close();
    }

    static int callback(Request r, String status) {
        try {
            HttpResponse<String> resp = HTTP.send(HttpRequest.newBuilder(URI.create(oidc(kcUrl, "ext/ciba/auth/callback")))
                .header("Authorization", r.bearer())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("""
                        {"status": "%s"}""".formatted(status)))
                .build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                System.out.println("callback failed: HTTP " + resp.statusCode() + " " + resp.body());
            }
            return resp.statusCode();
        }
        catch (IOException | InterruptedException e) {
            System.out.println("callback failed: " + e);
            return 599;
        }
    }

    // --- OpenID Connect relying party ------------------------------------------------------------------------

    static void login(HttpExchange x) throws IOException {
        String state = token(24);
        String verifier = token(48);
        LOGINS.put(state, new Login(verifier, Instant.now()));
        LOGINS.values().removeIf(l -> l.at().isBefore(Instant.now().minusSeconds(600)));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(verifier));
        redirect(x, oidc(kcPublicUrl, "auth") + "?response_type=code&client_id=" + enc(clientId) + "&redirect_uri="
                + enc(publicUrl + "/callback") + "&scope=" + enc("openid profile email") + "&state=" + enc(state)
                + "&code_challenge=" + challenge + "&code_challenge_method=S256");
    }

    static void callback(HttpExchange x) throws IOException {
        Map<String, String> q = form(x.getRequestURI().getRawQuery());
        Login login = q.get("state") == null ? null : LOGINS.remove(q.get("state"));
        if (login == null || q.get("code") == null) {
            redirect(x, "/?error=" + enc("login failed: "
                    + q.getOrDefault("error_description", q.getOrDefault("error", "no code or unknown state"))));
            return;
        }
        String tokens = post(oidc(kcUrl, "token"), "grant_type=authorization_code&client_id=" + enc(clientId) + "&code="
                + enc(q.get("code")) + "&redirect_uri=" + enc(publicUrl + "/callback") + "&code_verifier="
                + enc(login.verifier()));
        String accessToken = field(tokens, "access_token");
        User user = accessToken == null ? null : userinfo(accessToken);
        if (user == null) {
            redirect(x, "/?error=" + enc("login failed: the token exchange or userinfo call did not succeed"));
            return;
        }
        String session = token(32);
        SESSIONS.put(session, new Session(user, field(tokens, "id_token")));
        x.getResponseHeaders().add("Set-Cookie", COOKIE + "=" + session + "; Path=/; HttpOnly; SameSite=Lax");
        System.out.println(user.username() + " signed in");
        redirect(x, "/");
    }

    /** Ends the session here and at the provider (RP-initiated logout), then comes back to the sign-in page. */
    static void logout(HttpExchange x) throws IOException {
        String key = cookie(x);
        Session session = key == null ? null : SESSIONS.remove(key);
        x.getResponseHeaders().add("Set-Cookie", COOKIE + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        String url = oidc(kcPublicUrl, "logout") + "?client_id=" + enc(clientId) + "&post_logout_redirect_uri="
                + enc(publicUrl + "/");
        if (session != null && session.idToken() != null) {
            url += "&id_token_hint=" + enc(session.idToken());
            System.out.println(session.user().username() + " signed out");
        }
        redirect(x, url);
    }

    /** Who the provider says this access token belongs to; {@code null} when it is not accepted. */
    static User userinfo(String accessToken) {
        try {
            HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(oidc(kcUrl, "userinfo")))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                return null;
            }
            String username = field(r.body(), "preferred_username");
            return username == null ? null : new User(username, field(r.body(), "email"), field(r.body(), "name"));
        }
        catch (IOException | InterruptedException e) {
            return null;
        }
    }

    /** The requests still open for the user, newest first; expired ones are dropped on the way. */
    static List<Request> pendingFor(User u) {
        PENDING.values().removeIf(Request::expired);
        return PENDING.values().stream().filter(r -> r.belongsTo(u)).sorted(NEWEST_FIRST).toList();
    }

    /** The signed-in user: session cookie (browser) or bearer access token (scripts); {@code null} for nobody. */
    static User user(HttpExchange x) {
        String auth = x.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return userinfo(auth.substring(7).trim());
        }
        String key = cookie(x);
        Session session = key == null ? null : SESSIONS.get(key);
        return session == null ? null : session.user();
    }

    // --- the inbox -------------------------------------------------------------------------------------------

    static void pending(HttpExchange x) throws IOException {
        User u = user(x);
        if (u == null) {
            json(x, 401, """
                    {"error": "unauthorized", "message": "sign in at /login or send a bearer token"}""");
            return;
        }
        json(x, 200, pendingJson(u));
    }

    static void decide(HttpExchange x, String status) throws IOException {
        if (!"POST".equals(x.getRequestMethod())) {
            x.sendResponseHeaders(405, -1);
            x.close();
            return;
        }
        boolean html = String.valueOf(x.getRequestHeaders().getFirst("Accept")).contains("text/html");
        User u = user(x);
        if (u == null) {
            answer(x, html, 401, """
                    {"error": "unauthorized", "message": "sign in first"}""", "/?error=sign+in+first");
            return;
        }
        String path = x.getRequestURI().getPath();
        String key = path.substring(path.lastIndexOf('/') + 1);
        Map<String, String> params = form(x.getRequestURI().getRawQuery());
        params.putAll(form(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
        Request r;
        if ("latest".equals(key)) {
            r = pendingFor(u).stream().findFirst().orElse(null);
        }
        else {
            try {
                r = PENDING.get(Long.parseLong(key));
            }
            catch (NumberFormatException e) {
                r = null;
            }
            if (r != null && !r.belongsTo(u)) {
                System.out.printf("[%d] %s may not decide %s's request%n", r.id(), u.username(), r.loginHint());
                r = null; // somebody else's request looks like no request
            }
            if (r != null && r.expired()) {
                PENDING.remove(r.id());
                r = null;
            }
        }
        if (r == null) {
            answer(x, html, 404, """
                    {"error": "not_found", "message": "no pending request of yours"}""", "/?error=no+such+request");
            return;
        }
        if ("SUCCEED".equals(status) && r.code() != null && !r.code().equals(params.get("code"))) {
            System.out.printf("[%d] wrong number %s from %s, not approved%n", r.id(), params.get("code"), u.username());
            answer(x, html, 403, """
                    {"error": "wrong_code", "message": "The number does not match the request; it stays pending."}""",
                    "/?error=wrong+number+for+request+" + r.id());
            return;
        }
        int code = callback(r, status);
        PENDING.remove(r.id());
        String outcome = code < 300 ? ("SUCCEED".equals(status) ? "approved" : "declined")
                : code == 403 ? "too late, the request had expired at Keycloak" : "failed, Keycloak answered HTTP " + code;
        DECIDED.put(r.id(), new Decision(r.id(), Instant.now(), u.username(),
                "%s: %s (binding message %s)".formatted(outcome, r.operation(), r.bindingMessage())));
        System.out.printf("[%d] %s by %s, Keycloak answered HTTP %d%n", r.id(), status, u.username(), code);
        answer(x, html, code < 300 ? 200 : 502, """
                {"id": %d, "status": "%s", "keycloak": %d, "bindingMessage": "%s"}"""
            .formatted(r.id(), status, code, esc(r.bindingMessage())), "/");
    }

    /** Declines every pending request of the signed-in user. */
    static void declineAll(HttpExchange x) throws IOException {
        if (!"POST".equals(x.getRequestMethod())) {
            x.sendResponseHeaders(405, -1);
            x.close();
            return;
        }
        boolean html = String.valueOf(x.getRequestHeaders().getFirst("Accept")).contains("text/html");
        User u = user(x);
        if (u == null) {
            answer(x, html, 401, """
                    {"error": "unauthorized", "message": "sign in first"}""", "/?error=sign+in+first");
            return;
        }
        List<Request> mine = pendingFor(u);
        for (Request r : mine) {
            int code = callback(r, "CANCELLED");
            PENDING.remove(r.id());
            DECIDED.put(r.id(), new Decision(r.id(), Instant.now(), u.username(), "%s: %s (binding message %s)"
                .formatted(code < 300 ? "declined" : "too late, the request had expired at Keycloak", r.operation(),
                        r.bindingMessage())));
            System.out.printf("[%d] CANCELLED by %s (decline all), Keycloak answered HTTP %d%n", r.id(), u.username(),
                    code);
        }
        answer(x, html, 200, """
                {"declined": %d}""".formatted(mine.size()), "/");
    }

    /** Forgets the signed-in user's decided list. */
    static void clearHistory(HttpExchange x) throws IOException {
        if (!"POST".equals(x.getRequestMethod())) {
            x.sendResponseHeaders(405, -1);
            x.close();
            return;
        }
        boolean html = String.valueOf(x.getRequestHeaders().getFirst("Accept")).contains("text/html");
        User u = user(x);
        if (u == null) {
            answer(x, html, 401, """
                    {"error": "unauthorized", "message": "sign in first"}""", "/?error=sign+in+first");
            return;
        }
        int before = DECIDED.size();
        DECIDED.values().removeIf(d -> d.by().equals(u.username()));
        answer(x, html, 200, """
                {"cleared": %d}""".formatted(before - DECIDED.size()), "/");
    }

    static void page(HttpExchange x) throws IOException {
        if (!"/".equals(x.getRequestURI().getPath())) {
            x.sendResponseHeaders(404, -1);
            x.close();
            return;
        }
        Map<String, String> q = form(x.getRequestURI().getRawQuery());
        String error = q.containsKey("error") ? "<p class=error>" + esc(q.get("error")) + "</p>" : "";
        User u = user(x);
        if (u == null) {
            send(x, SIGNED_OUT.formatted(STYLE, error));
            return;
        }
        List<Request> mine = pendingFor(u);
        StringBuilder html = new StringBuilder(HEADER.formatted(STYLE,
                esc(u.name() != null ? u.name() : u.username()), esc(u.username()), error));
        if (mine.isEmpty()) {
            html.append("<p class=empty>Nothing pending for you.</p>");
        }
        else if (mine.size() > 1) {
            html.append("""
                    <div class=toolbar><h2>%d pending</h2>
                      <form method=post action=/decline-all><button class=secondary>Decline all</button></form>
                    </div>
                    """.formatted(mine.size()));
        }
        for (Request r : mine) {
            html.append(REQUEST.formatted(r.id(),
                    r.requester() == null ? "a request" : "requested through " + esc(r.requester()), r.at(), r.at(),
                    esc(r.operation() == null ? "an operation" : r.operation()), esc(r.bindingMessage()), r.id(),
                    r.code() == null ? "" : NUMBER_FIELD, r.id()));
        }
        String history = DECIDED.values().stream()
            .filter(d -> d.by().equals(u.username()))
            .sorted(Comparator.comparingLong(Decision::id).reversed())
            .map(d -> "<li class=" + outcomeClass(d) + "><time datetime=\"" + d.at() + "\">" + d.at() + "</time><span class=num>#" + d.id()
                    + "</span>" + esc(d.text()) + "</li>")
            .collect(Collectors.joining());
        if (!history.isEmpty()) {
            html.append("""
                    <div class=toolbar><h2>Your decisions</h2>
                      <form method=post action=/history/clear><button class=secondary>Clear</button></form>
                    </div>
                    <ul class=history>%s</ul>
                    """.formatted(history));
        }
        html.append("</main>");
        send(x, html.toString());
    }

    // --- helpers ---------------------------------------------------------------------------------------------

    static String pendingJson(User u) {
        return pendingFor(u).stream().map(r -> """
                {"id": %d, "loginHint": "%s", "bindingMessage": "%s", "operation": "%s", "requester": "%s", \
                "expectsCode": %b, "at": "%s"}""".formatted(r.id(), esc(r.loginHint()), esc(r.bindingMessage()),
                esc(r.operation()), esc(r.requester()), r.code() != null, r.at()))
            .collect(Collectors.joining(",", "[", "]"));
    }

    static String post(String url, String form) {
        try {
            HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                System.out.println("token request failed: HTTP " + r.statusCode() + " " + r.body());
                return null;
            }
            return r.body();
        }
        catch (IOException | InterruptedException e) {
            System.out.println("token request failed: " + e);
            return null;
        }
    }

    static void answer(HttpExchange x, boolean html, int status, String json, String location) throws IOException {
        if (html) {
            redirect(x, location);
            return;
        }
        json(x, status, json);
    }

    static void redirect(HttpExchange x, String location) throws IOException {
        x.getResponseHeaders().add("Location", location);
        x.sendResponseHeaders(303, -1);
        x.close();
    }

    static void send(HttpExchange x, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        x.getResponseHeaders().add("Cache-Control", "no-store");
        x.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(bytes);
        }
    }

    static void json(HttpExchange x, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(bytes);
        }
    }

    static String cookie(HttpExchange x) {
        for (String header : x.getRequestHeaders().getOrDefault("Cookie", List.of())) {
            for (String part : header.split(";")) {
                String[] kv = part.trim().split("=", 2);
                if (kv.length == 2 && kv[0].equals(COOKIE) && !kv[1].isBlank()) {
                    return kv[1];
                }
            }
        }
        return null;
    }

    /** A string field of a flat JSON object; enough for Keycloak's channel request, token and userinfo answers. */
    static String field(String json, String name) {
        if (json == null) {
            return null;
        }
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return m.find() ? m.group(1).replace("\\\"", "\"").replace("\\\\", "\\") : null;
    }

    /** The text of a nested object with string values, e.g. {@code additional_parameters}. */
    static String object(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(\\{[^}]*\\})").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    static Map<String, String> form(String encoded) {
        Map<String, String> out = new HashMap<>();
        if (encoded == null || encoded.isBlank()) {
            return out;
        }
        for (String kv : encoded.split("&")) {
            int eq = kv.indexOf('=');
            String k = URLDecoder.decode(eq < 0 ? kv : kv.substring(0, eq), StandardCharsets.UTF_8);
            String v = eq < 0 ? "" : URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8);
            out.put(k, v.trim());
        }
        return out;
    }

    static String token(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    static String first(String a, String b) {
        return a != null ? a : b;
    }

    static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;");
    }

    static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
