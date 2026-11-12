#!/usr/bin/env python3
"""Produces the symptoms the troubleshooting demo investigates, by behaving like browsers and a broken application.

    ./seed.py          # needs the stack up (docker compose up -d); KEYCLOAK_URL defaults to http://localhost:8104

  1. grace logs in to shop-web and it works, only slowly: the realm's password policy asks for 5 million
     PBKDF2 iterations, and every password check pays for them
  2. erin mistypes her password three times and is locked out; her fourth attempt, with the right password, is
     refused as well, and the login page still says "Invalid username or password"
  3. an administrator regenerates the secret of shop-web; the application keeps the old one. frank logs in, the
     application fails to redeem the code and sends him to Keycloak again, which has his session and answers at
     once: a redirect loop, six rounds of it

Run it once per stack; `docker compose down -v` resets the realm.
"""
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8104")
REALM = "shop"
CLIENT = "shop-web"
OLD_SECRET = "shop-web-secret"                      # what the application was deployed with
REDIRECT = "http://localhost:3000/callback"         # nothing listens there: the redirect is read, not followed
OIDC = f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Browser:
    """One user's browser: follows nothing by itself and keeps Keycloak's cookies."""

    def __init__(self):
        self.opener = urllib.request.build_opener(_NoRedirect)
        # Keycloak marks its cookies Secure; browsers accept that on localhost, Python's cookie jar does not: by hand
        self.cookies = {}

    def send(self, url, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        headers = {"content-type": "application/x-www-form-urlencoded"} if form is not None else {}
        if self.cookies:
            headers["cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        try:
            with self.opener.open(urllib.request.Request(url, data, headers)) as r:
                status, body, response_headers = r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            status, body, response_headers = e.code, e.read().decode(), e.headers
        for header in response_headers.get_all("set-cookie") or []:
            name, _, value = header.split(";", 1)[0].partition("=")
            self.cookies[name.strip()] = value.strip()
        return status, body, response_headers

    def authorize(self):
        """The application sends the browser to Keycloak: a login page, or with a session the code at once."""
        query = urllib.parse.urlencode({"client_id": CLIENT, "response_type": "code", "redirect_uri": REDIRECT,
                                        "scope": "openid", "state": "demo"})
        return self._answer(*self.send(f"{OIDC}/auth?{query}"))

    def submit(self, action, username, password):
        return self._answer(*self.send(action, {"username": username, "password": password}))

    def _answer(self, status, body, headers):
        """("code", code) when Keycloak redirects back to the application, else ("form", action, message)."""
        if status in (302, 303):
            location = headers.get("Location")
            if location.startswith(REDIRECT):
                answer = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                if "code" not in answer:
                    sys.exit(f"Keycloak answered {answer.get('error')}: {answer.get('error_description')}")
                return "code", answer["code"][0], None
            return self._answer(*self.send(urllib.parse.urljoin(KEYCLOAK, location)))
        action = re.search(r'<form[^>]*action="([^"]+)"', body)
        if not action:
            sys.exit(f"neither a redirect nor a login form: HTTP {status}\n{body[:400]}")
        message = re.search(r'kc-feedback-text[^>]*>\s*(.*?)\s*<', body, re.S)
        return "form", html.unescape(action.group(1)), message and " ".join(message.group(1).split())


def redeem(code, secret):
    """The application's back channel: the code for tokens, authenticated with the client secret."""
    form = urllib.parse.urlencode({"grant_type": "authorization_code", "client_id": CLIENT, "client_secret": secret,
                                   "code": code, "redirect_uri": REDIRECT}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(f"{OIDC}/token", form)) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def admin(method, path, token, body=None):
    request = urllib.request.Request(f"{KEYCLOAK}/admin/realms/{REALM}{path}",
                                     json.dumps(body).encode() if body is not None else None,
                                     {"authorization": "Bearer " + token, "content-type": "application/json"},
                                     method=method)
    with urllib.request.urlopen(request) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def admin_token():
    form = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                                   "password": "admin"}).encode()
    with urllib.request.urlopen(f"{KEYCLOAK}/realms/master/protocol/openid-connect/token", form) as r:
        return json.loads(r.read())["access_token"]


def step(text):
    print(f"\n\033[1m== {text}\033[0m")


def main():
    step("1. grace logs in to shop-web: it works, slowly")
    grace = Browser()
    _, action, _ = grace.authorize()
    started = time.monotonic()
    kind, code, _ = grace.submit(action, "grace", "grace-demo")
    print(f"Keycloak took {time.monotonic() - started:.1f} s to check the password and answer ({kind})")
    status, _ = redeem(code, OLD_SECRET)
    print(f"the application redeems the code: HTTP {status}")

    step("2. erin mistypes her password three times, then enters the right one")
    erin = Browser()
    _, action, _ = erin.authorize()
    for password in ("erin-demo1", "Erin-Demo", "erin_demo", "erin-demo"):
        kind, action, message = erin.submit(action, "erin", password)
        outcome = "logged in" if kind == "code" else f"login page again: {message or 'no message'}"
        print(f"{password:<11} -> {outcome}")
        if kind == "code":
            print("erin got in: was the stack seeded before and the lockout has run out? (docker compose down -v)")
            break

    step("3. an administrator regenerates the secret of shop-web; the application keeps the old one")
    token = admin_token()
    client = admin("GET", "/clients?" + urllib.parse.urlencode({"clientId": CLIENT}), token)[0]
    admin("POST", f"/clients/{client['id']}/client-secret", token)
    print("secret regenerated")
    time.sleep(1)
    frank = Browser()
    _, action, _ = frank.authorize()
    kind, code, _ = frank.submit(action, "frank", "frank-demo")
    for round_number in range(1, 7):
        status, answer = redeem(code, OLD_SECRET)
        print(f"round {round_number}: Keycloak logged frank in, the application redeems the code: HTTP {status} "
              f"{answer.get('error', '')}; it sends frank to the login again")
        time.sleep(1)
        kind, code, _ = frank.authorize()                 # Keycloak has frank's session: a code without a login page
        if kind != "code":
            sys.exit("expected single sign-on to answer with a code")
    print("... and so on, until the browser gives up with 'too many redirects'")


if __name__ == "__main__":
    main()
