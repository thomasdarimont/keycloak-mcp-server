# Prompts

Every `.md` file here is one MCP prompt: a header that declares it, then the recipe with placeholders
(`docs/tools.md`, *Prompts as text files*). The files are read at startup, after the built-in prompts and those of
the extensions in `providers/`: a file with the name of an existing prompt replaces it, and the log says so.

```markdown
---
name: acme_vpn_login_troubleshoot
title: Why does the VPN login fail?
description: Read-only check of a user's VPN login.
arguments:
  - name: username
    description: Who cannot log in
    required: true
  - name: realm
    description: Realm of the user
tools: [keycloak_user_get, keycloak_events_login, keycloak_client_get]
---
Find out why {{username}} cannot log in to the VPN{{#realm}} in realm {{realm}}{{/realm}}.

1. Read the user: enabled, required actions.
2. Read the user's login events for the client vpn-gateway and name the error codes.
3. Report the cause and the fix; change nothing.
```

`{{name}}` is an argument's value, `{{#name}}...{{/name}}` stays when the argument was given, `{{^name}}...{{/name}}`
when it was not. A file that does not parse stops the start with its name and the problem. The text is an instruction
to the model: keep the directory writable by administrators only.
