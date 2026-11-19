# Architecture: one server, two instance roles

The server is one program that can run in two roles on the same database (`kc-mcp.instance-role`): the **MCP
instance** is what MCP clients and the models behind them talk to, the **admin instance** is where the server itself
is configured. A single instance with the role `all` (the default) does both; a shared deployment splits them, so that
nothing the MCP side can reach is able to change what the admin side set up.

```mermaid
flowchart TB
    subgraph W["MCP Host"]
        C("MCP client<br/>Claude, VS Code Copilot,<br/>LM Studio, ...")
    end
    subgraph O["Operations"]
        R("Management client<br/>curl, scripts, CI")
        B("Management UI<br/>in the browser")
    end
    subgraph K["Keycloak systems"]
        K1("Keycloak 1<br/>Admin REST API")
        K2("Keycloak 2<br/>Admin REST API")
    end
    subgraph F["Offered to the model"]
        T("Tools")
        P("Prompts")
        SK("Skills")
    end
    subgraph S["Server"]
        M("keycloak-mcp-server<br/>instance role <i>mcp</i><br/>headless")
        A("keycloak-mcp-server<br/>instance role <i>admin</i><br/>admin API<br/>UI (BFF)")
        D[("Server database")]
    end
    C -- "MCP<br/>JSON-RPC over HTTP(S)" --> M
    M -- "SQL (reads)" --> D
    M ---- T
    M ---- P
    M ---- SK
    M -- "REST HTTP(S)" ---> K1
    M -- "REST HTTP(S)" ---> K2
    A -- "SQL (reads, writes)" --> D
    R -- "REST HTTP(S)<br/>/admin" --> A
    B -- "HTTPS<br/>/ui, /bff" --> A
    classDef client fill:#dbeafe,stroke:#2563eb,color:#1e3a8a
    classDef server fill:#ede9fe,stroke:#7c3aed,color:#4c1d95
    classDef keycloak fill:#ccfbf1,stroke:#0d9488,color:#134e4a
    classDef infra fill:#fef3c7,stroke:#d97706,color:#78350f
    classDef audit fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class C,B,R client
    class M,A server
    class K1,K2 keycloak
    class D infra
    class T,P,SK audit
```

## The parts

Who issues the tokens in this picture, and what the server is towards each of them:
[Identity providers, authorization servers and Keycloak systems](providers-and-systems.md).

| part | what it is | talks to |
|---|---|---|
| MCP client | Claude Code, Claude Desktop, VS Code with Copilot, LM Studio, Cursor, Codex on the MCP host, typically a person's workstation ([Integrations](integrations.md)) | the MCP instance, over streamable HTTP; the person logs in at Keycloak first |
| MCP instance | `kc-mcp.instance-role=mcp`: the MCP endpoint and nothing else, no admin API and no UI | the Keycloak systems' Admin REST API; the database, to read |
| tools and prompts | what the MCP instance offers the model: the Keycloak tools and the prompts ([Tools](tools.md)) | |
| Keycloak systems | the Keycloaks the server administers, static from the configuration or registered at runtime ([Several Keycloak systems](systems.md)) | |
| admin instance | `kc-mcp.instance-role=admin`: the admin API under `/admin` and, when enabled, the management UI with its backend-for-frontend; `/mcp` answers 404 | the database, to read and write |
| management client | anything that speaks REST to the admin API: `curl`, a script, a pipeline | the admin instance |
| management UI | the browser application for the same tasks ([Management UI](management-ui.md)) | the admin instance, which signs the person in and keeps the session |
| server database | systems, realms, secrets, signing keys, audit events, sessions ([Database storage](storage.md)) | |

## Why the split

- **Two database users.** The admin instance owns the schema, runs the migrations and writes systems, secrets and
  keys. The MCP instance's user reads them, appends audit rows and keeps the short-lived state of its calls
  (approvals, rate limits). It may not change a system, add a secret or replace a key, and it reads neither the audit
  rows nor the UI's sessions. Even a compromised MCP instance cannot rewrite what the admin side configured.
- **Two networks.** The MCP instance sits behind the public ingress; the admin instance stays on the internal
  network. MCP clients, and the models behind them, never reach the admin API.
- **Two audiences.** A token issued for the MCP endpoint does not open the admin API and the other way round, even
  on an instance that serves both.
- **Whose roles.** In delegation mode `exchange` the MCP instance sends neither its own nor the person's token to a
  Keycloak, but a delegated one Keycloak issued for the two together: Keycloak enforces that person's roles on every
  call ([Security](security.md)).

What each side can and cannot do, table by table and request by request:
[Several instances on one database](storage.md#several-instances-on-one-database) and the runnable
[`examples/split-deployment`](../examples/split-deployment/). The other ways the server runs, each with a diagram:
[Scenarios in pictures](scenarios.md).
