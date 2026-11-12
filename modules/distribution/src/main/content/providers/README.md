# Extensions

Put extension jars here: tools, prompts, access checks, confirmers, audit listeners, system repositories
(`docs/extending.md`). They are loaded at startup; the log lists the jars found. A jar may also carry prompts as text files under
`META-INF/kc-mcp/prompts/`, with or without code. The jars see the server's `api`
module and may depend on nothing else.
