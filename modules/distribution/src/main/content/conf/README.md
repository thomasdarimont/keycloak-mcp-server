# Configuration

`kcmcp.conf` is read on every start (`bin/kcmcp.sh start`); the settings are documented in `docs/configuration.md`.
`systems/` takes one file per Keycloak system (`--config conf/systems/` reads the whole directory, see the README there).
`scenarios/` holds templates with complete settings for common setups: copy one here without its `.example`
(`cp conf/scenarios/<name>.conf.example conf/<name>.conf`), adjust it and start with `bin/kcmcp.sh start --config
conf/<name>.conf`, which adds that file on top of `kcmcp.conf`; a relative path is taken from the current directory,
else from the distribution's directory. The templates themselves may be replaced by an upgrade. Every setting can also be an environment variable (`kc-mcp.systems.default.url` →
`KC_MCP_SYSTEMS_DEFAULT_URL`) or a command line option (`--kc-mcp.systems.default.url=...`).

`prompts/` takes prompts as text files, one per file (see the README there); a file with the name of a built-in
prompt replaces it.

`truststores/` holds additional trusted certificates, such as the private CA of your Keycloak (`docs/tls.md`).

Private keys for `private_key_jwt` and TLS certificates can live here too; keep the directory readable by the user
the server runs as only.

Without the scripts, the same files are read with `-Dkc-mcp.config-files=<file>,<file>` on the `java -jar` command line, followed by the command (`start`).
A later file overrides an earlier one, settings from the environment and the command line override every file, and
the files override the server's defaults. A file's path cannot contain a comma. The scripts list the `KC_MCP_*` and
`QUARKUS_*` variables they inherit from the shell, since those silently override the files; `--clean-env` drops them.
