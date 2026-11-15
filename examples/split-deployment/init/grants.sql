-- What the MCP instances (user kcmcp_mcp) may do, granted by the owner kcmcp_admin once the admin instance has
-- migrated the schema. Run again after every upgrade: a new table has no grants until it is listed here.
--
-- The rule: the MCP side reads the configuration the tools run under and never changes it. A compromised or
-- misbehaving MCP instance cannot register a system, switch an access check off, replace a secret or a key.

-- systems, realms (with their access and tools blocks), secrets, signing keys: read only
GRANT SELECT ON kc_mcp_system, kc_mcp_realm, kc_mcp_secret, kc_mcp_signing_key TO kcmcp_mcp;

-- the audit trail: append only, the rows stay unreadable for the MCP side (the server writes them with a plain
-- INSERT, no RETURNING). The retention purge runs on the admin instance.
GRANT INSERT ON kc_mcp_audit_event TO kcmcp_mcp;

-- CIBA confirmations: the MCP instance that asks for an approval stores and finishes it
GRANT SELECT, INSERT, UPDATE, DELETE ON kc_mcp_pending_approval TO kcmcp_mcp;

-- rate limits: the calls the rate-limit access check counts, shared by the MCP instances. An instance locks the
-- caller's bucket row (SELECT ... FOR UPDATE, which PostgreSQL allows only with UPDATE), counts the calls and adds
-- its own; DELETE is for the hourly purge of calls older than the longest window. Without these grants the
-- rate-limit check refuses the calls it would count (access_check_failed).
GRANT SELECT, INSERT, UPDATE, DELETE ON kc_mcp_rate_limit_bucket TO kcmcp_mcp;
GRANT SELECT, INSERT, DELETE ON kc_mcp_rate_limit_call TO kcmcp_mcp;

-- short-lived state shared by the instances (the state store), such as the tickets of the step-up check's own login:
-- the instance that handles a call stores, replaces (SELECT ... FOR UPDATE, which needs UPDATE) and takes entries;
-- DELETE is also for the hourly purge of expired ones. Without these grants what keeps its state there refuses.
GRANT SELECT, INSERT, UPDATE, DELETE ON kc_mcp_state TO kcmcp_mcp;

-- not listed, so not granted: kc_mcp_user_session (management UI logins) and Liquibase's own tables
