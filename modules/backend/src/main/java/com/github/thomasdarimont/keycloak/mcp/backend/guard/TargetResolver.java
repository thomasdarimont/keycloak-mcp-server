package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.backend.tools.OrgToolProvider;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.catalog.Target;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.confirm.ResolvedTarget;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * Finds what a call acts on before a human is asked to confirm it. The arguments are the
 * model's: an id says nothing to the person approving, and a name may stand for nothing
 * at all. The targets a tool declares ({@link ToolSpec#targets()}) are looked up the way
 * the tools themselves resolve them, so the confirmation names what the call would
 * change, and a call for something that does not exist ends here instead of after the
 * approval.
 */
final class TargetResolver {

    private static final Logger LOG = Logger.getLogger(TargetResolver.class);

    private TargetResolver() {
    }

    /**
     * @throws ToolException when a target does not exist or is ambiguous, with the answer
     * the tool itself would give
     */
    static List<ResolvedTarget> resolve(ToolSpec spec, KeycloakAdmin kc, String realm, Map<String, Object> args) {
        List<ResolvedTarget> resolved = new ArrayList<>();
        for (Target target : spec.targets()) {
            Object raw = args.get(target.arg());
            if (raw == null || String.valueOf(raw).isBlank() || Sensitive.argument(spec.inputSchema(), target.arg())) {
                continue;
            }
            String value = String.valueOf(raw);
            if (target.kind() == Target.Kind.NAMED || kc == null || realm == null) {
                resolved.add(new ResolvedTarget(target.label(), value, null, target.kind() == Target.Kind.NAMED));
                continue;
            }
            try {
                resolved.add(lookUp(target, kc, realm, value));
            }
            catch (ToolException e) {
                throw e;
            }
            catch (RuntimeException e) {
                // Keycloak refused or failed the lookup itself: the tool reports that as
                // it does for every call; the confirmation shows the argument, marked
                LOG.debugf(e, "%s: could not look up %s '%s' before the confirmation", spec.name(), target.label(),
                        value);
                resolved.add(new ResolvedTarget(target.label(), value, null, false));
            }
        }
        return resolved;
    }

    private static ResolvedTarget lookUp(Target target, KeycloakAdmin kc, String realm, String value) {
        return switch (target.kind()) {
            case USER -> {
                UserRepresentation u = kc.findUser(realm, value);
                yield new ResolvedTarget(target.label(), u.getUsername(), u.getId(), true);
            }
            case CLIENT -> {
                ClientRepresentation c = kc.findClient(realm, value);
                yield new ResolvedTarget(target.label(), c.getClientId(), c.getId(), true);
            }
            case GROUP -> {
                GroupRepresentation g = kc.findGroup(realm, value);
                yield new ResolvedTarget(target.label(), g.getPath() != null ? g.getPath() : g.getName(), g.getId(),
                        true);
            }
            case ORGANIZATION -> {
                OrganizationRepresentation o = OrgToolProvider.find(kc, realm, value);
                yield new ResolvedTarget(target.label(), o.getName() != null ? o.getName() : o.getAlias(), o.getId(),
                        true);
            }
            case NAMED -> new ResolvedTarget(target.label(), value, null, true);
        };
    }
}
