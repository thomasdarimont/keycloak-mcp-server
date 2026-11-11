package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ScopeType;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Unmatched;

/**
 * The command line. It runs before Quarkus starts, because settings have to be in place
 * by the time Quarkus reads its configuration. They become system properties, so they
 * override the environment and the configuration files.
 * <p>
 * {@code build} is not here: the launch scripts run it, Quarkus handles it before this
 * class is reached.
 */
@QuarkusMain
@Command(name = "kcmcp", description = "Keycloak MCP Server", subcommands = { KcMcpMain.Start.class,
        KcMcpMain.StartDev.class, KcMcpMain.ShowConfig.class, KcMcpMain.Validate.class, KcMcpMain.Providers.class })
public class KcMcpMain implements Callable<Integer> {

    static final int USAGE_ERROR = CommandLine.ExitCode.USAGE;

    @Spec
    CommandSpec spec;

    @Option(names = { "-h", "--help" }, usageHelp = true, scope = ScopeType.INHERIT, description = "Show this help.")
    boolean help;

    public static void main(String... args) {
        int exitCode = commandLine().execute(args);
        // a server that ran has already exited through Quarkus; dev mode has to return
        // from here to keep running
        if (exitCode != CommandLine.ExitCode.OK) {
            System.exit(exitCode);
        }
    }

    static CommandLine commandLine() {
        // an argument starting with @ is a value here, not a file of arguments
        return new CommandLine(new KcMcpMain()).setExpandAtFiles(false);
    }

    /** No command: the server only starts when asked to. */
    @Override
    public Integer call() {
        spec.commandLine().usage(spec.commandLine().getErr());
        return USAGE_ERROR;
    }

    /** A command that takes settings. */
    abstract static class ConfigCommand implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Unmatched
        List<String> arguments = new ArrayList<>();

        void applySettings() {
            Map<String, String> properties;
            try {
                properties = ConfigArguments.parse(arguments);
            }
            catch (IllegalArgumentException e) {
                throw new ParameterException(spec.commandLine(), e.getMessage(), e);
            }
            properties.forEach(System::setProperty);
        }
    }

    abstract static class ServerCommand extends ConfigCommand {

        @Override
        public Integer call() {
            applySettings();
            beforeStart();
            Quarkus.run();
            return CommandLine.ExitCode.OK;
        }

        void beforeStart() {
        }
    }

    @Command(name = "start",
            description = "Start the server. Settings: --kc-mcp.<name>=<value>, --quarkus.<name>=<value>.")
    static class Start extends ServerCommand {
    }

    @Command(name = "start-dev",
            description = "Start the server in development mode: profile local, startup checks warn, "
                    + "Keycloak at http://localhost:8080 unless a system is configured, the UI, an H2 database and dynamic systems "
                    + "in a distribution, no HTTPS needed. Not for a server other people reach.")
    static class StartDev extends ServerCommand {

        @Override
        void beforeStart() {
            System.err.println(
                    "development mode (start-dev): profile local, startup checks warn, Keycloak at http://localhost:8080 "
                            + "unless a system is configured, session cookies without Secure; use 'start' for a shared server");
            System.setProperty("kc-mcp.profile", "local");
            System.setProperty("kc-mcp.startup-check", "warn");
            System.setProperty("kc-mcp.dev-mode", "true");
        }
    }

    @Command(name = "show-config",
            description = "Print each setting in effect and where it comes from, secrets masked. Does not start the server.")
    static class ShowConfig extends ConfigCommand {

        @Parameters(arity = "0..1", paramLabel = "all", description = "Also print the quarkus.* settings.")
        String filter;

        @Override
        public Integer call() {
            if (filter != null && !filter.equals("all")) {
                throw new ParameterException(spec.commandLine(), "Unknown argument: '" + filter + "'. Expected 'all'.");
            }
            applySettings();
            ShownConfig.print(filter != null, spec.commandLine().getOut());
            spec.commandLine().getOut().flush();
            return CommandLine.ExitCode.OK;
        }
    }

    @Command(name = "validate",
            description = "Run the startup checks, print every problem and exit non-zero if there is one. Opens no port, "
                    + "migrates nothing and changes no data.")
    static class Validate extends ConfigCommand {

        @Option(names = "--offline", description = "Do not contact Keycloak.")
        boolean offline;

        @Override
        public Integer call() {
            applySettings();
            System.setProperty(ValidateApplication.OFFLINE, String.valueOf(offline));
            bootWithoutServing(ValidateApplication.class);
            return CommandLine.ExitCode.OK;
        }
    }

    @Command(name = "providers",
            description = "List the installed extensions and whether each takes part. Opens no port, migrates nothing "
                    + "and changes no data.")
    static class Providers extends ConfigCommand {

        @Override
        public Integer call() {
            applySettings();
            bootWithoutServing(ProvidersApplication.class);
            return CommandLine.ExitCode.OK;
        }
    }

    /** Boots the application for a command that inspects it and then exits. */
    private static void bootWithoutServing(Class<? extends QuarkusApplication> application) {
        System.setProperty(ValidationRun.PROPERTY, "true");
        // the listeners, migrations and timers of a real start must not happen here
        System.setProperty("quarkus.http.host-enabled", "false");
        System.setProperty("quarkus.liquibase.migrate-at-start", "false");
        System.setProperty("quarkus.scheduler.enabled", "false");
        // the Keycloak checks run only when ValidateApplication asks for them
        System.setProperty("kc-mcp.startup-check", "off");
        // unknown settings are reported with the other problems instead of ending the
        // boot
        System.setProperty("smallrye.config.mapping.validate-unknown", "false");
        System.setProperty("quarkus.banner.enabled", "false");
        System.setProperty("quarkus.log.level", "WARN");
        // a failed boot is reported below, not as a stack trace
        System.setProperty("quarkus.log.category.\"io.quarkus.runtime.Application\".level", "OFF");
        Quarkus.run(application, (exitCode, failure) -> {
            if (failure != null) {
                ValidationRun.add(ValidationRun.message(failure));
                System.exit(ValidateApplication.report());
            }
            System.exit(exitCode);
        });
    }
}
