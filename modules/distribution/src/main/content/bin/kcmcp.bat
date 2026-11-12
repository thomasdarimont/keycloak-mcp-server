@echo off
rem Starts keycloak-mcp-server from this distribution.
rem
rem   bin\kcmcp.bat start                                     conf\kcmcp.conf
rem   bin\kcmcp.bat start-dev                                 the same, in development mode: profile local, insecure
rem                                                          settings warned about, Keycloak at http://localhost:8080
rem                                                          unless a system is configured
rem                                                          settings are warned about instead of refused
rem   bin\kcmcp.bat start --config conf\read-only.conf          a copy of a conf\scenarios\*.conf.example template
rem   bin\kcmcp.bat start --config conf\systems\              every *.conf file in it, e.g. one per Keycloak system
rem   bin\kcmcp.bat start --kc-mcp.systems.default.url=https://sso.example.com --quarkus.http.port=8082
rem   bin\kcmcp.bat start --debug 5005
rem   bin\kcmcp.bat start --clean-env                         ignore KC_MCP_* and QUARKUS_* variables of the shell
rem   bin\kcmcp.bat show-config [all]                         the settings in effect and their sources, secrets masked
rem   bin\kcmcp.bat validate [--offline]                      run the startup checks and print every problem; starts no server
rem   bin\kcmcp.bat providers                                 the installed extensions and whether each takes part
rem   bin\kcmcp.bat build --db=postgresql                    build for a database, h2 or postgresql; stop the server first
rem   bin\kcmcp.bat --version | --help
rem
rem Any --kc-mcp.name=value or --quarkus.name=value sets that configuration property; environment variables (KC_MCP_SYSTEMS_DEFAULT_URL=...) work as well and
rem override the configuration files, so the script lists the ones it inherits from the shell.
rem JAVA_HOME or JAVA pick the JVM (Java 21 or newer); JAVA_OPTS replaces the default JVM options, JAVA_OPTS_APPEND
rem adds to them. KCMCP_DEBUG=true, KCMCP_DEBUG_PORT and KCMCP_DEBUG_SUSPEND enable remote debugging.

setlocal enabledelayedexpansion

set "BIN_DIR=%~dp0"
pushd "%BIN_DIR%.."
set "KCMCP_HOME=%CD%"
popd

set DEBUG_MODE=false
set DEBUG_ADDRESS=5005
set DEBUG_SUSPEND_VAR=n
if not "%KCMCP_DEBUG%" == "" set DEBUG_MODE=%KCMCP_DEBUG%
if not "%KCMCP_DEBUG_PORT%" == "" set DEBUG_ADDRESS=%KCMCP_DEBUG_PORT%
if not "%KCMCP_DEBUG_SUSPEND%" == "" set DEBUG_SUSPEND_VAR=%KCMCP_DEBUG_SUSPEND%

rem the configuration files, read by the server from kc-mcp.config-files (plain paths, comma separated)
set "CONFIG_FILES=%KCMCP_HOME%\conf\kcmcp.conf"
set SERVER_OPTS=
set SERVER_ARGS=
set COMMAND=
set CLEAN_ENV=false
set DB=

rem cmd splits "--name=value" and "-Dname=value" at the "=": KEY is the part before it, VALUE the part after
:READ_ARGS
set "KEY=%~1"
if "%KEY%" == "" goto MAIN
if "%KEY%" == "start" (
    set COMMAND=start
    shift
    goto READ_ARGS
)
if "%KEY%" == "start-dev" (
    set COMMAND=start-dev
    shift
    goto READ_ARGS
)
if "%KEY%" == "show-config" (
    set COMMAND=show-config
    shift
    goto READ_ARGS
)
if "%KEY%" == "providers" (
    set COMMAND=providers
    shift
    goto READ_ARGS
)
if "%KEY%" == "validate" (
    set COMMAND=validate
    shift
    goto READ_ARGS
)
if "%KEY%" == "all" (
    set "SERVER_ARGS=!SERVER_ARGS! all"
    shift
    goto READ_ARGS
)
if "%KEY%" == "--offline" (
    set "SERVER_ARGS=!SERVER_ARGS! --offline"
    shift
    goto READ_ARGS
)
if "%KEY%" == "build" (
    set COMMAND=build
    shift
    goto READ_ARGS
)
if "%KEY%" == "--db" (
    set "DB=%~2"
    shift
    shift
    goto READ_ARGS
)
if "%KEY%" == "--clean-env" (
    set CLEAN_ENV=true
    shift
    goto READ_ARGS
)
if "%KEY%" == "--help" goto USAGE
if "%KEY%" == "-h" goto USAGE
if "%KEY%" == "--version" goto VERSION
if "%KEY%" == "-v" goto VERSION
if "%KEY%" == "--debug" (
    set DEBUG_MODE=true
    set "NEXT=%~2"
    if not "!NEXT!" == "" (
        echo !NEXT!| findstr /R "^[0-9][0-9]*$" >nul && (
            set DEBUG_ADDRESS=!NEXT!
            shift
        )
    )
    shift
    goto READ_ARGS
)
if "%KEY%" == "--config" (
    rem absolute, relative to the current directory, or relative to the distribution
    set "CFG=%~f2"
    if not exist "!CFG!" if exist "%KCMCP_HOME%\%~2" set "CFG=%KCMCP_HOME%\%~2"
    if not exist "!CFG!" (
        echo configuration file not found: %~2 1>&2
        exit /b 2
    )
    set "CONFIG_FILES=!CONFIG_FILES!,!CFG!"
    shift
    shift
    goto READ_ARGS
)
if "%KEY:~0,2%" == "-D" (
    set "VALUE=%~2"
    if not "!VALUE!" == "" if not "!VALUE:~0,1!" == "-" (
        set "SERVER_OPTS=!SERVER_OPTS! "%KEY%=!VALUE!""
        shift
        shift
        goto READ_ARGS
    )
    set "SERVER_OPTS=!SERVER_OPTS! "%KEY%""
    shift
    goto READ_ARGS
)
if "%KEY:~0,2%" == "--" (
    set "NAME=%KEY:~2%"
    set "VALUE=%~2"
    if "!VALUE!" == "" (
        echo --!NAME! needs a value, as --!NAME!=value 1>&2
        exit /b 2
    )
    set "SERVER_ARGS=!SERVER_ARGS! "--!NAME!=!VALUE!""
    shift
    shift
    goto READ_ARGS
)
echo unknown argument: %KEY% (try --help^) 1>&2
exit /b 2

:USAGE
for /f "usebackq skip=1 tokens=* delims=" %%L in ("%~f0") do (
    set "LINE=%%L"
    if "!LINE:~0,3!" == "rem" (
        echo !LINE:~4!
    ) else (
        goto :EOF
    )
)
goto :EOF

:VERSION
if exist "%KCMCP_HOME%\version.txt" (type "%KCMCP_HOME%\version.txt") else (echo unknown)
goto :EOF

:MAIN
if "%COMMAND%" == "" goto USAGE
if not "%COMMAND%" == "build" if not "%DB%" == "" (
    echo --db belongs to the build command 1>&2
    exit /b 2
)
if "%COMMAND%" == "build" if not "%DB%" == "h2" if not "%DB%" == "postgresql" (
    echo build needs --db=h2 or --db=postgresql 1>&2
    exit /b 2
)

rem configuration inherited from the shell overrides the files; list it, or drop it with --clean-env
set INHERITED=
for /f "delims==" %%v in ('set KC_MCP_ 2^>nul') do set "INHERITED=!INHERITED!%%v "
for /f "delims==" %%v in ('set QUARKUS_ 2^>nul') do set "INHERITED=!INHERITED!%%v "
if not "!INHERITED!" == "" (
    if "%CLEAN_ENV%" == "true" (
        for %%v in (!INHERITED!) do set "%%v="
        echo ignoring the environment's !INHERITED! 1>&2
    ) else (
        echo note: the environment sets !INHERITED!^(these override the configuration files; --clean-env ignores them^) 1>&2
    )
)

if "%JAVA%" == "" (
    if not "%JAVA_HOME%" == "" (
        set "JAVA=%JAVA_HOME%\bin\java"
    ) else (
        set "JAVA=java"
    )
)

if "%COMMAND%" == "build" goto BUILD

if "%JAVA_OPTS%" == "" (
    set "JAVA_OPTS=-Xms64m -Xmx512m -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError -Dfile.encoding=UTF-8"
)
if not "%JAVA_OPTS_APPEND%" == "" set "JAVA_OPTS=%JAVA_OPTS% %JAVA_OPTS_APPEND%"
if "%DEBUG_MODE%" == "true" (
    set "JAVA_OPTS=%JAVA_OPTS% -agentlib:jdwp=transport=dt_socket,address=%DEBUG_ADDRESS%,server=y,suspend=%DEBUG_SUSPEND_VAR%"
)

rem where this distribution keeps things; the configuration may refer to ${kcmcp.home.dir}
set "HOME_OPTS=-Dkcmcp.home.dir="%KCMCP_HOME%" -Dkc-mcp.config-files="%CONFIG_FILES%""
set "HOME_OPTS=%HOME_OPTS% -Dkc-mcp.providers-dir="%KCMCP_HOME%\providers" -Dkc-mcp.keys-dir="%KCMCP_HOME%\data\keys" -Dkc-mcp.prompts-dir="%KCMCP_HOME%\conf\prompts""
set "HOME_OPTS=%HOME_OPTS% -Djava.util.logging.manager=org.jboss.logmanager.LogManager"

if "%KCMCP_PRINT_ENV%" == "true" (
    echo Using JAVA: %JAVA%
    echo Using JAVA_OPTS: %JAVA_OPTS%
    echo Using SERVER_OPTS: %HOME_OPTS% %SERVER_OPTS%
)

cd /d "%KCMCP_HOME%"
"%JAVA%" %JAVA_OPTS% %HOME_OPTS% %SERVER_OPTS% -jar "%KCMCP_HOME%\lib\quarkus-run.jar" %COMMAND% %SERVER_ARGS%
exit /b %ERRORLEVEL%

rem Quarkus re-augments the package from lib\lib\deployment: no Maven or network. It expects lib\providers to exist,
rem and leaves a partial copy of the package in quarkus-app\ next to the output directory.
:BUILD
echo Building for %DB%. Please wait. 1>&2
if not exist "%KCMCP_HOME%\lib\providers" mkdir "%KCMCP_HOME%\lib\providers"
cd /d "%KCMCP_HOME%"
"%JAVA%" -Dquarkus.launch.rebuild=true -Dquarkus.package.output-directory=lib -Dquarkus.datasource.db-kind=%DB% -jar "%KCMCP_HOME%\lib\quarkus-run.jar"
set STATUS=%ERRORLEVEL%
if exist "%KCMCP_HOME%\quarkus-app" rmdir /s /q "%KCMCP_HOME%\quarkus-app"
if exist "%KCMCP_HOME%\quarkus-artifact.properties" del "%KCMCP_HOME%\quarkus-artifact.properties"
if "%STATUS%" == "0" (echo %DB%> "%KCMCP_HOME%\lib\quarkus\db-kind" & echo Built for %DB%. 1>&2) else (echo The build failed; the previous build is unchanged. 1>&2)
exit /b %STATUS%
