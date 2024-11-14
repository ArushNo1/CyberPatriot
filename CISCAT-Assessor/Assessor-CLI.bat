@ECHO OFF
::
:: Wrapper for invoking CIS-CAT 
::

SET DEBUG=0

::
:: Setting Java to the bundled jre one
::

SET JAVA="%~dp0\jre\bin\java.exe"

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

IF %ERRORLEVEL%==9009 GOTO NOJAVAERROR
IF %ERRORLEVEL%==3 GOTO NOJAVAERROR

::
:: Invoke CIS-CAT Pro Assessor (CLI) with a 2048 heap
::

:RUNCISCAT

IF %DEBUG%==1 (
	ECHO Found Java at %JAVA%
	ECHO Running CIS-CAT Pro Assessor from "%~dp0"
	%JAVA% -Xmx2048M -jar "%~dp0\Assessor-CLI.jar" %* --verbose
) ELSE (
	%JAVA% -Xmx2048M -jar "%~dp0\Assessor-CLI.jar" %*
)

GOTO EXIT

:NOJAVAERROR

ECHO The Java runtime was not found in the jre folder of the bundle.  Please ensure all paths and files are present.
PAUSE

:EXIT


