@ECHO OFF
::
:: Wrapper for invoking CIS-CAT
::
SET timestamp=%1

@echo off
echo %*
set _tail=%*
call set _tail=%%_tail:*%1=%%
echo %_tail%

SET DEBUG=0

::
:: Setting Java to the bundled jre one
::

SET JAVA="%~dp0\..\..\jre\bin\java.exe"

%JAVA% 2> NUL > NUL

IF NOT %ERRORLEVEL%==9009 IF NOT %ERRORLEVEL%==3 GOTO RUNCISCAT

IF %ERRORLEVEL%==9009 GOTO NOJAVAERROR
IF %ERRORLEVEL%==3 GOTO NOJAVAERROR

::
:: Invoke CIS-CAT Pro Assessor (CLI) with a 2048MB heap
::

:RUNCISCAT

IF %DEBUG%==1 (
	ECHO Found Java at %JAVA%
	ECHO Running CIS-CAT Pro Assessor from "%~dp0"
	%JAVA% -Xmx2048M -jar "..\..\%~dp0\Assessor-CLI.jar" %_tail% --verbose
) ELSE (
	if not exist "%~dp0\..\..\logs" mkdir %~dp0\..\..\logs
	if not exist "%~dp0\..\..\logs\GUI_console_logs" mkdir %~dp0\..\..\logs\GUI_console_logs
	%JAVA% -Xmx2048M -jar "%~dp0\..\..\Assessor-CLI.jar" %_tail% > %~dp0\..\..\logs\GUI_console_logs\batchlog-%timestamp%.txt
)

GOTO EXIT

:NOJAVAERROR

ECHO The Java runtime was not found in the jre folder of the bundle.  Please ensure all paths and files are present.
PAUSE

:EXIT


