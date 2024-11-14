#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd         10/12/23   5.10/5.11 Ensure XProtect Is Running and Updated
# 

xprotectenable=$(
/bin/launchctl list | /usr/bin/grep -cE "(com.apple.XprotectFramework.PluginService$|com.apple.XProtect.daemon.scan$)"
)


if [ $xprotectenable -eq 2 ] ; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" = True ] ; then
	echo "PASSED: XProtect is enabled"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: XProtect is disabled and needs to be investigated"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi
