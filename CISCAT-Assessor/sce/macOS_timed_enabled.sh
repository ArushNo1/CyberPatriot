#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd		  06/18/24   Check timed is enabled
#

timeservice=$(
/bin/launchctl list | /usr/bin/grep -c com.apple.timed
)

if [ $timeservice -eq 1 ] ; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" == True ] ; then
	echo "PASSED: The httpd service is disabled"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: The httpd service is running and needs to be unloaded and disabled"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi

