#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd         10/12/23   6.3.11 Ensure Show Status Bar Is Enabled
#

safaristatusbar=$(
profiles -P -o stdout | /usr/bin/grep -c "ShowOverlayStatusBar = 1;")

if [ "$safaristatusbar" == "1" ]; then
  output=True
else
  output=False
fi

# If test passed, then no output would be generated. If so, we pass
if [ "$output" = True ] ; then
	echo "PASSED: Profile installed to enable show status bar in Safari"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: A profile needs to be installed that enables the status bar in Safari"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi




