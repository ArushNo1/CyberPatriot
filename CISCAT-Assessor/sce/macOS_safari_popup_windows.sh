#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd         10/12/23   6.3.9 Ensure Pop-up Windows Are Blocked
#

safaripopup=$(
profiles -P -o stdout | /usr/bin/grep -c "safariAllowPopups = 0;")

if [ "$safaripopup" == "1" ]; then
  output=True
else
  output=False
fi

# If test passed, then no output would be generated. If so, we pass
if [ "$output" = True ] ; then
	echo "PASSED: Profile installed to disable popups in Safari"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: A profile needs to be installed that disables popups in Safari"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi




