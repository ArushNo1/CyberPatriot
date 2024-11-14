#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd         09/02/20   Ensure system is set to require at least one alphabetical character in passwords
# Edward Byrd 		  11/08/22   Updated for the new naming and new audit
# Edward Byrd		  07/12/23	 Update to output
# 

pwminalpha=$(
pref=$(/usr/bin/sudo /usr/bin/pwpolicy -getaccountpolicies | /usr/bin/sudo /usr/bin/grep -A1 minimumLetters | /usr/bin/sudo /usr/bin/tail -1 | /usr/bin/sudo /usr/bin/cut -d'>' -f2 | /usr/bin/sudo /usr/bin/cut -d '<' -f1) && if [[ "$pref" != "" && pref -ge 1 ]]; then echo "true"; else echo "false"; fi
)


if [ "$pwminalpha" == "true" ] ; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" == True ] ; then
	echo "PASSED: The password policy requires at least 1 alphabetic character"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: The password policy does not require at least 1 alphabetic character"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi

