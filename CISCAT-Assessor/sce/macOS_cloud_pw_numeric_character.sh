#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd		  04/16/24	 Create for macOS Cloud-tailored Benchmark
# 

pwminnum=$(
pref=$(/usr/bin/pwpolicy -getaccountpolicies | /usr/bin/sudo /usr/bin/grep -A1 minimumNumericCharacters | /usr/bin/sudo /usr/bin/tail -1 | /usr/bin/sudo /usr/bin/cut -d '>' -f2 | /usr/bin/sudo /usr/bin/cut -d '<' -f1) && if [[ "$pref" != "" && pref -ge 1 ]]; then echo "true"; else echo "false"; fi
)


if [ "$pwminnum" = "true" ] ; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" == True ] ; then
	echo "PASSED: The password policy requires at least 1 numeric character"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: The password policy does not require at least 1 numeric character"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi

