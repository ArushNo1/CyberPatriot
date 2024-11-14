#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/29/21   Ensure no users have shadow as primary group
# E. Pinnell   02/01/24   Modified to run in bash, improve, and modernize

l_output="" l_output2=""

l_output2="$(awk -F: '($4 == '"$(getent group shadow | awk -F: '{print $3}' | xargs)"') {print "  - user: \"" $1 "\" primary group is the shadow group"}' /etc/passwd)"

# If the tests produce no failing output, we pass
if [ -z "$l_output2" ]; then
	l_output="  - No users have group shadow as their primary group"
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi