#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   04/05/21   Find firewalld state
# E. Pinnell   11/30/23   Modified to use bash, modernize, and to improve efficiency and output

# XCCDF_VALUE_REGEX="running" # <- Example XCCDF_VALUE_REGEX setting
l_output="" l_output2=""

if command -v firewall-cmd &>/dev/null; then
	l_firewalld_state="$(firewall-cmd --state)"
	if grep -Pqi -- "$XCCDF_VALUE_REGEX" <<< "$l_firewalld_state"; then
		l_output=" - firewalld state is: \"$l_firewalld_state\""
	else
		l_output2=" - firewalld state is: \"$l_firewalld_state\""
	fi
else
	l_output2="  - firewall-cmd command not fount on the system\n    Manual assessment may be required"
fi

if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  *** PASS ***\n- * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
	[ -n "$l_output" ] && echo -e " - * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi