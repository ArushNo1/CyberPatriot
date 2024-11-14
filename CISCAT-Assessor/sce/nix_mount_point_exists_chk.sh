#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/10/23   Mount point check

#XCCDF_VALUE_REGEX="/tmp" #<- Example XCCDF_VALUE_REGEX

l_output="" l_output2=""
l_mount_point="$XCCDF_VALUE_REGEX"

if findmnt -kn "$l_mount_point" &>/dev/null; then
   l_output=" - Mount point: \"$l_mount_point\" exists"
else
   l_output2=" - Mount point: \"$l_mount_point\" does not exist"
fi

# Output results
if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  *** PASS ***\n- * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
	[ -n "$l_output" ] && echo -e " - * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi