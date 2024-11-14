#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/10/23   Mount point option check

#XCCDF_VALUE_REGEX="/tmp:noexec" #<- Example XCCDF_VALUE_REGEX

l_output="" l_output2=""

while IFS=":" read -r l_mount_point l_mount_point_option; do
   if findmnt -kn "$l_mount_point" &>/dev/null; then
      if findmnt -kn "$l_mount_point" | grep -Pq "\b$l_mount_point_option\b"; then
         l_output=" - Mount point option: \"$l_mount_point_option\" exists on: \"$l_mount_point\""
      else
         l_output2=" - Mount point option: \"$l_mount_point_option\" does not exist on: \"$l_mount_point\""
      fi
   else
      l_output=" - Not applicable. Mount point \"$l_mount_point\" does not exist on the system"
   fi
done <<< "$XCCDF_VALUE_REGEX"

# Output results
if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  *** PASS ***\n- * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
	[ -n "$l_output" ] && echo -e " - * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi