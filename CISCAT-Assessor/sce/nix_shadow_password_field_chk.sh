#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   12/07/23   Check if /etc/shadow password field is empty

l_output="" l_output2=""

while IFS=: read -r l_username l_pass _ _ _ _ _ _ _; do
   [ -z "$l_pass" ] && l_output2="$l_output2\n - User: \"$l_username\" password field is empty in /etc/shadow"
done < /etc/shadow
# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   l_output=" - No users password field is empty in /etc/shadow"
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi