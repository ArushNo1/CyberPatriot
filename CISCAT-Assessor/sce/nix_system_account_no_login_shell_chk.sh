#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   01/23/24   Verify system accounts are disabled (supersedes account_disabled.sh)

l_output2=""
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"

while IFS= read -r l_account; do
	[ -n "$l_account" ] && l_output2="$l_output2\n  - $l_account"
done < <(awk -v pat="$l_valid_shells" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) && $(NF) ~ pat) {print "Service account: \"" $1 "\" has a valid shell: " $7}' /etc/passwd)

if [ -z "$l_output2" ]; then # If l_output2 is empty, we pass
   echo -e "\n- Audit Result:\n  ** PASS **\n - All service accounts are locked\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi