#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/15/19   Check sshd running configuration
# E. Pinnell   12/04/19   Modified to be POSIX compliant
# E. Pinnell   04/30/19   Modified to add pass or fail reason to CIS-CAT
# E. Pinnell   08/11/20   Modified to add user, host, and addr info
# E. Pinnell   08/17/22   Modified to accept horizontal whitespace "\h" and change environment to bash
# E. Pinnell   11/15/22   Modified ha variable for more reliable output. Corrected where output variable could be unintentionally blank

output=""
passing=""
hn="$(hostname)"
ha="$(hostname -I | cut -d ' ' -f1)"
l_var="$(sshd -t 2>&1)"
XCCDF_VALUE_REGEX="${XCCDF_VALUE_REGEX//(?i)/}"

if [ -z "$l_var" ]; then
   # Set output for CIS-CAT to print
   if echo "$XCCDF_VALUE_REGEX" | grep -Pq -- '^\^\\[sh]\*'; then
      output="$(sshd -T -C user=root -C host="$hn" -C addr="$ha" | grep -P -- "$(echo "$XCCDF_VALUE_REGEX" | cut -d'*' -f2 | cut -d'\' -f1)")"
   elif echo "$XCCDF_VALUE_REGEX" | grep -Pq -- '^\^\\[sh]\*\('; then
      output="$(sshd -T -C user=root -C host="$hn" -C addr="$ha" | grep -P -- "$(echo "$XCCDF_VALUE_REGEX" | cut -d'*' -f2)")"
   elif echo "$XCCDF_VALUE_REGEX" | grep -Pq -- '^(\^\(|\()'; then
      if sshd -T -C user=root -C host="$hn" -C addr="$ha" | grep -Pq -- "$XCCDF_VALUE_REGEX"; then
         output="$(sshd -T -C user=root -C host="$hn" -C addr="$ha" | grep -P -- "$XCCDF_VALUE_REGEX")" 
      else
         output="$(echo "$XCCDF_VALUE_REGEX" | awk -F"[()]" '{print $2}')"
      fi
   else
      output="$(sshd -T -C user=root -C host="$hn" -C addr="$ha" | grep -P -- "$(echo "$XCCDF_VALUE_REGEX" | cut -d'\' -f1)")"
   fi
   # Test if we should pass or fail, if pass passing=true
   sshd -T -C user=root -C host="$hn" -C addr="$ha" | grep -Pq "$XCCDF_VALUE_REGEX" && passing=true
else
   output="\n - **WARNING**\n openSSH server is misconfigured\n  \"$l_var\""
fi

# If passing=true, we pass
if [ "$passing" = true ] ; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - sshd parameter: \"$output\""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   # print the reason why we are failing
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n - check sshd parameter: \"$output\""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi