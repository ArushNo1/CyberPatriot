#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/24/19   Check iptables list output
# E. Pinnell   01/13/22   Modified to stop dns lookup
# E. Pinnell   02/20/24   Modified to use Bash and grep -P and check if ip6tables is installed
# R. Bejar     03/27/24   Update to which, ip6tables are installed by default
# E. Pinnell   04/05/24   Modified to use command -v for consistency

# XCCDF_VALUE_REGEX="^\h*Chain\h+INPUT\h+\(policy (DROP|REJECT)\)" #<- example XCCDF_VALUE_REGEX variable

l_output="" l_output2="" l_out=""

if command -v ip6tables &>/dev/null; then
   l_out="$(ip6tables -L -n | grep -P -- "$XCCDF_VALUE_REGEX")"
   if [ -n "$l_out" ]; then
      l_output="$l_output\n  - ip6tables rule exists:\n  - $l_out\n"
   else
      l_output2="$l_output2\n  - Missing ip6tables rule"
   fi
else
   l_output2="$l_output2\n  - command \"ip6tables\" not found\n   verify iptables is installed if iptables is in use on the system"
fi


if [ -z "$l_output2" ]; then # Provide output from checks
   echo -e "\n- Audit Result:\n  ** PASS **$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi