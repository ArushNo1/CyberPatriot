#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/24/19   Check iptables list output
# E. Pinnell   01/13/22   Modified to stop dns lookup
# E. Pinnell   02/08/22   Modified to fix iptables command and add XCCDF_VALUE_REGEX value example
# E. Pinnell   02/20/24   Modified to use Bash and grep -P and check if iptables is installed

# Example XCCDF_VALUE_REGEX value: "^Chain OUTPUT \(policy (DROP|REJECT)\)$"

l_output="" l_output2=""

if dpkg-query -s iptables &>/dev/null; then
   l_output="$(iptables -L -n | grep -P -- "$XCCDF_VALUE_REGEX")"
else
   l_output2=" - iptables package is not installed"
fi
[ -n "$l_output" ] && l_output="  - iptables rule exists:\n$l_output\n"
if [ -z "$l_output" ] && [ -z "$l_output2" ]; then
   l_output2="  - Missing iptables rule"
fi

if [ -z "$l_output2" ]; then # Provide output from checks
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi