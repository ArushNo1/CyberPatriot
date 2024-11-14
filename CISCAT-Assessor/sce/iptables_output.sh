#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   11/14/19   Check iptables OUTPUT Chain
# E. Pinnell   02/20/24   Modified to use Bash and grep -P and check if iptables is installed

l_output="" l_output2=""

if dpkg-query -s iptables &>/dev/null; then
   l_output="$(iptables -L OUTPUT -v -n | grep -P -- "$XCCDF_VALUE_REGEX")"
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