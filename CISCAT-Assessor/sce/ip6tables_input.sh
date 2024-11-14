#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   11/14/19   Check iptables INPUT Chain
# E. Pinnell   02/20/24   Modified to use Bash and grep -P and check if ip6tables is installed

l_output="" l_output2=""

if dpkg-query -s ip6tables &>/dev/null; then
   l_output="$(ip6tables -L INPUT -v -n | grep -P -- "$XCCDF_VALUE_REGEX")"
else
   l_output2=" - ip6tables package is not installed"
fi
[ -n "$l_output" ] && l_output="  - ip6tables rule exists:\n$l_output\n"
if [ -z "$l_output" ] && [ -z "$l_output2" ]; then
   l_output2="  - Missing ip6tables rule"
fi

if [ -z "$l_output2" ]; then # Provide output from checks
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi