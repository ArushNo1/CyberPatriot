#!/usr/bin/env bash
#
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar    09/03/24  Check iptables INPUT Chain
#

l_output="" l_output2=""

if command -v iptables &>/dev/null; then
   l_output="$(iptables -L INPUT -v -n | grep -P -- "$XCCDF_VALUE_REGEX")"
   if [ -z "$l_output" ]; then
      l_output2="  - Missing iptables rule"
   fi
else
   l_output2=" - iptables package is not installed"
fi

if [ -z "$l_output2" ]; then # Provide output from checks
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi