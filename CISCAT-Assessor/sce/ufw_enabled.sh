#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   07/10/20   Check that Uncomplicated Firewall (UFW) is enabled (active)
# E. Pinnell   10/11/23   Modified to use Bash
# E. Pinnell   02/20/24   Modified to improve software existence check

l_out="" l_output="" l_output2=""

if dpkg-query -s ufw &>/dev/null;then
   l_out=$(ufw status | grep -Pi -- 'Status:')
   if grep -Piq -- '\bactive\b' <<< "$l_out"; then
      l_output="  - UFW status is: \"$l_out\""
   else
      l_output2="  - UFW status is: \"$l_out\""
   fi
else
   l_output2="  - UFW is not installed"
fi

if [ -z "$l_output2" ]; then # Provide output from checks
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi