#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/15/19   Check sshd running configuration not match
# E. Pinnell   04/29/20   Updated test to make it more resilient.
# E. Pinnell   08/11/20   Modified to add user, host, and addr info
# E. Pinnell   11/14/22   Modified to use bash and fail if output from the command is empty or an error
#

l_output="" l_output2=""
l_hostname="$(hostname)"
l_host_address="$(hostname -I | cut -d ' ' -f1)"
l_var="$(sshd -t 2>&1)"
XCCDF_VALUE_REGEX="${XCCDF_VALUE_REGEX//(?i)/}"

if [ -z "$l_var" ]; then
   a_sshd_parameters=()
   while IFS= read -r l_sshd_parameter; do
      [ -n "$l_sshd_parameter" ] && a_sshd_parameters+=("$l_sshd_parameter")
   done < <(sshd -T -C user=root -C host="$l_hostname" -C addr="$l_host_address" 2>/dev/null)
   if (( ${#a_sshd_parameters[@]} > 0 )); then
      for l_parameter in "${a_sshd_parameters[@]}"; do
         l_var="$(grep -P -- "$XCCDF_VALUE_REGEX" <<< "$l_parameter")"
         [ -n "$l_var" ] && l_output2="$l_output2\n - \"$l_var\" contains incorrect values"
      done
      [ -z "$l_output2" ] && l_output=" - No incorrect values found"
   else
      l_output2=" - check sshd configuration file(s)\n - No output provided"
   fi
else
   l_output2="\n - openSSH server is misconfigured:\n  $l_var\n"
fi

# Provide output from checks
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi