#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/22/24   Check sshd configuration parameter match for non match block parameters
# E. Pinnell   05/30/24   Modified to handle warning and unsupported test output to address false failures

# XCCDF_VALUE_REGEX="allowusers,allowgroups,denyusers,denygroups:\H+\b(\h+\H+\b)*" # <- example complex XCCDF_VALUE_REGEX variable

l_output="" l_output2="" l_output3=""
l_var="$(sshd -t 2>&1 | grep -Pvi -- '\bterminating\b')"

# Create error message if sshd_config is misconfigured
if grep -Piq -- '\bunsupported\b' <<< "$l_var"; then
   l_output2="\n - openSSH server configuration includes an unsupported option:\n  $l_var\n"
else
   [ -n "$l_var" ] && l_output3="\n  ** WARNING **\n  - $l_var"
   # create associative array of openSSH server parameters and their values
   unset A_sshd_config
   declare -A A_sshd_config

   while IFS= read -r l_sshd_config_value; do
      if [ -n "$l_sshd_config_value" ]; then
         l_parameter_name="$(cut -d' ' -f1 <<< "$l_sshd_config_value" | xargs)"
         l_parameter_value="$(awk '{ $1=""; print}' <<< "$l_sshd_config_value" | xargs)"
         A_sshd_config+=(["$l_parameter_name"]="$l_parameter_value")
      fi
   done < <(sshd -T 2>/dev/null)

   # Split XCCDF_VALUE_REGEX variable into needed parts
   while IFS=: read -r l_sshd_parameter_search_name l_sshd_parameter_search_value; do
      l_sshd_parameter_search_name="${l_sshd_parameter_search_name,,}"
      # Check each variable name for configuration
      for l_sshd_parameter_name in ${l_sshd_parameter_search_name//,/ }; do
         l_var2="${A_sshd_config["$l_sshd_parameter_name"]}"
         if grep -Piq -- "\"?\h*$l_sshd_parameter_search_value" <<< "$l_var2"; then
            l_output="$l_output\n - sshd parameter: \"$l_sshd_parameter_name\" is correctly set to: \"$l_var2\""
         else
            if [ -n "$l_var2" ]; then
               l_output2="$l_output2\n - sshd parameter: \"$l_sshd_parameter_name\" is incorrectly set to: \"$l_var2\""
            else
               l_output2="$l_output2\n - sshd parameter: \"$l_sshd_parameter_name\" is not configured"
            fi
         fi
      done
      # If a parameter matched, reset l_output2 to null
      [ -n "$l_output" ] && l_output2=""
   done <<< "$XCCDF_VALUE_REGEX"
fi

unset A_sshd_config

# Provide output from checks
if [ -z "$l_output2" ]; then
   [ -n "$l_output3" ] && echo -e "$l_output3"
   echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   [ -n "$l_output3" ] && echo -e "$l_output3"
   echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi