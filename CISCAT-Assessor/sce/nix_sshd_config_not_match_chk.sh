#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   12/05/23   Check sshd configuration parameter not match (Replaces deprecated sshd_running_config_nm.sh)
# E. Pinnell   05/30/24   Modified to handle warning and unsupported test output to address false failures

# XCCDF_VALUE_REGEX="macs:hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh\.com,hmac-md5-etm@openssh\.com,hmac-md5-96-etm@openssh\.com,hmac-ripemd160-etm@openssh\.com,hmac-sha1-96-etm@openssh\.com,umac-64-etm@openssh\.com" # <- example complex XCCDF_VALUE_REGEX variable
l_output="" l_output2="" l_output3=""
l_var="$(sshd -t 2>&1 | grep -Pvi -- '\bterminating\b')"

if grep -Piq -- '\bunsupported\b' <<< "$l_var"; then
   l_output2="\n - openSSH server configuration includes an unsupported option:\n  $l_var\n"
else
   [ -n "$l_var" ] && l_output3="\n  ** WARNING **\n  - $l_var"
   # Set hostname and hast address variables for sshd -T command
   l_hostname="$(hostname)"
   l_host_address="$(hostname -I | cut -d ' ' -f1)"
   # create associative array of openSSH server parameters and their values
   unset A_sshd_config
   declare -A A_sshd_config
   while IFS= read -r l_sshd_config_value; do
      if [ -n "$l_sshd_config_value" ]; then
         l_parameter_name="$(cut -d' ' -f1 <<< "$l_sshd_config_value" | xargs)"
         l_parameter_value="$(awk '{ $1=""; print}' <<< "$l_sshd_config_value" | xargs)"
         A_sshd_config+=(["$l_parameter_name"]="$l_parameter_value")
      fi
   done < <(sshd -T -C user=root -C host="$l_hostname" -C addr="$l_host_address" 2>/dev/null)

   while IFS=: read -r l_sshd_parameter_search_name l_sshd_parameter_search_value; do # Split XCCDF_VALUE_REGEX variable into needed parts
      # Check each variable name for configuration
      for l_sshd_parameter_name in ${l_sshd_parameter_search_name//,/ }; do
         for l_sshd_parameter_value in ${l_sshd_parameter_search_value//,/ }; do
            l_var2="${A_sshd_config["$l_sshd_parameter_name"]}"
            if grep -Pq -- "\"?\b$l_sshd_parameter_value\b" <<< "$l_var2"; then
               if [ -z "$l_output2" ]; then
                  l_output2=" - sshd parameter: \"$l_sshd_parameter_name\" incorrectly includes:\n   - ${l_sshd_parameter_value//\\/}"
               else
                  l_output2="$l_output2, ${l_sshd_parameter_value//\\/}"
               fi
            else
               l_output="$l_output\n - sshd parameter: \"$l_sshd_parameter_name\" does not include: \"${l_sshd_parameter_value//\\/}\""
            fi
         done
      done
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