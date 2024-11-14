#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   07/01/24   Check system kernel parameters
# E. Pinnell   07/22/24   Modified to use more efficient check

# Note:
# - Allows simple regex to allow for more than one acceptable value
# - Supersedes the deprecated nix_kernel_parameter_chk_v2.sh

# XCCDF_VALUE_REGEX="kernel.yama.ptrace_scope=(1|2|3)" #<- Example XCCDF_VALUE_REGEX variable

# Initialize arrays and set variables
a_output=(); a_output2=(); l_ipv6_disabled=""
l_ufw_sysctl_file="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
l_analyze_cmd="$(readlink -f /lib/systemd/systemd-sysctl)"

# Function to check if IPv6 is enabled
f_ipv6_chk()
{
   l_ipv6_disabled="no"
   ! grep -Pqs -- '^\h*0\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled="yes"
   if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \
      sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then
      l_ipv6_disabled="yes"
   fi
}

# Function to check kernel parameter values 
f_kernel_parameter_chk()
{
   # Check kernel parameter in the running configuration
   l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= '{print $2}' | xargs)"
   if grep -Pq -- '\b'"$l_parameter_value"'\b' <<< "$l_running_parameter_value"; then
      a_output+=("  - Parameter: \"$l_parameter_name\"" \
      "    correctly set to \"$l_running_parameter_value\" in the running configuration")
   else
      a_output2+=("  - Parameter: \"$l_parameter_name\"" \
      "    is incorrectly set to \"$l_running_parameter_value\" in the running configuration" \
      "    Should be set to: \"$l_value_out\"")
   fi

   # Check kernel parameter value loaded from the configuration files
   l_used_parameter_setting="$(grep -PHs -- '^\h*'"$l_parameter_name"'\b' "$l_ufw_sysctl_file" | tail -n 1)"
   if [ -z "$l_used_parameter_setting" ]; then
      while IFS= read -r l_file; do
         l_file="$(tr -d '# ' <<< "$l_file")"
         l_used_parameter_setting="$(grep -PHs -- '^\h*'"$l_parameter_name"'\b' "$l_file" | tail -n 1)"
         [ -n "$l_used_parameter_setting" ] && break
      done < <($l_analyze_cmd --cat-config | tac | grep -Pio '^\h*#\h*\/[^#\n\r\h]+\.conf\b')
   fi
   if [ -n "$l_used_parameter_setting" ]; then
      while IFS=: read -r l_file_name l_file_parameter; do
         while IFS="=" read -r l_file_parameter_name l_file_parameter_value; do
            if grep -Pq -- "$l_parameter_value" <<< "$l_file_parameter_value"; then
               a_output+=("  - Parameter: \"${l_file_parameter_name// }\"" \
               "    correctly set to: \"${l_file_parameter_value// }\" in the file: \"$l_file_name\"")
            else
               a_output2+=("  - Parameter: \"${l_file_parameter_name// }\"" \
               "    incorrectly set to: \"${l_file_parameter_value// }\" in the file: \"$l_file_name\"" \
               "    Should be set to: \"$l_value_out\"")
            fi
         done <<< "$l_file_parameter"
      done <<< "$l_used_parameter_setting"
   else
      a_output2+=("  - Parameter: \"$l_parameter_name\" is not set in an included file" \
      "  *** Note: \"$l_parameter_name\" May be set in a file that's ignored by load procedure ***")
   fi
}

# Main loop for XCCDF_VALUE_REGEX value
while IFS="=" read -r l_parameter_name l_parameter_value; do # Check parameters
   l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}"
   l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
   l_value_out="$(tr -d '(){}' <<< "$l_value_out")"
   if grep -q '^net.ipv6.' <<< "$l_parameter_name"; then
      [ -z "$l_ipv6_disabled" ] && f_ipv6_chk
      if [ "$l_ipv6_disabled" = "yes" ]; then
         a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
      else
         f_kernel_parameter_chk
      fi
   else
      f_kernel_parameter_chk
   fi
done <<< "$XCCDF_VALUE_REGEX"

# Send test results and output to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi