#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
# 
# Name           Date       Description
# ------------------------------------------------------------------------
# E. Pinnell     08/05/24   Check systemd parameter version 3. Added support for a regex in the value field
#

# XCCDF_VALUE_REGEX="0137" #<-Example XCCDF_VALUE_REGEX variable 

# Initialize arrays and set variables
a_output=() a_output2=() l_analyze_cmd="$(readlink -f /bin/systemd-analyze)"
l_include='\$IncludeConfig' a_config_files=("rsyslog.conf") l_parameter_name='\$FileCreateMode'

f_parameter_chk()
{
   l_perm_mask="$XCCDF_VALUE_REGEX"; l_maxperm="$( printf '%o' $(( 0777 & ~$l_perm_mask )) )"
   l_mode="$(awk '{print $2}' <<< "$l_used_parameter_setting" | xargs)"
   if [ $(( $l_mode & $l_perm_mask )) -gt 0 ]; then
      a_output2+=("  - Parameter: \"${l_parameter_name//\\/}\" is incorrectly set to mode: \"$l_mode\"" \
      "    in the file: \"$l_file\"" "    Should be mode: \"$l_maxperm\" or more restrictive")
   else
      a_output+=("  - Parameter: \"${l_parameter_name//\\/}\" is correctly set to mode: \"$l_mode\"" \
      "    in the file: \"$l_file\"" "    Should be mode: \"$l_maxperm\" or more restrictive")
   fi
}

# Loop to find base config files
while IFS= read -r l_file; do
   l_conf_loc="$(awk '$1~/^\s*'"$l_include"'$/ {print $2}' "$(tr -d '# ' <<< "$l_file")" | tail -n 1)"
   [ -n "$l_conf_loc" ] && break
done < <($l_analyze_cmd cat-config "${a_config_files[*]}" | tac | grep -Pio '^\h*#\h*\/[^#\n\r\h]+\.conf\b')

# If include location exists, add additional files to a_config_files array
if [ -d "$l_conf_loc" ]; then
   l_dir="$l_conf_loc" l_ext="*"
elif  grep -Psq '\/\*\.([^#/\n\r]+)?\h*$' <<< "$l_conf_loc" || [ -f "$(readlink -f "$l_conf_loc")" ]; then
   l_dir="$(dirname "$l_conf_loc")" l_ext="$(basename "$l_conf_loc")"
fi

while read -r -d $'\0' l_file_name; do
   [ -f "$(readlink -f "$l_file_name")" ] && a_config_files+=("$(readlink -f "$l_file_name")")
done < <(find -L "$l_dir" -type f -name "$l_ext" -print0 2>/dev/null)

# While loop to find setting being used by the service
while IFS= read -r l_file; do
   l_file="$(tr -d '# ' <<< "$l_file")"
   l_used_parameter_setting="$(grep -PHs -- '^\h*'"$l_parameter_name"'\b' "$l_file" | tail -n 1)"
   [ -n "$l_used_parameter_setting" ] && break
done < <($l_analyze_cmd cat-config "${a_config_files[@]}" | tac | grep -Pio '^\h*#\h*\/[^#\n\r\h]+\.conf\b')

# Run the check if the setting exists, else log that it is missing
if [ -n "$l_used_parameter_setting" ]; then
   f_parameter_chk
else
   a_output2+=("  - Parameter: \"${l_parameter_name//\\/}\" is not set in a configuration file" \
   "   *** Note: \"${l_parameter_name//\\/}\" May be set in a file that's ignored by load procedure ***")
fi

# Send check results and output to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi