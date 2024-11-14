#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   07/05/24   Cinnamon desktop key setting string check
#
# Note: values for XCCDF_VALUE_REGEX must be 
# XCCDF_VALUE_REGEX=org.cinnamon.desktop.media-handling:automount:false #<- Example XCCDF_VALUE_REGEX variable

a_output=(); a_output2=() # Initialize output arrays

f_screen_lock_chk()
{
   l_system_key_value="$(gsettings get $l_schema_name $l_key_name)"
   if [ -n "$l_system_key_value" ]; then
      if [ "$l_system_key_value" = "$l_key_value" ]; then
         a_output+=(" - \"$l_schema_name $l_key_name\" is correctly set to: \"$l_system_key_value\"")
      else
         a_output2+=("  - \"$l_schema_name $l_key_name\"" "    is incorrectly set to: \"$l_system_key_value\" and should be set to: \"$l_key_value\"")
      fi
   else
      a_output2+=("  - \"$l_schema_name $l_key_name\" is not set")
   fi
}

while IFS=: read -r l_schema_name l_key_name l_key_value; do
   f_screen_lock_chk
done <<< "$XCCDF_VALUE_REGEX"

# Send test results and assessment evidence to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi