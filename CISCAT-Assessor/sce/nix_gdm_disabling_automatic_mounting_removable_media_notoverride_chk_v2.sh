#!/usr/bin/env bash

# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     08/01/24   Ensure GDM disabling automatic mounting of removable media is not overridden
#

# Function to check and report if a specific setting is locked and set to false
check_setting() 
{
 #  local section="\[$2\]"
   grep -Psrilq "^\h*$1\h*=\h*false\b" /etc/dconf/db/local.d/locks/* 2> /dev/null && echo "- \"$3\" is locked and set to false" || echo "- \"$3\" is not locked or not set to false" 
}

# Array of settings to check
declare -A settings=(
   ["automount"]="org/gnome/desktop/media-handling"
   ["automount-open"]="org/gnome/desktop/media-handling"
)

# Check GNOME Desktop Manager configurations
a_output=() a_output2=()
for setting in "${!settings[@]}"; do
   result=$(check_setting "$setting" "${settings[$setting]}" "$setting")
   if [[ $result == *"is not locked"* || $result == *"not set to false"* ]]; then
      a_output2+=("$result")
   else
      a_output+=("$result")
   fi
done

# Report results
printf '%s\n' "" "- Audit Result:"
if [ "${#a_output2[@]}" -gt 0 ]; then
   printf '%s\n' "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
else
   printf '%s\n' "  ** PASS **" "${a_output[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
fi