#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   07/05/24   Ensure Cinnamon desktop screen locks when the user is idle
#
# Note: values for XCCDF_VALUE_REGEX must be 
# XCCDF_VALUE_REGEX=5:900 #<- Example XCCDF_VALUE_REGEX variable

a_output=(); a_output2=() # Initialize output arrays
# Get the current values of the GSettings keys lock-delay_value:idle-delay_value
l_lock_delay=$(gsettings get org.cinnamon.desktop.screensaver lock-delay | awk '{print $2}' | xargs)
l_idle_delay=$(gsettings get org.cinnamon.desktop.session idle-delay | awk '{print $2}' | xargs)

f_screen_lock_chk()
{
   if [ "$l_lock_delay" -le "$l_lock_delay_value" ]; then
      a_output+=(" - lock_delay is correctly set to: \"$l_lock_delay\"")
   else
      a_output2+=("  - lock_delay is incorrectly set to: \"$l_lock_delay\"" "    and should be \"$l_lock_delay_value\" or less")
   fi
   if [[ "$l_idle_delay" -le "$l_idle_delay_value" && "$l_idle_delay" -gt "0" ]]; then
      a_output+=(" - idle_delay is correctly set to: \"$l_idle_delay\"")
   else
      a_output2+=("  - idle_delay is incorrectly set to: \"$l_idle_delay\"" "    and should be \"$l_idle_delay_value\" or less and not \"0\"")
   fi
}

while IFS=: read -r l_lock_delay_value l_idle_delay_value; do
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