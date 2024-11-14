#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   09/18/24   Check mount points for mount options by file type

# XCCDF_VALUE_REGEX="nfs:nodev" #<- XCCDF_VALUE_REGEX variable example

a_output=() a_output2=() a_output3=()

while IFS=: read -r l_fstype l_mp_option; do
   while IFS= read -r l_mount_point; do
      if findmnt -kn "$l_mount_point" | grep -Pvsq -- '\b'"$l_mp_option"'\b'; then
         a_output2+=("  - Mount point: \"$l_mount_point\" does not include \"$l_mp_option\"")
      else
         a_output+=("  - Mount point: \"$l_mount_point\" includes \"$l_mp_option\"")
      fi
   done < <(findmnt -Dkerno fstype,target | awk '$1=="'"$l_fstype"'" {print $2}')
   [[ "${#a_output[@]}" -le 0 && "${#a_output2[@]}" -le 0 ]] && a_output3+=("  - No \"$l_fstype\" mount points exist on the system")
done <<< "$XCCDF_VALUE_REGEX"

# Create output for CIS-CAT
if [ "${#a_output3[@]}" -gt 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** Not Applicable **" "${a_output3[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
elif [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi