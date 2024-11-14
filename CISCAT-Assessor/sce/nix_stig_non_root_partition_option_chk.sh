#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   09/18/24   STIG check non root partitions include partition option

# XCCDF_VALUE_REGEX="nodev" #<- Example XCCDF_VALUE_REGEX variable

a_output=() a_output2=()
l_mp_option="$XCCDF_VALUE_REGEX"

while IFS= read -r l_mount_point; do
   a_output2+=("  - Mount point \"$l_mount_point\" does not include the \"$l_mp_option\" option")
done < <(mount | grep '^/dev\S* on /\S' | awk '($0 !~ /(\s|,)"'"$l_mp_option"'"(,|\s)/){print $3}')

# Create output for CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   a_output+=("  - No non-root mount points exist on the system with out the \"$l_mp_potion\" option")
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi