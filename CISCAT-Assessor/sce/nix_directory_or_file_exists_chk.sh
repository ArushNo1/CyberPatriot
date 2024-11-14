#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name       Date       Description
# -------------------------------------------------------------------
# E. Pinnell 09/18/24   Check if file exists
#

# XCCDF_VALUE_REGEX="*.conf" # <- Example XCCDF_VALUE_REGEX variable

a_output=() a_output2=()
l_file_name="$XCCDF_VALUE_REGEX"
# Set report output limit
l_limit="20"

# Populate array with paths to be excluded
a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")

# Find failing directories or files
while IFS= read -r l_mount; do
   while IFS= read -r -d $'\0' l_file; do
      [ -d "$l_file" ] && l_ftype="directory"
      [ -f "$l_file" ] && l_ftype="file"
      a_output2+=("  - $l_ftype: \"$(basename "$l_file")\" exists as:" "    \"$l_file\"")
   done < <(find -L "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -name "$l_file_name" -print0 2> /dev/null)
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')

# Create output for CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   a_output+=("  - No \"$l_file_name\" files found on the system")
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]:0:$l_limit}"
   [ "${#a_output2[@]}" -ge "$l_limit" ] && printf '%s\n' "" "  ** NOTE **" "  - more than \"$(( l_limit / 2 ))\" $l_ftype(s) found" \
   "    Displaying only the first $(( l_limit / 2 ))"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi