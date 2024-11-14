#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name       Date       Description
# -------------------------------------------------------------------
# E. Pinnell 03/27/23   Check for unowned or ungrouped files or directories
# E. Pinnell 04/10/23   Modified to work of Debian and exclude "/*/containerd/*" and "/*/kubelet/pods/*"
# E. Pinnell 02/01/24   Modified to add to exclude list
# E. Pinnell 02/08/24   Modified to add to exclude list
# E. Pinnell 02/09/24   Modified to clean up exclude list and add vfat to the excluded targets
# E. Pinnell 03/07/24   Modified to improve search efficiency 
#

l_output="" l_output2=""

# Set report output limit
l_limit="50"

# Initialize arrays
a_nouser=()
a_nogroup=()

# Populate array with paths to be excluded
a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")

# Find and test "relevant" files
while IFS= read -r l_mount; do
   while IFS= read -r -d $'\0' l_file; do
      if [ -e "$l_file" ]; then
         while IFS=: read -r l_user l_group; do
            [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_file")
            [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_file")
         done < <(stat -Lc '%U:%G' "$l_file")
      fi
   done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2> /dev/null)
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')

if ! (( ${#a_nouser[@]} > 0 )); then
   l_output="$l_output\n  - No files or directories without an owner exist on the local filesystem."
else
   l_output2="$l_output2\n  - There are \"$(printf '%s' "${#a_nouser[@]}")\" files or directories without an owner on the system.\n   - The following is a list of unowned files and/or directories:\n$(printf '%s\n' "${a_nouser[@]:0:$l_limit}")\n   - end of list"
fi

if ! (( ${#a_nogroup[@]} > 0 )); then
   l_output="$l_output\n  - No files or directories without a group exist on the local filesystem."
else
   l_output2="$l_output2\n  - There are \"$(printf '%s' "${#a_nogroup[@]}")\" files or directories without a group on the system.\n   - The following is a list of ungrouped files and/or directories:\n$(printf '%s\n' "${a_nogroup[@]:0:$l_limit}")\n   - end of list"
fi

if (( ${#a_nouser[@]} > "$l_limit" )) || (( ${#a_nogroup[@]} > "$l_limit" )); then
   l_output2="\n  ** Note: more than \"$l_limit\" files and/or directories without a owner and/or group have been found **\n  ** only the first \"$l_limit\" will be listed **\n$l_output2"
fi

# Remove arrays
unset a_path
unset a_arr
unset a_nouser
unset a_nogroup

# If l_output2 is empty, we pass
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
   [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi