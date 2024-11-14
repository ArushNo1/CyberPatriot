#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   06/08/21   Check that audit log files are not read or write-accessible by unauthorized users
# E. Pinnell   02/27/24   Modified to use bash, exit if /etc/audit/auditd.conf doesn't exist, fix awk statement, simplify perm check, modernize variable names and output
# **Note:** This SCE script is deprecated. Please update to nix_auditd_logfile_mode_chk.sh

l_output="" l_output2=""

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   if [ -d "$l_audit_log_directory" ]; then
      l_perm_mask="0177"
      l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
      a_files=()
      while IFS= read -r -d $'\0' l_file; do
         [ -e "$l_file" ] && a_files+=("$l_file")
      done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask" -print0)
   else
      l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
   fi
else
   l_output2="$l_output2\n  - File: \"/etc/audit/auditd.conf\" not found.\n  - ** Verify auditd is installed **"
fi

if (( "${#a_files[@]}" > 0 )); then
   for l_file in "${a_files[@]}"; do
      l_mode="$(stat -Lc '%#a' "$l_file")"
      l_output2="$l_output2\n  - File: \"$l_file\" is mode: \"$l_mode\" and should be mode: \"$l_maxperm\" or more restrictive"
   done
else
   l_output="$l_output\n  - All files in \"$l_audit_log_directory\" are mode: \"$l_maxperm\" or more restrictive"
fi

# Remove array
unset a_files

# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi