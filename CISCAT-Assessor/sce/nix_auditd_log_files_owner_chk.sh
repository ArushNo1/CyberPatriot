#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/11/24   check audit log files owner

# Note: supersedes deprecated nix_audit_log_files_group_owner_chk.sh

# XCCDF_VALUE_REGEX="(root|adm)" #<- example XCCDF_VALUE_REGEX variable

l_output="" l_output2="" l_count="0"
l_owner="$XCCDF_VALUE_REGEX"

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   if [ -d "$l_audit_log_directory" ]; then
      while IFS= read -r -d $'\0' l_file; do
         (( l_count++ ))
         l_file_owner="$(stat -Lc '%U' "$l_file")"
         if [[ ! "$l_file_owner" =~ $l_owner\s*$ ]]; then
            l_output2="$l_output2\n  - File: \"$l_file\" is owned by user: \"$l_file_owner\"\n     (should be owned by user: \"${l_owner/|/ or }\")\n"
         fi
      done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -print0)
   else
      l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
   fi
else
   l_output2="$l_output2\n  - File: \"/etc/audit/auditd.conf\" not found.\n  - ** Verify auditd is installed **"
fi
# Create output (If needed)
if [ -z "$l_output2" ]; then
   if [ "$l_count" -gt "0" ]; then
      l_output="$l_output\n - All files in: \"$l_audit_log_directory\" are owned by: \"${l_owner/|/ or }\""
   else
      l_output="$l_output\n - No files exist in: \"$l_audit_log_directory\""
   fi
fi
# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi