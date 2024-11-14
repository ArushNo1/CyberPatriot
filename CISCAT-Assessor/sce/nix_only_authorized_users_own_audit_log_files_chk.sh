#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   05/12/22   Check that audit log files are owned by the root user
# E. Pinnell   02/13/23   Modified to improve output
# E. Pinnell   02/27/24   Modified to add additional tests for existence of auditd log directory

l_output="" l_output2=""

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   if [ -d "$l_audit_log_directory" ]; then
      while IFS= read -r -d $'\0' l_file; do
         l_output2="$l_output2\n  - File: \"$l_file\" is owned by user: \"$(stat -Lc '%U' "$l_file")\"\n     (should be owned by user: \"root\")\n"
      done < <(find "$l_audit_log_directory" -maxdepth 1 -type f ! -user root -print0)
   else
      l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
   fi
else
   l_output2="$l_output2\n  - File: \"/etc/audit/auditd.conf\" not found.\n  - ** Verify auditd is installed **"
fi

# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
   l_output="$l_output\n  - All files in \"$l_audit_log_directory\" are owned by user: \"root\"\n"
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e "\n - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi