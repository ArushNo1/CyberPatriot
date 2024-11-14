#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   05/12/22   Check that only authorized groups are assigned ownership of audit log files
# E. Pinnell   02/27/23   Modified to improve method used to assess and improve output
# E. Pinnell   02/28/24   Modified to add additional tests for existence of /etc/audit/auditd.conf and audit log file directory

l_output="" l_output2=""

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   l_audit_log_group="$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)"
   # Test is log_group is configured correctly
   if grep -Pq -- '^\h*(root|adm)\h*$' <<< "$l_audit_log_group"; then
      l_output="$l_output\n  - Log file group correctly set to: \"$l_audit_log_group\" in \"/etc/audit/auditd.conf\""
   else
      l_output2="$l_output2\n  - Log file group is set to: \"$l_audit_log_group\" in \"/etc/audit/auditd.conf\"\n     (should be set to group: \"root or adm\")\n"
   fi
   # Test for incorrect group ownership in the auditd log file directory
   if [ -d "$l_audit_log_directory" ]; then
      while IFS= read -r -d $'\0' l_file; do
         l_output2="$l_output2\n  - File: \"$l_file\" is group owned by group: \"$(stat -Lc '%G' "$l_file")\"\n     (should be group owned by group: \"root or adm\")\n"
      done < <(find "$l_audit_log_directory" -maxdepth 1 -type f \( ! -group root -a ! -group adm \) -print0)
   else
      l_output2="$l_output2\n  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory"
   fi
else
   l_output2="$l_output2\n  - File: \"/etc/audit/auditd.conf\" not found.\n  - ** Verify auditd is installed **"
fi

# Send output to CIS-CAT and exit
if [ -z "$l_output2" ]; then
   l_output="$l_output\n  - All files in \"$l_audit_log_directory\" are group owned by group: \"root or adm\"\n"
   echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :$l_output"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :$l_output2\n"
   [ -n "$l_output" ] && echo -e " - * Correctly configured * :\n$l_output\n"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi
