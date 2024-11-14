#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/11/24   check audit log files group owner
# E. Pinnell   06/19/24   Modified to improve output

# XCCDF_VALUE_REGEX="(root|adm)" #<- example XCCDF_VALUE_REGEX variable

a_output=(); a_output2=(); a_output3=(); a_out2=(); l_count="0"

# Function to check if log_group agreement is configured correctly
f_log_group_assigned_chk()
{
   l_audit_log_group="$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)"
   if grep -Pq -- "^\h*$l_group\b" <<< "$l_audit_log_group"; then
      a_output+=("  - Log file group correctly set to: \"$l_audit_log_group\" in \"/etc/audit/auditd.conf\"")
   else
      a_output2+=("  - Log file group is set to: \"$l_audit_log_group\" in \"/etc/audit/auditd.conf\"" "    (should be set to group: \"root or adm\")")
   fi
}

# Function check if auditd files in auditd log file directory for correct group ownership
f_log_files_group_ownership_chk()
{
   if [ -d "$l_audit_log_directory" ]; then
      l_group="$XCCDF_VALUE_REGEX"
      while IFS= read -r -d $'\0' l_file; do
         (( l_count++ ))
         l_file_group="$(stat -Lc '%G' "$l_file")"
         if ! grep -Pq -- '\b'"$l_group"'\b' <<< "$l_file_group"; then
            a_out2+=("  - File: \"$l_file\" is group owned by user: \"$l_file_group\"" "    (should be group owned by user: \"${l_group/|/ or }\")")
         fi 
      done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -print0)
      if [ "$l_count" -gt "0" ]; then
         if [ "${#a_out2[@]}" -le 0 ]; then
            a_output+=("  - All files in: \"$l_audit_log_directory\" are group owned by group: \"${l_group/|/ or }\"")
         else
            a_output2+=("${a_out2[@]}")
         fi
      else
         a_output+=("  - No files exist in: \"$l_audit_log_directory\"")
      fi
   else
      a_output2+=("  - Log file directory not set in \"/etc/audit/auditd.conf\" please set log file directory")
   fi
}

if [ -e "/etc/audit/auditd.conf" ]; then
   l_audit_log_directory="$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
   f_log_group_assigned_chk
   f_log_files_group_ownership_chk
else
   a_output3+=("  - File: \"/etc/audit/auditd.conf\" not found." "  ** Verify auditd is installed **")
fi

# Send test results and output to CIS-CAT report
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}"
   [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" "  ** WARNING **" "${a_output3[@]}"
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" "  * Reasons for audit failure *"
   if [ "${#a_output2[@]}" -gt 50 ]; then
      printf '%s\n' "  ** Note more that 50 files found with incorrect group ownership **" \
      "     Showing only the first 50" "${a_output2[@]:0:50}"
   else
      printf '%s\n' "${a_output2[@]}"
   fi
   [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" "  ** WARNING **" "${a_output3[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" " * Correctly configured: *" "${a_output[@]}"
   exit "${XCCDF_RESULT_FAIL:-102}"
fi