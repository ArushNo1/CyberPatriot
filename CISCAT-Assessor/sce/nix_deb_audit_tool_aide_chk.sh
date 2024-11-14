#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   08/12/24   Debian check cryptographic mechanisms are used to protect the integrity of audit tools

# Note: 
# - Check required the use of the `-p` option for the `aide --config` command.
# - This option is only available in Debian 11 and above based distributions

a_output=() a_output2=() l_tool_dir="$(readlink -f /sbin)"
a_items=("p" "i" "n" "u" "g" "s" "b" "acl" "xattrs" "sha512")
l_aide_cmd="$(whereis aide | awk '{print $2}')"
a_audit_files=("auditctl" "auditd" "ausearch" "aureport" "autrace" "augenrules")
if [ -f "$l_aide_cmd" ] && command -v "$l_aide_cmd" &>/dev/null; then
   a_aide_conf_files=("$(find -L /etc -type f -name 'aide.conf')")
   f_file_par_chk()
   {
      a_out2=()
      for l_item in "${a_items[@]}"; do
         ! grep -Psiq -- '(\h+|\+)'"$l_item"'(\h+|\+)' <<< "$l_out" && \
         a_out2+=("  - Missing the \"$l_item\" option")
      done
      if [ "${#a_out2[@]}" -gt "0" ]; then
         a_output2+=(" - Audit tool file: \"$l_file\"" "${a_out2[@]}")
      else
         a_output+=(" - Audit tool file: \"$l_file\" includes:" "   \"${a_items[*]}\"")
      fi
   }
   for l_file in "${a_audit_files[@]}"; do
      if [ -f "$l_tool_dir/$l_file" ]; then
         l_out="$("$l_aide_cmd" --config "${a_aide_conf_files[@]}" -p f:"$l_tool_dir/$l_file")"
         f_file_par_chk
      else
         a_output+=("  - Audit tool file \"$l_file\" doesn't exist")
      fi
   done
else
   a_output2+=("  - The command \"aide\" was not found"  "    Please install AIDE")
fi
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi