#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   08/29/24   Check remote access methods are monitored (STIG)

a_output=() a_output2=() a_parameters=("auth" "authpriv" "daemon")
l_analyze_cmd="$(readlink -f /bin/systemd-analyze)" l_include='\$IncludeConfig' a_config_files=("/etc/rsyslog.conf")
while IFS= read -r l_file; do
   l_conf_loc="$(awk '$1~/^\s*'"$l_include"'$/ {print $2}' "$(tr -d '# ' <<< "$l_file")" | tail -n 1)"
   [ -n "$l_conf_loc" ] && break
done < <($l_analyze_cmd cat-config "${a_config_files[@]}" | tac | grep -Pio '^\h*#\h*\/[^#\n\r\h]+\.conf\b')
if [ -d "$l_conf_loc" ]; then
   l_dir="$l_conf_loc" l_ext="*"
elif  grep -Psq '\/\*\.([^#/\n\r]+)?\h*$' <<< "$l_conf_loc" || [ -f "$(readlink -f "$l_conf_loc")" ]; then
   l_dir="$(dirname "$l_conf_loc")" l_ext="$(basename "$l_conf_loc")"
fi
while read -r -d $'\0' l_file_name; do
   [ -f "$(readlink -f "$l_file_name")" ] && a_config_files+=("$(readlink -f "$l_file_name")")
done < <(find -L "$l_dir" -type f -name "$l_ext" -print0 2>/dev/null)
for l_parameter in "${a_parameters[@]}"; do
   a_out=() a_out2=()
   for l_logfile in "${a_config_files[@]}"; do
      l_out=$(grep -Ps -- '^\h*([^#\n\r]+;)?'"$l_parameter"'\b([^#\n\r]+)?\h+\/var\/log\/.*$' "$l_logfile")
      if [ -n "$l_out" ]; then
         if grep -Psq -- '^\h*([^#\n\r]+;)?'"$l_parameter"'\.\*(;[^#\n\r]+)?\h+\/var\/log\/secure\b' <<< "$l_out"; then
            a_out+=("  - access method: \"$l_parameter\" exists in \"$l_logfile\" correctly configured" \
            "    as: \"$l_out\"")
         else
            a_out2+=("  - access method: \"$l_parameter\" exists in \"$l_logfile\" incorrectly configured" \
            "    as: \"$l_out\"")
         fi
      fi
   done
   [ "${#a_out[@]}" -gt 0 ] && a_output+=("${a_out[@]}")
   [ "${#a_out2[@]}" -gt 0 ] && a_output2+=("${a_out2[@]}")
   [[ "${#a_out[@]}" -le 0 && "${#a_out2[@]}" -le 0 ]] && \
   a_output2+=("  - access method: \"$l_parameter\" does not exist in the rsyslog configuration")
done
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi