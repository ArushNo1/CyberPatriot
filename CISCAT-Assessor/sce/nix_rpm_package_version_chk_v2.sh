#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# ------------------------------------------------------------
# E. Pinnell   08/29/24     Check rpm package version (nix_rpm_package_version_chk_v2.sh)

# Note this version supersedes detracted nix_rpm_package_version_chk.sh and nix_rpm_version_regex_check_var.sh

# XCCDF_VALUE_REGEX examples:
# XCCDF_VALUE_REGEX="pam-1.3.1-26" # <- Example XCCDF_VALUE_REGEX
# XCCDF_VALUE_REGEX="libvirt-daemon-driver-storage-logical-8.0.0-23.2"
# XCCDF_VALUE_REGEX="sane-backends-drivers-scanners-1.0.27-22.2"

a_output=() a_output2=()

f_version()
{ 
   awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }' <<< "$@"
}

l_package_name="$(grep -Po -- '^\h*\w+(-\w+)*-' <<< "$XCCDF_VALUE_REGEX")"
l_package_name="${l_package_name%-}"
l_package_version="$(grep -Po -- '-\d+(\.\d+)*(-\d+)?(\.\d+)*' <<< "$XCCDF_VALUE_REGEX")"
l_system_output="$(rpm -qa --queryformat "%{VERSION}-%{RELEASE}" "$l_package_name")"
# l_package_version="${l_package_version#-}" (Replaced by awk statement)

while IFS=: read -r l_req_version l_req_sub_version; do
   while IFS="-" read -r l_out_version l_out_sub_version; do
      l_out_sub_version="$(cut -d. -f1 <<< "$l_out_sub_version")"
      if [ "$(f_version "$l_out_version")" -gt "$(f_version "$l_req_version")" ]; then
         a_output+=(" - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\"" \
         "    which is newer than required version: \"$l_req_version-$l_req_sub_version\"")
      elif [ "$(f_version "$l_out_version")" -lt "$(f_version "$l_req_version")" ]; then
         a_output2+=(" - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\"" \
         "    which is older than required version: \"$l_req_version-$l_req_sub_version\"")
      else
         if [ "$(f_version "$l_out_sub_version")" -ge "$(f_version "$l_req_sub_version")" ]; then
            a_output+=(" - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\"" \
            "    which is newer or equal to required version: \"$l_req_version-$l_req_sub_version\"")
         else
            a_output2+=(" - \"$l_package_name\" is version: \"$l_out_version-$l_out_sub_version\"" \
            "    which is older than required version: \"$l_req_version-$l_req_sub_version\"")
         fi
      fi
   done <<< "$l_system_output"
done < <(awk -F- '{print $2 ":" $3}' <<< "$l_package_version")

# Send test results and assessment evidence to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi