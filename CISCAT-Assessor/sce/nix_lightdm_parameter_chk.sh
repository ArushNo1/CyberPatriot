#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
# 
# Name            Date       Description
# ------------------------------------------------------------------------
# E. Pinnell      07/08/24    Check lightdm parameter 

# XCCDF_VALUE_REGEX="greeter-hide-users=true" #<- Sample XCCDF_VALUE_REGEX

a_output=();a_output2=()

unset A_files;declare -A A_files;unset A_key_pair;declare -A A_key_pair
while IFS=" " read -r l_letter l_value; do
   if grep -Pq -- '^\h*\/' <<< "$l_value"; then
      A_files+=(["$l_letter"]="$l_value")
   elif grep -q -- '=' <<< "$l_value"; then
      A_key_pair+=(["$l_value"]="$l_letter")
   fi
done < <(lightdm --show-config 2>&1 | awk '/^[A-Z]+\s+/{print}')

while IFS='=' read -r l_required_key l_required_value; do
   while IFS='=' read -r l_key l_key_value; do
      if [ "$l_key" = "$l_required_key" ]; then
         l_file="${A_files["${A_key_pair[$l_key=$l_key_value]}"]}"
         if grep -Pq -- '\b'"$l_required_value"'\b' <<< "$l_key_value"; then
            a_output+=("  - \"$l_required_key\" is correctly set to: \"$l_key_value\"" "    in: \"$l_file\"")
         else
            a_output2+=("  - \"$l_required_key\" is incorrectly set to: \"$l_key_value\"" "    in: \"$l_file\"")
         fi
      fi
   done < <(printf '%s\n' "${!A_key_pair[@]}")
done <<< "$XCCDF_VALUE_REGEX"

[[ "${#a_output[@]}" -le 0 && "${#a_output2[@]}" -le 0 ]] && a_output2+=(" - \"$l_required_key\" is not set in the lightdm config")

# Send check results and output to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi