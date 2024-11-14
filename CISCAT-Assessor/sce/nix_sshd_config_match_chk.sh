#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   07/23/24   Check sshd configuration parameter match

# Note: 
# - Variable XCCDF_VALUE_REGEX:
#  - is a three part colon separated variable (Parameter: MaxStartups is a "special" case. See example below)
#  - is made up as "{OPTION}:{OPERATOR}:{OPTION_VALUE}"
#  - OPERATORS:
#    - match <- Pass if the set option value matches a string or regex in the {OPTION_VALUE} field
#    - not_match <- Pass if the set option value does not match a string or regex in the {OPTION_VALUE} field
#    - lt <- Pass if the set option value is less than the integer in the {OPTION_VALUE} field
#    - le <- Pass if the set option value is less than to equal to the integer in the {OPTION_VALUE} field
#    - gt <- Pass if the set option value is greater than the integer in the {OPTION_VALUE} field
#    - ge <- Pass if the set option value is greater than or equal to the integer in the {OPTION_VALUE} field
#  - Examples included below
# XCCDF_VALUE_REGEX="MaxStartups::10:30:60" # <- example complex XCCDF_VALUE_REGEX variable
# XCCDF_VALUE_REGEX="kexalgorithms:not_match:diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256"
# XCCDF_VALUE_REGEX="allowusers,allowgroups,denyusers,denygroups:match:.+$"
# XCCDF_VALUE_REGEX="banner:match:\/\H+"

a_output=(); a_output2=(); a_output3=()
l_file="/etc/ssh/sshd_config"; a_sshd_config_files=("$l_file")
l_include_location="$(awk '{IGNORECASE=1; if ($1~/^\s*include$/) print $2}' "$l_file" 2>/dev/null)"
l_sshd_cmd="$(readlink -f /sbin/sshd)"
l_var="$(sshd -t 2>&1 | grep -Pvi -- '\bterminating\b')"

f_sshd_chk()
{
   # Check Functions
   # Function to check string matching options
   f_regex_match()
   {
      while IFS= read -r l_match_option_name; do
         l_match_option="${l_match_option_name,,}"
         l_match_config_value="$($l_sshd_command | awk '{IGNORECASE=1; if ($1~/^\s*'"$l_match_option"'$/) print tolower($2)}')"
         if [ -n "$l_match_config_value" ]; then
            if grep -Pqsi -- '\b('"$l_value"')\b' <<< "$l_match_config_value"; then
               a_output+=("  - Option: \"$l_match_option_name\" correctly set to: \"$l_match_config_value\"")
            else
               a_output2+=("  - Option(s): \"$l_match_option_name\" incorrectly set to: \"$l_match_config_value\"" \
               "    In the file: \"$l_sshd_config_file\"" "    Should be set to: \"${l_value//|/ or }\"")
            fi
         fi
      done < <(echo -e "${l_option_name//,/\\n}")
   }

   # Function to check string not match options (cyphers, MACs, key exchange, etc)
   f_regex_not_match()
   {
      a_wrong_value=(); 
      while IFS= read -r l_wrong_value; do
   #echo -e "\nl_wrong_value is: \"$l_wrong_value\""
         grep -Psiq -- '\b'"$l_wrong_value"'\b' <<< "$l_config_value" && a_wrong_value+=("$l_wrong_value")
      done < <(echo -e "${l_value//|/\\n}")
      if [ "${#a_wrong_value[@]}" -gt "0" ]; then
         l_wrong_out="${a_wrong_value[*]}" && a_output2+=("  - Option: \"$l_option_name\" incorrectly includes the following value(s):" \
         "    ${l_wrong_out// /, }" "    In the file: \"$l_sshd_config_file\"")
      else
         a_output+=("  - Option: \"$l_option_name\" does not include and of the following incorrect values:" \
         "    ${l_value//|/, }")
      fi
   }

   # Function to check integers
   f_integer_chk()
   {
      l_test=""
      case "$l_operator" in
         lt )
            l_int_op_display="less than"
            [ "$l_config_value" -lt "$l_value" ] && l_test="pass" ;;
         le )
            l_int_op_display="less than or equal to"
            [ "$l_config_value" -le "$l_value" ] && l_test="pass" ;;
         gt )
            l_int_op_display="greater than"
            [ "$l_config_value" -gt "$l_value" ] && l_test="pass" ;;
         ge )
            l_int_op_display="greater than or equal to"
            [ "$l_config_value" -ge "$l_value" ] && l_test="pass" ;;
         * )
            l_int_op_display="equal to"
            [ "$l_config_value" = "$l_value" ] && l_test="pass" ;;
      esac
      if [ "$l_test" = "pass" ]; then
         a_output+=("  - Option: \"$l_option_name\" correctly set to: \"$l_config_value\"" \
         "    Should be set to a value $l_int_op_display: \"${l_value//|/ or }\"")
      else
         a_output2+=("  - Option: \"$l_option_name\" incorrectly set to: \"$l_config_value\"" \
         "    In the file: \"$l_sshd_config_file\"" \
         "    Should be set to a value $l_int_op_display: \"${l_value//|/ or }\"")
      fi
   }

   # Function to check "MaxStartups" option
   f_maxstartups_chk()
   {
      while IFS=: read -r _ _ l_value1 l_value2 l_value3; do
   #echo -e "\nl_value1 is: \"$l_value1\" l_value2 is: \"$l_value2\" l_value3 is: \"$l_value3\"\n"
         while IFS=: read -r l_config_value1 l_config_value2 l_config_value3; do
            if [[ "$l_config_value1" -le "$l_value1" && "$l_config_value2" -le "$l_value2" && "$l_config_value3" -le "$l_value3" ]]; then
               a_output+=("  - Option: \"$l_option_name\" correctly set to: \"$l_config_value1:$l_config_value2:$l_config_value3\"")
            else
               a_output2+=("  - Option: \"$l_option_name\" incorrectly set to: \"$l_config_value1:$l_config_value2:$l_config_value3\"" \
               "    In the file: \"$l_sshd_config_file\"" \
               "    Should be set to: \"$l_value1:$l_value2:$l_value3\" or lower values")
            fi
         done <<< "$l_config_value"
      done <<< "$XCCDF_VALUE_REGEX"
   }

   # Main script
   # if grep -Piq -- '\b(bad|unsupported)\b' <<< "$l_var"; then
   #    if sshd -T 2>&1 | grep -Pqsi '\bterminating\b'; then
   #       a_output2+=(" - openSSH server configuration includes bad and/or unsupported option(s):" "  - $l_var" \
   #       " - Unable to test configuration")
   #    else
   #       a_output2+=(" - openSSH server configuration includes bad and/or unsupported option(s):" "  - $l_var")
   #    fi
   # else
   [ -n "$l_var" ] && a_output3+=("  ** WARNING **" "  - $l_var")
   while IFS=: read -r l_option_name l_operator l_value; do
      l_option="${l_option_name,,}"; l_value="${l_value//,/|}"; # l_value="${l_value,,}"
      grep -q -- ',' <<< "$l_option" && l_option="(${l_option//,/|})"
      l_config_value="$($l_sshd_command | awk '{IGNORECASE=1; if ($1~/^\s*'"$l_option"'$/) print tolower($2)}')"
      if [ -n "$l_config_value" ]; then
         if [ "$l_option" = "maxstartups" ]; then
            f_maxstartups_chk
         else
            case "$l_operator" in
               match )
                  f_regex_match ;;
               not_match )
                  f_regex_not_match ;;
               * )
                  f_integer_chk ;;
            esac
         fi
      else
         a_output2+=("  - Parameter(s): \"${l_option_name//,/, }\"" "    does not exist in the openSSH daemon configuration")
      fi
   done <<< "$XCCDF_VALUE_REGEX"
#   fi
}

f_add_sshd_config_files()
{
# echo -e "\n ** CALLED FUNCTION **\n"
   while IFS= read -r -d $'\0' l_file; do
# echo -e "lfile is: \"$l_file\"\n readlink is: \"$(readlink -f "$l_file")\""
      [ -f "$(readlink -f "$l_file")" ] && a_sshd_config_files+=("$(readlink -f "$l_file")")
   done < <(find -L "$l_directory" -name "$l_ext" -type f -print0)
}

f_match_value_chk()
{
   while IFS=, read -r l_value; do
      l_sshd_command="$l_sshd_cmd -T -C $l_match_type=$l_value"
      f_sshd_chk
   done <<< "$l_match_value"
}

# Main Script
if grep -Piq -- '\b(bad|unsupported)\b' <<< "$l_var"; then
   if sshd -T 2>&1 | grep -Pqsi '\bterminating\b'; then
      a_output2+=(" - openSSH server configuration includes bad and/or unsupported option(s):" "  - $l_var" \
      " - Unable to test configuration")
   else
      a_output2+=(" - openSSH server configuration includes bad and/or unsupported option(s):" "  - $l_var")
   fi
else
   [ -n "$l_var" ] && a_output3+=("  ** WARNING **" "  - $l_var")
   if [ -n "$l_include_location" ]; then
      # Lets work out the default include if set
      if ! grep -Psiq -- '[*]' <<< "$l_include_location"; then
         if [ -f "$(readlink -f "$l_include_location")" ]; then
            l_include_location="$(readlink -f "$l_include_location")"
            ! grep -Psiq '\b'"$l_include_location"'\b' "${a_sshd_config_files[*]}" && a_sshd_config_files+=("$l_include_location")
         elif [ -d "$(readlink -f "$l_include_location")" ]; then
            l_ext='*'; l_directory="$(readlink -f "$l_include_location")"; f_add_sshd_config_files
         elif [ -f "/etc/ssh/$l_include_location" ]; then
            a_sshd_config_files+=("/etc/ssh/$l_include_location")
         fi
      else
         l_directory="$(readlink -f "$(dirname "$l_include_location")")" l_ext="$(basename "$l_include_location")"
         f_add_sshd_config_files
      fi
   fi

   for l_sshd_config_file in "${a_sshd_config_files[@]}"; do
      while IFS=" " read -r _ l_match l_match_value; do
         a_output3+=("  - File: \"$l_sshd_config_file\" Includes Match statement:" "    Match $l_match $l_match_value")
   echo -e "l_match is: \"$l_match\" l_match_value is: \"$l_match_value\""
         case "${l_match,,}" in
            user )
               l_match_type="user"
               f_match_value_chk ;;
            host )
               l_match_type="host"
               f_match_value_chk ;;
            localaddress )
               l_match_type="laddr"
               l_match_value="$(sed 's/\/[0-9]*//g' <<< "$l_match_value")"
               f_match_value_chk ;;
            localport )
               l_match_type="lport"
               f_match_value_chk ;;
            address )
               l_match_type="addr"
               l_match_value="$(sed 's/\/[0-9]*//g' <<< "$l_match_value")"
               f_match_value_chk ;;
            * )
#               l_match_type="unknown" ;;
               a_output2+=("  - Unable to test Match in file: \"$l_sshd_config_file\"" "    Please review manually") ;;
         esac

   #   done < <(awk '{IGNORECASE=1; if ($1~/^\s*match$/) (i=2; i<=NF; i++) print $i}' "$l_sshd_config_file" 2>/dev/null)
   #   done < <(awk '{IGNORECASE=1; if ($1~/^\s*match$/) print}' "$l_sshd_config_file" 2>/dev/null | cut -d ' ' -f 2-)
      done < <(awk '{IGNORECASE=1; if ($1~/^\s*match$/) print $0}' "$l_sshd_config_file" 2>/dev/null)
   done
fi

if [ "${#a_output[@]}" -le 0 ] && [ "${#a_output2[@]}" -le 0 ]; then
   a_output+=("  - No Match Blocks found in the openSSH daemon configuration file(s)")
fi
# Send check results and output to CIS-CAT
if [ "${#a_output2[@]}" -le 0 ]; then
   [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" "${a_output3[@]}"
   printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_PASS:-101}"
else
   [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "" "${a_output3[@]}"
   printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" ""
   [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}" ""
   exit "${XCCDF_RESULT_FAIL:-102}"
fi