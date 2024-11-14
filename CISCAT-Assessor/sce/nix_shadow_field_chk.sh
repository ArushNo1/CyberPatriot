#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   04/18/24   Check shadow field

# option:operator:value
# XCCDF_VALUE_REGEX="pass_max_days:<:1" # <- example XCCDF_VALUE_REGEX variable

l_output="" l_output2="" l_field=""

f_set_field()
{
   case "${l_option,,}" in
      username)
         l_field="1";;
      passwd)
         l_field="2";;
      last_pass_change)
         l_field="3";;
      pass_min_days)
         l_field="4";;
      pass_max_days)
         l_field="5";;
      pass_warn_age)
         l_field="6";;
      inactive)
         l_field="7";;
      expiration_date)
         l_field="8";;
      reserved)
         l_field="9";;
      *)
         l_field="error";;
   esac
}

while IFS=: read -r l_option l_operator l_value; do
   [ -z "$l_field" ] && f_set_field
   if [ "$l_field" = "error" ]; then
      l_output2=" - Error, unknown option given"
   else
      while IFS=' ' read -r l_user l_found_value; do
         l_output2="$l_output2\n - User: \"$l_user\" ${l_option^^} is: \"$l_found_value\""
      done < <(awk -F: '($2~/^\$.+\$/) {if($'"$l_field"' '"$l_operator"' '"$l_value"')print $1 " " $'"$l_field"'}' "/etc/shadow")
   fi
   [ -z "$l_output2" ] && l_output="$l_output\n - All local users \"${l_option^^}\" is not \"$l_operator\" than \"$l_value\""
done <<< "$XCCDF_VALUE_REGEX"

if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
	[ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi