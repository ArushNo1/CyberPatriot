#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   09/22/23   Authselect current profile check
# E. Pinnell   04/01/24   Modified to account for vendor supplied profiles

l_output="" l_output2=""
l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
   l_pam_profile_path="/etc/authselect/$l_pam_profile"
elif [ -d /usr/share/authselect/vendor/$l_pam_profile ]; then
   l_pam_profile_path="/usr/share/authselect/vendor/$l_pam_profile"
else
   l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi

pam_faillock_chk()
{
   l_out2=""
   if ! grep -Pq -- '^\h*auth\h+(required|requisite)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?preauth\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - auth stack \"pam_faillock.so with preauth\" line missing in: \"$l_authselect_file\""
   fi
   if ! grep -Pq -- '^\h*auth\h+(required|requisite)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?authfail\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - auth stack \"pam_faillock.so with authfail\" line missing in: \"$l_authselect_file\""
   fi
   if ! grep -Pq -- '^\h*account\h+(required|requisite)\h+pam_faillock\.so\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - account stack \"pam_faillock.so\" line missing in: \"$l_authselect_file\""
   fi
   if [ -z "$l_out2" ]; then
      l_output="$l_output\n  - \"pam_faillock\" is correctly listed in: \"$l_authselect_file\""
   else
      l_output2="$l_output2\n$l_out2"
   fi
}
pam_unix_chk()
{
   l_out2=""
   if ! grep -Pq -- '^\h*auth\h+(required|requisite|sufficient)\h+pam_unix\.so\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - auth stack \"pam_unix.so\" line missing in: \"$l_authselect_file\""
   fi
   if ! grep -Pq -- '^\h*account\h+(required|requisite)\h+pam_unix\.so\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - account stack \"pam_unix.so\" line missing in: \"$l_authselect_file\""
   fi
   if ! grep -Pq -- '^\h*password\h+(required|requisite|sufficient)\h+pam_unix\.so\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - password stack \"pam_unix.so\" line missing in: \"$l_authselect_file\""
   fi
   if ! grep -Pq -- '^\h*session\h+(required|requisite)\h+pam_unix\.so\b' "$l_authselect_file"; then
      l_out2="$l_out2\n  - session stack \"pam_unix.so\" line missing in: \"$l_authselect_file\""
   fi
   if [ -z "$l_out2" ]; then
      l_output="$l_output\n  - \"pam_unix\" is correctly listed in: \"$l_authselect_file\""
   else
      l_output2="$l_output2\n$l_out2"
   fi   
}
pam_module_chk()
{
   l_out2=""
   if ! grep -Pq -- "^\h*password\h+(required|requisite)\h+$l_pam_module\.so\b" "$l_authselect_file"; then
      l_out2="$l_out2\n  - password stack \"$l_pam_module.so\" line missing in: \"$l_authselect_file\""
   fi
   if [ -z "$l_out2" ]; then
      l_output="$l_output\n  - \"$l_pam_module\" is correctly listed in: \"$l_authselect_file\""
   else
      l_output2="$l_output2\n$l_out2"
   fi
}
for l_authselect_file in "$l_pam_profile_path/password-auth" "$l_pam_profile_path/system-auth"; do
   pam_faillock_chk
   pam_unix_chk
   l_pam_module="pam_pwquality"
   pam_module_chk
   l_pam_module="pam_pwhistory"
   pam_module_chk
done #<<< "$l_pam_profile_path/{password,system}-auth"

# Output results
if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  *** PASS ***\n- * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
	[ -n "$l_output" ] && echo -e " - * Correctly set * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi
