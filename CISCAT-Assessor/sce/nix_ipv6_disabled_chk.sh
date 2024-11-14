#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   11/03/22   Check that IPv6 has been disabled
# E. Pinnell   04/03/24   Modified to account for IPv6 being disabled in sysctl
	
l_output="" l_output2=""

f_ipv6_chk()
{
	l_ipv6_disabled=""
	# Check if disabled in grub
	! grep -Pqs -- '^\h*0\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled="yes"
	# Check network files
	if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \
		sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then
		l_ipv6_disabled="yes"
	fi
}
f_ipv6_chk

if [ "$l_ipv6_disabled" = "yes" ]; then
   l_output=" - IPv6 is not enabled on the system"
else
   l_output2=" - IPv6 is enabled on the system"
fi

if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
	[ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi