#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   02/12/20   Check ip6tables Loopback
# E. Pinnell   07/14/20   Modified to work with both Debian and Fedora derived systems
# E. Pinnell   02/20/24   Modified to use bash
# E. Pinnell   04/03/24   Modified to use grep -P and accept either all or 0 (Needed for Debian 12), enhanced check for ipv6 being disabled
#

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
if [ "$l_ipv6_disabled" = yes ]; then
	l_output="$l_output\n  - IPv6 is disabled, this check in not applicable to the system"
else
	if command -v ip6tables &>/dev/null; then
		if ip6tables -L INPUT -v -n | grep -Pq -- '^\h*\H+\h+\H+\h+ACCEPT\s+(all|0)\h+(--\h+)?lo\h+\*\h+\:\:\/0\h+\:\:\/0\b'; then
			l_output="$l_output\n  - ipv6tables correctly configured loopback address to accept all inbound traffic"
		else
			l_output2="$l_output2\n  - ipv6tables loopback address not configured to accept all inbound traffic"
		fi
		if ip6tables -L INPUT -v -n | grep -Pq -- '^\h*\H+\h+\H+\h+DROP\h+(all|0)\b\h+(--\h+)?\*\h+\*\h+\:\:1\h+\:\:\/0\b'; then
			l_output="$l_output\n  - ipv6tables correctly configured to drop traffic from loopback address"
		else
			l_output2="$l_output2\n  - ipv6tables not configured to drop traffic from loopback address"
		fi
		if ip6tables -L OUTPUT -v -n | grep -Pq -- '^\h*\H+\h+\H+\h+ACCEPT\h+(all|0)\b\h+(--\h+)?\*\h+lo\h+\:\:\/0\h+\:\:\/0\b'; then
			l_output="$l_output\n  - ipv6tables correctly configured loopback address to accept traffic from loopback address"
		else
			l_output2="$l_output2\n  - ipv6tables loopback address is not configured to accept traffic from loopback address"
		fi
	else
		l_output2="$l_output2\n  - command \"ip6tables\" not found\n   verify ip6tables is installed if iptables is in use on the system"
	fi
fi

if [ -z "$l_output2" ]; then
	echo -e "\n- Audit Result:\n  ** PASS **\n - * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
	[ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi