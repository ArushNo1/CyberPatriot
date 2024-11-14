#!/usr/bin/env bash

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/11/21   Check ip6tables firewall rules exist for all open ports
# E. Pinnell   02/20/24   Modified to use bash
# E. Pinnell   04/04/24   Modified to check for command availability and improve output

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
		l_ip6trules=$(ip6tables -L INPUT -v -n)
		while IFS= read -r l_open_port; do
			if [ -n "$l_open_port" ]; then
				if grep -Pq -- ":$l_open_port\b" <<< "$l_ip6trules"; then
					l_output="$l_output\n  - ip6tables rule exists for open port: \"$l_open_port\""
				else
					l_output2="$l_output2\n  - ip6tables rule does not exist for open port: \"$l_open_port\""
				fi
			fi
		done < <(ss -6tuln | awk '($2~/(LISTEN|UNCONN|ESTAB)/ && $5!~/\{?::1\]?:/){print}' | sed -E 's/^.*:([0-9]+)\s+.*$/\1/')
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