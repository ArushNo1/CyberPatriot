#!/usr/bin/env bash
#
#
# CIS-CAT Script Check Engine
# 
# Name            Date       Description
# ------------------------------------------------------------------------
# R.Bejar        05/30/24    Ensure only one logging system is in use
#

{
    # Check the status of rsyslog and journald
    l_output="" l_output2=""
    if systemctl is-active --quiet rsyslog; then
        l_output="$l_output\n - rsyslog is in use\n- follow the recommendations in Configure rsyslog subsection only"
    elif systemctl is-active --quiet systemd-journald; then
        l_output="$l_output\n - journald is in use\n- follow the recommendations in Configure journald subsection only"
    else
        echo -e 'unable to determine system logging'
        l_output2="$l_output2\n - unable to determine system logging\n- Configure only ONE system logging: rsyslog OR journald"
    fi
    # Provide audit results
    if [ -z "$l_output2" ]; then
        echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
        exit "${XCCDF_RESULT_PASS:-101}"
    else
        echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2"
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi
}