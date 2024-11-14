#!/usr/bin/env bash
#
#
# CIS-CAT Script Check Engine
# 
# Name            Date       Description
# ------------------------------------------------------------------------
# R.Bejar        05/29/24    Ensure journald ForwardToSyslog is disabled, Ensure journald Compress is configured, Ensure journald Storage is configured
# Example $XCCDF_VALUE_REGEX="^ForwardToSyslog=no"

{
    l_output="" XCCDF_VALUE_REGEX=""
    if systemctl is-active --quiet rsyslog; then
        echo -e "- rsyslog is in use"
    elif systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* 2>/dev/null | grep -qE "$XCCDF_VALUE_REGEX"; then
        echo -e "- $XCCDF_VALUE_REGEX is set correctly"
    else
        echo -e "- $XCCDF_VALUE_REGEX is configured incorrectly"
        l_output="$l_output\n- $XCCDF_VALUE_REGEX is set incorrectly"
    fi    
    # Provide output to CIS-CAT
    if [ -z "$l_output" ]; then # Provide output from checks
    echo -e "\n- Audit Result:\n  ** PASS **\n"
    exit "${XCCDF_RESULT_PASS:-101}"
    else
    echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output\n"
    exit "${XCCDF_RESULT_FAIL:-102}"
    fi
}