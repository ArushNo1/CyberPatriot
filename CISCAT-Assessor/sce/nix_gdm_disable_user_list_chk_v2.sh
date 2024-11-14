#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     01/22/24   SCE Ensure GDM disable-user-list option is enabled

{
    # Get the current value of the GSettings key
    l_disable_user_list=$(gsettings get org.gnome.login-screen disable-user-list)

    # Check if the disable-user-list is true
    if [ "$l_disable_user_list" == "true" ]; then
        echo -e "Audit Result:\n ** PASS **\n org.gnome.login-screen disable-user-list is set to true."
        exit "${XCCDF_RESULT_PASS:-101}"
    else
        echo -e "Audit Result:\n ** FAIL **\n org.gnome.login-screen disable-user-list is not set to true."
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi
}