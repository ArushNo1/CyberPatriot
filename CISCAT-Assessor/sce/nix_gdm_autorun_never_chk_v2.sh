#!/usr/bin/env bash
#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# R. Bejar     01/22/24   SCE Ensure GDM disable-user-list option is enabled

{
    # Get the current value of the GSettings key
    l_autorun_never=$(gsettings get org.gnome.desktop.media-handling autorun-never)

    # Check if the disable-user-list is true
    if [ "$l_autorun_never" == "true" ]; then
        echo -e "Audit Result:\n ** PASS **\n org.gnome.desktop.media-handling autorun-never is set to true."
        exit "${XCCDF_RESULT_PASS:-101}"
    else
        echo -e "Audit Result:\n ** FAIL **\n org.gnome.desktop.media-handling autorun-never is not set to true."
        exit "${XCCDF_RESULT_FAIL:-102}"
    fi
}