#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd		  04/16/24	 Create for macOS Cloud-tailored Benchmark
#

appstoreupdate=$(
/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.commerce')\
.objectForKey('AutoUpdate').js
EOS)


if [ "$appstoreupdate" == "true" ]; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" = True ] ; then
	echo "PASSED: App Store updates are being automatically installed"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: App Store updates are not being installed automatically"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi
