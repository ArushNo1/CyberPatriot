#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name		       Date       Description
# -------------------------------------------------------------------
# Edward Byrd 	 	  06/18/24   Check if Listen for (Siri) Is Disabled
#

heysiri=$(
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Siri')\
.objectForKey('VoiceTriggerUserEnabled').js
EOS
)

if [ "$heysiri" = false ]; then
  output=True
else
  output=False
fi

# If test passed, then no output would be generated. If so, we pass
if [ "$heysiri" = false ] ; then
	echo "PASSED: A profile is installed that disables listen for Siri"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: FAILED: A profile needs to be installed that disables listen for Siri"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi
fi


