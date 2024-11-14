#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd		  04/16/24	 Create for macOS Cloud-tailored Benchmark
#

firewall=$(
/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
  let firewallstate = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.alf')\
.objectForKey('globalstate'))
  if ( ( firewallstate == 1 ) || ( firewallstate == 2 ) ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)


if [ "$firewall" == "true" ]; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" = True ] ; then
	echo "PASSED: The firewall is enabled"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: The firewall is not enabled"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi
