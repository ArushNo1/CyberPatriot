#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd		  04/16/24	 Create for macOS Cloud-tailored Benchmark
# 

automaticlogin=$(
/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
  .objectForKey('autoLoginUser'))
  if ( pref ==  null ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
)

if [ "$automaticlogin" = "true" ] ; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" == True ] ; then
	echo "PASSED: Automatic login is disabled"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: Automatic login is enabled and needs to be disabled"
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi


