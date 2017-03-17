#!/bin/sh
idevicesyslog | egrep --invert-match -e "AppleBiometricSensor|AudioToolbox|CFNetwork|com.apple.BackgroundTaskAgentPlugin|Callstack|CoreMotion|libdispatch.dylib|libsystem_network.dylib|mDNSResponder|MultitouchHID|PersistentConnection|softwareupdateservicesd|SpringBoardUIServices|UIKit"

