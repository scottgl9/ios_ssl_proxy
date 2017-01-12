#!/bin/sh
idevicesyslog | egrep --invert-match -e "AppleBiometricSensor|AudioToolbox|CoreMotion|MultitouchHID|SpringBoardUIServices|UIKit"
