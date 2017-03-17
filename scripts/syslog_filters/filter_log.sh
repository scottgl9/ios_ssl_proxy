#!/bin/sh
cat syslog.log | egrep --invert-match -i "com.apple.MobileAsset|AVSpeechSynthesisVoice|com.apple.accessibility|com.apple.ttsbundle|Predicate|Assets|Attributes|_Measurement" | egrep --color=auto "com.apple|APS|Token|([A-Fa-f0-9]{2}){10,11}" > syslog_filtered.log
