## Information related to using frida to hook functions

### service apsd:

CC_SHA1: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/libSystem.B.dylib/CC_SHA1.js"
arc4random_buf: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/libSystem.B.dylib/arc4random_buf.js"
APSAlert: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/ApplePushService/APSAlert.js"
APSAuditTokenTaskHasEntitlement: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/apsd/APSAuditTokenTaskHasEntitlement.js"
SecureRandomBytes: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/apsd/SecureRandomBytes.js"
APSGenerateNonceAndSignature: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/apsd/APSGenerateNonceAndSignature.js"
APSSHA1Data: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/apsd/APSSHA1Data.js"
APSCopyStringHashForString: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/apsd/APSCopyStringHashForString.js"
APSCopyHashForData: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/apsd/APSCopyHashForData.js"

 13022 ms  aps_peer_event_handler()
 13022 ms     | APSCopyStringHashForString()
 13022 ms     |    | APSCopyHashForData()
 13023 ms     |    | APSCopyStringRepresentationOfData()
 13048 ms     | APSCopyHashForString()
 13048 ms     |    | APSCopyHashForData()

