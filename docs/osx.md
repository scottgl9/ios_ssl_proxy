## OSX Misc info relevant to testing fmip

### OSX functions related to SSL cert verification / pinning:

SSLGetEnableCertVerify
SSLGetPeerSecTrust
SecTrustGetTrustResult
SecTrustSetAnchorCertificates
SecTrustGetTrustResult

func SecTrustEvaluate(_ trust: SecTrust, 
                    _ result: UnsafeMutablePointer<SecTrustResultType>?) -> OSStatus

OSStatus SSLSetEnableCertVerify(SSLContextRef context, Boolean enableVerify);

