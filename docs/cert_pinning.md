## In this document I will describe hostnames with certificate pinning enabled on iOS


### pXX-escrowproxy.icloud.com (syslog output when using proxy):

	Mar 13 13:51:20 scottgls-iPhone com.apple.sbd[284] <Notice>: escrowService getAccountInfoWithInfo: returned Error Domain=CloudServicesErrorDomain Code=310 "Certificate pinning error" UserInfo={NSLocalizedDescription=Certificate pinning error, NSUnderlyingError=0x100216ed0 {Error Domain=NSURLErrorDomain Code=-999 "cancelled" UserInfo={NSErrorFailingURLKey=https://p15-escrowproxy.icloud.com:443/escrowproxy/api/get_records, NSLocalizedDescription=cancelled, NSErrorFailingURLStringKey=https://p15-escrowproxy.icloud.com:443/escrowproxy/api/get_records}}} 

	Mar 13 13:51:20 scottgls-iPhone com.apple.sbd(Security)[284] <Notice>: could not disable pinning: not an internal release 
	Mar 13 13:51:20 scottgls-iPhone com.apple.sbd(Security)[284] <Notice>: could not enable test cert: not an internal release 
	Mar 13 13:51:20 scottgls-iPhone com.apple.sbd(Security)[284] <Notice>: could not enable test hierarchy: ApplePinningAllowTestCertsEscrow not true 
	Mar 13 13:51:20 scottgls-iPhone com.apple.sbd(Security)[284] <Notice>: could not enable test hierarchy: AppleServerAuthenticationAllowUAT not true

## pXX-fmip.icloud.com (syslog output when using proxy):

	Mar 13 13:44:39 scottgls-iPhone findmydeviced(Security)[154] <Notice>: could not disable pinning: not an internal release 
	Mar 13 13:44:39 scottgls-iPhone findmydeviced(Security)[154] <Notice>: could not enable test cert: not an internal release 
	Mar 13 13:44:39 scottgls-iPhone findmydeviced(Security)[154] <Notice>: could not enable test hierarchy: ApplePinningAllowTestCertsFMiP not true 
	Mar 13 13:44:39 scottgls-iPhone findmydeviced(Security)[154] <Notice>: could not enable test hierarchy: AppleServerAuthenticationAllowUAT not true 

## gsa.apple.com (syslog output when using proxy):

	Mar 13 13:51:20 scottgls-iPhone akd(AppleIDAuthSupport)[135] <Notice>: -[AIASSession URLSession:task:didReceiveChallenge:completionHandler:]: checking pinning 
	Mar 13 13:51:20 scottgls-iPhone akd(Security)[135] <Notice>: could not disable pinning: not an internal release 
	Mar 13 13:51:20 scottgls-iPhone akd(Security)[135] <Notice>: could not enable test cert: not an internal release 
	Mar 13 13:51:20 scottgls-iPhone akd(Security)[135] <Notice>: could not enable test hierarchy: ApplePinningAllowTestCertsGS not true 
	Mar 13 13:51:20 scottgls-iPhone akd(Security)[135] <Notice>: could not enable test hierarchy: AppleServerAuthenticationAllowUAT not true 

