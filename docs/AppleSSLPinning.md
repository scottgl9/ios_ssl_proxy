https://github.com/aosm/Security/blob/master/Security/libsecurity_keychain/lib/SecPolicy.cpp

SecPolicyRef SecPolicyCreateAppleSSLService(CFStringRef hostname)
{
	// SSL server, pinned to an Apple intermediate
	SecPolicyRef policy = SecPolicyCreateSSL(true, hostname);
	if (policy) {
		// change options for policy evaluation
		char *strbuf = NULL;
		const char *hostnamestr = NULL;
		if (hostname) {
			hostnamestr = CFStringGetCStringPtr(hostname, kCFStringEncodingUTF8);
			if (hostnamestr == NULL) {
				CFIndex maxLen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(hostname), kCFStringEncodingUTF8) + 1;
				strbuf = (char *)malloc(maxLen);
				if (CFStringGetCString(hostname, strbuf, maxLen, kCFStringEncodingUTF8)) {
					hostnamestr = strbuf;
				}
			}
		}
		uint32 hostnamelen = (hostnamestr) ? (uint32)strlen(hostnamestr) : 0;
		uint32 flags = 0x00000002; // 2nd-lowest bit set to require Apple intermediate pin
		CSSM_APPLE_TP_SSL_OPTIONS opts = {CSSM_APPLE_TP_SSL_OPTS_VERSION, hostnamelen, hostnamestr, flags};
		CSSM_DATA data = {sizeof(opts), (uint8*)&opts};
		SecPolicySetValue(policy, &data);
	}
	return policy;
}
