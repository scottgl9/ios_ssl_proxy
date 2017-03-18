## From syslog:

Mar  7 17:04:38 Scotts-iPhone Preferences(Security)[487] <Notice>: could not disable pinning: not an internal release
Mar  7 17:04:38 Scotts-iPhone Preferences(Security)[487] <Notice>: could not enable test cert: not an internal release
Mar  7 17:04:38 Scotts-iPhone Preferences(Security)[487] <Notice>: could not enable test hierarchy: ApplePinningAllowTestCertsGS not true
Mar  7 17:04:38 Scotts-iPhone Preferences(Security)[487] <Notice>: could not enable test hierarchy: AppleServerAuthenticationAllowUAT not true
Mar 16 10:25:15 scottgls-iPhone SpringBoard(Security)[57] <Notice>: could not enable test hierarchy: ApplePinningAllowTestCertsiPhoneApplicationSigning not true
AppleServerAuthenticationAllowUATFMiP

Idea: modify using proxy to indicate that this in fact an internal release.

### Possible tokens from syslog
### For DNRQJS30GRY8 (iPhone 6s):

    <bb5ddb5d 1674248f 6a18c0b9 ec4fec0b a9477d60> = "com.apple.maps.icloud";
    <f24b72ab 9a582e23 12bfaf26 12b0364a 6e6362fb> = "com.icloud.askpermission";
    <65566246 78181498 29c61b3d 0e778190 230ff6f2> = "com.apple.mobileme.fmf3";
    <9f2f37ad ef10040f e9128e6f b3c6743a debb41cd> = "com.apple.icloud-container.com.apple.kbd";
    <3c9243e9 598b2040 d83f8698 7d721d1e 609c4cd2> = "com.apple.passd";
    <2387cc2e a493aeb5 279b1532 7b799f19 e6ee4d61> = "com.apple.idmsauth";
    <654e65b3 3667bab7 51ed57e8 3e6ebd55 3dc61fa0> = "com.apple.icloud-container.com.apple.AdSheetPhone";
    <0e78aac3 90b04804 d33bee75 8f4fc582 b9d1115b> = "com.apple.seld.fake";
    <81cf23af 0800e019 178a8137 05a3eca1 7b3c3d8d> = "com.apple.storebookkeeper";
    <81ea80a8 e292d1e6 996ce771 c2bb099d c284f055> = "com.apple.icloud-container.com.apple.callhistory.sync-helper

Also from same iPhone 6s:

Mar 17 18:20:49 scottgls-iPhone pasted[179] <Notice>: Loading item 0x100210820 54E89761-6B54-4BD8-8E8F-D26680B65A22 type public.utf8-plain-text from URL file:///var/mobile/Library/Caches/com.apple.Pasteboard/eb77e5f8f043896faf63b5041f0fbd121db984dd/be488e997c0cfa9c10690213cfc758577689d00e

Mar 17 18:21:52 scottgls-iPhone securityd[106] <Notice>: replaced <genp,rowid=19,cdat=2016-12-14 21:18:13 +0000,mdat=2017-03-17 23:20:32 +0000,desc=null,icmt=null,crtr=null,type=null,scrp=null,labl=null,alis=null,invi=null,nega=null,cusi=null,prot=null,acct=registrationV1,svce=com.apple.facetime,gena=null,data=013b:030000800B000000...|955537739a038af,agrp=apple,pdmn=dku,sync=0,tomb=0,sha1=B97EDB5343F2C0853994A023762C14EB3CCCDD9E,vwht=null,tkid=null,v_Data=<?>,v_pk=2DB75237258C37ECDF43ECD79FD8DA795363DE46,accc=310D300B0C0470726F740C03646B75,u_Tomb=null,musr=> with <genp,rowid=19,cdat=2016-12-14 21:18:13 +0000,mdat=2017-03-17 23:21:52 +0000,desc=null,icmt=null,crtr=null,type=null,scrp=null,labl=null,alis=null,invi=null,nega=null,cusi=null,prot=null,acct=registrationV1,svce=com.apple.facetime,gena=null,data=013b:030000800B000000...|283bff918464a6d4,agrp=apple,pdmn=dku,sync=0,tomb=0,sha1=BF5434EF6F6FC9EEC1F31BB5BA4695059CEEFC67,vwht=null,tkid=null,v_Data=<?>,v_pk=2DB75237258C37ECDF43ECD79FD8DA795363DE46,accc=310D300B0C0470726F740C03646B75,u_Tomb=null,musr=> in <SecDbConnection rw open

Mar 17 18:21:51 scottgls-iPhone apsd(PersistentConnection)[89] <Notice>: 2017-03-17 18:21:51 -0500 apsd[89]: copyTokenForDomain push.apple.com ,ffffff99ffffff8c5d4c6f0bffffffb047fffffffcffffff827e79ffffff9bffffffb2ffffff88562a61ffffff9642
Mar 17 18:21:51 scottgls-iPhone apsd(PersistentConnection)[89] <Notice>: 2017-03-17 18:21:51 -0500 apsd[89]: <APSCourier: 0x10050b560> found cached token for topic: com.apple.idmsauthagent, token: (null) for appSpecificIdentifier ,ffffff99ffffff8c5d4c6f0bffffffb047fffffffcffffff827e79ffffff9bffffffb2ffffff88562a61ffffff9642

Mar 17 18:21:52 scottgls-iPhone apsd(PersistentConnection)[89] <Notice>: 2017-03-17 18:21:52 -0500 apsd[89]: copyTokenForDomain push.apple.com ,270a0f2affffffa05d36167c43ffffffb83012ffffff956677ffffff8affffffc37671
Mar 17 18:21:52 scottgls-iPhone apsd(PersistentConnection)[89] <Notice>: 2017-03-17 18:21:52 -0500 apsd[89]: <APSCourier: 0x10050b560> found cached token for topic: SELD, token: (null) for appSpecificIdentifier ,270a0f2affffffa05d36167c43ffffffb83012ffffff956677ffffff8affffffc37671

Mar 17 18:21:58 scottgls-iPhone apsd(PersistentConnection)[89] <Notice>: 2017-03-17 18:21:58 -0500 apsd[89]: setTokenForDomain sandbox.push.apple.com token (null) appSpecificIdentifier ,fffffffc1d0f16184dfffffff60213ffffff82fffffff0fffffff3ffffffafffffff8effffffb553ffffffeefffffffaffffffb137
        1 : <CFString 0x1003059c0 [0x1adad6bb8]>{contents = "RSEPDigest"} = <CFData 0x100305b00 [0x1adad6bb8]>{length = 20, capacity = 20, bytes = 0x23ea87e732213cd316451efb369ed0d8c0419abf}
        3 : <CFString 0x100309230 [0x1adad6bb8]>{contents = "_Measurement"} = <CFData 0x100309370 [0x1adad6bb8]>{length = 20, capacity = 20, bytes = 0xd36d68b286a45c82387b7b0fd26a0223645ca19b}
        33 : SEPDigest = <CFData 0x100305cd0 [0x1adad6bb8]>{length = 20, capacity = 20, bytes = 0xa7a13467d30dc6c29c6e5541b26b00e566cdc010}

Mar 17 18:44:36 scottgls-iPhone apsd(PersistentConnection)[332] <Notice>: 2017-03-17 18:44:36 -0500 apsd[332]: copyTokenForDomain push.apple.com ,ffffff9f2f37ffffffadffffffef10040fffffffe912ffffff8e6fffffffb3ffffffc6743affffffdeffffffbb41ffffffcd
Mar 17 18:44:36 scottgls-iPhone apsd(PersistentConnection)[332] <Notice>: 2017-03-17 18:44:36 -0500 apsd[332]: <APSCourier: 0x111d13e00> found cached token for topic: com.apple.icloud-container.com.apple.kbd, token: (null) for appSpecificIdentifier ,ffffff9f2f37ffffffadffffffef10040fffffffe912ffffff8e6fffffffb3ffffffc6743affffffdeffffffbb41ffffffcd


Mar 17 18:32:58 scottgls-iPhone apsd(PersistentConnection)[91] <Notice>: 2017-03-17 18:32:58 -0500 apsd[91]: setTokenForDomain push.apple.com token (null) appSpecificIdentifier ,fffffffc1d0f16184dfffffff60213ffffff82fffffff0fffffff3ffffffafffffff8effffffb553ffffffeefffffffaffffffb137
Mar 17 18:32:58 scottgls-iPhone apsd(PersistentConnection)[91] <Notice>: 2017-03-17 18:32:58 -0500 apsd[91]: <APSCourier: 0x10de4d170> Deleting token for appSpecificIdentifier ,fffffffc1d0f16184dfffffff60213ffffff82fffffff0fffffff3ffffffafffffff8effffffb553ffffffeefffffffaffffffb137
Mar 17 18:32:58 scottgls-iPhone apsd(PersistentConnection)[91] <Notice>: 2017-03-17 18:32:58 -0500 apsd[91]: setTokenForDomain sandbox.push.apple.com token (null) appSpecificIdentifier ,fffffffc1d0f16184dfffffff60213ffffff82fffffff0fffffff3ffffffafffffff8effffffb553ffffffeefffffffaffffffb137

