## Comparing backup UUIDs from the iPhone 6s Plus, the iPhone 5c, the iPhone 5, and the iPad Pro:
D:d9614827b8f0bfd998267f638bccff0acb597f8f
D:e7f4930075aa28869a14bba01924e079678cb87a
D:17f899e7ececa6cf4d60eb216311d007abeb11d0
D:244a0c883f3ceec33f8e4d3ccf36772858251766


These values don't look completely random (such as in a hash).
iPhone5,3: e 7f 4 9 30075aa28869a14b b a01924e 0 79678cb87a
iPhone5,1: 1 7f 8 9 9e7ececa6cf4d60e b 216311d 0 07abeb11d0

## the backup UUID is derrived from the keybag UUID (I think)

Possibly useful functions from iOS9 MobileBackup.framework:
-(BOOL)deleteBackupUDID:(id)arg1 error:(id*)arg2 ;
-(BOOL)saveKeybagsForBackupUDID:(id)arg1 withError:(id*)arg2 ;
-(void)startRestoreForBackupUDID:(id)arg1 snapshotID:(unsigned long long)arg2 ;
-(BOOL)startRestoreForBackupUDID:(id)arg1 snapshotID:(unsigned long long)arg2 error:(id*)arg3 ;
-(id)journalForBackupUUID:(id)arg1 error:(id*)arg2 ;
-(id)getAppleIDsForBackupUDID:(id)arg1 snapshotID:(unsigned long long)arg2 error:(id*)arg3 ;
-(id)getAppleIDsForBackupUDID:(id)arg1 snapshotID:(unsigned long long)arg2 activeAppleID:(id*)arg3 error:(id*)arg4 ;
-(BOOL)setupBackupWithPasscode:(id)arg1 error:(id*)arg2 ;
-(id)initWithDelegate:(id)arg1 ;

## Functions which might relate to the deviceBackupUUID:

__IOHIDDeviceGetUUIDKey: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/IOKit/__IOHIDDeviceGetUUIDKey.js"
__IOHIDDeviceGetUUIDString: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/IOKit/__IOHIDDeviceGetUUIDString.js"
MBDeviceUUID: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileBackup/MBDeviceUUID.js"
MKBBackupValidateBackupKeyWithUUID: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileKeyBag/MKBBackupValidateBackupKeyWithUUID.js"
MKBBackupCopyBackupKeyUUID: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileKeyBag/MKBBackupCopyBackupKeyUUID.js"
MKBBackupValidateKeyUUID: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileKeyBag/MKBBackupValidateKeyUUID.js"
MKBKeyBagCopyUUID: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileKeyBag/MKBKeyBagCopyUUID.js"
MKBKeyBagCreateBackup: Loaded handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileKeyBag/MKBKeyBagCreateBackup.js"
MCGestaltGetDeviceUUID: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/ManagedConfiguration/MCGestaltGetDeviceUUID.js"
MBMobileUID: Auto-generated handler at "/home/scottgl/sandbox/proxy2/__handlers__/MobileBackup/MBMobileUID.js"

Keybag location:
/var/root/Library/Backup/RestoreKeyBag.plist

## When capturing the data passed into the CC_SHA1 function for the cdpd process for the iPhone 5, here is the input data that is used to calculate the hash:

C38K4AG6DTTN3170157339530c8:6f:1d:0a:52:3cc8:6f:1d:0a:52:3d

C38K4AG6DTTN -> SerialNumber
317015733953 -> UniqueChipID
c8:6f:1d:0a:52:3c -> WiFiAddress
c8:6f:1d:0a:52:3d -> BluetoothAddress

SHA1(C38K4AG6DTTN3170157339530c8:6f:1d:0a:52:3cc8:6f:1d:0a:52:3d) = 3fbace309f3896cb8607d7e1e31d6d9945536b61 (UDID)

## NOTE: the master key, when converted from hex to ascii:

MasterKey =                 {
PublicIdentities = (<6181c330 81c00201 01020101 042025e4 1fff9cc9 d2af74a1 e4f77ed2 b2872fef 7f713606 fd8148bf 29d87169 e5faa031 302f302d 02010104 283026a0 110c0f69 50686f6e 65204f53 3b313347 3334a111 180f3230 31363132 32333134 31313231 5aa16330 610414e9 78173c2c 31cfa1fd e6746ca8 798b813e 658b5902 01010446 30440220 1d0d968c 73fc513e 925ab4a8 1ee63649 6784097f 62a2aa14 c0a435b8 d2a15f5a 0220655e dc573773 05d9610c 4f960bfc dd58739c 6219061b f8b2ecdb ad5f38aa 4ab7>);

ASCII Version of Master Key (base64 encoded):
YcKBw4MwwoHDgAIBAQIBAQQgJcOkH8O/wpzDicOSwq90wqHDpMO3fsOSwrLChy/Dr39xNgbDvcKBSMK/KcOYcWnDpcO6wqAxMC8wLQIBAQQoMCbCoBEMD2lQaG9uZSBPUzsxM0czNMKhERgPMjAxNjEyMjMxNDExMjFawqFjMGEEFMOpeBc8LDHDj8Khw73DpnRswqh5wovCgT5lwotZAgEBBEYwRAIgHQrClsKMc8O8UT7CklrCtMKoHsOmNklnwoQJf2LCosKqFMOAwqQ1wrjDksKhX1oCIGVew5xXN3MFw5lhDE/ClgvDvMOdWHPCnGIZBhvDuMKyw6zDm8KtXzjCqkrCtw==

# This is where the sha1 is computed for BackupKeybagDigest:

	id __cdecl -[NSData(SecureBackup) sha1Digest](struct NSData *self, SEL a2)
	{
	  struct NSData *v2; // r5@1
	  void *v3; // r4@1
	  const UInt8 *v4; // r6@1
	  void *v5; // r0@1
	  void *v6; // r0@1
	  void *v7; // r0@1

	  v2 = self;
	  v3 = malloc(0x14u);
	  v4 = CFDataGetBytePtr(v2);
	  v5 = objc_msgSend((void *)v2, "length");
	  CC_SHA1((int)v4, (int)v5, (int)v3);
	  v6 = objc_msgSend(&OBJC_CLASS___NSData, "alloc");
	  v7 = objc_msgSend(v6, "initWithBytesNoCopy:length:freeWhenDone:", v3, 20, 1);
	  return (id)j__objc_autoreleaseReturnValue(v7);
	}

# the following is an example from the iPhone 5 syslog:

ay 12 23:25:00 iPhone accountsd[524] <Warning>: ValidateCredentials start 
May 12 23:25:00 iPhone accountsd[524] <Warning>:   running ValidateCredentials step LogStatus 
May 12 23:25:00 iPhone accountsd[524] <Warning>: Master identity: <PCSIdentity@0x16e1f730  pubkey: HjoXTAq29tvck68n9YxhZdsbLdYg932aBRcCMsFb6lo= service: MasterKey> BAT: 20170324212026;iPhone OS;13E238 <> 
May 12 23:25:00 iPhone accountsd[524] <Error>: KeychainGetICDPStatus: keychain: -25300 
May 12 23:25:00 iPhone accountsd[524] <Error>: KeychainGetICDPStatus: status: off 
May 12 23:25:00 iPhone accountsd[524] <Warning>: Local iCDP status is 0 
May 12 23:25:00 iPhone accountsd[524] <Warning>:   running ValidateCredentials step PreCheckKeychain 
May 12 23:25:00 iPhone accountsd[524] <Warning>:   running ValidateCredentials step FixupKeychainItems 
May 12 23:25:00 iPhone com.apple.lakitu[620] <Warning>: === SSL Kill Switch 2: replaced_SSLCopyPeerTrust 
May 12 23:25:00 iPhone cdpd[638] <Warning>: Updated account info cache with { 
	    SecureBackupContainsiCloudIdentity = 1; 
	    SecureBackupEnabled = 0; 
	    SecureBackupStingrayMetadata =     { 
	        BackupKeybagDigest = <2e09d348 cbb5fb9b fab2a073 f4058153 418bda3f>; 
	        ClientMetadata =         { 
	            SecureBackupKeyRegistry =             { 
	                Backup =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010802 01010420 b13709d4 0570b0bd 4bee7e97 0f94c812 95fc0317 e9721fe0 3c644634 3cfe46d9> 
	                    ); 
	                }; 
	                CloudKit =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010402 01010420 5097dd51 a0ae3c26 329e0aed f6e5a953 c3eeb519 011480a8 a2763c71 da87f659> 
	                    ); 
	                }; 
	                FDE =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010602 01010420 3a251735 a29cdcbe 5e698f17 28c5f5f9 a31908d4 65e88100 4537b56c 05c39160> 
	                    ); 
	                }; 
	                Maildrop =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010702 01010420 3931c6f4 eb3bbcad c3354acc c64b867a f2fc346d 79abd529 c8a1726f ce7498b6> 
	                    ); 
	                }; 
	                News =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010b02 01010420 56577dd7 9b1fad36 bef017bd a10c1cb9 1164324f cf2587a2 f6bd0f18 9bae67d4> 
	                    ); 
	                }; 
	                Notes =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010902 01010420 dcec1e48 11fbe378 d7930931 da6512b9 cc488683 183fc11f 725c2841 ed78cb7b> 
	                    ); 
	                }; 
	                Photos =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010302 01010420 84d4f014 d39e10a2 9a513142 68791e09 821dd136 86494bd0 0d595f99 7367d5d2> 
	                    ); 
	                }; 
	                Sharing =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010c02 01010420 7e79f05a dc34af91 7a5ebcd1 69aa9d2b 03ac50a1 359be87e 421d1232 8431a7ab> 
	                    ); 
	                }; 
	                iCloudDrive =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010202 01010420 701d92b5 5eeb31dd 32b4867d dc375897 12f130c4 25a91d4a c7b94864 ae4eee43> 
	                    ); 
	                }; 
	                iMessage =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010a02 01010420 be56c3c0 af3e3169 f0a025ae 81ccef39 bce2f824 e520e072 d4b3c5ba 18dc0dd5> 
	                    ); 
	                }; 
	            }; 
	            SecureBackupLiverpoolPublicData = <61819130 818e0201 04020101 04205097 dd51a0ae 3c26329e 0aedf6e5 a953c3ee b5190114 80a8a276 3c71da87 f659a164 30620414 212a7265 cc66142f 58f459c6 3a7d9e2d b43d3f46 02010104 47304502 20679791 eb0d50a6 78ca2411 c675b949 01f86478 356bbe75 4e6843bc 6af09c53 ea022100 83ae6787 7b440072 2d3b514a 9366ec9d 2aeaa987 2148afa4 11de55f9 e5c0e1f7>; 
	            SecureBackupMetadataTimestamp = "2017-03-24 21:20:27"; 
	            SecureBackupiCloudDataProtection =             { 

This subset of the hex value of SecureBackupLiverpoolPublicData (binary form of hex below appears in alot of the logged https requests):
411c675b94901f86478356bbe754e6843bc6af09c53ea02210083ae67877b4400722d3b514a9366ec9d2aeaa9872148afa411de55f9e5c0e1f7


# the following is from the iPhone 5 syslog (the backupDeviceUUID is 1fc9cef18fbcf929281c518e4445763e60a65b3b):

Apr 28 16:59:23 iPhone cdpd[1444] <Warning>: Updated account info cache with { 
	    SecureBackupContainsiCloudIdentity = 1; 
	    SecureBackupEnabled = 0; 
	    SecureBackupStingrayMetadata =     { 
	        BackupKeybagDigest = <1fc9cef1 8fbcf929 281c518e 4445763e 60a65b3b>; 
	        ClientMetadata =         { 
	            SecureBackupClientVersion = "iPhone OS;14B100"; 
	            SecureBackupKeyRegistry =             { 
	                Activities =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 0e020101 0420d627 85af27f0 68b1d646 bc3adfbf 7cf8d8b9 87cd9116 274629a0 452c8739 132ea164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 2100f293 a04106c0 446258b9 9933a588 004fb5ef 0aa40823 8d235daf 2412ed1a b3980220 72b78270 db794011 f4e3b608 5aaa2c0e b69ffa23 8156a816 2ce89050 1c1a4fac> 
	                    ); 
	                }; 
	                BTAnnouncement =                 { 
	                    PublicIdentities =                     ( 
	                        <61819030 818d0201 13020101 0420f223 94e1bc7a 6eaaddea f25c4aab b7e9fe28 3b2bc11b c6cfa6b1 35981236 3af7a163 30610414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 46304402 205896c4 d84cb4ee b8aca0d8 886cf4c5 4e70885b 696c3ce4 0e974888 f2c71db7 8d02206f 4af5b2d6 23b647c0 840a6354 4fd0577f b07cc246 33f6484a 42550437 1e020b> 
	                    ); 
	                }; 
	                BTPairing =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 12020101 0420e63c 746975d2 b2117cea 88a43406 df91b053 53bf317c d6b3d6c7 8e0eda13 759ea164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 2100e95f 5fad768f 91f628da fea0a5ed 8fc960da 98320825 0dc9fbd5 4588e35a 2eda0220 616dbeb2 83cbdc90 1cb8ab1a d642f9e6 6a406765 34f46a77 4e96cd66 f3abe16d> 
	                    ); 
	                }; 
	                Backup =                 { 
	                    PublicIdentities =                     ( 
	                        <61819230 818f0201 08020101 0420e0c3 0adf1732 2b626843 1688384d b97f192d f2c1ac9a bf933607 c64fb117 9956a165 30630414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 48304602 2100a3fd ac85aca3 d2a54e06 df0b3701 dc1018e4 7c0b8bcc 975fc142 3a282e66 7bd50221 00f09cd4 af7a72ff c6247316 ea89067d 04517120 087cd7bd 506f0c0b d9f7fec9 a9> 
	                    ); 
	                }; 
	                BulkMail =                 { 
	                    PublicIdentities =                     ( 
	                        <61819030 818d0201 11020101 0420ffbe cb0c54c8 8a082e7e aa345549 136f3c6b 04a4bb6d 26da1859 23704ed2 9e32a163 30610414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 46304402 20341f7b 3e315af9 cc368ae9 8f869334 77b4e8ee 110714ad 41886d2b a0608952 fd022064 0c4e88d6 a2c0c032 9273b15f 3afb198e bdca6568 252e3939 a7d640cb 8ce71b> 
	                    ); 
	                }; 
	                CloudKit =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 04020101 04200a23 68820c28 60044d01 484e635e a8a064a8 d65512f2 69a167fa a2620b54 c347a164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 2100a7f5 46fab402 6c9481b9 340959df 9ada72c0 8f9b8938 010b2559 afacec14 8af70220 297f0829 27818147 e4acce67 9004730c fe8a2451 1de66c5b 6d92b3b9 f26d0e37> 
	                    ); 
	                }; 
	                Continuity =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 15020101 0420aaad 2f90bd0d 75095cd4 1891f5b7 2791e4bf 5f1c5283 c99274a4 c769833f 5ceda164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 2100e0c1 3df9662e a7557ba7 19f66fd4 ecde7965 e3bc16fa 0a619eaf 429bc5d4 343b0220 643e95bf 528a2bfe 70fc43db 5ade47e3 1f28c6f1 5939d46e 67a9e809 07e97c99> 
	                    ); 
	                }; 
	                Escrow =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010502 01010420 2a4d62ec aeaf5d8a cf80e755 11aacb19 f62f33b7 f4336478 e3ee9773 4cc25cca> 
	                    ); 
	                }; 
	                FDE =                 { 
	                    PublicIdentities =                     ( 
	                        <612a3028 02010602 01010420 dacf0fa1 01805a1c bc12afa9 4a86a561 f6bc0fd9 b10a5ca9 5e8347f1 5197f4a1> 
	                    ); 
	                }; 
	                Gaming =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 0f020101 04204107 bb0fa4cd c6cd2ff7 235a3cd0 2e392e35 2aacf930 da3df351 a6382b1c a822a164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 202a7fea e9ab2692 a57ef5eb 96492ef1 0bba793d a7994a86 895efde1 0b5a1c8d 75022100 f070581f 9c73b85a b873b834 28aeb57a d48b1955 f78285a7 7721d47a 0afbebf9> 
	                    ); 
	                }; 
	                KeyboardServices =                 { 
	                    PublicIdentities =                     ( 
	                        <61819230 818f0201 0d020101 0420e4fc 7584f75f 43ddaac6 1e48789d 3a09dfdb b6178139 3c238b2a a0f9a882 700aa165 30630414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 48304602 2100baef 6a1f241b 2efd0175 fb6738a6 7e018a1a 328b65a6 069ea0ec b286ccc9 2bc40221 008e4356 ba187542 10309e90 ed0b5075 8b1031d7 e8f0651e 70fe7ad7 3bc114c1 5d> 
	                    ); 
	                }; 
	                Maildrop =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 07020101 0420b270 2a7cd341 c2f2d2d1 ffcb61af c0a108fa ec71d085 2f9c5469 18806ffb deeda164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 201ec4ce 483cd5ca 61881255 e9d4be55 1448246f b4baf301 6e628169 1774eccc 5b022100 e5043e66 a57e21d5 35e94126 523c66dc 616f4d57 d3fef953 9ee5b799 15c938fa> 
	                    ); 
	                }; 
	                MasterKey =                 { 
	                    PublicIdentities =                     ( 
	                        <6181c330 81c00201 01020101 042025e4 1fff9cc9 d2af74a1 e4f77ed2 b2872fef 7f713606 fd8148bf 29d87169 e5faa031 302f302d 02010104 283026a0 110c0f69 50686f6e 65204f53 3b313347 3334a111 180f3230 31363132 32333134 31313231 5aa16330 610414e9 78173c2c 31cfa1fd e6746ca8 798b813e 658b5902 01010446 30440220 1d0d968c 73fc513e 925ab4a8 1ee63649 6784097f 62a2aa14 c0a435b8 d2a15f5a 0220655e dc573773 05d9610c 4f960bfc dd58739c 6219061b f8b2ecdb ad5f38aa 4ab7> 
	                    ); 
	                }; 
	                News =                 { 
	                    PublicIdentities =                     ( 
	                        <61819230 818f0201 0b020101 0420f8af a8a708d6 e2b14bf7 f6a4e7c5 3f42543a 31c57608 e0626d93 fefebf37 93b2a165 30630414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 48304602 2100eda2 b38797f6 3258b5a8 21f93d1e 3322774a dddc259a 14d183a5 ece1af5e b63a0221 008c8e64 d5584487 36afef78 10ffcd1e a5aeea8c d66c2a68 bae89e31 2a897853 ce> 
	                    ); 
	                }; 
	                Notes =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 09020101 0420c8cd 48b410e6 2c1058a0 a8ef622e e6d51c6f 65e3ce16 cabfb059 c0d2b2f1 5090a164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 20155a57 ba5086de ccb7a4f4 77636398 29f71a60 7dd3dabe 44c67482 af060c55 ab022100 8858ec6b ff3abf9f eaf71027 c0dd4d0e 5bdbdee6 b024dc18 4bc98464 aa1e76ac> 
	                    ); 
	                }; 
	                Photos =                 { 
	                    PublicIdentities =                     ( 
	                        <61819030 818d0201 03020101 0420a5cc 163f0114 fc0aab52 bb6c8b77 0f10a74a 2a80fdbe 99987ec5 ebc73b48 a240a163 30610414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 46304402 2061a5f0 8987ce87 ef04ec3a 9d209929 d3cc5795 7352c459 8be247c9 3103f5e0 b1022029 0a5deb3f 5fe2e1e2 2e8fa3cc 5a9cc861 18f2a3ff 66c1ac72 147623da 7b6d54> 
	                    ); 
	                }; 
	                Sharing =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 0c020101 042071cd a413b772 ccf09191 19eccebf 9358071e dbcd8aeb 4cf0a253 89960e45 ea09a164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 2100e71c 424c14f4 1303a592 de8eea79 ba6df776 eaf238eb a669016b 34631228 8f070220 505c6084 2baca410 0d79dc70 856dd21d 9bce99ac e713c898 d6382f3b 06dc4e87> 
	                    ); 
	                }; 
	                TTYCallHistory =                 { 
	                    PublicIdentities =                     ( 
	                        <61819030 818d0201 14020101 04205657 acf17be4 a5cc9910 145580ee cdc33964 eecabe46 26e626da e374f51b e8eaa163 30610414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 46304402 206de7c3 27480673 ec7f6f0b 656949b5 a4eb516f 2ebdf160 cfd662d0 d4789be0 9a02204f 2e8d1926 d8ee35f5 d1e7bff4 5dd26a02 32208990 7ce10a26 7ab1486e 92a7a0> 
	                    ); 
	                }; 
	                iAD =                 { 
	                    PublicIdentities =                     ( 
	                        <61819230 818f0201 10020101 0420f46d d1855e2e fb6f063c f10e3c03 079ca950 b14447a1 c3f43e65 6dbe59b6 556aa165 30630414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 48304602 21008711 4af8e573 d7ea2ebe 90ea7716 1a6b43b7 2bd7f250 e6117079 cf66b0f2 a32c0221 00e4b16c 0e687f74 ea95eabd a083853a 6856e346 89115663 9fbabb48 41b00d55 76> 
	                    ); 
	                }; 
	                iCloudDrive =                 { 
	                    PublicIdentities =                     ( 
	                        <61819230 818f0201 02020101 04203904 25fb992f 2775a848 6dbbe7d4 38f865cd 50409f02 6973bfef cf05c7d5 ab37a165 30630414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 48304602 2100a872 3615aabf 8537d0f0 8684b08f 17b3a17e a724e54b 1fcf9ce0 66976d39 bf020221 00e2a27d b50cfcfc 182872d5 03e9bdc4 10a07774 0219f6a3 edf9d652 e7b16e89 79> 
	                    ); 
	                }; 
	                iMessage =                 { 
	                    PublicIdentities =                     ( 
	                        <61819130 818e0201 0a020101 042062f6 fe29517e bc44087b 146027c0 76253fc8 622e789e d7d7600d 5c85bb93 ac2ba164 30620414 e978173c 2c31cfa1 fde6746c a8798b81 3e658b59 02010104 47304502 205a313a 0b7d6940 f63bb2eb 95476ed6 b4c6a3e5 05e35cee df18f7f5 fbdcbfe4 ba022100 caa91e72 01cd72fb e6805f7c c10d493e c96f10d4 88b208dd 1f3575c7 fcc4cff9> 
	                    ); 
	                }; 
	            }; 
	            SecureBackupStableMetadata =             { 
	                EscrowKey = "Kk1i7K6v


# The private framework MobileBackup seems to be where the backupUUID is generated. Either in the MBBackup class,
# or in the MBManager class.

Note that when I search the root filesystem on the iPhone for the backupDeviceUUID, it appears to be stored here:
Binary file /User/Library/Caches/com.apple.Preferences/Cache.db-wal matches

// MBSBackupAttributes - (unsigned int)hash
unsigned int __cdecl -[MBSBackupAttributes hash](struct MBSBackupAttributes *self, SEL a2)
{
  struct MBSBackupAttributes *v2; // r4@1
  void *v3; // r6@1
  unsigned int v4; // r6@1
  unsigned int v5; // r6@1
  unsigned int v6; // r6@1
  unsigned int v7; // r6@1
  unsigned int v8; // r6@1

  v2 = self;
  v3 = objc_msgSend(self->_deviceClass, "hash");
  v4 = (unsigned int)v3 ^ (unsigned int)objc_msgSend(v2->_productType, "hash");
  v5 = v4 ^ (unsigned int)objc_msgSend(v2->_serialNumber, "hash");
  v6 = v5 ^ (unsigned int)objc_msgSend(v2->_deviceColor, "hash");
  v7 = v6 ^ (unsigned int)objc_msgSend(v2->_hardwareModel, "hash");
  v8 = v7 ^ (unsigned int)objc_msgSend(v2->_marketingName, "hash");
  return (unsigned int)objc_msgSend(v2->_deviceEnclosureColor, "hash") ^ v8;
}


// MBSBackup - (unsigned int)hash
unsigned int __cdecl -[MBSBackup hash](struct MBSBackup *self, SEL a2)
{
  struct MBSBackup *v2; // r4@1
  void *v3; // r0@1
  int v4; // r1@2
  int v5; // r1@3
  unsigned int v6; // r6@6
  unsigned int v7; // r0@6
  int v8; // r1@7
  int v9; // r1@8

  v2 = self;
  v3 = objc_msgSend(self->_attributes, "hash");
  if ( (unsigned int)v2->_snapshots & 2 )
  {
    v5 = HIDWORD(v2->_keysLastModified);
    if ( !v5 )
      v5 = 0;
    v4 = -1640531535 * v5;
  }
  else
  {
    v4 = 0;
  }
  v6 = v4 ^ (unsigned int)v3 ^ (unsigned int)objc_msgSend((void *)v2->_backupUDID, "hash");
  v7 = (unsigned int)objc_msgSend((void *)HIDWORD(v2->_quotaUsed), "hash") ^ v6;
  if ( (unsigned int)v2->_snapshots & 1 )
  {
    v9 = *(_DWORD *)&v2->PBCodable_opaque[4];
    if ( !v9 )
      v9 = 0;
    v8 = -1640531535 * v9;
  }
  else
  {
    v8 = 0;
  }
  return v7 ^ v8;
}
