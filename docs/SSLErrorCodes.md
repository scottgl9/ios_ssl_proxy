enum {
  errSSLProtocol                  = -9800,  /* SSL protocol error */
  errSSLNegotiation               = -9801,  /* Cipher Suite negotiation failure */
  errSSLFatalAlert                = -9802,  /* Fatal alert */
  errSSLWouldBlock                = -9803,  /* I/O would block (not fatal) */
  errSSLSessionNotFound           = -9804,  /* attempt to restore an unknown session */
  errSSLClosedGraceful            = -9805,  /* connection closed gracefully */
  errSSLClosedAbort               = -9806,  /* connection closed via error */
  errSSLXCertChainInvalid         = -9807,  /* Invalid certificate chain */
  errSSLBadCert                   = -9808,  /* bad certificate format */
  errSSLCrypto                    = -9809,  /* underlying cryptographic error */
  errSSLInternal                  = -9810,  /* Internal error */
  errSSLModuleAttach              = -9811,  /* module attach failure */
  errSSLUnknownRootCert           = -9812,  /* valid cert chain, untrusted root */
  errSSLNoRootCert                = -9813,  /* cert chain not verified by root */
  errSSLCertExpired               = -9814,  /* chain had an expired cert */
  errSSLCertNotYetValid           = -9815,  /* chain had a cert not yet valid */
  errSSLClosedNoNotify            = -9816,  /* server closed session with no notification */
  errSSLBufferOverflow            = -9817,  /* insufficient buffer provided */
  errSSLBadCipherSuite            = -9818,  /* bad SSLCipherSuite */
	
  /* fatal errors detected by peer */
  errSSLPeerUnexpectedMsg         = -9819,  /* unexpected message received */
  errSSLPeerBadRecordMac          = -9820,  /* bad MAC */
  errSSLPeerDecryptionFail        = -9821,  /* decryption failed */
  errSSLPeerRecordOverflow        = -9822,  /* record overflow */
  errSSLPeerDecompressFail        = -9823,  /* decompression failure */
  errSSLPeerHandshakeFail         = -9824,  /* handshake failure */
  errSSLPeerBadCert               = -9825,  /* misc. bad certificate */
  errSSLPeerUnsupportedCert       = -9826,  /* bad unsupported cert format */
  errSSLPeerCertRevoked           = -9827,  /* certificate revoked */
  errSSLPeerCertExpired           = -9828,  /* certificate expired */
  errSSLPeerCertUnknown           = -9829,  /* unknown certificate */
  errSSLIllegalParam              = -9830,  /* illegal parameter */
  errSSLPeerUnknownCA             = -9831,  /* unknown Cert Authority */
  errSSLPeerAccessDenied          = -9832,  /* access denied */
  errSSLPeerDecodeError           = -9833,  /* decoding error */
  errSSLPeerDecryptError          = -9834,  /* decryption error */
  errSSLPeerExportRestriction     = -9835,  /* export restriction */
  errSSLPeerProtocolVersion       = -9836,  /* bad protocol version */
  errSSLPeerInsufficientSecurity  = -9837,  /* insufficient security */
  errSSLPeerInternalError         = -9838,  /* internal error */
  errSSLPeerUserCancelled         = -9839,  /* user canceled */
  errSSLPeerNoRenegotiation       = -9840,  /* no renegotiation allowed */

  /* more errors detected by us */
  errSSLHostNameMismatch          = -9843,  /* peer host name mismatch */
  errSSLConnectionRefused         = -9844,  /* peer dropped connection before responding */
  errSSLDecryptionFail            = -9845,  /* decryption failure */
  errSSLBadRecordMac              = -9846,  /* bad MAC */
  errSSLRecordOverflow            = -9847,  /* Record Overflow */
  errSSLBadConfiguration          = -9848,  /* configuration error */
  errSSLLast                      = -9849   /* end of range, to be deleted */
};
