# the backup UUID is derrived from the keybag UUID

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
