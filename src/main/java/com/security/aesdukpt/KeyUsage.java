package com.security.aesdukpt;

//B.3.1. Enumerations
public enum KeyUsage {
    _KeyEncryptionKey(0x0002),
    _PINEncryption(0x1000),
    _MessageAuthenticationGeneration(0x2000),
    _MessageAuthenticationVerification(0x2001),
    _MessageAuthenticationBothWays(0x2002),
    _DataEncryptionEncrypt(0x3000),
    _DataEncryptionDecrypt(0x3001),
    _DataEncryptionBothWays(0x3002),
    _KeyDerivation(0x8000),
    _KeyDerivationInitialKey(9);

    private final int keyUsage;

    private KeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
    }

    public int getKeyUsage() {
        return this.keyUsage;
    }
}
