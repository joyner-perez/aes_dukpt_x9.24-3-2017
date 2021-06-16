package com.security.aesdukpt;

//B.3.1. Enumerations
public enum KeyType {
    _2TDEA(0),
    _3TDEA(1),
    _AES128(2),
    _AES192(3),
    _AES256(4);

    private final int keyType;

    private KeyType(int keyType) {
        this.keyType = keyType;
    }

    public int getKeyType() {
        return this.keyType;
    }
}
