package com.security.aesdukpt;

//B.3.1. Enumerations
public enum DerivationPurpose {
    _InitialKey(0),
    _DerivationOrWorkingKey(1);

    private final int derivationPurpose;

    private DerivationPurpose(int derivationPurpose) {
        this.derivationPurpose = derivationPurpose;
    }

    public int getDerivationPurpose() {
        return this.derivationPurpose;
    }
}
