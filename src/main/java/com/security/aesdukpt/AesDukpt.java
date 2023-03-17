package com.security.aesdukpt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class AesDukpt {

    private static final int NUMREG = 32;
    private static final int MAX_WORK = 16;

    private String[] intermediateDerivationKeyRegister;
    private boolean[] intermediateDerivationKeyInUse;
    private int currentKey;
    private byte[] deviceID;
    private long counter;
    private long shiftRegister;
    private KeyType deriveKeyType;

    String[] getIntermediateDerivationKeyRegister() {
        return intermediateDerivationKeyRegister;
    }

    void setIntermediateDerivationKeyRegister(String[] intermediateDerivationKeyRegister) {
        this.intermediateDerivationKeyRegister = intermediateDerivationKeyRegister;
    }

    boolean[] getIntermediateDerivationKeyInUse() {
        return intermediateDerivationKeyInUse;
    }

    void setIntermediateDerivationKeyInUse(boolean[] intermediateDerivationKeyInUse) {
        this.intermediateDerivationKeyInUse = intermediateDerivationKeyInUse;
    }

    int getCurrentKey() {
        return currentKey;
    }

    void setCurrentKey(int currentKey) {
        this.currentKey = currentKey;
    }

    byte[] getDeviceID() {
        return deviceID;
    }

    void setDeviceID(byte[] deviceID) {
        this.deviceID = deviceID;
    }

    public long getCounter() {
        return counter;
    }

    void setCounter(long counter) {
        this.counter = counter;
    }

    long getShiftRegister() {
        return shiftRegister;
    }

    void setShiftRegister(long shiftRegister) {
        this.shiftRegister = shiftRegister;
    }

    public KeyType getDeriveKeyType() {
        return deriveKeyType;
    }

    void setDeriveKeyType(KeyType deriveKeyType) {
        this.deriveKeyType = deriveKeyType;
    }

    //Convert a 32-bit unsigned integer to a list of bytes in big-endian order.  Used to convert counter values to byte lists.
    static byte[] intToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(x);
        byte[] longArray = buffer.array();
        byte[] intArray = new byte[Integer.SIZE / Byte.SIZE];
        System.arraycopy(longArray, intArray.length, intArray, 0, intArray.length);
        return intArray;
    }

    //Count the number of 1 bits in a counter value.  Readable, but not efficient.
    static int countOneBits(long n) {
        return Long.bitCount(n);
    }

    /**
     * Unsigned/logical right shift of whole byte array by shiftBitCount bits.
     * This method will alter the input byte array.
     */
    static byte[] shiftRight(byte[] byteArray, int shiftBitCount) {
        final int shiftMod = shiftBitCount % 8;
        final byte carryMask = (byte) (0xFF << (8 - shiftMod));
        final int offsetBytes = (shiftBitCount / 8);

        int sourceIndex;
        for (int i = byteArray.length - 1; i >= 0; i--) {
            sourceIndex = i - offsetBytes;
            if (sourceIndex < 0) {
                byteArray[i] = 0;
            } else {
                byte src = byteArray[sourceIndex];
                byte dst = (byte) ((0xff & src) >>> shiftMod);
                if (sourceIndex - 1 >= 0) {
                    dst |= byteArray[sourceIndex - 1] << (8 - shiftMod) & carryMask;
                }
                byteArray[i] = dst;
            }
        }
        return byteArray;
    }

    /**
     * Accepts legacy format KSN (80 bits) and AES standard format KSN (96 bits).
     * Returns just the initial key ID part of the KSN for internal use.
     */
    public static byte[] ksnToInitialKeyId(byte[] ksn) {
        byte[] initialKeyId = new byte[8];

        if (ksn.length == 10) {
            // Legacy KSN
            // +-----------------------+---------------------+
            // | Legacy Initial key ID | Transaction Counter |
            // |       (59 bits)       |      (21 bits)      |
            // +-----------------------+---------------------+
            //
            // It is recommended that legacy initial key ID starting with the byte “0E” SHOULD be
            // reserved for use with KSN compatibility mode
            //
            // Key Set ID = 0E11111111
            // Device ID = 22222
            // Initial Key ID = 0E1111111122222
            // Legacy KSN = 0E111111112222200000
            // Internal KSN = 00E111111112222200000000
            if (ksn[0] != 0x0E) {
                // Just warn, it is only a recommendation
                System.out.println("Warning: legacy initial key id does not start with 0E");
            }

            // Legacy KSN packs key id in first 59 bits, remaining 21 bits are the counter, copy
            // just bytes that contain the key id
            System.arraycopy(ksn, 0, initialKeyId, 0, 8);

            // need to zero counter bits in the last byte that is border between key id and counter
            initialKeyId[7] &= 0xE0;

            // Pad first 4 bits with zero per KSN Compatibility Mode
            return shiftRight(initialKeyId, 4);
        } else if (ksn.length == 12) {
            // New 96-bit KSN
            // +-----------------------+---------------------+
            // |    Initial key ID     | Transaction Counter |
            // |       (64 bits)       |      (32 bits)      |
            // +-----------------------+---------------------+
            //
            // Example 123456789012345600000001
            System.arraycopy(ksn, 0, initialKeyId, 0, 8);
            return initialKeyId;
        } else {
            throw new UnsupportedOperationException("Unsupported IKSN length: " + ksn.length);
        }
    }

    /**
     * Extract the counter from a KSN. Returns a long to ensure it is always positive.
     */
    public static long ksnToCounter(byte[] ksn) {
        // Destination is java-size long
        byte[] counterBytes = new byte[8];

        if (ksn.length == 10) {
            // Legacy KSN, counter is right 21 bits
            // Position of the byte where key id and counter meet
            int borderBytePos = counterBytes.length - 3;
            // Copy right 24 bits to the end of a 32 bit buffer
            System.arraycopy(ksn, 7, counterBytes, borderBytePos, 3);
            // Clear left 3 bits of the 24 bits copied to preserve just 21 bits
            counterBytes[borderBytePos] &= 0x1F;
        } else if (ksn.length == 12) {
            // New 96-bit KSN, counter is right 32 bits
            System.arraycopy(ksn, 8, counterBytes, counterBytes.length - 4, 4);
        } else {
            throw new UnsupportedOperationException("Unsupported IKSN length: " + ksn.length);
        }

        ByteBuffer buffer = ByteBuffer.wrap(counterBytes);
        return buffer.getLong();
    }

    //B.3.2. Key Length function
    //Length of an algorithm's key, in bits.
    public static int keyLength(KeyType keyType) {
        switch (keyType) {
            case _2TDEA:
            case _AES128:
                return 128;
            case _3TDEA:
            case _AES192:
                return 192;
            case _AES256:
                return 256;
            default:
                return 0;
        }
    }

    //B.4.1. Derive Key algorithm
    //AES DUKPT key derivation function.
    public static byte[] deriveKey(byte[] derivationKey, KeyType keyType, byte[] derivationData) throws Exception {
        int L = keyLength(keyType);
        byte[] result = encryptAes(derivationKey, derivationData);
        int n = L / 8;
        return Arrays.copyOfRange(result, 0, n);
    }

    //B.4.3. Create Derivation Data
    //Compute derivation data for an AES DUKPT key derivation operation.
    public static byte[] createDerivationData(DerivationPurpose derivationPurpose, KeyUsage keyUsage, KeyType keyType, byte[] initialKeyID, long counter) {
        byte[] derivationData = new byte[16];
        derivationData[0] = 0x01;
        derivationData[1] = 0x01;

        if (keyUsage == KeyUsage._KeyEncryptionKey) {
            derivationData[2] = 0x00;
            derivationData[3] = 0x02;
        } else if (keyUsage == KeyUsage._PINEncryption) {
            derivationData[2] = 0x10; // for 0x16 replace with 0x10
            derivationData[3] = 0x00;
        } else if (keyUsage == KeyUsage._MessageAuthenticationGeneration) {
            derivationData[2] = 0x20; // for 0x32 replace with 0x20
            derivationData[3] = 0x00;
        } else if (keyUsage == KeyUsage._MessageAuthenticationVerification) {
            derivationData[2] = 0x20; // for 0x32 replace with 0x20
            derivationData[3] = 0x01;
        } else if (keyUsage == KeyUsage._MessageAuthenticationBothWays) {
            derivationData[2] = 0x20; // for 0x32 replace with 0x20
            derivationData[3] = 0x02;
        } else if (keyUsage == KeyUsage._DataEncryptionEncrypt) {
            derivationData[2] = 0x30; // for 0x48 replace with 0x30
            derivationData[3] = 0x00;
        } else if (keyUsage == KeyUsage._DataEncryptionDecrypt) {
            derivationData[2] = 0x30; // for 0x48 replace with 0x30
            derivationData[3] = 0x01;
        } else if (keyUsage == KeyUsage._DataEncryptionBothWays) {
            derivationData[2] = 0x30; // for 0x48 replace with 0x30
            derivationData[3] = 0x02;
        } else if (keyUsage == KeyUsage._KeyDerivation) {
            derivationData[2] = -128;
            derivationData[3] = 0x00;
        } else if (keyUsage == KeyUsage._KeyDerivationInitialKey) {
            derivationData[2] = -128;
            derivationData[3] = 0x01;
        } else {
            return null;
        }

        if (keyType == KeyType._2TDEA) {
            derivationData[4] = 0x00;
            derivationData[5] = 0x00;
        } else if (keyType == KeyType._3TDEA) {
            derivationData[4] = 0x00;
            derivationData[5] = 0x01;
        } else if (keyType == KeyType._AES128) {
            derivationData[4] = 0x00;
            derivationData[5] = 0x02;
        } else if (keyType == KeyType._AES192) {
            derivationData[4] = 0x00;
            derivationData[5] = 0x03;
        } else if (keyType == KeyType._AES256) {
            derivationData[4] = 0x00;
            derivationData[5] = 0x04;
        } else {
            return null;
        }

        if (keyType == KeyType._2TDEA) {
            derivationData[6] = 0x00;
            derivationData[7] = -128;
        } else if (keyType == KeyType._3TDEA) {
            derivationData[6] = 0x00;
            derivationData[7] = -64;
        } else if (keyType == KeyType._AES128) {
            derivationData[6] = 0x00;
            derivationData[7] = -128;
        } else if (keyType == KeyType._AES192) {
            derivationData[6] = 0x00;
            derivationData[7] = -64;
        } else {
            derivationData[6] = 0x01;
            derivationData[7] = 0x00;
        }

        if (derivationPurpose == DerivationPurpose._InitialKey) {
            derivationData[8] = initialKeyID[0];
            derivationData[9] = initialKeyID[1];
            derivationData[10] = initialKeyID[2];
            derivationData[11] = initialKeyID[3];
            derivationData[12] = initialKeyID[4];
            derivationData[13] = initialKeyID[5];
            derivationData[14] = initialKeyID[6];
            derivationData[15] = initialKeyID[7];
        } else if (derivationPurpose == DerivationPurpose._DerivationOrWorkingKey) {
            derivationData[8] = initialKeyID[4];
            derivationData[9] = initialKeyID[5];
            derivationData[10] = initialKeyID[6];
            derivationData[11] = initialKeyID[7];

            byte[] value = intToBytes(counter);
            derivationData[12] = value[0];
            derivationData[13] = value[1];
            derivationData[14] = value[2];
            derivationData[15] = value[3];
        } else {
            return null;
        }

        return derivationData;
    }

    //B.5. Derive Initial Key
    //Derive the initial key for a particular initialKeyID from a BDK.
    public static byte[] deriveInitialKey(byte[] bdk, KeyType keyType, byte[] initialKeyId) throws Exception {
        byte[] derivationData = createDerivationData(DerivationPurpose._InitialKey, KeyUsage._KeyDerivationInitialKey, keyType, initialKeyId, 0);
        return deriveKey(bdk, keyType, derivationData);
    }

    //B.6.3. Processing Routines
    //Load an initial key for computing terminal transaction keys in sequence.
    public void loadInitialKey(byte[] initialKey, KeyType keyType, byte[] initialKeyID) throws Exception {
        intermediateDerivationKeyRegister = new String[NUMREG];
        intermediateDerivationKeyInUse = new boolean[NUMREG];

        intermediateDerivationKeyRegister[0] = toHex(initialKey);
        intermediateDerivationKeyInUse[0] = true;
        deviceID = initialKeyID;
        counter = 0;
        shiftRegister = 1L;
        currentKey = 0;
        deriveKeyType = keyType;

        updateDerivationKeys(NUMREG-1, keyType);
        counter = counter + 1;
    }

    //B.6.3. Update Initial Key
    //Load a new terminal initial key under a pre-existing terminal initial key.
    public void updateInitialKey(byte[] newInitialKey, KeyType keyType, byte[] newDeviceID) throws Exception {
        loadInitialKey(newInitialKey, keyType, newDeviceID);
    }

    /**
     * Derive the working key that the terminal used for encryption using the KSN.
     */
    public static byte[] hostDeriveWorkingKey(byte[] initialKey, KeyType deriveKeyType, KeyUsage workingKeyUsage,
                                              KeyType workingKeyType, byte[] ksn) throws Exception {
        boolean isLegacy = ksn.length == 10;

        // set the most significant bit to one and all other bits to zero
        // legacy mode uses 21-bit counter, otherwise counter is 32-bit
        long mask = isLegacy ? 1L << 21 : 1L << 31;
        long workingCounter = 0;
        long transactionCounter = ksnToCounter(ksn);
        byte[] initialKeyID = ksnToInitialKeyId(ksn);
        byte[] derivationData;
        byte[] derivationKey = initialKey;

        while (mask > 0) {
            if ((mask & transactionCounter) != 0) {
                workingCounter = workingCounter | mask;
                derivationData = createDerivationData(DerivationPurpose._DerivationOrWorkingKey,
                        KeyUsage._KeyDerivation, deriveKeyType, initialKeyID, workingCounter);
                derivationKey = deriveKey(derivationKey, deriveKeyType, derivationData);
            }
            mask = mask >> 1;
        }

        derivationData = createDerivationData(DerivationPurpose._DerivationOrWorkingKey,
                workingKeyUsage, workingKeyType, initialKeyID, transactionCounter);
        return deriveKey(derivationKey, workingKeyType, derivationData);
    }

    //B.6.3. Generate Working Keys
    //Generate a transaction key from the intermediate derivation key registers, and update the state to prepare for the next transaction.
    public byte[] generateWorkingKeys(KeyUsage keyUsage, KeyType keyType) throws Exception {
        setShiftRegister();
        while (!intermediateDerivationKeyInUse[currentKey]) {
            counter = counter + shiftRegister;
            if (counter > ((1L << NUMREG) - 1)) {
                return null;
            }
            setShiftRegister();
        }

        byte[] derivationData = createDerivationData(DerivationPurpose._DerivationOrWorkingKey, keyUsage, keyType, deviceID, counter);
        if (!intermediateDerivationKeyInUse[currentKey]) {
            return null;
        }
        byte[] workingKey = deriveKey(toByteArray(intermediateDerivationKeyRegister[currentKey]), keyType, derivationData);
        updateStateForNextTransaction();
        return workingKey;
    }

    //B.6.3. Update State for next Transaction
    //Move the counter forward, and derive new intermediate derivation keys for the next transaction.
    public boolean updateStateForNextTransaction() throws Exception {
        int oneBits = countOneBits(counter);
        if (oneBits <= MAX_WORK) {
            updateDerivationKeys(currentKey, deriveKeyType);
            intermediateDerivationKeyRegister[currentKey] = "0";
            intermediateDerivationKeyInUse[currentKey] = false;
            counter++;
        } else {
            intermediateDerivationKeyRegister[currentKey] = "0";
            intermediateDerivationKeyInUse[currentKey] = false;
            counter += shiftRegister;
        }

        return counter <= (1L << NUMREG) - 1;
    }

    //B.6.3. Update Derivation Keys
    //Update all the intermediate derivation key registers below a certain point.
    //This is used to:
    // 1. Update all the intermediate derivation key registers below the shift register after computing a transaction key.
    // 2. Update all the intermediate derivation key registers when an initial key is loaded.
    public boolean updateDerivationKeys(int start, KeyType keyType) throws Exception {
        int i = start;
        long j = 1L << start;

        String baseKey = intermediateDerivationKeyRegister[currentKey];
        while (j != 0) {
            byte[] derivationData = createDerivationData(DerivationPurpose._DerivationOrWorkingKey, KeyUsage._KeyDerivation, keyType, deviceID, counter | j);
            if (!intermediateDerivationKeyInUse[currentKey]) {
                return false;
            }
            intermediateDerivationKeyRegister[i] = toHex(deriveKey(toByteArray(baseKey), keyType, derivationData));
            intermediateDerivationKeyInUse[i] = true;
            j = j >> 1L;
            i = i - 1;
        }

        return true;
    }

    //B.6.3. Set Shift Register
    //Set the shift register to the value of the rightmost '1' bit in the counter.
    public boolean setShiftRegister() {
        shiftRegister = 1L;
        currentKey = 0;

        if (counter == 0) {
            return true;
        }

        while ((shiftRegister & counter) == 0) {
            shiftRegister = shiftRegister << 1L;
            currentKey = currentKey + 1;
        }

        return true;
    }

    /**
     * <p>Performs Single AES Encryption without padding.
     *
     * <p>This is supplied for use generic encryption and decryption purposes, but is not a part of the Dukpt algorithm.
     *
     * @param key The key for encryption.
     * @param data The data to encrypt.
     * @return The encrypted data.
     */
    static byte[] encryptAes(byte[] key, byte[] data) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        SecretKeySpec encryptKey = new SecretKeySpec(key, "AES");
        Cipher encryptor = Cipher.getInstance("AES/CBC/NoPadding");
        encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv);
        return encryptor.doFinal(data);
    }

    /**
     * <p>Performs Single AES Decryption.
     *
     * <p>This is supplied for use generic encryption and decryption purposes, but is not a part of the Dukpt algorithm.
     *
     * @param key The key for decryption.
     * @param data The data to decrypt.
     * @return The decrypted data.
     */
    static byte[] decryptAes(byte[] key, byte[] data) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        SecretKeySpec decryptKey = new SecretKeySpec(key, "AES");
        Cipher decryptor = Cipher.getInstance("AES/CBC/NoPadding");
        decryptor.init(Cipher.DECRYPT_MODE, decryptKey, iv);
        return decryptor.doFinal(data);
    }

    /**
     * <p>Converts a hexadecimal String into a byte array (Big-Endian).
     *
     * @param s A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
     */
    static byte[] toByteArray(String s) {
        s = s.replace(" ", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * <p>Converts a byte array into a hexadecimal string (Big-Endian).
     *
     * @return A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
     */
    static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }

    /**
     * <p>Converts a string into a padding string with 0.
     *
     * @return A string with zeros in the end, enter: 1234567890, return 12345678900000000000000000000000.
     */
    static String paddingDataText(String data) {
        int padding = 32;
        if (data.length() % padding != 0) {
            StringBuilder dataToEncryptBuilder = new StringBuilder(data);
            while (dataToEncryptBuilder.length() % padding != 0) {
                dataToEncryptBuilder.append("0");
            }
            data = dataToEncryptBuilder.toString();
        }

        return data;
    }
}
