package com.security.aesdukpt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.Buffer;
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

    //Convert a 32-bit integer to a list of bytes in big-endian order.  Used to convert counter values to byte lists.
    static byte[] intToBytes(long x) {
        long b1 = x & 0xff;
        long b2 = (x >>  8) & 0xff;
        long b3 = (x >> 16) & 0xff;
        long b4 = (x >> 24) & 0xff;

        long value = b1 << 24 | b2 << 16 | b3 << 8 | b4;

        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(value);
        ((Buffer) buffer).flip();

        byte[] bufferArray = buffer.array();
        for (int i = 0; i < bufferArray.length / 2; i++) {
            byte temp = bufferArray[i];
            bufferArray[i] = bufferArray[bufferArray.length - 1 - i];
            bufferArray[bufferArray.length - 1 - i] = temp;
        }
        return bufferArray;
    }

    //Count the number of 1 bits in a counter value.  Readable, but not efficient.
    static int countOneBits(long n) {
        return Long.bitCount(n);
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

    //B.6.3. Generate Working Keys
    //Generate a transaction key from the intermediate derivation key registers, and update the state to prepare for the next transaction.
    public byte[] generateWorkingKeys(KeyUsage keyUsage, KeyType keyType) throws Exception {
        setShiftRegister();
        while (!intermediateDerivationKeyInUse[currentKey]) {
            counter = counter + shiftRegister;
            if (counter > ((1 << NUMREG) - 1)) {
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

        return counter <= (1 << NUMREG) - 1;
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
