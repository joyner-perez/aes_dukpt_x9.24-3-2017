package com.security.aesdukpt;

import org.junit.Assert;
import org.junit.Test;

public class DukptTests {

    @Test
    public void testIntToBytes() {
        byte[] intBytes;
        intBytes = AesDukpt.intToBytes(4294967295L);
        Assert.assertArrayEquals(AesDukpt.toByteArray("FFFFFFFF"), intBytes);

        intBytes = AesDukpt.intToBytes(1);
        Assert.assertArrayEquals(AesDukpt.toByteArray("00000001"), intBytes);

        intBytes = AesDukpt.intToBytes(2147483648L);
        Assert.assertArrayEquals(AesDukpt.toByteArray("80000000"), intBytes);
    }

    @Test
    public void testKsnToCounter80bit() {
        byte[] ksn = AesDukpt.toByteArray("0E11111111FFFFFF0000");
        long counter = AesDukpt.ksnToCounter(ksn);
        Assert.assertEquals(2031616L, counter);
    }

    @Test
    public void testKsnToCounter96bit() {
        byte[] ksn = AesDukpt.toByteArray("123456789012345680000001");
        long counter = AesDukpt.ksnToCounter(ksn);
        Assert.assertEquals(2147483649L, counter);
    }

    @Test
    public void testKsnToKeyId80bit() {
        byte[] ksn = AesDukpt.toByteArray("0E11111111FFFFFF0000");
        byte[] keyId = AesDukpt.ksnToInitialKeyId(ksn);
        Assert.assertArrayEquals(AesDukpt.toByteArray("00E11111111FFFFE"), keyId);
    }

    @Test
    public void testKsnToKeyId96bit() {
        byte[] ksn = AesDukpt.toByteArray("123456789012345600000001");
        byte[] keyId = AesDukpt.ksnToInitialKeyId(ksn);
        Assert.assertArrayEquals(AesDukpt.toByteArray("1234567890123456"), keyId);
    }

    @Test
    public void testIntermediateDerivationKeys() throws Exception {
        String expectedValue = "1273671EA26AC29AFA4D1084127652A1";

        byte[] key = AesDukpt.toByteArray("FEDCBA9876543210F1F1F1F1F1F1F1F1");//is BDK
        byte[] initialDataKeyId = AesDukpt.toByteArray("1234567890123456");
        byte[] deriveInitialKey = AesDukpt.deriveInitialKey(key, KeyType._AES128, initialDataKeyId);
        System.out.println("Derivar initial key: " + AesDukpt.toHex(deriveInitialKey));

        // Assert
        Assert.assertEquals(expectedValue, AesDukpt.toHex(deriveInitialKey));
    }

    @Test
    public void testGenerate32IntermediateGenerationKeys() throws Exception {
        AesDukpt workingDukpt = new AesDukpt();

        String[] expectedValue = {
                "4F21B565BAD9835E112B6465635EAE44",
                "2F34D68DE10F68D38091A73B9E7C437C",
                "0EEFC7ADA628BA68878DA9165A8A1887",
                "718EE6CF0B27E53D5F7AF99C4D8146A2",
                "7459762EED7F51D08567ED6598DFBEA2",
                "1ED39390B4448C69819EB55F4C616564",
                "C13BDA0A56D6998E544E0A10A3D979DA",
                "089F6B989CA13D49A6A0317F85460CE5",
                "065355A6A3DD4C2260BDDDFA0C16704E",
                "CF16FEBC5CFD1A741A3280564A9681F2",
                "4BF8EB1DAF9F4244332ED01663EB654E",
                "492248FEE0FE87E8B5DB7BB2AC7BC955",
                "18690547EB19D28EFAF5EF6D22C271AA",
                "84F4CCA45C4F1D4E063F1CE5B95B6C7F",
                "4EC5FC0C3CD62AFF174A37B6FDC2B0D9",
                "9EF99A4D5FD548A23D299074047F7F6B",
                "F4C6237DB49E28BF96E6A18CD8CDDA00",
                "F7AE9025468A25D37B7249CFFED224C8",
                "579594A986E87917382A181576FA7A9A",
                "5AAF46AAD7593E0D224E05E13629ED1E",
                "5787EB837B6FFB3AF24759F8625CEC19",
                "988A3AB89B9332A15D0BE2C54C279923",
                "E55171636976BDC5758A6FA4C25F0008",
                "DF16D5BAC52FFA7564D7DBD2DE7C6CCF",
                "145E8C933FC0D61900592035CF18A5AF",
                "FBDF917E209B42F9DB8843D18BEE8033",
                "61C70779F920BBD37815C21B5A1A7B75",
                "97D7BB3FC342B9E961308BB8B801775B",
                "69B453118411404DB54AE2B751F02F43",
                "7CCE4E679F4FC3478E3CD4509D64A7F3",
                "36AF4AA9FC1100B2AE7742101540340A",
                "9DC56486499A2E857FDEFC4740641EA8"
        };

        byte[] key = AesDukpt.toByteArray("FEDCBA9876543210F1F1F1F1F1F1F1F1");//is BDK
        byte[] initialDataKeyId = AesDukpt.toByteArray("1234567890123456");

        byte[] deriveInitialKey = AesDukpt.deriveInitialKey(key, KeyType._AES128, initialDataKeyId);
        System.out.println("Derivar initial key: " + AesDukpt.toHex(deriveInitialKey));
        workingDukpt.loadInitialKey(deriveInitialKey, KeyType._AES128, initialDataKeyId);

        // Assert
        Assert.assertArrayEquals(expectedValue, workingDukpt.getIntermediateDerivationKeyRegister());
    }

    @Test
    public void testGenerateKeyEncryption() throws Exception {
        AesDukpt workingDukpt = new AesDukpt();
        
        String[] expectedValue = {
                "A35C412EFD41FDB98B69797C02DCD08F",
                "D639514AA33AC43AD9229E433D6D4E5B",
                "EF17F6AB45B4820C93A3DCB21BC491AD",
                "B3BD44C08BB6BA27C3BB4711D7D70387",
                "CA02DF6F30B39E14BD0B4A30E460920F",
                "C9B8A7C4E486180B2229115164F0B293",
                "0FA8F1F0A2DD7B1005A862D77CDED698",
                "650F34204ABD4E57764D61AC3D266FB1"
        };

        byte[] key = AesDukpt.toByteArray("FEDCBA9876543210F1F1F1F1F1F1F1F1");//is BDK
        byte[] initialDataKeyId = AesDukpt.toByteArray("1234567890123456");

        byte[] deriveInitialKey = AesDukpt.deriveInitialKey(key, KeyType._AES128, initialDataKeyId);
        System.out.println("Derivar initial key: " + AesDukpt.toHex(deriveInitialKey));
        workingDukpt.loadInitialKey(deriveInitialKey, KeyType._AES128, initialDataKeyId);

        // execute 8 transactions and save 8 keys
        String[] keys = new String[8];
        for (int i = 1; i < 9; i++) {
            System.out.println("");
            System.out.println("Counter: " + i);

            byte[] keyEncryption = workingDukpt.generateWorkingKeys(KeyUsage._DataEncryptionEncrypt, KeyType._AES128);
            System.out.println("");
            System.out.println("Encryption Key: " + AesDukpt.toHex(keyEncryption));
            keys[i - 1] = AesDukpt.toHex(keyEncryption);
        }

        // Assert
        Assert.assertArrayEquals(expectedValue, keys);
    }

    @Test
    public void testEncryption() throws Exception {
        AesDukpt workingDukpt = new AesDukpt();
        
        String[] expectedValue = {
                "578D868399E773DFA8375199FE91D5C7",
                "2D4E67D6BB3FEADDD76549EAB4BFFAF9",
                "155BD182AECFE2B91ED96F37BAEA298D",
                "C5972720C139D19BD0F9346FFEBE612A",
                "219FA3584004049424A483AA817A21DB",
                "991EC6FB35C557F1A1CB223C187020BA",
                "7C10E9892D3B7B13EAC3011CDC05D43E",
                "363FEECE0C394AE71092C6DA38946F6B"
        };

        byte[] key = AesDukpt.toByteArray("FEDCBA9876543210F1F1F1F1F1F1F1F1");//is BDK
        byte[] initialDataKeyId = AesDukpt.toByteArray("1234567890123456");
        byte[] dataTest = AesDukpt.toByteArray(AesDukpt.paddingDataText("1234567890"));

        byte[] deriveInitialKey = AesDukpt.deriveInitialKey(key, KeyType._AES128, initialDataKeyId);
        System.out.println("Derivar initial key: " + AesDukpt.toHex(deriveInitialKey));
        workingDukpt.loadInitialKey(deriveInitialKey, KeyType._AES128, initialDataKeyId);

        // execute 8 transactions and save 8 data encrypted
        String[] datasEncrypted = new String[8];
        for (int i = 1; i < 9; i++) {
            System.out.println("");
            System.out.println("Counter: " + i);

            byte[] keyEncryption = workingDukpt.generateWorkingKeys(KeyUsage._DataEncryptionEncrypt, KeyType._AES128);
            System.out.println("");
            System.out.println("PIN Encryption Key:" + AesDukpt.toHex(keyEncryption));
            String dataEncrypted = AesDukpt.toHex(AesDukpt.encryptAes(keyEncryption, dataTest));
            System.out.println("Data Encryption: " + dataEncrypted);
            datasEncrypted[i - 1] = dataEncrypted;
        }

        // Assert
        Assert.assertArrayEquals(expectedValue, datasEncrypted);
    }

    @Test
    public void testDecrypt() throws Exception {
        AesDukpt workingDukpt = new AesDukpt();
        
        String[] expectedValue = {
                "12345678900000000000000000000000",
                "12345678900000000000000000000000",
                "12345678900000000000000000000000",
                "12345678900000000000000000000000",
                "12345678900000000000000000000000",
                "12345678900000000000000000000000",
                "12345678900000000000000000000000",
                "12345678900000000000000000000000"
        };

        byte[] key = AesDukpt.toByteArray("FEDCBA9876543210F1F1F1F1F1F1F1F1");//is BDK
        byte[] initialDataKeyId = AesDukpt.toByteArray("1234567890123456");
        byte[] dataTest = AesDukpt.toByteArray(AesDukpt.paddingDataText("1234567890"));

        byte[] deriveInitialKey = AesDukpt.deriveInitialKey(key, KeyType._AES128, initialDataKeyId);
        System.out.println("Derivar initial key: " + AesDukpt.toHex(deriveInitialKey));
        workingDukpt.loadInitialKey(deriveInitialKey, KeyType._AES128, initialDataKeyId);

        // execute 8 transactions and save 8 data encrypted
        String[] datasDecrypted = new String[8];
        for (int i = 1; i < 9; i++) {
            System.out.println("");
            System.out.println("Counter: " + i);

            byte[] keyEncryption = workingDukpt.generateWorkingKeys(KeyUsage._DataEncryptionEncrypt, KeyType._AES128);
            System.out.println("");
            System.out.println("PIN Encryption Key:" + AesDukpt.toHex(keyEncryption));
            String dataEncrypted = AesDukpt.toHex(AesDukpt.encryptAes(keyEncryption, dataTest));
            System.out.println("Data Encryption: " + dataEncrypted);
            String dataDecrypted = AesDukpt.toHex(AesDukpt.decryptAes(keyEncryption, AesDukpt.toByteArray(dataEncrypted)));
            System.out.println("Data Decrypted: " + dataDecrypted);
            datasDecrypted[i - 1] = dataDecrypted;
        }

        // Assert
        Assert.assertArrayEquals(expectedValue, datasDecrypted);
    }

    @Test
    public void testHostDeriveWorkingKeyPinEncryption() throws Exception {
        String initialKeyIdHex = "12345678 90123456";
        byte[] initialKey = AesDukpt.toByteArray("1273671E A26AC29A FA4D1084 127652A1");
        long[] counterTestVector = new long[] { 1, 2, 3, 7, 131073L, 8675309L, 4294901760L, };
        byte[][] pinEncryptionKeysExpected = new byte[][] {
                AesDukpt.toByteArray("AF8CB133 A78F8DC2 D1359F18 527593FB"),
                AesDukpt.toByteArray("D30BDC73 EC9714B0 00BEC66B DB7B6D09"),
                AesDukpt.toByteArray("7D69F01F 3B45449F 62C7816E CE723268"),
                AesDukpt.toByteArray("6ECF912F 3B18CA11 A7A27BB6 0705FD09"),
                AesDukpt.toByteArray("8AC85C93 EED24605 4ADC3104 479115A6"),
                AesDukpt.toByteArray("D1DDA386 AA4A556A F0119FDC B5D132C6"),
                AesDukpt.toByteArray("27EFAC1D 15863258 8F4AC69E 45C247C4"),
        };
        byte[][] macGenerationKeysExpected = new byte[][] {
                AesDukpt.toByteArray("A2DC23DE 6FDE0824 A2BC321E 08E4B8B7"),
                AesDukpt.toByteArray("484C3B06 E8562704 528CD5B4 6FB12FB6"),
                AesDukpt.toByteArray("A5DF7D9D 800CA769 766F0C77 CA4E6E6C"),
                AesDukpt.toByteArray("BAA08CA2 63C69525 BC6B1BA8 F4275D69"),
                AesDukpt.toByteArray("EF7C9461 E2AFED2A 8012CC63 01CFEEBE"),
                AesDukpt.toByteArray("89365C79 70950CAC 0A6261FF C7DB26C6"),
                AesDukpt.toByteArray("AE558BAB C206D303 FDF68B11 81F228C6"),
        };
        byte[][] dataEncryptionKeysExpected = new byte[][] {
                AesDukpt.toByteArray("A35C412E FD41FDB9 8B69797C 02DCD08F"),
                AesDukpt.toByteArray("D639514A A33AC43A D9229E43 3D6D4E5B"),
                AesDukpt.toByteArray("EF17F6AB 45B4820C 93A3DCB2 1BC491AD"),
                AesDukpt.toByteArray("0FA8F1F0 A2DD7B10 05A862D7 7CDED698"),
                AesDukpt.toByteArray("B93B4BF0 D52163B3 CF9312F8 E55629A3"),
                AesDukpt.toByteArray("B1E4D900 6A87DD08 D87F11A1 24D35517"),
                AesDukpt.toByteArray("08878BFC C45CA5AE F6A1AB40 BAC882B5"),
        };

        for (int i = 0; i < counterTestVector.length; i++) {
            long counter = counterTestVector[i];
            byte[] ksn = AesDukpt.toByteArray(initialKeyIdHex + AesDukpt.toHex(AesDukpt.intToBytes(counter)));

            byte[] pinKey = AesDukpt.hostDeriveWorkingKey(initialKey, KeyType._AES128, KeyUsage._PINEncryption,
                    KeyType._AES128, ksn);
            byte[] macKey = AesDukpt.hostDeriveWorkingKey(initialKey, KeyType._AES128, KeyUsage._MessageAuthenticationGeneration,
                    KeyType._AES128, ksn);
            byte[] dataKey = AesDukpt.hostDeriveWorkingKey(initialKey, KeyType._AES128, KeyUsage._DataEncryptionEncrypt,
                    KeyType._AES128, ksn);

            Assert.assertArrayEquals(pinEncryptionKeysExpected[i], pinKey);
            Assert.assertArrayEquals(macGenerationKeysExpected[i], macKey);
            Assert.assertArrayEquals(dataEncryptionKeysExpected[i], dataKey);
        }
    }

}
