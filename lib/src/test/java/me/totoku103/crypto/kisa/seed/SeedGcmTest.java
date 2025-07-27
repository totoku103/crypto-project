package me.totoku103.crypto.kisa.seed;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Random;

import me.totoku103.crypto.kisa.seed.dto.EncryptGcmResult;
import me.totoku103.crypto.kisa.seed.mode.SeedGcm;
import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SeedGcmTest {

    @Test
    void testEncryptionDecryption() {
        SeedGcm seedGcm = new SeedGcm();

        // 1. Define test parameters
        //        byte[] mKey = {
        //                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
        // (byte) 0x06, (byte) 0x07,
        //                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D,
        // (byte) 0x0E, (byte) 0x0F
        //        };
        byte[] mKey = "HELLO_WORLD_12345678".getBytes(); // Example key, must be 16 bytes for SEED
        System.out.println(mKey.length);

        //        byte[] nonce = {
        //                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
        // (byte) 0x06, (byte) 0x07,
        //                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B
        //        };
        byte[] nonce = "1234567890AB".getBytes(); // Example nonce, must be 12 bytes for SEED GCM
        System.out.println(nonce.length);

        //        byte[] aad = {
        //                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
        // (byte) 0x06, (byte) 0x07
        //        };

        byte[] aad = "Additional Authenticated Data".getBytes(); // Example AAD, can be any length
        System.out.println(aad.length);

        byte[] pt =
                "동해물과 백두산이 마르고 닳도록. 하느님이 보우하사 우리나라 만세. 무궁화 삼천리 화려강산. 대한사람 대한으로 길이 보전하세..".getBytes();
        int ptLen = pt.length;
        int macLen = 16; // 16 bytes for the authentication tag

        // 2. Encryption
        byte[] ct = new byte[ptLen + macLen];
        int ctLen =
                seedGcm.encryptionGcm(ct, pt, ptLen, macLen, nonce, nonce.length, aad, aad.length, mKey);

        assertEquals(ptLen + macLen, ctLen, "Encryption returned incorrect length");

        System.out.println("Original Plaintext: " + new String(pt));
        System.out.println("Ciphertext (hex): " + ByteUtils.toHexString(ct));
        System.out.println("Ciphertext length: " + ctLen);

        // 3. Decryption
        byte[] decryptedPt = new byte[ptLen];
        int decryptedPtLen =
                seedGcm.decryptionGcm(
                        decryptedPt, ct, ctLen, macLen, nonce, nonce.length, aad, aad.length, mKey);

        assertEquals(ptLen, decryptedPtLen, "Decryption returned incorrect length");

        System.out.println("Decrypted Plaintext: " + new String(decryptedPt));

        // 4. Verification
        assertArrayEquals(pt, decryptedPt, "Decrypted plaintext does not match original plaintext");
        System.out.println("\nEncryption and decryption successful!");
    }

    @Test
    public void simpleTest() {
        final String mKey = "ABCDEFGHIJKLMNOP";
        final String plainText = "나랏말싸미듕귁에달아문자와로 서로 사맛디 아니할쎄 이런 전차로 어린 백셩이 니르고져 홀베이셔도";
        final String nonce = "1234567890AB";
        final String aad = "Additional Authenticated Data";

        final SeedGcm seedGcm = new SeedGcm();
        final String encrypt = seedGcm.encrypt(mKey, plainText, nonce, aad);
        System.out.println(encrypt);

        final String decrypt = seedGcm.decrypt(mKey, encrypt, nonce, aad);
        System.out.println(decrypt);
        Assertions.assertEquals(plainText, decrypt);
    }

    @Test
    public void simpleTestAddMissMatch() {
        final String mKey = "ABCDEFGHIJKLMNOP";
        final String plainText = "나랏말싸미듕귁에달아문자와로 서로 사맛디 아니할쎄 이런 전차로 어린 백셩이 니르고져 홀베이셔도";

        final long epochSecond = LocalDateTime.now().atZone(ZoneId.of("Asia/Seoul")).toEpochSecond();
        final int i = new Random().nextInt(9);
        final String nonce = i + "" + epochSecond + i;

        final String aad1 = "Additional Authenticated Data";
        final String aad2 = "Additional Authenticated Datb";

        final SeedGcm seedGcm = new SeedGcm();
        final String encrypt = seedGcm.encrypt(mKey, plainText, nonce, aad1);
        final String decrypt = seedGcm.decrypt(mKey, encrypt, nonce, aad2);
        Assertions.assertNotEquals(plainText, decrypt);
    }

    @Test
    public void testBase64() {
        final String key = "Rd3PVzCG5Yr9vj7wBHf7AQ==";
        final byte[] decode = Base64.getDecoder().decode(key);

        final SecureRandom secureRandom2 = new SecureRandom();
        final byte[] nonce = new byte[12];
        secureRandom2.nextBytes(nonce);

        final String plainText = "나랏말싸미듕귁에달아문자와로 서로 사맛디 아니할쎄 이런 전차로 어린 백셩이 니르고져 홀베이셔도";

        final SeedGcm seedGcm = new SeedGcm();
        final EncryptGcmResult encryptGcmResult =
                seedGcm.encryptBase64(
                        decode,
                        plainText,
                        nonce,
                        "Additional Authenticated Data".getBytes(StandardCharsets.UTF_8));
        System.out.println(encryptGcmResult.toJson());

        final SeedGcm seedGcm1 = new SeedGcm();
        final String s =
                seedGcm1.decryptBase64(
                        decode,
                        encryptGcmResult.getCipherText(),
                        encryptGcmResult.getNonce(),
                        encryptGcmResult.getAad());
        System.out.println(s);

        Assertions.assertEquals(plainText, s);
    }

    @Test
    public void testReuseNonceAndAdd() {
    }
}
