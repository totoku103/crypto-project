package me.totoku103.crypto.kisa.seed;

import me.totoku103.crypto.kisa.seed.mode.SeedGcm;
import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SeedGcmTest {

    @Test
    void testEncryptionDecryption() {
        SeedGcm seedGcm = new SeedGcm();

        // 1. Define test parameters
//        byte[] mKey = {
//                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
//                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F
//        };
        byte[] mKey = "HELLO_WORLD_12345678".getBytes(); // Example key, must be 16 bytes for SEED
        System.out.println(mKey.length);

//        byte[] nonce = {
//                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
//                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B
//        };
        byte[] nonce = "1234567890AB".getBytes(); // Example nonce, must be 12 bytes for SEED GCM
        System.out.println(nonce.length);

//        byte[] aad = {
//                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07
//        };

        byte[] aad = "Additional Authenticated Data".getBytes(); // Example AAD, can be any length
        System.out.println(aad.length);

        byte[] pt = "동해물과 백두산이 마르고 닳도록. 하느님이 보우하사 우리나라 만세. 무궁화 삼천리 화려강산. 대한사람 대한으로 길이 보전하세..".getBytes();
        int ptLen = pt.length;
        int macLen = 16; // 16 bytes for the authentication tag

        // 2. Encryption
        byte[] ct = new byte[ptLen + macLen];
        int ctLen = seedGcm.encryption(ct, pt, ptLen, macLen, nonce, nonce.length, aad, aad.length, mKey);

        assertEquals(ptLen + macLen, ctLen, "Encryption returned incorrect length");

        System.out.println("Original Plaintext: " + new String(pt));
        System.out.println("Ciphertext (hex): " + HexConverter.fromBytes(ct));
        System.out.println("Ciphertext length: " + ctLen);


        // 3. Decryption
        byte[] decryptedPt = new byte[ptLen];
        int decryptedPtLen = seedGcm.decryption(decryptedPt, ct, ctLen, macLen, nonce, nonce.length, aad, aad.length, mKey);

        assertEquals(ptLen, decryptedPtLen, "Decryption returned incorrect length");

        System.out.println("Decrypted Plaintext: " + new String(decryptedPt));


        // 4. Verification
        assertArrayEquals(pt, decryptedPt, "Decrypted plaintext does not match original plaintext");
        System.out.println("\nEncryption and decryption successful!");
    }
}