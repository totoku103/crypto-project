package me.totoku103.crypto.kisa.seed;

import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SeedGcmTest {

    @Test
    void testEncryptionDecryption() {
        SeedGcm seedGcm = new SeedGcm();

        // 1. Define test parameters
        byte[] mKey = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F
        };
        byte[] nonce = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B
        };
        byte[] aad = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07
        };
        byte[] pt = "This is the plaintext to be encrypted.".getBytes();
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