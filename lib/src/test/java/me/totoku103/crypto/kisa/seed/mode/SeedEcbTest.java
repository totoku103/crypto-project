package me.totoku103.crypto.kisa.seed.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SeedEcbTest {

  @Test
  void testEncryptDecrypt() {
    // Given
    byte[] userKey = {
      (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
          (byte) 0x07,
      (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E,
          (byte) 0x0F
    };
    byte[] originalData = "This is a test for SEED ECB!!".getBytes();
    // When
    byte[] encryptedData = SeedEcb.seedEcbEncrypt(userKey, originalData, 0, originalData.length);
    byte[] decryptedData = SeedEcb.seedEcbDecrypt(userKey, encryptedData, 0, encryptedData.length);
    // Then
    assertArrayEquals(
        originalData, decryptedData, "Decrypted data should match the original data.");
  }

  @Test
  void simpleEncryptTest() {
    final String key = "1234567890ABCDEF"; // 16 bytes key

    final String message = "테스트 테스트 테스트 테스트 테스트 테스트 테스트 테스트 테스트 테스트";
    final String encrypt = SeedEcb.encrypt(key, message);
    final String decrypt = SeedEcb.decrypt(key, encrypt);

    Assertions.assertEquals(message, decrypt, "Encrypted data should match the original data.");
  }
}
