package me.totoku103.crypto.algorithms.cipher;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import org.junit.jupiter.api.Test;

/** SeedBlockCipher 알고리즘을 테스트합니다. */
class SeedBlockCipherTest {

  @Test
  void testGetAlgorithmName() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    assertEquals("SEED", cipher.getAlgorithmName());
  }

  @Test
  void testGetVersion() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    assertEquals("1.0.0", cipher.getVersion());
  }

  @Test
  void testGetBlockSize() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    assertEquals(16, cipher.getBlockSize());
  }

  @Test
  void testGetKeySize() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    assertEquals(16, cipher.getKeySize());
  }

  @Test
  void testEncryptAndDecrypt() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();

    String plaintext = "Hello, World!";
    byte[] plaintextBytes = plaintext.getBytes();
    byte[] key = "1234567890123456".getBytes(); // 16 bytes

    // 암호화
    byte[] encrypted = cipher.encrypt(plaintextBytes, key);
    assertNotNull(encrypted);
    assertEquals(16, encrypted.length); // 블록 크기만큼 출력

    // 복호화
    byte[] decrypted = cipher.decrypt(encrypted, key);
    assertNotNull(decrypted);

    // 원본과 복호화된 결과가 같아야 함
    assertArrayEquals(plaintextBytes, decrypted);
  }

  @Test
  void testEncryptWithNullPlaintext() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] key = "1234567890123456".getBytes();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.encrypt(null, key);
        });
  }

  @Test
  void testEncryptWithNullKey() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] plaintext = "Hello".getBytes();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.encrypt(plaintext, null);
        });
  }

  @Test
  void testEncryptWithInvalidKeySize() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] plaintext = "Hello".getBytes();
    byte[] invalidKey = "123".getBytes(); // 3 bytes

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.encrypt(plaintext, invalidKey);
        });
  }

  @Test
  void testDecryptWithNullCiphertext() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] key = "1234567890123456".getBytes();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.decrypt(null, key);
        });
  }

  @Test
  void testDecryptWithNullKey() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] ciphertext = new byte[16];

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.decrypt(ciphertext, null);
        });
  }

  @Test
  void testDecryptWithInvalidKeySize() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] ciphertext = new byte[16];
    byte[] invalidKey = "123".getBytes(); // 3 bytes

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.decrypt(ciphertext, invalidKey);
        });
  }

  @Test
  void testMultipleEncryptDecrypt() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] key = "1234567890123456".getBytes();

    String[] testStrings = {"Hello", "Hello, World!", "안녕하세요", "Test with spaces"};

    for (String testString : testStrings) {
      byte[] plaintext = testString.getBytes();
      byte[] encrypted = cipher.encrypt(plaintext, key);
      byte[] decrypted = cipher.decrypt(encrypted, key);

      // 원본과 복호화된 결과가 같아야 함
      assertArrayEquals(plaintext, decrypted);
    }
  }

  @Test
  void testDifferentKeys() throws InvalidKeyException {
    SeedBlockCipher cipher = new SeedBlockCipher();
    byte[] plaintext = "Hello, World!".getBytes();

    byte[] key1 = "1234567890123456".getBytes();
    byte[] key2 = "6543210987654321".getBytes();

    byte[] encrypted1 = cipher.encrypt(plaintext, key1);
    byte[] encrypted2 = cipher.encrypt(plaintext, key2);

    // 다른 키로 암호화한 결과는 달라야 함
    assertFalse(java.util.Arrays.equals(encrypted1, encrypted2));

    // 각각의 키로 복호화
    byte[] decrypted1 = cipher.decrypt(encrypted1, key1);
    byte[] decrypted2 = cipher.decrypt(encrypted2, key2);

    // 원본과 같아야 함
    assertArrayEquals(plaintext, decrypted1);
    assertArrayEquals(plaintext, decrypted2);
  }
}
