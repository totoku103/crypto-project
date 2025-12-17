package me.totoku103.crypto.algorithms.cipher;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Aes256BlockCipher 알고리즘을 테스트합니다. */
class Aes256BlockCipherTest {

  private static final byte[] DEFAULT_KEY =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

  @Test
  void testGetAlgorithmName() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    assertEquals("AES-256", cipher.getAlgorithmName());
  }

  @Test
  void testGetVersion() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    assertEquals("1.0.0", cipher.getVersion());
  }

  @Test
  void testGetSizes() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    assertEquals(16, cipher.getBlockSize());
    assertEquals(32, cipher.getKeySize());
  }

  @Test
  @DisplayName("AES-256: 암호화/복호화 round-trip")
  void testEncryptAndDecrypt() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    String plaintext = "Hello, AES-256 with padding!";
    byte[] encrypted = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);

    assertNotNull(encrypted);
    assertEquals(0, encrypted.length % cipher.getBlockSize());

    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY);
    assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decrypted);
  }

  @Test
  @DisplayName("AES-256: 한글 암호화/복호화 round-trip")
  void testEncryptAndDecryptKoreanText() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    String plaintext = "안녕하세요 AES-256 테스트입니다!";
    byte[] encrypted = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);

    assertNotNull(encrypted);
    assertEquals(0, encrypted.length % cipher.getBlockSize());

    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY);
    assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decrypted);
  }

  @Test
  void testEncryptDecryptMultipleBlocks() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    String longPlaintext = new String(new char[64]).replace('\0', 'A'); // 4 blocks after padding

    byte[] ciphertext = cipher.encrypt(longPlaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);
    assertEquals(80, ciphertext.length); // 64 bytes + 16 bytes padding

    byte[] decrypted = cipher.decrypt(ciphertext, DEFAULT_KEY);
    assertEquals(longPlaintext, new String(decrypted, StandardCharsets.UTF_8));
  }

  @Test
  void testDifferentKeysProduceDifferentCiphertext() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext = "Key sensitivity check".getBytes(StandardCharsets.UTF_8);

    byte[] key1 = DEFAULT_KEY;
    byte[] key2 = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8);

    byte[] cipher1 = cipher.encrypt(plaintext, key1);
    byte[] cipher2 = cipher.encrypt(plaintext, key2);

    assertFalse(ByteUtils.toHexString(cipher1).equals(ByteUtils.toHexString(cipher2)));

    assertArrayEquals(plaintext, cipher.decrypt(cipher1, key1));
    assertArrayEquals(plaintext, cipher.decrypt(cipher2, key2));
  }

  @Test
  void testEncryptWithNullPlaintext() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(null, DEFAULT_KEY));
  }

  @Test
  void testEncryptWithInvalidKey() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] invalidKey = "short-key".getBytes(StandardCharsets.UTF_8);
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.encrypt("data".getBytes(StandardCharsets.UTF_8), invalidKey));
  }

  @Test
  void testDecryptWithInvalidCiphertextLength() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[5], DEFAULT_KEY));
  }

  @Test
  void testDecryptWithInvalidKey() {
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] ciphertext = cipher.encrypt("valid".getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);
    byte[] invalidKey = new byte[16];
    assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(ciphertext, invalidKey));
  }
}
