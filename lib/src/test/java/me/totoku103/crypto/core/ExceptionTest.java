package me.totoku103.crypto.core;

import me.totoku103.crypto.algorithms.cipher.AriaBlockCipher;
import me.totoku103.crypto.algorithms.cipher.SeedBlockCipher;
import me.totoku103.crypto.algorithms.hash.Sha256Jdk;
import me.totoku103.crypto.algorithms.hash.Sha256Kisa;
import me.totoku103.crypto.core.factory.CryptoFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 예외 처리 테스트 클래스 */
@DisplayName("예외 처리 테스트")
class ExceptionTest extends BaseCryptoTest {

  @Test
  @DisplayName("해시 알고리즘 null 입력 테스트")
  void testHashAlgorithmNullInput() {
    HashAlgorithm sha256Jdk = new Sha256Jdk();
    HashAlgorithm sha256Kisa = new Sha256Kisa();

    // null 입력 테스트
    assertThrows(
        RuntimeException.class,
        () -> {
          sha256Jdk.hash(null);
        },
        "JDK SHA-256 should throw exception for null input");

    assertThrows(
        RuntimeException.class,
        () -> {
          sha256Kisa.hash(null);
        },
        "KISA SHA-256 should throw exception for null input");
  }

  @Test
  @DisplayName("블록 암호화 null 입력 테스트")
  void testBlockCipherNullInput() throws InvalidKeyException {
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    AriaBlockCipher ariaCipher = new AriaBlockCipher();

    // null plaintext 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          seedCipher.encrypt(null, TEST_KEY_16);
        },
        "SEED should throw exception for null plaintext");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ariaCipher.encrypt(null, TEST_KEY_16);
        },
        "ARIA should throw exception for null plaintext");

    // null key 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          seedCipher.encrypt(TEST_STRING_1.getBytes(), null);
        },
        "SEED should throw exception for null key");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ariaCipher.encrypt(TEST_STRING_1.getBytes(), null);
        },
        "ARIA should throw exception for null key");

    // null ciphertext 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          seedCipher.decrypt(null, TEST_KEY_16);
        },
        "SEED should throw exception for null ciphertext");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ariaCipher.decrypt(null, TEST_KEY_16);
        },
        "ARIA should throw exception for null ciphertext");
  }

  @Test
  @DisplayName("잘못된 키 크기 테스트")
  void testInvalidKeySize() throws InvalidKeyException {
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    AriaBlockCipher ariaCipher = new AriaBlockCipher();

    byte[] invalidKey = "123".getBytes(); // 3 bytes
    byte[] validData = TEST_STRING_1.getBytes();

    // 잘못된 키 크기로 암호화 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          seedCipher.encrypt(validData, invalidKey);
        },
        "SEED should throw exception for invalid key size");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ariaCipher.encrypt(validData, invalidKey);
        },
        "ARIA should throw exception for invalid key size");

    // 잘못된 키 크기로 복호화 테스트
    byte[] validCiphertext = new byte[16];
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          seedCipher.decrypt(validCiphertext, invalidKey);
        },
        "SEED should throw exception for invalid key size in decrypt");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ariaCipher.decrypt(validCiphertext, invalidKey);
        },
        "ARIA should throw exception for invalid key size in decrypt");
  }

  @Test
  @DisplayName("잘못된 암호문 크기 테스트")
  void testInvalidCiphertextSize() throws InvalidKeyException {
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    AriaBlockCipher ariaCipher = new AriaBlockCipher();

    byte[] invalidCiphertext = "123".getBytes(); // 3 bytes

    // 잘못된 암호문 크기로 복호화 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          seedCipher.decrypt(invalidCiphertext, TEST_KEY_16);
        },
        "SEED should throw exception for invalid ciphertext size");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          ariaCipher.decrypt(invalidCiphertext, TEST_KEY_16);
        },
        "ARIA should throw exception for invalid ciphertext size");
  }

  @Test
  @DisplayName("팩토리 null 입력 테스트")
  void testFactoryNullInput() {
    // null 해시 타입 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          CryptoFactory.createHashAlgorithm(null);
        },
        "Factory should throw exception for null hash type");

    // null 암호화 타입 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          CryptoFactory.createBlockCipher(null);
        },
        "Factory should throw exception for null cipher type");
  }

    @Test
  @DisplayName("빈 바이트 배열 테스트")
  void testEmptyByteArray() throws InvalidKeyException {
    HashAlgorithm sha256Jdk = new Sha256Jdk();
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    AriaBlockCipher ariaCipher = new AriaBlockCipher();

    byte[] emptyBytes = new byte[0];

    // 빈 바이트 배열로 해시 테스트
    byte[] hash = sha256Jdk.hash(emptyBytes);
    assertValidBytes(hash, "Empty input hash");
    assertEquals(32, hash.length, "Empty input hash should be 32 bytes");

    // 빈 바이트 배열로 암호화 테스트 (빈 배열은 패딩 후 16바이트가 됨)
    byte[] encrypted = seedCipher.encrypt(emptyBytes, TEST_KEY_16);
    assertValidBytes(encrypted, "Empty input encryption");
    assertEquals(16, encrypted.length, "Empty input encryption should be 16 bytes");

    byte[] decrypted = seedCipher.decrypt(encrypted, TEST_KEY_16);
    assertValidBytes(decrypted, "Empty input decryption");
  }
}
