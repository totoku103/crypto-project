package me.totoku103.crypto.core.factory;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.HashAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CryptoFactory 라운드트립 및 회귀 테스트.
 *
 * <p>기존 CryptoFactoryTest가 커버하지 않은 영역:
 * <ul>
 *   <li>ARIA 암호화/복호화 라운드트립</li>
 *   <li>AES-256 암호화/복호화 라운드트립</li>
 *   <li>SHA-256(JDK) 빈 입력 회귀 안전망</li>
 * </ul>
 */
class CryptoFactoryRoundtripTest {

  // ARIA: 16-byte 키
  private static final byte[] ARIA_KEY =
      new byte[]{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
      };

  // AES-256: 32-byte 키
  private static final byte[] AES256_KEY =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

  private BlockCipher ariaCipher;
  private BlockCipher aes256Cipher;

  @BeforeEach
  void setUp() throws InvalidKeyException {
    // AriaBlockCipher 생성자가 InvalidKeyException을 선언하므로 @BeforeEach에서 처리
    ariaCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.ARIA);
    aes256Cipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.AES256);
  }

  // ─── ARIA 라운드트립 ────────────────────────────────────────────────────────

  @Test
  @DisplayName("ARIA: 16-byte 키 + 1-byte 평문 → 암호화 후 복호화하면 원문과 일치해야 한다")
  void aria_roundtrip_1bytePlaintext() {
    // Arrange
    byte[] plaintext = new byte[]{(byte) 0xAB}; // 1-byte 평문

    // Act
    byte[] ciphertext = ariaCipher.encrypt(plaintext, ARIA_KEY);
    byte[] decrypted = ariaCipher.decrypt(ciphertext, ARIA_KEY);

    // Assert: 암호문은 블록 크기(16바이트) 단위여야 하고, 복호화 결과는 원문과 일치해야 함
    assertEquals(0, ciphertext.length % ariaCipher.getBlockSize(),
        "암호문 길이는 블록 크기의 배수여야 한다");
    assertArrayEquals(plaintext, decrypted,
        "복호화된 결과가 원래 1-byte 평문과 일치해야 한다");
  }

  @Test
  @DisplayName("ARIA: 동일한 평문을 동일한 키로 두 번 암호화하면 같은 암호문을 반환해야 한다 (결정론적 검증)")
  void aria_encrypt_isDeterministic() {
    // Arrange
    byte[] plaintext = new byte[]{0x42};

    // Act
    byte[] ciphertext1 = ariaCipher.encrypt(plaintext, ARIA_KEY);
    byte[] ciphertext2 = ariaCipher.encrypt(plaintext, ARIA_KEY);

    // Assert
    assertArrayEquals(ciphertext1, ciphertext2,
        "ARIA ECB 모드는 결정론적이어야 한다 (같은 키+평문 → 같은 암호문)");
  }

  // ─── AES-256 라운드트립 ─────────────────────────────────────────────────────

  @Test
  @DisplayName("AES-256: 32-byte 키 + 'Hello' 평문 → 암호화 후 복호화하면 원문과 일치해야 한다")
  void aes256_roundtrip_helloPlaintext() {
    // Arrange
    byte[] plaintext = "Hello".getBytes(StandardCharsets.UTF_8);

    // Act
    byte[] ciphertext = aes256Cipher.encrypt(plaintext, AES256_KEY);
    byte[] decrypted = aes256Cipher.decrypt(ciphertext, AES256_KEY);

    // Assert
    assertEquals(0, ciphertext.length % aes256Cipher.getBlockSize(),
        "AES-256 암호문 길이는 블록 크기(16바이트)의 배수여야 한다");
    assertArrayEquals(plaintext, decrypted,
        "복호화된 결과가 원래 'Hello' 평문과 일치해야 한다");
  }

  @Test
  @DisplayName("AES-256: 서로 다른 키로 암호화한 암호문은 달라야 한다 (키 민감도 회귀)")
  void aes256_differentKeys_produceDifferentCiphertext() {
    // Arrange
    byte[] plaintext = "Hello".getBytes(StandardCharsets.UTF_8);
    byte[] anotherKey = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8);

    // Act
    byte[] ciphertext1 = aes256Cipher.encrypt(plaintext, AES256_KEY);
    byte[] ciphertext2 = aes256Cipher.encrypt(plaintext, anotherKey);

    // Assert: 다른 키 → 다른 암호문
    assertFalse(java.util.Arrays.equals(ciphertext1, ciphertext2),
        "서로 다른 키는 서로 다른 암호문을 생성해야 한다");

    // 각 키로 정확히 복호화되어야 함
    assertArrayEquals(plaintext, aes256Cipher.decrypt(ciphertext1, AES256_KEY));
    assertArrayEquals(plaintext, aes256Cipher.decrypt(ciphertext2, anotherKey));
  }

  // ─── SHA-256 (JDK) 빈 입력 회귀 안전망 ────────────────────────────────────

  @Test
  @DisplayName("SHA256_JDK: 빈 입력(new byte[0])에 대해 예외 없이 32-byte 해시를 반환해야 한다")
  void sha256Jdk_emptyInput_returns32BytesWithoutException() {
    // Arrange
    HashAlgorithm sha256 = CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_JDK);

    // Act — 예외가 발생하면 테스트 실패
    byte[] result = assertDoesNotThrow(
        () -> sha256.hash(new byte[0]),
        "빈 바이트 배열 입력 시 예외가 발생해서는 안 된다");

    // Assert: SHA-256 출력은 항상 32바이트
    assertNotNull(result, "해시 결과는 null이 아니어야 한다");
    assertEquals(32, result.length, "SHA-256 해시 결과는 정확히 32바이트여야 한다");

    // RFC 6234 / FIPS 180-4 KAT 벡터: SHA-256("") =
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    byte[] expected = hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assertArrayEquals(expected, result,
        "빈 입력에 대한 SHA-256 해시는 FIPS 180-4 KAT 벡터와 일치해야 한다");
  }

  // ─── 헬퍼 ──────────────────────────────────────────────────────────────────

  /** 16진수 문자열을 byte 배열로 변환합니다. */
  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] result = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return result;
  }
}
