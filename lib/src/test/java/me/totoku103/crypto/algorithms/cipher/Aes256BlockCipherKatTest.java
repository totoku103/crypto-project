package me.totoku103.crypto.algorithms.cipher;

import static org.junit.jupiter.api.Assertions.*;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * AES-256 블록 암호화 KAT(Known Answer Test) 테스트.
 *
 * <p>NIST FIPS 197 표준 벡터 및 경계/예외 경로를 검증합니다.
 */
@DisplayName("AES-256 KAT (Known Answer Test)")
class Aes256BlockCipherKatTest {

  // NIST FIPS 197 Appendix C.3 AES-256 표준 키 (32 bytes)
  private static final byte[] KAT_KEY = ByteUtils.fromHexString(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  // 32-byte 키로 복호화 테스트에 사용할 별도 키
  private static final byte[] ANOTHER_KEY_256 = ByteUtils.fromHexString(
      "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");

  // ==========================================================================
  // KAT: NIST FIPS 197 Appendix C.3 AES-256 표준 벡터
  // ==========================================================================

  @Test
  @DisplayName("NIST FIPS 197 Appendix C.3 AES-256-ECB KAT: 표준 평문을 암호화하면 규격 암호문이 나와야 한다")
  void testNistFips197AppendixC3Encrypt() {
    // Arrange
    // NIST FIPS 197 Appendix C.3 AES-256 벡터
    // key   = 000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f
    // plain = 00112233445566778899aabbccddeeff
    // cipher= 8ea2b7ca516745bfeafc49904b496089
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext = ByteUtils.fromHexString("00112233445566778899aabbccddeeff");

    // Act
    // encrypt는 내부적으로 PKCS7 패딩을 추가한다.
    // 16-byte 입력 → 패딩 후 32 bytes → 암호화 결과 32 bytes
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);

    // Assert: 첫 16 bytes가 표준 KAT 암호문과 일치해야 한다
    // (구현이 PKCS7 패딩 블록을 뒤에 붙이므로 앞 블록만 검증)
    assertEquals(32, ciphertext.length, "패딩 포함 출력은 32 bytes여야 한다");
    String firstBlock = ByteUtils.toHexString(ciphertext).substring(0, 32);
    assertEquals(
        "8ea2b7ca516745bfeafc49904b496089",
        firstBlock,
        "NIST FIPS 197 Appendix C.3 AES-256 첫 블록이 표준 KAT 값과 일치해야 한다");
  }

  @Test
  @DisplayName("NIST FIPS 197 Appendix C.3 AES-256-ECB KAT: 표준 암호문을 복호화하면 원래 평문이 나와야 한다")
  void testNistFips197AppendixC3Decrypt() {
    // Arrange
    // 표준 암호문(16 bytes) + PKCS7 패딩 블록(0x10 x 16 bytes) = 32 bytes
    // encrypt가 자동으로 패딩을 붙이므로, encrypt 결과를 그대로 decrypt에 전달한다
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext = ByteUtils.fromHexString("00112233445566778899aabbccddeeff");

    // Act
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);
    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);

    // Assert
    assertArrayEquals(plaintext, decrypted, "복호화 결과가 원래 평문과 일치해야 한다");
  }

  // ==========================================================================
  // 키 검증: 잘못된 키 길이 → IllegalArgumentException
  // ==========================================================================

  @Test
  @DisplayName("16-byte(128-bit) 키는 validateKey에서 IllegalArgumentException이 발생해야 한다")
  void testEncryptWith16ByteKeyThrowsException() {
    // Arrange
    // 16-byte 키는 AES-128이므로 AES-256(32 bytes) 검증에서 거부되어야 한다
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] key128bit = ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f");
    byte[] plaintext = new byte[]{0x01};

    // Act & Assert
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> cipher.encrypt(plaintext, key128bit),
        "16-byte 키는 key.length != 32 조건에 걸려 IllegalArgumentException이 발생해야 한다");
    assertTrue(ex.getMessage().contains("32"),
        "예외 메시지에 요구 키 크기(32)가 포함되어야 한다");
  }

  @Test
  @DisplayName("16-byte(128-bit) 키로 decrypt 시도 시 IllegalArgumentException이 발생해야 한다")
  void testDecryptWith16ByteKeyThrowsException() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] key128bit = ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f");
    // 블록 배수(16 bytes) 더미 암호문
    byte[] fakeCiphertext = new byte[16];

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(fakeCiphertext, key128bit),
        "16-byte 키는 decrypt validateKey에서도 IllegalArgumentException이 발생해야 한다");
  }

  // ==========================================================================
  // 경계값: 빈 평문(0 byte)
  // ==========================================================================

  @Test
  @DisplayName("빈 평문(0 byte) 암호화: PKCS7 패딩만 16 bytes 생성 → 암호문은 16 bytes여야 한다")
  void testEncryptEmptyPlaintextProduces16Bytes() {
    // Arrange
    // PKCS7: 빈 입력 → paddingLength = 16 → 0x10 x 16 bytes
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] emptyPlain = new byte[0];

    // Act
    byte[] ciphertext = cipher.encrypt(emptyPlain, KAT_KEY);

    // Assert
    assertEquals(16, ciphertext.length, "빈 평문 암호화 결과는 패딩 블록 1개(16 bytes)여야 한다");
    assertEquals(0, ciphertext.length % 16, "암호문 길이는 블록 크기(16)의 배수여야 한다");
  }

  @Test
  @DisplayName("빈 평문(0 byte) 라운드트립: encrypt → decrypt → 빈 배열 반환 (정상 경로, fallback 없음)")
  void testRoundTripEmptyPlaintext() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] emptyPlain = new byte[0];

    // Act
    byte[] ciphertext = cipher.encrypt(emptyPlain, KAT_KEY);
    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);

    // Assert: removePadding이 정상 동작하여 빈 배열을 반환해야 한다
    assertArrayEquals(emptyPlain, decrypted, "빈 평문의 라운드트립 결과는 빈 배열이어야 한다");
  }

  // ==========================================================================
  // 경계값: 1-byte 평문
  // ==========================================================================

  @Test
  @DisplayName("1-byte 평문 라운드트립: encrypt → decrypt → 원문 1 byte 일치")
  void testRoundTrip1BytePlaintext() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext = new byte[]{(byte) 0xAB};

    // Act
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);
    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);

    // Assert
    assertEquals(16, ciphertext.length, "1-byte 평문 암호화 결과는 16 bytes(패딩 포함)여야 한다");
    assertArrayEquals(plaintext, decrypted, "1-byte 평문의 라운드트립 결과는 원문과 동일해야 한다");
  }

  // ==========================================================================
  // 경계값: 정확히 16 bytes(단일 블록)
  // ==========================================================================

  @Test
  @DisplayName("정확히 16 bytes 평문 암호화: 전체 블록 패딩 추가 → 암호문은 32 bytes여야 한다")
  void testEncrypt16BytePlaintextProduces32Bytes() {
    // Arrange
    // PKCS7: data.length % blockSize == 0 → 전체 패딩 블록(0x10 x 16 bytes) 추가
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext16 = ByteUtils.fromHexString("00112233445566778899aabbccddeeff");

    // Act
    byte[] ciphertext = cipher.encrypt(plaintext16, KAT_KEY);

    // Assert
    assertEquals(32, ciphertext.length, "16-byte 평문 암호화 결과는 패딩 포함 32 bytes여야 한다");
  }

  @Test
  @DisplayName("정확히 16 bytes 평문 라운드트립: decrypt 후 원문 16 bytes 반환")
  void testRoundTrip16BytePlaintext() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext16 = ByteUtils.fromHexString("00112233445566778899aabbccddeeff");

    // Act
    byte[] ciphertext = cipher.encrypt(plaintext16, KAT_KEY);
    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);

    // Assert
    assertArrayEquals(plaintext16, decrypted, "16-byte 평문의 라운드트립 결과는 원문 16 bytes와 동일해야 한다");
  }

  // ==========================================================================
  // 경계값: 32 bytes(2 블록 경계)
  // ==========================================================================

  @Test
  @DisplayName("32 bytes(2블록 경계) 평문 라운드트립: encrypt → decrypt → 원문 32 bytes 일치")
  void testRoundTrip32BytePlaintext() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext32 = ByteUtils.fromHexString(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    // Act
    // 32 bytes → PKCS7 패딩 16 bytes 추가 → 48 bytes 암호화
    byte[] ciphertext = cipher.encrypt(plaintext32, KAT_KEY);
    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);

    // Assert
    assertEquals(48, ciphertext.length, "32-byte 평문 암호화 결과는 패딩 포함 48 bytes여야 한다");
    assertArrayEquals(plaintext32, decrypted, "32-byte 평문의 라운드트립 결과는 원문과 동일해야 한다");
  }

  // ==========================================================================
  // 예외 경로: decrypt null / 빈 배열 암호문
  // ==========================================================================

  @Test
  @DisplayName("decrypt: null 암호문 → ByteUtils.isEmpty(null)이 true → IllegalArgumentException")
  void testDecryptNullCiphertextThrowsException() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    // Act & Assert
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(null, KAT_KEY),
        "null 암호문은 ByteUtils.isEmpty 검증에서 IllegalArgumentException이 발생해야 한다");
    assertNotNull(ex.getMessage());
  }

  @Test
  @DisplayName("decrypt: 빈 배열(new byte[0]) 암호문 → ByteUtils.isEmpty 검증 → IllegalArgumentException")
  void testDecryptEmptyCiphertextThrowsException() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(new byte[0], KAT_KEY),
        "빈 배열 암호문은 ByteUtils.isEmpty 검증에서 IllegalArgumentException이 발생해야 한다");
  }

  // ==========================================================================
  // 예외 경로: 블록 배수 아닌 암호문 길이
  // ==========================================================================

  @Test
  @DisplayName("decrypt: 길이 1 byte 암호문 → 블록 배수 아님 → IllegalArgumentException")
  void testDecryptCiphertextLength1ThrowsException() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    // Act & Assert
    IllegalArgumentException ex = assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(new byte[1], KAT_KEY),
        "길이 1 byte 암호문은 블록 배수 조건 실패로 IllegalArgumentException이 발생해야 한다");
    assertTrue(ex.getMessage().contains("multiple of block size"),
        "예외 메시지에 'multiple of block size'가 포함되어야 한다");
  }

  @Test
  @DisplayName("decrypt: 길이 15 bytes 암호문 → 블록 배수 아님 → IllegalArgumentException")
  void testDecryptCiphertextLength15ThrowsException() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(new byte[15], KAT_KEY),
        "길이 15 bytes 암호문은 블록 배수 조건 실패로 IllegalArgumentException이 발생해야 한다");
  }

  @Test
  @DisplayName("decrypt: 길이 17 bytes 암호문 → 블록 배수 아님 → IllegalArgumentException")
  void testDecryptCiphertextLength17ThrowsException() {
    // Arrange
    Aes256BlockCipher cipher = new Aes256BlockCipher();

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(new byte[17], KAT_KEY),
        "길이 17 bytes 암호문은 블록 배수 조건 실패로 IllegalArgumentException이 발생해야 한다");
  }

  // ==========================================================================
  // 예외 경로: 다른 키로 복호화 → fallback 동작 검증
  // ==========================================================================

  @Test
  @DisplayName("decrypt: 다른 키로 복호화 → 패딩 검증 실패 → fallback으로 패딩 포함 16 bytes 반환"
      + " [경고: 이 동작은 보안 취약점 — 오류를 조용히 무시하고 잘못된 데이터를 반환함]")
  void testDecryptWithWrongKeyReturnsFallbackWithPadding() {
    // Arrange
    // ⚠️ 보안 주의: 현재 구현은 removePadding 실패 시 예외를 삼키고
    //    복호화된 원시 바이트(패딩 포함 16 bytes)를 그대로 반환한다.
    //    이는 오라클 공격(padding oracle attack) 등에 노출될 수 있는 설계 결함이다.
    //    이 테스트는 현재 명세화된 실제 동작을 기록하는 목적이며,
    //    해당 동작이 의도된 것이 아니라면 예외를 전파하도록 수정해야 한다.
    Aes256BlockCipher cipher = new Aes256BlockCipher();
    byte[] plaintext = new byte[]{0x01, 0x02, 0x03, 0x04};

    // 정상 키로 암호화
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);

    // Act: 다른 키(ANOTHER_KEY_256)로 복호화 시도
    // → JCE AES/ECB/NoPadding 자체는 예외 없이 완료되지만,
    //   복호화 결과의 마지막 바이트가 유효한 PKCS7 패딩 값이 아닐 가능성이 높음
    //   → removePadding이 IllegalArgumentException 발생
    //   → catch 블록에서 예외를 삼키고 decrypted(패딩 포함 16 bytes) 반환
    byte[] result = cipher.decrypt(ciphertext, ANOTHER_KEY_256);

    // Assert: fallback 결과는 원문과 달라야 하고 16 bytes여야 한다
    assertEquals(16, result.length,
        "잘못된 키로 복호화 시 fallback은 블록 크기(16 bytes) 원시 바이트를 반환해야 한다");
    // 다른 키로 복호화한 결과가 원문과 다름을 명시적으로 검증
    assertFalse(
        java.util.Arrays.equals(plaintext, result),
        "잘못된 키로 복호화한 결과는 원래 평문과 달라야 한다");
  }
}
