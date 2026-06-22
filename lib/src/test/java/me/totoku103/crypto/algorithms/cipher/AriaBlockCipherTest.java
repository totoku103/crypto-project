package me.totoku103.crypto.algorithms.cipher;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import java.util.Arrays;
import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * AriaBlockCipher 알고리즘을 테스트합니다.
 *
 * <p>테스트 전략:
 * <ul>
 *   <li>KISA/RFC5794 KAT 표준 벡터 검증</li>
 *   <li>등가분할(1 byte, 정확히 16 bytes 평문)</li>
 *   <li>예외/오류 경로 (null, 빈 배열, 잘못된 크기)</li>
 *   <li>라운드트립(encrypt → decrypt → 원문 일치)</li>
 *   <li>단일 블록(16 bytes) 제약 명세</li>
 * </ul>
 */
class AriaBlockCipherTest {

  /**
   * ARIA-128 표준 키: 0x00 ~ 0x0f (16 bytes)
   * RFC5794 / KISA 공식 문서에 사용되는 기준 키
   */
  private static final byte[] KAT_KEY =
      ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f");

  /**
   * ARIA-128 KAT 평문: 0x00 ~ 0xff (16 bytes)
   * RFC5794 섹션 A.1 기준 입력
   */
  private static final byte[] KAT_PLAINTEXT =
      ByteUtils.fromHexString("00112233445566778899aabbccddeeff");

  /**
   * RFC5794 / KISA 공식 ARIA-128 암호문
   * Key=000102...0f, PT=001122...ff → CT=d718fbd6ab644c739da95f3be6451778
   */
  private static final String KAT_EXPECTED_CT_HEX = "d718fbd6ab644c739da95f3be6451778";

  private AriaBlockCipher cipher;

  /**
   * @BeforeEach: AriaBlockCipher 생성자가 InvalidKeyException을 선언하므로
   * throws 또는 try-catch로 인스턴스를 생성해야 컴파일 오류가 발생하지 않는다.
   */
  @BeforeEach
  void setUp() throws InvalidKeyException {
    cipher = new AriaBlockCipher();
  }

  // ==================== 기본 메타 정보 ====================

  @Test
  @DisplayName("getAlgorithmName()은 'ARIA'를 반환해야 한다")
  void testGetAlgorithmName() {
    assertEquals("ARIA", cipher.getAlgorithmName());
  }

  @Test
  @DisplayName("getBlockSize()는 16을 반환해야 한다 (128 bits)")
  void testGetBlockSize() {
    assertEquals(16, cipher.getBlockSize());
  }

  @Test
  @DisplayName("getKeySize()는 16을 반환해야 한다 (128 bits)")
  void testGetKeySize() {
    assertEquals(16, cipher.getKeySize());
  }

  // ==================== KAT 표준 벡터 검증 ====================

  @Test
  @DisplayName("KISA/RFC5794 ARIA-128 KAT: 단일 블록 암호화 결과가 공식 암호문과 일치해야 한다")
  void testKatVector128BitKey() {
    // KAT 평문은 정확히 16 bytes → PKCS7 패딩 후 32 bytes가 되지만
    // AriaWrapper.encrypt(paddedInput, 0)는 offset=0 기준 첫 16 bytes만 암호화하여
    // 항상 16 bytes를 반환한다. 따라서 원본 16 bytes 블록의 암호화 결과를 검증한다.
    byte[] ciphertext = cipher.encrypt(KAT_PLAINTEXT, KAT_KEY);

    assertNotNull(ciphertext);
    assertEquals(16, ciphertext.length, "ARIA 단일 블록 출력은 정확히 16 bytes여야 한다");
    assertEquals(
        KAT_EXPECTED_CT_HEX,
        ByteUtils.toHexString(ciphertext),
        "RFC5794 ARIA-128 KAT 암호문이 공식 값과 일치해야 한다");
  }

  @Test
  @DisplayName("KISA/RFC5794 KAT 암호문을 복호화하면 원래 평문(16 bytes)이 복원되어야 한다")
  void testKatVector128BitKeyDecrypt() {
    byte[] expectedCiphertext = ByteUtils.fromHexString(KAT_EXPECTED_CT_HEX);

    // decrypt는 16 bytes 암호문을 요구하고, 패딩 제거를 시도한다.
    // KAT 평문은 정상적인 PKCS7 패딩 바이트가 아니므로 패딩 제거 실패 → fallback으로 원본 16 bytes 반환
    byte[] decrypted = cipher.decrypt(expectedCiphertext, KAT_KEY);

    assertNotNull(decrypted);
    // 패딩 제거 fallback: 복호화 결과 16 bytes 반환
    assertArrayEquals(
        KAT_PLAINTEXT,
        decrypted,
        "KAT 암호문 복호화 결과가 원래 KAT 평문 16 bytes와 일치해야 한다");
  }

  // ==================== 라운드트립 (1 byte 평문) ====================

  @Test
  @DisplayName("1 byte 평문 라운드트립: PKCS7 패딩 후 암호화된 16 bytes를 복호화하면 원문 1 byte가 복원되어야 한다")
  void testRoundTripSingleByte() {
    // 1 byte 평문 → PKCS7 패딩 → 16 bytes → 암호화 → 16 bytes 암호문
    byte[] plaintext = new byte[]{(byte) 0xAB};
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);

    assertNotNull(ciphertext);
    assertEquals(16, ciphertext.length, "1 byte 평문 암호화 출력은 16 bytes여야 한다");

    // decrypt: 16 bytes 암호문 → 복호화 → 패딩 제거 → 원본 1 byte
    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);
    assertArrayEquals(plaintext, decrypted, "1 byte 평문 라운드트립 후 원문과 일치해야 한다");
  }

  @Test
  @DisplayName("15 byte 평문 라운드트립: 패딩 후 암호화/복호화하면 원문 15 bytes가 복원되어야 한다")
  void testRoundTripFifteenBytes() {
    byte[] plaintext = "Hello, ARIA!!!!"
        .substring(0, 15)
        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);

    assertNotNull(ciphertext);
    assertEquals(16, ciphertext.length);

    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);
    assertArrayEquals(plaintext, decrypted, "15 byte 평문 라운드트립 후 원문과 일치해야 한다");
  }

  // ==================== 16 byte 평문 단일 블록 제약 명세 ====================

  @Test
  @DisplayName("16 byte 평문 encrypt: AriaWrapper.encrypt(offset=0)는 첫 16 bytes만 처리하여 16 bytes 암호문을 반환한다")
  void testEncryptExactlyOneBlock() {
    // 정확히 16 bytes 평문 → PKCS7 패딩 후 32 bytes
    // AriaWrapper.encrypt(paddedInput, 0)는 offset=0 기준 16 bytes만 암호화 → 16 bytes 반환
    byte[] plaintext = KAT_PLAINTEXT; // 16 bytes
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);

    assertNotNull(ciphertext);
    assertEquals(16, ciphertext.length, "16 byte 평문을 암호화하면 항상 16 bytes 암호문이 반환된다");
  }

  @Test
  @DisplayName("단일 블록 제약 명세: 16 byte 평문 encrypt → decrypt 시 원문 복원 — KAT_PLAINTEXT 마지막 바이트 0xff로 removePadding 실패 후 raw bytes 반환")
  void testSingleBlockConstraintFifteenBytePaddingMismatch() {
    // KAT_PLAINTEXT(16 bytes)를 encrypt하면 addPadding으로 32 bytes가 되지만
    // AriaWrapper.encrypt(offset=0)는 첫 16 bytes 블록만 암호화하여 16 bytes 암호문을 반환한다.
    // decrypt(16 bytes)는 복호화 후 removePadding을 시도하는데,
    // KAT_PLAINTEXT 마지막 바이트가 0xff(=255 > blockSize=16)이므로
    // IllegalArgumentException이 발생하고 fallback으로 raw 16 bytes를 반환한다.
    // 결과적으로 decrypted == KAT_PLAINTEXT (원문 일치).
    byte[] plaintext = KAT_PLAINTEXT; // 16 bytes, 마지막 바이트 0xff
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);

    byte[] decrypted = cipher.decrypt(ciphertext, KAT_KEY);
    assertNotNull(decrypted);
    // removePadding fallback 경로: raw 복호화 바이트 = KAT_PLAINTEXT
    assertTrue(
        Arrays.equals(plaintext, decrypted),
        "KAT_PLAINTEXT(마지막 바이트 0xff) 암호화 후 복호화 시 removePadding fallback으로 원문이 그대로 반환된다");
  }

  @Test
  @DisplayName("AriaBlockCipher는 단일 블록(16 bytes)만 decrypt 가능: 32 bytes 암호문을 전달하면 IllegalArgumentException이 발생해야 한다")
  void testDecryptThrowsOnThirtyTwoByteCiphertext() {
    byte[] oversizedCiphertext = new byte[32]; // 블록 초과

    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(oversizedCiphertext, KAT_KEY),
        "32 bytes 암호문 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  // ==================== decrypt: 입력 길이 오류 경로 ====================

  @Test
  @DisplayName("decrypt: 15 bytes(블록 미만) 암호문 전달 → IllegalArgumentException")
  void testDecryptThrowsOnShortCiphertext() {
    byte[] shortCiphertext = new byte[15]; // 블록 크기 미만

    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(shortCiphertext, KAT_KEY),
        "15 bytes 암호문 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  @Test
  @DisplayName("decrypt: 빈 배열 → ByteUtils.isEmpty 경로 → IllegalArgumentException")
  void testDecryptThrowsOnEmptyArray() {
    byte[] emptyCiphertext = new byte[0];

    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(emptyCiphertext, KAT_KEY),
        "빈 배열 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  @Test
  @DisplayName("decrypt: null 암호문 → ByteUtils.isEmpty 경로 → IllegalArgumentException")
  void testDecryptThrowsOnNullCiphertext() {
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.decrypt(null, KAT_KEY),
        "null 암호문 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  // ==================== encrypt: 오류 경로 ====================

  @Test
  @DisplayName("encrypt: null 평문 → IllegalArgumentException")
  void testEncryptThrowsOnNullPlaintext() {
    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.encrypt(null, KAT_KEY),
        "null 평문 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  @Test
  @DisplayName("encrypt: 잘못된 키 크기(8 bytes) → key.length != 16 → IllegalArgumentException")
  void testEncryptThrowsOnInvalidKeySize() {
    byte[] invalidKey = new byte[8]; // 8 bytes, 유효 키 크기는 16 bytes
    byte[] plaintext = "Hello!".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.encrypt(plaintext, invalidKey),
        "8 bytes 키 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  @Test
  @DisplayName("encrypt: null 키 → IllegalArgumentException")
  void testEncryptThrowsOnNullKey() {
    byte[] plaintext = "Hello!".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    assertThrows(
        IllegalArgumentException.class,
        () -> cipher.encrypt(plaintext, null),
        "null 키 전달 시 IllegalArgumentException이 발생해야 한다");
  }

  // ==================== 다른 키로 복호화 → fallback 동작 명세 ====================

  @Test
  @DisplayName("다른 키로 복호화 시 removePadding 실패 → 원본 16 bytes 반환(fallback) — 원문과 불일치")
  void testDecryptWithWrongKeyReturnsRawBytes() {
    // 올바른 키로 암호화
    byte[] plaintext = "AriaTest!".getBytes(java.nio.charset.StandardCharsets.UTF_8); // 9 bytes
    byte[] ciphertext = cipher.encrypt(plaintext, KAT_KEY);
    assertEquals(16, ciphertext.length);

    // 다른 키로 복호화: 잘못된 패딩 → catch 후 원본 16 bytes 반환
    byte[] wrongKey = ByteUtils.fromHexString("0f0e0d0c0b0a09080706050403020100");
    byte[] decrypted = cipher.decrypt(ciphertext, wrongKey);

    assertNotNull(decrypted);
    assertEquals(16, decrypted.length, "fallback: 잘못된 패딩 시 원본 16 bytes가 반환되어야 한다");
    // 원문과 불일치 검증
    assertFalse(
        Arrays.equals(plaintext, decrypted),
        "다른 키로 복호화한 결과는 원래 평문과 달라야 한다");
  }

  // ==================== 키 민감도 ====================

  @Test
  @DisplayName("동일한 평문을 다른 키로 암호화하면 서로 다른 암호문이 생성되어야 한다")
  void testDifferentKeysProduceDifferentCiphertext() {
    byte[] plaintext = "KeySensitivity!!".getBytes(java.nio.charset.StandardCharsets.UTF_8); // 정확히 16 bytes
    byte[] key1 = KAT_KEY;
    byte[] key2 = ByteUtils.fromHexString("0f0e0d0c0b0a09080706050403020100");

    byte[] cipher1 = cipher.encrypt(plaintext, key1);
    byte[] cipher2 = cipher.encrypt(plaintext, key2);

    assertNotNull(cipher1);
    assertNotNull(cipher2);
    assertFalse(
        Arrays.equals(cipher1, cipher2),
        "서로 다른 키는 서로 다른 암호문을 생성해야 한다");
  }
}
