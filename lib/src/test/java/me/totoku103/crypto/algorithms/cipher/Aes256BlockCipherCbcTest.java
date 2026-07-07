package me.totoku103.crypto.algorithms.cipher;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import me.totoku103.crypto.core.utils.ByteUtils;
import me.totoku103.crypto.enums.CipherMode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Aes256BlockCipher CBC 모드를 테스트합니다. */
@DisplayName("AES-256 CBC 모드")
class Aes256BlockCipherCbcTest {

  private static final byte[] DEFAULT_KEY =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final byte[] FIXED_IV = ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f");

  /** 평문·암호문·복호문을 콘솔에 찍어 눈으로 확인하려고 쓴다. */
  private static void printRoundTrip(String label, byte[] plaintext, byte[] encrypted, byte[] decrypted) {
    System.out.println("===== " + label + " =====");
    System.out.println("  평문      : " + new String(plaintext, StandardCharsets.UTF_8));
    System.out.println("  평문(hex) : " + ByteUtils.toHexString(plaintext));
    System.out.println("  암호문(hex): " + ByteUtils.toHexString(encrypted));
    System.out.println("  복호문    : " + new String(decrypted, StandardCharsets.UTF_8));
    System.out.println("  복호문(hex): " + ByteUtils.toHexString(decrypted));
  }

  // ==========================================================================
  // 2-arg: IV 자동 생성 + prepend
  // ==========================================================================

  @Test
  @DisplayName("CBC 2-arg: 암호화/복호화 round-trip")
  void testCbcAutoIvRoundTrip() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    String plaintext = "Hello, AES-256 CBC mode!";
    byte[] encrypted = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);

    assertNotNull(encrypted);
    // [IV(16B)][암호문] 이므로 IV를 제외한 나머지가 블록 크기의 배수여야 한다
    assertEquals(0, (encrypted.length - cipher.getBlockSize()) % cipher.getBlockSize());

    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY);
    printRoundTrip("CBC 2-arg 기본", plaintext.getBytes(StandardCharsets.UTF_8), encrypted, decrypted);
    assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decrypted);
  }

  @Test
  @DisplayName("CBC 2-arg: 한글 round-trip")
  void testCbcAutoIvKoreanRoundTrip() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    String plaintext = "안녕하세요 AES-256 CBC 테스트입니다!";
    byte[] encrypted = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);
    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY);

    printRoundTrip("CBC 2-arg 한글", plaintext.getBytes(StandardCharsets.UTF_8), encrypted, decrypted);
    assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decrypted);
  }

  @Test
  @DisplayName("CBC 2-arg: 특수문자 round-trip")
  void testCbcAutoIvSpecialCharactersRoundTrip() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    String plaintext = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\ 特殊 🔐🚀 \t\n\r\0";
    byte[] encrypted = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY);
    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY);

    printRoundTrip("CBC 2-arg 특수문자", plaintext.getBytes(StandardCharsets.UTF_8), encrypted, decrypted);
    assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decrypted);
  }

  @Test
  @DisplayName("CBC 3-arg: 특수문자 round-trip (고정 IV)")
  void testCbcExplicitIvSpecialCharactersRoundTrip() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    String plaintext = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\ 特殊 🔐🚀 \t\n\r\0";
    byte[] encrypted = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), DEFAULT_KEY, FIXED_IV);
    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY, FIXED_IV);

    System.out.println("  IV(hex)   : " + ByteUtils.toHexString(FIXED_IV));
    printRoundTrip("CBC 3-arg 특수문자(고정 IV)", plaintext.getBytes(StandardCharsets.UTF_8), encrypted, decrypted);
    assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), decrypted);
  }

  @Test
  @DisplayName("CBC 2-arg: 모든 바이트 값(0x00~0xFF) round-trip")
  void testCbcAutoIvAllByteValuesRoundTrip() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    byte[] plaintext = new byte[256];
    for (int i = 0; i < 256; i++) {
      plaintext[i] = (byte) i;
    }

    byte[] encrypted = cipher.encrypt(plaintext, DEFAULT_KEY);
    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  @DisplayName("CBC 2-arg: 동일 평문+키라도 랜덤 IV로 매번 다른 암호문이 나와야 한다")
  void testCbcAutoIvIsNonDeterministic() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] plaintext = "Same plaintext, same key".getBytes(StandardCharsets.UTF_8);

    byte[] c1 = cipher.encrypt(plaintext, DEFAULT_KEY);
    byte[] c2 = cipher.encrypt(plaintext, DEFAULT_KEY);

    assertFalse(Arrays.equals(c1, c2), "랜덤 IV로 인해 두 암호문은 달라야 한다");
    // 그래도 각각 복호화하면 동일 평문
    assertArrayEquals(plaintext, cipher.decrypt(c1, DEFAULT_KEY));
    assertArrayEquals(plaintext, cipher.decrypt(c2, DEFAULT_KEY));
  }

  @Test
  @DisplayName("CBC 2-arg: 출력 앞 16바이트가 실제 사용된 IV여야 한다")
  void testCbcAutoIvIsPrepended() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] plaintext = "check iv prefix".getBytes(StandardCharsets.UTF_8);

    byte[] encrypted = cipher.encrypt(plaintext, DEFAULT_KEY);
    byte[] iv = Arrays.copyOfRange(encrypted, 0, 16);
    byte[] body = Arrays.copyOfRange(encrypted, 16, encrypted.length);

    // 분리한 IV/본문을 3-arg 복호화에 넣으면 동일 평문이 나와야 한다
    byte[] decrypted = cipher.decrypt(body, DEFAULT_KEY, iv);
    assertArrayEquals(plaintext, decrypted);
  }

  // ==========================================================================
  // 3-arg: 명시적 IV
  // ==========================================================================

  @Test
  @DisplayName("CBC 3-arg: 고정 IV round-trip, 결과에 IV가 붙지 않아야 한다")
  void testCbcExplicitIvRoundTrip() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] plaintext = "explicit iv round trip".getBytes(StandardCharsets.UTF_8);

    byte[] encrypted = cipher.encrypt(plaintext, DEFAULT_KEY, FIXED_IV);
    // 순수 암호문(패딩 포함)만 반환 → 블록 크기 배수
    assertEquals(0, encrypted.length % cipher.getBlockSize());

    byte[] decrypted = cipher.decrypt(encrypted, DEFAULT_KEY, FIXED_IV);
    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  @DisplayName("CBC 3-arg: 동일 IV+키+평문은 결정적 암호문을 생성해야 한다")
  void testCbcExplicitIvIsDeterministic() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] plaintext = "deterministic".getBytes(StandardCharsets.UTF_8);

    byte[] c1 = cipher.encrypt(plaintext, DEFAULT_KEY, FIXED_IV);
    byte[] c2 = cipher.encrypt(plaintext, DEFAULT_KEY, FIXED_IV);

    assertArrayEquals(c1, c2, "동일 IV로 암호화하면 동일 암호문이어야 한다");
  }

  @Test
  @DisplayName("CBC 3-arg: 서로 다른 IV는 다른 암호문을 생성해야 한다")
  void testCbcDifferentIvProducesDifferentCiphertext() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] plaintext = "iv sensitivity".getBytes(StandardCharsets.UTF_8);
    byte[] iv2 = ByteUtils.fromHexString("0f0e0d0c0b0a09080706050403020100");

    byte[] c1 = cipher.encrypt(plaintext, DEFAULT_KEY, FIXED_IV);
    byte[] c2 = cipher.encrypt(plaintext, DEFAULT_KEY, iv2);

    assertFalse(Arrays.equals(c1, c2));
  }

  // ==========================================================================
  // KAT: NIST SP 800-38A F.2 AES-256-CBC
  // ==========================================================================

  @Test
  @DisplayName("NIST SP 800-38A F.2.5 AES-256-CBC KAT: 표준 IV/키/평문 첫 블록이 규격 암호문과 일치해야 한다")
  void testNistSp80038aCbcKat() {
    // NIST SP 800-38A Appendix F.2.5 CBC-AES256.Encrypt
    // key = 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
    // iv  = 000102030405060708090a0b0c0d0e0f
    // block1 plaintext  = 6bc1bee22e409f96e93d7e117393172a
    // block1 ciphertext = f58c4c04d6e5f1ba779eabfb5f7bfbd6
    byte[] key = ByteUtils.fromHexString(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    byte[] iv = ByteUtils.fromHexString("000102030405060708090a0b0c0d0e0f");
    byte[] plaintext = ByteUtils.fromHexString("6bc1bee22e409f96e93d7e117393172a");

    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] ciphertext = cipher.encrypt(plaintext, key, iv);

    // 16바이트 입력 → PKCS7 패딩으로 32바이트 출력. 첫 블록만 표준 벡터와 비교
    String firstBlock = ByteUtils.toHexString(ciphertext).substring(0, 32);
    assertEquals("f58c4c04d6e5f1ba779eabfb5f7bfbd6", firstBlock,
        "NIST SP 800-38A F.2.5 AES-256-CBC 첫 블록이 표준 KAT 값과 일치해야 한다");
  }

  // ==========================================================================
  // 예외 경로
  // ==========================================================================

  @Test
  @DisplayName("ECB 모드 인스턴스에서 3-arg encrypt 호출 시 UnsupportedOperationException")
  void testEcbModeRejectsExplicitIvEncrypt() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.ECB);
    assertThrows(UnsupportedOperationException.class,
        () -> cipher.encrypt("x".getBytes(StandardCharsets.UTF_8), DEFAULT_KEY, FIXED_IV));
  }

  @Test
  @DisplayName("ECB 모드 인스턴스에서 3-arg decrypt 호출 시 UnsupportedOperationException")
  void testEcbModeRejectsExplicitIvDecrypt() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.ECB);
    assertThrows(UnsupportedOperationException.class,
        () -> cipher.decrypt(new byte[16], DEFAULT_KEY, FIXED_IV));
  }

  @Test
  @DisplayName("CBC 3-arg: 잘못된 IV 길이는 IllegalArgumentException")
  void testCbcInvalidIvLength() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    byte[] shortIv = new byte[8];
    assertThrows(IllegalArgumentException.class,
        () -> cipher.encrypt("x".getBytes(StandardCharsets.UTF_8), DEFAULT_KEY, shortIv));
  }

  @Test
  @DisplayName("CBC 2-arg decrypt: IV보다 짧은 암호문은 IllegalArgumentException")
  void testCbcDecryptTooShort() {
    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);
    assertThrows(IllegalArgumentException.class,
        () -> cipher.decrypt(new byte[8], DEFAULT_KEY));
  }

  @Test
  @DisplayName("생성자에 null 모드 전달 시 IllegalArgumentException")
  void testNullModeRejected() {
    assertThrows(IllegalArgumentException.class, () -> new Aes256BlockCipher(null));
  }

  @Test
  @DisplayName("getMode: 지정한 모드를 반환해야 한다")
  void testGetMode() {
    assertEquals(CipherMode.CBC, new Aes256BlockCipher(CipherMode.CBC).getMode());
    assertEquals(CipherMode.ECB, new Aes256BlockCipher().getMode());
  }

  // ==========================================================================
  // 사용자 입력 암호문 복호화 (직접 값을 넣어 눈으로 확인)
  // ==========================================================================

  @Test
  @DisplayName("CBC 3-arg: 사용자가 입력한 암호문(hex)을 고정 IV로 복호화")
  void testDecryptUserSuppliedCiphertextExplicitIv() {
    // 확인하려는 암호문(hex)을 넣는다. 비워두면 아래에서 데모 값을 만들어 쓴다.
    String cipherTextHex = "";
    byte[] key = DEFAULT_KEY; // 암호화에 썼던 키(32바이트)
    byte[] iv = FIXED_IV; // 암호화에 썼던 IV(16바이트)

    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    if (cipherTextHex.isEmpty()) {
      // 비어 있으면 샘플 평문을 한 번 암호화해서 확인용 암호문을 만든다
      String demoPlain = "복호화 테스트용 데모 평문 123!@#";
      cipherTextHex =
          ByteUtils.toHexString(cipher.encrypt(demoPlain.getBytes(StandardCharsets.UTF_8), key, iv));
      System.out.println("(암호문 입력이 없어 데모 값으로 대체) " + cipherTextHex);
    }

    byte[] decrypted = cipher.decrypt(ByteUtils.fromHexString(cipherTextHex), key, iv);

    System.out.println("===== 사용자 입력 암호문 복호화 (3-arg, 고정 IV) =====");
    System.out.println("  키(hex)   : " + ByteUtils.toHexString(key));
    System.out.println("  IV(hex)   : " + ByteUtils.toHexString(iv));
    System.out.println("  암호문(hex): " + cipherTextHex);
    System.out.println("  복호문    : " + new String(decrypted, StandardCharsets.UTF_8));
    System.out.println("  복호문(hex): " + ByteUtils.toHexString(decrypted));

    assertNotNull(decrypted);
  }

  @Test
  @DisplayName("CBC 2-arg: 사용자가 입력한 암호문(hex, [IV|암호문])을 복호화")
  void testDecryptUserSuppliedCiphertextPrependedIv() {
    // 확인하려는 암호문(hex)을 넣는다. 앞 16바이트가 IV인 [IV][암호문] 형식이어야 한다.
    // (2-arg encrypt가 만든 값. 비워두면 아래에서 데모 값을 만들어 쓴다.)
    String cipherTextHex = "f3bc9ff7e46ebcfeafd63d5e8adb9bca002f905358f1d43a676e4c7bc0fdcc889f02923758d1645734e10bf655585f22442a4118fc88c155ce7094c12b16443b";
    byte[] key = DEFAULT_KEY; // 암호화에 썼던 키(32바이트)

    Aes256BlockCipher cipher = new Aes256BlockCipher(CipherMode.CBC);

    if (cipherTextHex.isEmpty()) {
      String demoPlain = "IV 포함 데모 평문 456$%^";
      cipherTextHex =
          ByteUtils.toHexString(cipher.encrypt(demoPlain.getBytes(StandardCharsets.UTF_8), key));
      System.out.println("(암호문 입력이 없어 데모 값으로 대체) " + cipherTextHex);
    }

    byte[] decrypted = cipher.decrypt(ByteUtils.fromHexString(cipherTextHex), key);

    System.out.println("===== 사용자 입력 암호문 복호화 (2-arg, IV 포함) =====");
    System.out.println("  키(hex)   : " + ByteUtils.toHexString(key));
    System.out.println("  암호문(hex): " + cipherTextHex);
    System.out.println("  복호문    : " + new String(decrypted, StandardCharsets.UTF_8));
    System.out.println("  복호문(hex): " + ByteUtils.toHexString(decrypted));

    assertNotNull(decrypted);
  }
}
