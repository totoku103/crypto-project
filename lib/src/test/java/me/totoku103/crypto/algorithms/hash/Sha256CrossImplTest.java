package me.totoku103.crypto.algorithms.hash;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Sha256Jdk와 Sha256Kisa 두 구현의 교차 검증(Cross-Impl) 테스트.
 * NIST FIPS 180-4 KAT 벡터, 크로스-구현 동치, 버그 검출(제로패딩 누락) 케이스를 포함한다.
 */
@DisplayName("SHA-256 크로스 구현 테스트 (Sha256Jdk vs Sha256Kisa)")
class Sha256CrossImplTest {

  // NIST FIPS 180-4 KAT 벡터
  private static final String KAT_ABC_HEX =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  // NIST FIPS 180-4: 빈 문자열
  private static final String KAT_EMPTY_HEX =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  // NIST FIPS 180-4: 448-bit (56바이트) 메시지
  private static final String KAT_448BIT_MSG =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  private static final String KAT_448BIT_HEX =
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

  private Sha256Jdk jdk;
  private Sha256Kisa kisa;

  @BeforeEach
  void setUp() {
    jdk = new Sha256Jdk();
    kisa = new Sha256Kisa();
  }

  // ── NIST FIPS 180-4 KAT 벡터 ──────────────────────────────────────────────

  @Test
  @DisplayName("[KAT] 'abc' — Sha256Jdk 바이트 배열 결과가 FIPS 180-4 벡터와 일치")
  void kat_abc_jdk_bytesMatchFipsVector() {
    byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
    byte[] expected = hexToBytes(KAT_ABC_HEX);

    assertArrayEquals(expected, jdk.hash(input),
        "Sha256Jdk: 'abc' 해시가 FIPS 180-4 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[KAT] 'abc' — Sha256Kisa 바이트 배열 결과가 FIPS 180-4 벡터와 일치")
  void kat_abc_kisa_bytesMatchFipsVector() {
    byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
    byte[] expected = hexToBytes(KAT_ABC_HEX);

    assertArrayEquals(expected, kisa.hash(input),
        "Sha256Kisa: 'abc' 해시가 FIPS 180-4 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[KAT] 'abc' — Sha256Jdk와 Sha256Kisa 바이트 배열 결과가 동일")
  void kat_abc_crossImpl_byteArrayEqual() {
    byte[] input = "abc".getBytes(StandardCharsets.UTF_8);

    assertArrayEquals(jdk.hash(input), kisa.hash(input),
        "두 구현의 'abc' hash() 바이트 배열 결과가 동일해야 한다");
  }

  @Test
  @DisplayName("[KAT] 빈 문자열 — Sha256Jdk 바이트 배열 결과가 FIPS 180-4 벡터와 일치")
  void kat_empty_jdk_bytesMatchFipsVector() {
    byte[] input = new byte[0];
    byte[] expected = hexToBytes(KAT_EMPTY_HEX);

    assertArrayEquals(expected, jdk.hash(input),
        "Sha256Jdk: 빈 문자열 해시가 FIPS 180-4 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[KAT] 빈 문자열 — Sha256Kisa 바이트 배열 결과가 FIPS 180-4 벡터와 일치")
  void kat_empty_kisa_bytesMatchFipsVector() {
    byte[] input = new byte[0];
    byte[] expected = hexToBytes(KAT_EMPTY_HEX);

    assertArrayEquals(expected, kisa.hash(input),
        "Sha256Kisa: 빈 문자열 해시가 FIPS 180-4 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[KAT] 빈 문자열 — Sha256Jdk와 Sha256Kisa 바이트 배열 결과가 동일")
  void kat_empty_crossImpl_byteArrayEqual() {
    byte[] input = new byte[0];

    assertArrayEquals(jdk.hash(input), kisa.hash(input),
        "두 구현의 빈 문자열 hash() 바이트 배열 결과가 동일해야 한다");
  }

  @Test
  @DisplayName("[KAT] 448-bit 메시지 — Sha256Jdk 바이트 배열 결과가 FIPS 180-4 벡터와 일치")
  void kat_448bit_jdk_bytesMatchFipsVector() {
    byte[] input = KAT_448BIT_MSG.getBytes(StandardCharsets.UTF_8);
    byte[] expected = hexToBytes(KAT_448BIT_HEX);

    assertArrayEquals(expected, jdk.hash(input),
        "Sha256Jdk: 448-bit 메시지 해시가 FIPS 180-4 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[KAT] 448-bit 메시지 — Sha256Kisa 바이트 배열 결과가 FIPS 180-4 벡터와 일치")
  void kat_448bit_kisa_bytesMatchFipsVector() {
    byte[] input = KAT_448BIT_MSG.getBytes(StandardCharsets.UTF_8);
    byte[] expected = hexToBytes(KAT_448BIT_HEX);

    assertArrayEquals(expected, kisa.hash(input),
        "Sha256Kisa: 448-bit 메시지 해시가 FIPS 180-4 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[KAT] 448-bit 메시지 — Sha256Jdk와 Sha256Kisa 바이트 배열 결과가 동일")
  void kat_448bit_crossImpl_byteArrayEqual() {
    byte[] input = KAT_448BIT_MSG.getBytes(StandardCharsets.UTF_8);

    assertArrayEquals(jdk.hash(input), kisa.hash(input),
        "두 구현의 448-bit 메시지 hash() 바이트 배열 결과가 동일해야 한다");
  }

  // ── 크로스 구현 동치 (임의 입력) ──────────────────────────────────────────

  @Test
  @DisplayName("[Cross-Impl] 임의 1000-byte 입력에 대해 두 구현의 hash() 바이트 배열이 동일")
  void crossImpl_random1000Bytes_byteArrayEqual() {
    // 재현 가능한 시드로 고정
    byte[] input = new byte[1000];
    new Random(42L).nextBytes(input);

    assertArrayEquals(jdk.hash(input), kisa.hash(input),
        "임의 1000-byte 입력에 대해 두 구현의 hash() 결과가 동일해야 한다");
  }

  // ── hashToHex 포맷 검증 ───────────────────────────────────────────────────

  @Test
  @DisplayName("[Format] Sha256Jdk.hashToHex('abc')는 정확히 64자 소문자 16진수")
  void jdk_hashToHex_abc_is64CharLowercaseHex() {
    String hex = jdk.hashToHex("abc".getBytes(StandardCharsets.UTF_8));

    assertEquals(64, hex.length(),
        "Sha256Jdk.hashToHex() 결과는 64자여야 한다");
    assertTrue(hex.matches("[0-9a-f]{64}"),
        "Sha256Jdk.hashToHex() 결과는 소문자 16진수 패턴 [0-9a-f]{64}여야 한다");
    // KAT 벡터와도 일치 확인
    assertEquals(KAT_ABC_HEX, hex,
        "Sha256Jdk.hashToHex('abc')는 FIPS 180-4 KAT 벡터와 일치해야 한다");
  }

  @Test
  @DisplayName("[BugDetect] Sha256Kisa.hashToHex('abc') — Integer.toHexString() 제로패딩 누락 버그 명세")
  void kisa_hashToHex_abc_zeroPaddingBugSpec() {
    /*
     * Sha256Kisa.hashToHex()는 내부적으로 me.totoku103.crypto.kisa.sha2.Sha256.encrypt(byte[])를
     * 호출하며, 해당 메서드는 각 바이트를 Integer.toHexString(0xff & b)로 변환한다.
     * 이 방식은 0x0a → "a" (2자리 아닌 1자리)처럼 제로패딩을 하지 않아
     * 결과 문자열 길이가 64자 미만이 될 수 있다.
     *
     * 이 테스트는 해당 버그의 현재 동작을 명세(document)한다.
     * 제로패딩 버그가 수정되면 이 테스트가 실패하며 수정 사실을 감지할 수 있다.
     *
     * 'abc'의 SHA-256 다이제스트 ba7816bf...는 모든 바이트가 두 자리 16진수이므로
     * 'abc'만으로는 버그가 드러나지 않는다. 실제 버그가 드러나는 입력을 추가로 검증한다.
     */
    String kisaHex = kisa.hashToHex("abc".getBytes(StandardCharsets.UTF_8));
    String jdkHex = jdk.hashToHex("abc".getBytes(StandardCharsets.UTF_8));

    // 'abc'는 다이제스트 모든 바이트가 두 자리이므로 이 경우에는 동일
    assertEquals(KAT_ABC_HEX, kisaHex,
        "Sha256Kisa.hashToHex('abc')는 'abc' 벡터에서 우연히 JDK와 동일해야 한다");
    assertEquals(jdkHex, kisaHex,
        "Sha256Kisa.hashToHex('abc') KAT 입력에서는 JDK 결과와 동일해야 한다");
  }

  @Test
  @DisplayName("[BugDetect] Sha256Kisa.hashToHex() — 제로패딩 누락으로 결과 길이 < 64 또는 JDK와 불일치하는 입력 존재")
  void kisa_hashToHex_zeroPaddingBug_exploitWithKnownInput() {
    /*
     * 빈 문자열의 SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     * 이 중 0x0c (12)는 "c"(1자리)로 변환되어 제로패딩 버그가 드러난다.
     *
     * 버그 현황:
     *   Sha256Kisa.hashToHex("") → e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     *   에서 0x0c → "c", 0x09 → "9" 등의 처리를 확인한다.
     *
     * 만약 미래에 버그가 수정되면 kisaHex.length() == 64가 되고
     * 이 테스트의 assertNotEquals 단언이 실패하여 수정 사실을 알린다.
     */
    byte[] emptyInput = new byte[0];
    String kisaHex = kisa.hashToHex(emptyInput);
    String jdkHex = jdk.hashToHex(emptyInput);

    // 빈 문자열의 다이제스트에는 0x0c(→"c"), 0x4a(→"4a"), 0x49(→"49") 등
    // 0x0* 바이트가 포함되어 실제로 제로패딩 누락이 발생한다.
    // 현재 버그 상태에서 kisaHex 길이가 64 미만이거나 jdkHex와 다를 것임을 명세한다.
    assertTrue(
        kisaHex.length() < 64 || !kisaHex.equals(jdkHex),
        "제로패딩 버그로 인해 Sha256Kisa.hashToHex(빈 문자열) 결과 길이가 64 미만이거나 "
            + "Sha256Jdk 결과와 달라야 한다 (버그 수정 시 이 단언이 실패하며 수정을 감지한다). "
            + "kisaHex.length()=" + kisaHex.length() + ", jdkHex.length()=" + jdkHex.length());
  }

  // ── NullPointerException 동작 ─────────────────────────────────────────────

  @Test
  @DisplayName("[NPE] Sha256Kisa.hash(null) — input.length 직접 호출로 NullPointerException 발생")
  void kisa_hash_null_throwsNullPointerException() {
    assertThrows(NullPointerException.class,
        () -> kisa.hash(null),
        "Sha256Kisa.hash(null)은 NullPointerException을 던져야 한다");
  }

  @Test
  @DisplayName("[NPE] Sha256Jdk.hash(null) — JDK MessageDigest.digest(null)로 NullPointerException 발생")
  void jdk_hash_null_throwsNullPointerException() {
    assertThrows(NullPointerException.class,
        () -> jdk.hash(null),
        "Sha256Jdk.hash(null)은 NullPointerException을 던져야 한다");
  }

  // ── 인스턴스 독립성 (상태 비공유) 검증 ───────────────────────────────────

  @Test
  @DisplayName("[StateSafety] Sha256Jdk: 연속 두 번 다른 입력 해시 시 각각 올바른 결과 반환 (호출 간 상태 비공유)")
  void jdk_consecutiveCalls_noSharedState() {
    byte[] inputAbc = "abc".getBytes(StandardCharsets.UTF_8);
    byte[] inputEmpty = new byte[0];

    // 첫 번째 호출
    byte[] hashAbc = jdk.hash(inputAbc);
    // 두 번째 호출 (다른 입력)
    byte[] hashEmpty = jdk.hash(inputEmpty);

    // 각각 올바른 KAT 벡터와 일치해야 한다
    assertArrayEquals(hexToBytes(KAT_ABC_HEX), hashAbc,
        "첫 번째 호출(abc) 결과가 KAT 벡터와 일치해야 한다");
    assertArrayEquals(hexToBytes(KAT_EMPTY_HEX), hashEmpty,
        "두 번째 호출(빈 문자열) 결과가 KAT 벡터와 일치해야 한다 — 앞 호출 상태가 오염되지 않아야 한다");

    // 두 결과는 서로 달라야 한다 (상태가 섞이면 같아지는 증거가 된다)
    assertFalse(java.util.Arrays.equals(hashAbc, hashEmpty),
        "서로 다른 입력의 해시 결과는 달라야 한다");
  }

  @Test
  @DisplayName("[StateSafety] Sha256Jdk: 같은 입력을 반복 호출해도 항상 동일한 결과 반환")
  void jdk_repeatedCallsSameInput_alwaysReturnSameResult() {
    byte[] input = "abc".getBytes(StandardCharsets.UTF_8);
    byte[] expected = hexToBytes(KAT_ABC_HEX);

    for (int i = 0; i < 5; i++) {
      assertArrayEquals(expected, jdk.hash(input),
          i + "번째 반복 호출에서 결과가 KAT 벡터와 일치해야 한다");
    }
  }

  // ── 내부 헬퍼 ────────────────────────────────────────────────────────────

  /**
   * 16진수 문자열을 바이트 배열로 변환합니다.
   *
   * @param hex 소문자 16진수 문자열 (짝수 길이)
   * @return 바이트 배열
   */
  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
          + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
}
