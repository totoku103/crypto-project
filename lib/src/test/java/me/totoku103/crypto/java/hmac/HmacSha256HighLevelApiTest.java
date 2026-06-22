package me.totoku103.crypto.java.hmac;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HmacSha256 고수준 API (toHmac / encrypt) 및
 * 저수준 API (hmacSha256) 의 동작 명세 테스트.
 *
 * <p>RFC 4231 벡터, 등가분할, 예외/오류 경로를 커버한다.
 */
@DisplayName("HmacSha256 고수준 API 테스트")
class HmacSha256HighLevelApiTest {

  // RFC 4231 벡터 #1
  // 키  : 20개의 0x0b
  // 데이터: "Hi There"
  // 기대값: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  private static final String RFC4231_VECTOR1_HEX =
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

  private HmacSha256 hmac;
  private byte[] rfc4231Key;   // 20개의 0x0b
  private byte[] rfc4231Data;  // "Hi There" UTF-8

  @BeforeEach
  void setUp() {
    hmac = new HmacSha256();

    rfc4231Key = new byte[20];
    Arrays.fill(rfc4231Key, (byte) 0x0b);

    rfc4231Data = "Hi There".getBytes(StandardCharsets.UTF_8);
  }

  // ===== toHmac() 테스트 =====

  @Test
  @DisplayName("toHmac(): RFC 4231 벡터 #1 → 32-byte 결과가 HmacSha256Test 기대값과 동일")
  void toHmac_rfc4231Vector1_returnsExpectedBytes() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    // 기존 HmacSha256Test 의 expected 와 동일한 벡터
    byte[] expected = ByteUtils.fromHexString(RFC4231_VECTOR1_HEX);

    byte[] actual = hmac.toHmac(rfc4231Key, rfc4231Data);

    assertEquals(32, actual.length, "HMAC-SHA256 결과는 항상 32바이트여야 한다");
    assertArrayEquals(expected, actual);
  }

  @Test
  @DisplayName("toHmac(): 빈 데이터(new byte[0])는 유효 입력 — 32-byte HMAC 정상 반환")
  void toHmac_emptyData_returns32Bytes() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    // RFC 4231 테스트 케이스 외 구현체 동작 명세:
    // 빈 메시지도 HMAC 의 합법적 입력이다.
    byte[] actual = hmac.toHmac(rfc4231Key, new byte[0]);

    assertNotNull(actual, "빈 데이터여도 null이 아닌 결과를 반환해야 한다");
    assertEquals(32, actual.length, "결과는 32바이트여야 한다");

    // 저수준 API와 동일한 값을 반환해야 한다 (크로스 검증)
    byte[] output = new byte[32];
    int rc = hmac.hmacSha256(output, output.length, rfc4231Key, rfc4231Key.length,
        new byte[0], 0);
    assertEquals(0, rc);
    assertArrayEquals(output, actual, "toHmac()과 hmacSha256() 결과가 동일해야 한다");
  }

  @Test
  @DisplayName("toHmac(): 빈 키(new byte[0])는 InvalidKeyException → IllegalArgumentException으로 래핑")
  void toHmac_emptyKey_throwsIllegalArgumentException() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    // JDK SecretKeySpec 은 0-byte 키에서 InvalidKeyException 을 던진다.
    // HmacSha256.toHmac() 은 이를 IllegalArgumentException 으로 래핑해야 한다.
    assertThrows(IllegalArgumentException.class,
        () -> hmac.toHmac(new byte[0], rfc4231Data),
        "빈 키는 IllegalArgumentException 을 유발해야 한다");
  }

  // ===== encrypt() 테스트 =====

  @Test
  @DisplayName("encrypt(): RFC 4231 벡터 #1 → 64자 소문자 16진수 문자열 반환")
  void encrypt_rfc4231Vector1_returns64CharLowerHex() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    String result = hmac.encrypt(rfc4231Key, rfc4231Data);

    assertNotNull(result);
    assertEquals(64, result.length(), "HmacSHA256 hex 문자열은 64자여야 한다");
    assertTrue(result.matches("[0-9a-f]{64}"), "소문자 16진수 패턴 [0-9a-f]{64} 이어야 한다");
    assertEquals(RFC4231_VECTOR1_HEX, result);
  }

  @Test
  @DisplayName("encrypt() 결과가 toHmac() 바이트를 %02x 포맷한 값과 동일")
  void encrypt_equalsManualHexFormattingOfToHmac() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    byte[] hmacBytes = hmac.toHmac(rfc4231Key, rfc4231Data);

    // %02x 수동 포맷
    StringBuilder sb = new StringBuilder();
    for (byte b : hmacBytes) {
      sb.append(String.format("%02x", b & 0xff));
    }
    String expected = sb.toString();

    String actual = hmac.encrypt(rfc4231Key, rfc4231Data);

    assertEquals(expected, actual,
        "encrypt() 는 toHmac() 결과를 %02x 포맷한 문자열과 동일해야 한다");
  }

  // ===== toHmac() ↔ hmacSha256() 일관성 =====

  @Test
  @DisplayName("toHmac()과 hmacSha256() 저수준 API가 동일 입력에 대해 동일 바이트 배열을 반환한다")
  void toHmac_andHmacSha256_returnSameBytes() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    // 고수준 API
    byte[] highLevel = hmac.toHmac(rfc4231Key, rfc4231Data);

    // 저수준 API
    byte[] lowLevel = new byte[32];
    int rc = hmac.hmacSha256(lowLevel, lowLevel.length,
        rfc4231Key, rfc4231Key.length,
        rfc4231Data, rfc4231Data.length);

    assertEquals(0, rc, "저수준 API는 OK(0) 을 반환해야 한다");
    assertArrayEquals(highLevel, lowLevel,
        "toHmac()과 hmacSha256()의 결과가 동일해야 한다");
  }

  // ===== hmacSha256() 저수준 API 경계 케이스 =====

  @Test
  @DisplayName("hmacSha256(outLen=31): System.arraycopy 로 앞 31바이트만 복사 → OK(0) 반환")
  void hmacSha256_outLen31_copiesFirst31BytesAndReturnsOk() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    byte[] output = new byte[32];
    // outLen=31 → System.arraycopy(result, 0, output, 0, 31) 만 실행되고 OK 반환
    int rc = hmac.hmacSha256(output, 31,
        rfc4231Key, rfc4231Key.length,
        rfc4231Data, rfc4231Data.length);

    assertEquals(0, rc,
        "outLen=31 이어도 System.arraycopy 는 정상 실행되므로 OK(0) 을 반환해야 한다");

    // 앞 31바이트는 RFC 4231 벡터의 앞 31바이트와 동일해야 한다
    byte[] expected = ByteUtils.fromHexString(RFC4231_VECTOR1_HEX);
    byte[] first31 = Arrays.copyOf(expected, 31);
    assertArrayEquals(first31, Arrays.copyOf(output, 31),
        "복사된 앞 31바이트는 RFC 4231 벡터의 앞 31바이트와 동일해야 한다");

    // 32번째 바이트(index 31)는 복사되지 않으므로 0이어야 한다
    assertEquals(0, output[31], "outLen=31 이므로 마지막 바이트는 초기값 0 이어야 한다");
  }

  @Test
  @DisplayName("hmacSha256(output=new byte[32], outLen=33): output 범위 초과 → ArrayIndexOutOfBoundsException 발생 (미명세 동작 회귀 고정)")
  void hmacSha256_outLen33WithBuffer32_throwsArrayIndexOutOfBoundsException() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());

    // output 은 32바이트이지만 outLen=33 을 전달하면
    // System.arraycopy(result, 0, output, 0, 33) 에서
    // output 배열 경계를 초과하여 ArrayIndexOutOfBoundsException 이 발생한다.
    // 이 동작을 회귀 테스트로 고정한다.
    byte[] output = new byte[32];

    assertThrows(ArrayIndexOutOfBoundsException.class,
        () -> hmac.hmacSha256(output, 33,
            rfc4231Key, rfc4231Key.length,
            rfc4231Data, rfc4231Data.length),
        "outLen > output.length 일 때 ArrayIndexOutOfBoundsException 이 발생해야 한다");
  }
}
