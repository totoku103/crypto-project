package me.totoku103.crypto.kisa.hmac;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * KISA_HMAC 클래스의 HMAC-SHA256 구현을 검증하는 테스트 클래스입니다.
 *
 * <p>NIST에서 제공하는 HMAC Test Vectors (RFC 4231)를 사용하여 구현의 정확성을 검증합니다. 테스트 벡터 파일은
 * src/test/resources/testvectors/hmac/HMAC_SHA-256_KAT.txt 에 위치합니다.
 */
@DisplayName("KISA HMAC-SHA256 구현 검증 테스트")
class KisaHmacSha256Test {

  /** HMAC-SHA256 테스트 벡터를 담는 정적 내부 클래스입니다. */
  static class HmacTestVector {
    private int count;
    private int kLen;
    private int tLen;
    private String key;
    private String msg;
    private String mac;

    @Override
    public String toString() {
      return "HmacTestVector{" + "count=" + count + ", kLen=" + kLen + ", tLen=" + tLen + '}';
    }
  }

  /**
   * 테스트 벡터 파일을 파싱하여 Stream<HmacTestVector> 형태로 제공하는 메서드입니다.
   *
   * @return HMAC 테스트 벡터의 스트림
   * @throws IOException 파일 읽기 중 오류 발생 시
   */
  private static Stream<HmacTestVector> hmacTestVectorProvider() throws IOException {
    final URL resource =
        KisaHmacSha256Test.class.getResource("/testvectors/hmac/HMAC_SHA-256_KAT.txt");
    Assertions.assertNotNull(resource, "테스트 벡터 파일을 찾을 수 없습니다.");

    final File file = new File(resource.getFile());
    final List<String> lines = Files.readAllLines(Paths.get(file.getPath()));
    final List<HmacTestVector> testVectors = new ArrayList<>();
    HmacTestVector current = null;

    for (String line : lines) {
      line = line.trim();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }

      if (line.startsWith("COUNT =")) {
        if (current != null) {
          testVectors.add(current);
        }
        current = new HmacTestVector();
        current.count = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("Klen =")) {
        current.kLen = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("Tlen =")) {
        current.tLen = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("Key =")) {
        current.key = getSplitAndValue(line);
      } else if (line.startsWith("Msg =")) {
        current.msg = getSplitAndValue(line);
      } else if (line.startsWith("Mac =")) {
        current.mac = getSplitAndValue(line);
      }
    }
    if (current != null) {
      testVectors.add(current);
    }

    return testVectors.stream();
  }

  /**
   * 라인에서 "="을 기준으로 값을 추출하는 헬퍼 메서드입니다.
   *
   * @param line 파싱할 라인
   * @return 추출된 값
   */
  private static String getSplitAndValue(String line) {
    final String[] split = line.split("=");
    if (split.length < 2) return "";
    return split[1].trim();
  }

  /**
   * NIST HMAC 테스트 벡터를 사용하여 KISA_HMAC 구현을 검증합니다.
   *
   * @param vector 파라미터로 제공되는 HMAC 테스트 벡터
   */
  @DisplayName("NIST HMAC 테스트 벡터 검증")
  @ParameterizedTest(name = "[{index}] {0}")
  @MethodSource("hmacTestVectorProvider")
  void testWithNistVectors(HmacTestVector vector) {
    final byte[] keyBytes = HexConverter.toBytes(vector.key);
    final byte[] messageBytes = HexConverter.toBytes(vector.msg);
    final byte[] expectedMac = HexConverter.toBytes(vector.mac);

    // Klen은 바이트 단위여야 하지만, 테스트 벡터는 비트 단위로 제공하는 경우가 있으므로,
    // HexConverter로 변환된 실제 키 길이를 사용합니다.
    Assertions.assertEquals(vector.kLen, keyBytes.length, "Klen과 실제 키 길이가 다릅니다.");
    Assertions.assertEquals(vector.tLen, expectedMac.length, "Tlen과 실제 MAC 길이가 다릅니다.");

    final byte[] actualMac = new byte[vector.tLen];

    KISA_HMAC.HMAC_SHA256_Transform(
        actualMac, keyBytes, keyBytes.length, messageBytes, messageBytes.length);

    Assertions.assertArrayEquals(
        expectedMac, actualMac, String.format("COUNT = %d 검증 실패", vector.count));
  }
}
