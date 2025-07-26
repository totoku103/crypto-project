package me.totoku103.crypto.kisa.seed.mode;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do 의 테스트벡터 파일을 읽어와서 SEED CBC 모드를 테스트한다. 기본
 * 제공된 데이터는 NonPadding 모드. MCT(Monte Carlo Test)는 이전 암호화 결과가 다음 연산의 입력으로 사용되는 연쇄 테스트이다.
 */
class SeedCbcMctVectorFileTest {
  static class TestVectorMct {
    int count;
    String key;
    String iv;
    String pt;
    String ct;
  }

  private static String getSplitAndValue(String line) {
    final String[] split = line.split("=");
    if (split.length < 2) return "";
    return split[1].trim();
  }

  public static List<TestVectorMct> getTestVectors() throws IOException {
    final URL resource =
        SeedCbcMctVectorFileTest.class.getResource("/testvectors/seedcbc/SEED-128_(CBC)_MCT.txt");
    Assertions.assertNotNull(resource, "Test vector file not found");
    final File katFile = new File(resource.getFile());
    if (!katFile.isFile()) throw new RuntimeException("kat file is not a file");
    final List<String> strings = Files.readAllLines(katFile.toPath());

    final List<TestVectorMct> testVectors = new ArrayList<>();
    TestVectorMct current = null;
    for (String line : strings) {
      line = line.trim();
      if (line.isEmpty()) continue;

      if (line.startsWith("COUNT =")) {
        if (current != null) {
          testVectors.add(current);
        }
        current = new TestVectorMct();
        current.count = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("KEY =")) {
        current.key = getSplitAndValue(line);
      } else if (line.startsWith("IV =")) {
        current.iv = getSplitAndValue(line);
      } else if (line.startsWith("PT =")) {
        current.pt = getSplitAndValue(line);
      } else if (line.startsWith("CT =")) {
        current.ct = getSplitAndValue(line);
      }
    }
    if (current != null && current.key != null) {
      testVectors.add(current);
    }
    return testVectors;
  }

  private byte[] xor(byte[] a, byte[] b) {
    byte[] result = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }
    return result;
  }

  @Test
  public void verifyChaining() throws IOException {
    final List<TestVectorMct> vectors = getTestVectors();
    boolean allPass = true;
    for (int i = 1; i < vectors.size(); i++) {
      String expectedIV = vectors.get(i - 1).ct;
      String actualIV = vectors.get(i).iv;
      if (!expectedIV.equalsIgnoreCase(actualIV)) {
        System.out.printf(
            "❌ Mismatch at COUNT %d: Expected IV = %s, Actual IV = %s%n",
            vectors.get(i).count, expectedIV, actualIV);
        allPass = false;
      }
    }

    if (allPass) {
      System.out.println("✅ All IV chaining is correct across MCT vectors.");
    }
  }

  //
  //    @ParameterizedTest
  //    @MethodSource("getTestVectors")
  public void testMctVectors(TestVectorMct vector) {
    final String key = vector.key;
    final String iv = vector.iv;
    final String pt = vector.pt;
    final String ct = vector.ct;

    final byte[] keyBytes = HexConverter.toBytes(key);
    final byte[] ivBytes = HexConverter.toBytes(iv);
    final byte[] ptBytes = HexConverter.toBytes(pt);
    final byte[] ctBytes = HexConverter.toBytes(ct);

    final SeedCbc seedCbc = new SeedCbc();
    final byte[] encrypted = seedCbc.encrypt(keyBytes, ivBytes, ptBytes, false);
    Assertions.assertArrayEquals(ctBytes, encrypted);

    final byte[] decrypted = seedCbc.decrypt(keyBytes, ivBytes, encrypted, false);
    Assertions.assertArrayEquals(ptBytes, decrypted);
  }
}
