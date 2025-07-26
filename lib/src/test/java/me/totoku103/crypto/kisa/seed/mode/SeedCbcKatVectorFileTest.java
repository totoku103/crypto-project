package me.totoku103.crypto.kisa.seed.mode;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import me.totoku103.crypto.utils.HexConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do 의 테스트벡터 파일을 읽어와서 SEED CBC 모드를 테스트한다. 기본
 * 제공된 데이터는 NonPadding 모드.
 */
class SeedCbcKatVectorFileTest {
  static class TestVectorKat {
    private String key;
    private String iv;
    private String pt;
    private String ct;
  }

  private static String getSplitAndValue(String line) {
    final String[] split = line.split("=");
    if (split.length == 1) return "";
    else if (split.length == 2) return split[1].trim();
    else return "";
  }

  public static Stream<TestVectorKat> getTestKatVectors() throws IOException {
    final URL resource =
        SeedCbcKatVectorFileTest.class.getResource("/testvectors/seedcbc/SEED-128_(CBC)_KAT.txt");
    Assertions.assertNotNull(resource);
    final File katFile = new File(resource.getFile());
    if (!katFile.isFile()) throw new RuntimeException("kat file is not a file");
    final List<String> strings = Files.readAllLines(katFile.toPath());

    final List<TestVectorKat> testVectors = new java.util.ArrayList<>();
    TestVectorKat current = null;
    for (String line : strings) {
      line = line.trim();
      if (line.isEmpty()) continue;

      if (line.startsWith("KEY =")) {
        current = new TestVectorKat();
        testVectors.add(current);
        current.key = getSplitAndValue(line);
      } else if (line.startsWith("IV =")) current.iv = getSplitAndValue(line);
      else if (line.startsWith("PT =")) current.pt = getSplitAndValue(line);
      else if (line.startsWith("CT =")) current.ct = getSplitAndValue(line);
    }
    return testVectors.stream();
  }

  @ParameterizedTest
  @MethodSource("getTestKatVectors")
  public void testKatVectors(TestVectorKat vector) {
    final String key = vector.key;
    final String iv = vector.iv;
    final String pt = vector.pt;
    final String ct = vector.ct;

    final byte[] keyBytes = HexConverter.toBytes(key);
    final byte[] ivBytes = HexConverter.toBytes(iv);
    final byte[] ptBytes = HexConverter.toBytes(pt);
    final byte[] ctBytes = HexConverter.toBytes(ct);

    SeedCbc seedCbc = new SeedCbc();
    final byte[] encrypted = seedCbc.encrypt(keyBytes, ivBytes, ptBytes, false);
    Assertions.assertArrayEquals(ctBytes, encrypted);

    final byte[] decrypted = seedCbc.decrypt(keyBytes, ivBytes, encrypted, false);
    Assertions.assertArrayEquals(ptBytes, decrypted);
  }

  @Test
  public void testSingleCase() {
    final SecureRandom randomKey = new SecureRandom();
    final byte[] keyBytes = new byte[16];
    randomKey.nextBytes(keyBytes);

    final SecureRandom randomIv = new SecureRandom();
    final byte[] ivBytes = new byte[16];
    randomIv.nextBytes(ivBytes);

    final byte[] ptBytes = "안녕하세요".getBytes(StandardCharsets.UTF_8);

    SeedCbc seedCbc = new SeedCbc();
    final byte[] encrypted = seedCbc.encrypt(keyBytes, ivBytes, ptBytes, true);
    System.out.println(Base64.getEncoder().encodeToString(encrypted));

    final byte[] decrypted = seedCbc.decrypt(keyBytes, ivBytes, encrypted, true);
    System.out.println(new String(decrypted, StandardCharsets.UTF_8));
  }
}
