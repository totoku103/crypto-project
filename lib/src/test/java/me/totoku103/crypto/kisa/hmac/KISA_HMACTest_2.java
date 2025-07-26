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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class KISA_HMACTest_2 {

  @Test
  public void testMainCode() {
    final byte[] keyBytes =
        HexConverter.toBytes("4DC5377E40EA0E6877A8EAD188CCB5075E284A8D398993B7F6E9EE7391E5D66A");
    final byte[] messageBytes =
        HexConverter.toBytes(
            "E871BF48C1CA41570FAC795371C6AD7AFC6B2EE23A8A830F72E0C3C52A6C431BEB2371D144E600E311B1465EFE15E27346E8A1CAC13BA3191D8CB9F46B3D12E7DE4517C2D0269334061F179B35A29D1BC5086BEDD4843AFA7E5598A95C408BF54A3E77C26E724171765DB5B220552599003353F57E4D92DD1EA4278B045EF56E");
    final byte[] ctBytes =
        HexConverter.toBytes("63C6510B16E8E4272F295A219606AC49F0E764720B3BB7405802F0B31F258A2D");

    final byte[] output = new byte[32];

    KISA_HMAC.HMAC_SHA256_Transform(
        output, keyBytes, keyBytes.length, messageBytes, messageBytes.length);
    final String s = HexConverter.fromBytes(output);
    Utils.print_hex("output", output, output.length);
    Assertions.assertArrayEquals(ctBytes, output);
  }

  static class HMac {
    private int count;
    private int kLen;
    private int tLen;
    private String key;
    private String msg;
    private String mac;
  }

  private static String getSplitAndValue(String line) {
    final String[] split = line.split("=");
    if (split.length == 1) return "";
    else if (split.length == 2) return split[1].trim();
    else return "";
  }

  public static Stream<HMac> readTestVectors() throws IOException {
    final URL resource =
        KISA_HMACTest_2.class.getResource("/testvectors/hmac/HMAC_SHA-256_KAT.txt");
    Assertions.assertNotNull(resource);
    final File file = new File(resource.getFile());
    final List<String> lines = Files.readAllLines(Paths.get(file.getPath()));

    final List<HMac> testVectors = new ArrayList<>();
    HMac current = null;

    for (String line : lines) {
      line = line.trim();
      if (line.isEmpty()) continue;

      if (line.startsWith("COUNT =")) {
        if (current != null) testVectors.add(current);
        current = new HMac();
        current.count = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("Klen =")) {
        current.kLen = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("Tlen = ")) {
        current.tLen = Integer.parseInt(getSplitAndValue(line));
      } else if (line.startsWith("Key =")) {
        current.key = getSplitAndValue(line);
      } else if (line.startsWith("Msg =")) {
        current.msg = getSplitAndValue(line);
      } else if (line.startsWith("Mac =")) {
        current.mac = getSplitAndValue(line);
      }
    }

    return testVectors.stream();
  }

  @ParameterizedTest
  @MethodSource("readTestVectors")
  public void test(HMac vector) {
    Assumptions.assumeTrue(vector.tLen == 32);

    final byte[] keyBytes = HexConverter.toBytes(vector.key);
    final byte[] messageBytes = HexConverter.toBytes(vector.msg);
    final byte[] ctBytes = HexConverter.toBytes(vector.mac);

    final byte[] output = new byte[vector.tLen];

    KISA_HMAC.HMAC_SHA256_Transform(
        output, keyBytes, keyBytes.length, messageBytes, messageBytes.length);
    final String s = HexConverter.fromBytes(output);
    Utils.print_hex("output", output, output.length);
    Assertions.assertArrayEquals(ctBytes, output);
  }
}
