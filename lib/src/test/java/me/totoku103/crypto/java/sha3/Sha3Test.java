package me.totoku103.crypto.java.sha3;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import me.totoku103.crypto.enums.Sha3AlgorithmType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class Sha3Test {
  // 바이트 배열을 16진수 문자열로 변환
  private static String toHex(final byte[] data) {
    final StringBuilder sb = new StringBuilder();
    for (final byte b : data) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  @Test
  @DisplayName("모든 Sha3AlgorithmType에 대해 MessageDigest 인스턴스가 생성되는지 확인")
  public void shouldCreateMessageDigestInstancesForAllBitSizes() {
    Assumptions.assumeTrue(Sha3.isSha3Available(Sha3AlgorithmType.SHA3_224));

    Arrays.asList(Sha3AlgorithmType.values())
        .forEach(
            type -> {
              try {
                final MessageDigest instance = MessageDigest.getInstance(type.getAlgorithmName());

                Assertions.assertNotNull(instance);
              } catch (NoSuchAlgorithmException e) {
                Assertions.fail(
                    "Failed to create MessageDigest instance for " + type.getAlgorithmName(), e);
              }
            });
  }

  @Test
  @DisplayName("지원되는 경우 최적화된 SHA3-512 구현으로 한글 문자열을 해싱하여 예상 값과 비교")
  public void shouldHashKoreanTextWithOptimizedSha3512() {
    Assumptions.assumeTrue(Sha3.isSha3Available(Sha3AlgorithmType.SHA3_512));

    final me.totoku103.crypto.java.sha3.Sha3 javaSha3 = new me.totoku103.crypto.java.sha3.Sha3();
    final byte[] input = "테스트".getBytes(StandardCharsets.UTF_8);
    final byte[] digest = javaSha3.toHash(input, Sha3AlgorithmType.SHA3_512);

    assertEquals(
        "1202c701bda679497bd9fae351efb4bc96656a4ba78b184711645515ce7aa410279865413bb67a8df2257ed866aa5f8688cc46a2f19e3ac9420197692b4fde18",
        toHex(digest));
  }

  @Test
  @DisplayName("이모지 문자열을 사용해 최적화 구현과 기본 구현의 SHA3-256 결과가 동일한지 확인")
  public void optimizedSha3256ShouldMatchOriginalForEmoji() {
    Assumptions.assumeTrue(Sha3.isSha3Available(Sha3AlgorithmType.SHA3_256));

    final me.totoku103.crypto.kisa.sha3.Sha3 kisaSha3 = new me.totoku103.crypto.kisa.sha3.Sha3();
    final me.totoku103.crypto.java.sha3.Sha3 optimized = new me.totoku103.crypto.java.sha3.Sha3();
    final byte[] input = "emoji \uD83D\uDE00".getBytes(StandardCharsets.UTF_8);
    final byte[] expected = new byte[32];
    final int rc = kisaSha3.toHash(expected, expected.length, input, input.length, 256, 0);
    final byte[] actual = optimized.toHash(input, Sha3AlgorithmType.SHA3_256);

    assertEquals(0, rc);
    assertArrayEquals(expected, actual);
    assertEquals("72a5ac0c9cbab2f48b1fc74e951d1102da6de1990c42d1610bfa2cee29e4f86f", toHex(actual));
  }

  @Test
  @DisplayName("최적화 구현이 모든 비트 크기에서 참조 구현과 동일한 해시를 생성하는지 검증")
  public void optimizedAndReferenceMatchForAllBitSizes() {
    Assumptions.assumeTrue(Sha3.isSha3Available(Sha3AlgorithmType.SHA3_256));

    final me.totoku103.crypto.kisa.sha3.Sha3 kisaSha3 = new me.totoku103.crypto.kisa.sha3.Sha3();
    final me.totoku103.crypto.java.sha3.Sha3 javaSha3 = new me.totoku103.crypto.java.sha3.Sha3();
    final byte[] input = "OpenAI".getBytes(StandardCharsets.UTF_8);
    Arrays.stream(Sha3AlgorithmType.values())
        .forEach(
            bitType -> {
              final int bit = bitType.getBitSize();
              final byte[] expected = new byte[bit / 8];
              final int rc =
                  kisaSha3.toHash(expected, expected.length, input, input.length, bit, 0);
              final byte[] actual = javaSha3.toHash(input, bitType);

              assertEquals(0, rc);
              assertArrayEquals(expected, actual, "bitSize=" + bit);
            });
  }

  @Test
  @DisplayName("최적화된 SHA3-256 결과가 KISA 구현과 완전히 일치하는지 검증")
  public void optimizedSha3256MatchesKisaImplementation() {
    Assumptions.assumeTrue(Sha3.isSha3Available(Sha3AlgorithmType.SHA3_256));

    final me.totoku103.crypto.kisa.sha3.Sha3 kisaSha3 = new me.totoku103.crypto.kisa.sha3.Sha3();
    final me.totoku103.crypto.java.sha3.Sha3 javaSha3 = new me.totoku103.crypto.java.sha3.Sha3();
    final byte[] input = "hello world".getBytes(StandardCharsets.UTF_8);

    final byte[] expected = new byte[32];
    final int rc = kisaSha3.toHash(expected, expected.length, input, input.length, 256, 0);
    final byte[] actual = javaSha3.toHash(input, Sha3AlgorithmType.SHA3_256);

    assertEquals(0, rc);
    assertArrayEquals(expected, actual);
  }
}
