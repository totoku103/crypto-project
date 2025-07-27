package me.totoku103.crypto.java.sha2;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class Sha512Test {
  private static String toHex(final byte[] data) {
    final StringBuilder sb = new StringBuilder();
    for (final byte b : data) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  @Test
  @DisplayName("JDK SHA-512 지원 확인")
  public void shouldHaveSha512MessageDigest() {
    assertTrue(Sha512.isSha512Available());
  }

  @Test
  @DisplayName("MessageDigest SHA512 결과가 예상 값과 일치")
  public void javaDigestMatchesVector() {
    Assumptions.assumeTrue(Sha512.isSha512Available());
    final Sha512 javaSha = new Sha512();
    byte[] digest = javaSha.toHash("OpenAI".getBytes(StandardCharsets.UTF_8));
    assertEquals(
        "96e6f54ad98f35ebaced4823dac3a4d0c85ae936e91a6688862d4a9c28f1d7d6d370c5f4bace322d27b305b6757fe9e4728d3a44ad3a0acaf483486fa46f78a0",
        toHex(digest));
  }

  @Test
  @DisplayName("KISA 구현과 결과 비교")
  public void matchesKisaImplementation() {
    Assumptions.assumeTrue(Sha512.isSha512Available());
    final Sha512 javaSha = new Sha512();
    final byte[] input = "hello world".getBytes(StandardCharsets.UTF_8);
    final byte[] expected = me.totoku103.crypto.kisa.sha2.Sha512.toHash(input);
    final byte[] actual = javaSha.toHash(input);
    assertArrayEquals(expected, actual);
    assertEquals(
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
        toHex(actual));
  }
}
