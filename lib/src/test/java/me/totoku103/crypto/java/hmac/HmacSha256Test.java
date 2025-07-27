package me.totoku103.crypto.java.hmac;

import me.totoku103.crypto.core.utils.ByteUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HmacSha256Test {

  private HmacSha256 hmac;

  @BeforeEach
  void setUp() {
    this.hmac = new HmacSha256();
  }

  @Test
  @DisplayName("JDK에서 HmacSHA256 지원 여부 확인")
  void isHmacSha256Available() {
    assertTrue(HmacSha256.isHmacSha256Available());
  }

  @Test
  @DisplayName("RFC 4231 테스트 벡터 #1 검증")
  void testVector1() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
    byte[] key = new byte[20];
    java.util.Arrays.fill(key, (byte) 0x0b);
    byte[] data = "Hi There".getBytes(StandardCharsets.UTF_8);
    byte[] expected =
        ByteUtils.fromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    byte[] out = new byte[32];

    int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
    assertEquals(0, rc);
    assertArrayEquals(expected, out);
  }

  @Test
  @DisplayName("RFC 4231 테스트 벡터 #2 검증")
  void testVector2() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
    byte[] key = "Jefe".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] data = "what do ya want for nothing?".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] expected =
        ByteUtils.fromHexString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    byte[] out = new byte[32];

    int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
    assertEquals(0, rc);
    assertArrayEquals(expected, out);
  }

  @Test
  @DisplayName("RFC 4231 테스트 벡터 #3 검증")
  void testVector3() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
    byte[] key = new byte[20];
    java.util.Arrays.fill(key, (byte) 0xaa);
    byte[] data = new byte[50];
    java.util.Arrays.fill(data, (byte) 0xdd);
    byte[] expected =
        ByteUtils.fromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    byte[] out = new byte[32];

    int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
    assertEquals(0, rc);
    assertArrayEquals(expected, out);
  }

  @Test
  @DisplayName("RFC 4231 테스트 벡터 #4 검증")
  void testVector4() {
    Assumptions.assumeTrue(HmacSha256.isHmacSha256Available());
    byte[] key = new byte[25];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) (i + 1);
    }
    byte[] data = new byte[50];
    java.util.Arrays.fill(data, (byte) 0xcd);
    byte[] expected =
        ByteUtils.fromHexString("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    byte[] out = new byte[32];

    int rc = hmac.hmacSha256(out, out.length, key, key.length, data, data.length);
    assertEquals(0, rc);
    assertArrayEquals(expected, out);
  }
}
