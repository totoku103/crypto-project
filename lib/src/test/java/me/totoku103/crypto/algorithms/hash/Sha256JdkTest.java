package me.totoku103.crypto.algorithms.hash;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** Sha256Jdk 알고리즘을 테스트합니다. */
class Sha256JdkTest {

  private final Sha256Jdk sha256Jdk = new Sha256Jdk();

  @Test
  void testGetAlgorithmName() {
    assertEquals("SHA-256", sha256Jdk.getAlgorithmName());
  }

  @Test
  void testGetVersion() {
    assertEquals("1.0.0", sha256Jdk.getVersion());
  }

  @Test
  void testGetHashLength() {
    assertEquals(32, sha256Jdk.getHashLength());
  }

  @Test
  void testHash() {
    String input = "Hello, World!";
    byte[] inputBytes = input.getBytes();
    byte[] hash = sha256Jdk.hash(inputBytes);

    assertEquals(32, hash.length);
    assertNotNull(hash);

    // 같은 입력에 대해 같은 해시가 나와야 함
    byte[] hash2 = sha256Jdk.hash(inputBytes);
    assertArrayEquals(hash, hash2);
  }

  @Test
  void testHashToHex() {
    String input = "Hello, World!";
    String hexHash = sha256Jdk.hashToHex(input.getBytes());

    assertEquals(64, hexHash.length()); // SHA-256은 32바이트 = 64자 16진수
    assertTrue(hexHash.matches("[0-9a-f]{64}"));

    // 같은 입력에 대해 같은 해시가 나와야 함
    String hexHash2 = sha256Jdk.hashToHex(input.getBytes());
    assertEquals(hexHash, hexHash2);
  }

  @Test
  void testHashWithEmptyInput() {
    byte[] emptyInput = new byte[0];
    byte[] hash = sha256Jdk.hash(emptyInput);

    assertEquals(32, hash.length);
    assertNotNull(hash);
  }

  @Test
  void testHashWithNullInput() {
    assertThrows(
        RuntimeException.class,
        () -> {
          sha256Jdk.hash(null);
        });
  }

  @Test
  void testIsAvailable() {
    assertTrue(Sha256Jdk.isAvailable());
  }

  @Test
  void testKnownHashValues() {
    // 빈 문자열의 SHA-256 해시
    String emptyHash = sha256Jdk.hashToHex("".getBytes());
    assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash);

    // "Hello"의 SHA-256 해시
    String helloHash = sha256Jdk.hashToHex("Hello".getBytes());
    assertEquals("185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969", helloHash);
  }

  @Test
  void testLargeInput() {
    // 큰 입력 데이터 테스트
    StringBuilder largeInput = new StringBuilder();
    for (int i = 0; i < 1000; i++) {
      largeInput.append("Hello, World! ");
    }

    byte[] inputBytes = largeInput.toString().getBytes();
    byte[] hash = sha256Jdk.hash(inputBytes);

    assertEquals(32, hash.length);
    assertNotNull(hash);
  }

  @Test
  void testUnicodeInput() {
    // 유니코드 문자열 테스트
    String unicodeInput = "안녕하세요, 世界! 🌍";
    String hexHash = sha256Jdk.hashToHex(unicodeInput.getBytes());

    assertEquals(64, hexHash.length());
    assertTrue(hexHash.matches("[0-9a-f]{64}"));
  }
}
