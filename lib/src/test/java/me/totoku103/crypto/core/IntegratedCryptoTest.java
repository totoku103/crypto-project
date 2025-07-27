package me.totoku103.crypto.core;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import me.totoku103.crypto.algorithms.cipher.AriaBlockCipher;
import me.totoku103.crypto.algorithms.cipher.SeedBlockCipher;
import me.totoku103.crypto.algorithms.hash.Sha256Jdk;
import me.totoku103.crypto.algorithms.hash.Sha256Kisa;
import me.totoku103.crypto.core.factory.CryptoFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 모든 암호화 알고리즘을 통합 테스트하는 클래스 */
@DisplayName("통합 암호화 테스트")
class IntegratedCryptoTest extends BaseCryptoTest {

  @Test
  @DisplayName("모든 해시 알고리즘 테스트")
  void testAllHashAlgorithms() {
    // JDK SHA-256 테스트
    HashAlgorithm sha256Jdk = new Sha256Jdk();
    testHashAlgorithm(sha256Jdk, "JDK SHA-256");

    // KISA SHA-256 테스트
    HashAlgorithm sha256Kisa = new Sha256Kisa();
    testHashAlgorithm(sha256Kisa, "KISA SHA-256");

    // 팩토리를 통한 생성 테스트
    HashAlgorithm factorySha256Jdk =
        CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_JDK);
    HashAlgorithm factorySha256Kisa =
        CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_KISA);

    testHashAlgorithm(factorySha256Jdk, "Factory JDK SHA-256");
    testHashAlgorithm(factorySha256Kisa, "Factory KISA SHA-256");
  }

  @Test
  @DisplayName("모든 블록 암호화 알고리즘 테스트")
  void testAllBlockCipherAlgorithms() throws InvalidKeyException {
    // SEED 테스트
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    testBlockCipher(seedCipher, "SEED");

    // ARIA 테스트
    AriaBlockCipher ariaCipher = new AriaBlockCipher();
    testBlockCipher(ariaCipher, "ARIA");

    // 팩토리를 통한 생성 테스트
    BlockCipher factorySeedCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.SEED);
    BlockCipher factoryAriaCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.ARIA);

    testBlockCipher(factorySeedCipher, "Factory SEED");
    testBlockCipher(factoryAriaCipher, "Factory ARIA");
  }

  @Test
  @DisplayName("다양한 입력 데이터로 테스트")
  void testWithVariousInputData() throws InvalidKeyException {
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    AriaBlockCipher ariaCipher = new AriaBlockCipher();

    for (String testString : TEST_STRINGS) {
      byte[] testData = testString.getBytes();

      // SEED 테스트
      byte[] seedEncrypted = seedCipher.encrypt(testData, TEST_KEY_16);
      byte[] seedDecrypted = seedCipher.decrypt(seedEncrypted, TEST_KEY_16);
      assertEncryptDecryptMatch(testData, seedDecrypted, "SEED with " + testString);

      // ARIA 테스트
      byte[] ariaEncrypted = ariaCipher.encrypt(testData, TEST_KEY_16);
      byte[] ariaDecrypted = ariaCipher.decrypt(ariaEncrypted, TEST_KEY_16);
      assertEncryptDecryptMatch(testData, ariaDecrypted, "ARIA with " + testString);
    }
  }

  @Test
  @DisplayName("성능 테스트")
  void testPerformance() throws InvalidKeyException {
    SeedBlockCipher seedCipher = new SeedBlockCipher();
    AriaBlockCipher ariaCipher = new AriaBlockCipher();
    Sha256Jdk sha256Jdk = new Sha256Jdk();

    // 큰 데이터로 성능 테스트
    StringBuilder largeData = new StringBuilder();
    for (int i = 0; i < 1000; i++) {
      largeData.append("Hello, World! ");
    }
    byte[] largeBytes = largeData.toString().getBytes();

    long startTime = System.currentTimeMillis();

    // SEED 성능 테스트
    for (int i = 0; i < 100; i++) {
      byte[] encrypted = seedCipher.encrypt(largeBytes, TEST_KEY_16);
      seedCipher.decrypt(encrypted, TEST_KEY_16);
    }
    long seedTime = System.currentTimeMillis() - startTime;

    // ARIA 성능 테스트
    startTime = System.currentTimeMillis();
    for (int i = 0; i < 100; i++) {
      byte[] encrypted = ariaCipher.encrypt(largeBytes, TEST_KEY_16);
      ariaCipher.decrypt(encrypted, TEST_KEY_16);
    }
    long ariaTime = System.currentTimeMillis() - startTime;

    // SHA-256 성능 테스트
    startTime = System.currentTimeMillis();
    for (int i = 0; i < 100; i++) {
      sha256Jdk.hash(largeBytes);
    }
    long hashTime = System.currentTimeMillis() - startTime;

    System.out.println("Performance Test Results:");
    System.out.println("SEED: " + seedTime + "ms");
    System.out.println("ARIA: " + ariaTime + "ms");
    System.out.println("SHA-256: " + hashTime + "ms");

    // 성능이 합리적인 범위 내에 있는지 확인
    assertTrue(seedTime < 10000, "SEED performance should be reasonable");
    assertTrue(ariaTime < 10000, "ARIA performance should be reasonable");
    assertTrue(hashTime < 5000, "SHA-256 performance should be reasonable");
  }

  private void testHashAlgorithm(HashAlgorithm algorithm, String algorithmName) {
    System.out.println("Testing " + algorithmName);

    // 기본 속성 테스트
    assertEquals(32, algorithm.getHashLength(), algorithmName + " hash length");
    assertNotNull(algorithm.getAlgorithmName(), algorithmName + " algorithm name");
    assertNotNull(algorithm.getVersion(), algorithmName + " version");

    // 다양한 입력으로 테스트
    for (String testString : TEST_STRINGS) {
      byte[] input = testString.getBytes();

      // 바이트 배열 해시 테스트
      byte[] hash = algorithm.hash(input);
      assertValidBytes(hash, algorithmName + " hash result");
      assertEquals(32, hash.length, algorithmName + " hash length should be 32 bytes");

      // 16진수 해시 테스트
      String hexHash = algorithm.hashToHex(input);
      assertValidHexString(hexHash, 64, algorithmName + " hex hash");

      // 같은 입력에 대해 같은 해시가 나와야 함
      byte[] hash2 = algorithm.hash(input);
      assertArrayEquals(hash, hash2, algorithmName + " should produce consistent hash");

      // 16진수 해시도 일관성이 있어야 함 (대소문자 차이 무시)
      String hexHash2 = algorithm.hashToHex(input);
      assertEquals(
          hexHash.toLowerCase(),
          hexHash2.toLowerCase(),
          algorithmName + " should produce consistent hex hash");
      
      // 해시 길이 확인 (KISA는 다른 형식일 수 있음)
      assertTrue(hexHash.length() >= 32, algorithmName + " hex hash should be at least 32 characters");
    }

    // 빈 입력 테스트
    byte[] emptyHash = algorithm.hash(new byte[0]);
    assertValidBytes(emptyHash, algorithmName + " empty input hash");

    // null 입력 테스트
    assertThrows(
        RuntimeException.class,
        () -> {
          algorithm.hash(null);
        },
        algorithmName + " should throw exception for null input");
  }

  private void testBlockCipher(BlockCipher cipher, String algorithmName)
      throws InvalidKeyException {
    System.out.println("Testing " + algorithmName);

    // 기본 속성 테스트
    assertEquals(16, cipher.getBlockSize(), algorithmName + " block size");
    assertEquals(16, cipher.getKeySize(), algorithmName + " key size");
    assertNotNull(cipher.getAlgorithmName(), algorithmName + " algorithm name");
    assertNotNull(cipher.getVersion(), algorithmName + " version");

    // 다양한 입력으로 테스트
    for (String testString : TEST_STRINGS) {
      byte[] input = testString.getBytes();

      // 암호화 테스트
      byte[] encrypted = cipher.encrypt(input, TEST_KEY_16);
      assertValidBytes(encrypted, algorithmName + " encrypted result");
      assertEquals(16, encrypted.length, algorithmName + " encrypted length should be 16 bytes");

      // 복호화 테스트
      byte[] decrypted = cipher.decrypt(encrypted, TEST_KEY_16);
      assertValidBytes(decrypted, algorithmName + " decrypted result");

      // 원본과 복호화된 결과가 같아야 함
      assertEncryptDecryptMatch(input, decrypted, algorithmName + " with " + testString);
    }

    // 잘못된 키 크기 테스트
    byte[] invalidKey = "123".getBytes();
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.encrypt(TEST_STRING_1.getBytes(), invalidKey);
        },
        algorithmName + " should throw exception for invalid key size");

    // null 입력 테스트
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.encrypt(null, TEST_KEY_16);
        },
        algorithmName + " should throw exception for null plaintext");

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          cipher.encrypt(TEST_STRING_1.getBytes(), null);
        },
        algorithmName + " should throw exception for null key");
  }
}
