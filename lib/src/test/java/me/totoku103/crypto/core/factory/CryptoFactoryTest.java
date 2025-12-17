package me.totoku103.crypto.core.factory;

import me.totoku103.crypto.algorithms.cipher.AriaBlockCipher;
import me.totoku103.crypto.algorithms.cipher.Aes256BlockCipher;
import me.totoku103.crypto.algorithms.cipher.SeedBlockCipher;
import me.totoku103.crypto.algorithms.hash.Sha256Jdk;
import me.totoku103.crypto.algorithms.hash.Sha256Kisa;
import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.HashAlgorithm;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.*;

/** CryptoFactory를 테스트합니다. */
class CryptoFactoryTest {

  @Test
  void testCreateHashAlgorithmSha256Jdk() {
    HashAlgorithm algorithm = CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_JDK);

    assertNotNull(algorithm);
    assertTrue(algorithm instanceof Sha256Jdk);
    assertEquals("SHA-256", algorithm.getAlgorithmName());
    assertEquals("1.0.0", algorithm.getVersion());
    assertEquals(32, algorithm.getHashLength());
  }

  @Test
  void testCreateHashAlgorithmSha256Kisa() {
    HashAlgorithm algorithm = CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_KISA);

    assertNotNull(algorithm);
    assertTrue(algorithm instanceof Sha256Kisa);
    assertEquals("SHA-256-KISA", algorithm.getAlgorithmName());
    assertEquals("1.0.0", algorithm.getVersion());
    assertEquals(32, algorithm.getHashLength());
  }

  @Test
  void testCreateHashAlgorithmWithInvalidType() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          CryptoFactory.createHashAlgorithm(null);
        });
  }

  @Test
  void testCreateBlockCipherSeed() throws InvalidKeyException {
    BlockCipher cipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.SEED);

    assertNotNull(cipher);
    assertTrue(cipher instanceof SeedBlockCipher);
    assertEquals("SEED", cipher.getAlgorithmName());
    assertEquals("1.0.0", cipher.getVersion());
    assertEquals(16, cipher.getBlockSize());
    assertEquals(16, cipher.getKeySize());
  }

  @Test
  void testCreateBlockCipherAria() throws InvalidKeyException {
    BlockCipher cipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.ARIA);

    assertNotNull(cipher);
    assertTrue(cipher instanceof AriaBlockCipher);
    assertEquals("ARIA", cipher.getAlgorithmName());
    assertEquals("1.0.0", cipher.getVersion());
    assertEquals(16, cipher.getBlockSize());
    assertEquals(16, cipher.getKeySize());
  }

  @Test
  void testCreateBlockCipherAes256() throws InvalidKeyException {
    BlockCipher cipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.AES256);

    assertNotNull(cipher);
    assertTrue(cipher instanceof Aes256BlockCipher);
    assertEquals("AES-256", cipher.getAlgorithmName());
    assertEquals("1.0.0", cipher.getVersion());
    assertEquals(16, cipher.getBlockSize());
    assertEquals(32, cipher.getKeySize());
  }

  @Test
  void testCreateBlockCipherWithInvalidType() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          CryptoFactory.createBlockCipher(null);
        });
  }

  @Test
  void testHashAlgorithmFunctionality() {
    HashAlgorithm sha256Jdk = CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_JDK);
    HashAlgorithm sha256Kisa =
        CryptoFactory.createHashAlgorithm(CryptoFactory.HashType.SHA256_KISA);

    String input = "Hello, World!";
    byte[] inputBytes = input.getBytes();

    // 두 알고리즘 모두 같은 입력에 대해 해시를 생성할 수 있어야 함
    byte[] hashJdk = sha256Jdk.hash(inputBytes);
    byte[] hashKisa = sha256Kisa.hash(inputBytes);

    assertEquals(32, hashJdk.length);
    assertEquals(32, hashKisa.length);

    // 16진수 변환도 작동해야 함
    String hexJdk = sha256Jdk.hashToHex(inputBytes);
    String hexKisa = sha256Kisa.hashToHex(inputBytes);

    assertEquals(64, hexJdk.length());
    assertTrue(hexJdk.matches("[0-9a-f]{64}"));
    assertTrue(hexKisa.matches("[0-9a-f]+")); // KISA는 다른 형식일 수 있음
  }

  @Test
  void testBlockCipherFunctionality() throws InvalidKeyException {
    BlockCipher seedCipher = CryptoFactory.createBlockCipher(CryptoFactory.CipherType.SEED);

    String plaintext = "Hello";
    byte[] plaintextBytes = plaintext.getBytes();
    byte[] key = "1234567890123456".getBytes(); // 16 bytes

    // SEED 암호화/복호화 테스트
    byte[] encryptedSeed = seedCipher.encrypt(plaintextBytes, key);
    byte[] decryptedSeed = seedCipher.decrypt(encryptedSeed, key);

    assertEquals(16, encryptedSeed.length);

    // 원본과 복호화된 결과가 같아야 함
    assertArrayEquals(plaintextBytes, decryptedSeed);
  }

  @Test
  void testHashTypeEnum() {
    // 모든 해시 타입이 올바르게 정의되어 있는지 확인
    assertEquals(2, CryptoFactory.HashType.values().length);

    assertNotNull(CryptoFactory.HashType.valueOf("SHA256_JDK"));
    assertNotNull(CryptoFactory.HashType.valueOf("SHA256_KISA"));
  }

  @Test
  void testCipherTypeEnum() {
    // 모든 암호화 타입이 올바르게 정의되어 있는지 확인
    assertEquals(3, CryptoFactory.CipherType.values().length);

    assertNotNull(CryptoFactory.CipherType.valueOf("SEED"));
    assertNotNull(CryptoFactory.CipherType.valueOf("ARIA"));
    assertNotNull(CryptoFactory.CipherType.valueOf("AES256"));
  }
}
