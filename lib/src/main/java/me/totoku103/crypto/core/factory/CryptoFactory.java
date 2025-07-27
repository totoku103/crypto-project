package me.totoku103.crypto.core.factory;

import me.totoku103.crypto.algorithms.cipher.AriaBlockCipher;
import me.totoku103.crypto.algorithms.cipher.SeedBlockCipher;
import me.totoku103.crypto.algorithms.hash.Sha256Jdk;
import me.totoku103.crypto.algorithms.hash.Sha256Kisa;
import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.HashAlgorithm;

import java.security.InvalidKeyException;

/** 암호화 알고리즘을 생성하는 팩토리 클래스 */
public class CryptoFactory {

  /** 해시 알고리즘 타입 */
  public enum HashType {
    SHA256_JDK,
    SHA256_KISA
  }

  /** 블록 암호화 알고리즘 타입 */
  public enum CipherType {
    SEED,
    ARIA
  }

  /**
   * SHA-256 해시 알고리즘을 생성합니다.
   *
   * @param type 해시 알고리즘 타입
   * @return 해시 알고리즘 인스턴스
   */
  public static HashAlgorithm createHashAlgorithm(HashType type) {
    if (type == null) {
      throw new IllegalArgumentException("Hash type cannot be null");
    }

    switch (type) {
      case SHA256_JDK:
        return new Sha256Jdk();
      case SHA256_KISA:
        return new Sha256Kisa();
      default:
        throw new IllegalArgumentException("Unsupported hash type: " + type);
    }
  }

  /**
   * 블록 암호화 알고리즘을 생성합니다.
   *
   * @param type 암호화 알고리즘 타입
   * @return 블록 암호화 알고리즘 인스턴스
   * @throws InvalidKeyException 키 크기가 유효하지 않은 경우
   */
  public static BlockCipher createBlockCipher(CipherType type) throws InvalidKeyException {
    if (type == null) {
      throw new IllegalArgumentException("Cipher type cannot be null");
    }

    switch (type) {
      case SEED:
        return new SeedBlockCipher();
      case ARIA:
        return new AriaBlockCipher();
      default:
        throw new IllegalArgumentException("Unsupported cipher type: " + type);
    }
  }
}
