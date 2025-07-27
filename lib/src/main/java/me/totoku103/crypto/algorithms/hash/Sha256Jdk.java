package me.totoku103.crypto.algorithms.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import me.totoku103.crypto.core.AbstractHashAlgorithm;

/** JDK MessageDigest를 이용한 SHA-256 해시 알고리즘 구현 */
public class Sha256Jdk extends AbstractHashAlgorithm {

  private static final String ALGORITHM_NAME = "SHA-256";
  private static final int HASH_LENGTH = 32;

  @Override
  public String getAlgorithmName() {
    return ALGORITHM_NAME;
  }

  @Override
  public byte[] hash(byte[] input) {
    try {
      MessageDigest md = MessageDigest.getInstance(ALGORITHM_NAME);
      return md.digest(input);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }
  }

  @Override
  public int getHashLength() {
    return HASH_LENGTH;
  }

  /**
   * JDK에서 SHA-256 알고리즘 지원 여부를 확인합니다.
   *
   * @return 지원 여부
   */
  public static boolean isAvailable() {
    try {
      MessageDigest.getInstance(ALGORITHM_NAME);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }
}
