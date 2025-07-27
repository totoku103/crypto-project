package me.totoku103.crypto.algorithms.hash;

import me.totoku103.crypto.core.AbstractHashAlgorithm;

/** KISA에서 제공하는 SHA-256 해시 알고리즘 구현 */
public class Sha256Kisa extends AbstractHashAlgorithm {

  private static final String ALGORITHM_NAME = "SHA-256-KISA";
  private static final int HASH_LENGTH = 32;

  @Override
  public String getAlgorithmName() {
    return ALGORITHM_NAME;
  }

  @Override
  public byte[] hash(byte[] input) {
    byte[] digest = new byte[HASH_LENGTH];
    me.totoku103.crypto.kisa.sha2.Sha256.encrypt(input, input.length, digest);
    return digest;
  }

  @Override
  public int getHashLength() {
    return HASH_LENGTH;
  }

  @Override
  public String hashToHex(byte[] input) {
    return me.totoku103.crypto.kisa.sha2.Sha256.encrypt(input);
  }
}
