package me.totoku103.crypto.core;

import me.totoku103.crypto.core.utils.ByteUtils;

/** 해시 알고리즘의 추상 기본 클래스 */
public abstract class AbstractHashAlgorithm implements HashAlgorithm {

  @Override
  public String hashToHex(byte[] input) {
    byte[] hash = hash(input);
    return ByteUtils.toHexString(hash);
  }

  @Override
  public String getVersion() {
    return "1.0.0";
  }
}
