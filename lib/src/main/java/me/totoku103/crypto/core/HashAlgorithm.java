package me.totoku103.crypto.core;

/** 해시 알고리즘 인터페이스 */
public interface HashAlgorithm extends CryptoAlgorithm {

  /**
   * 해시를 계산합니다.
   *
   * @param input 입력 데이터
   * @return 해시 값
   */
  byte[] hash(byte[] input);

  /**
   * 해시를 계산하여 16진수 문자열로 반환합니다.
   *
   * @param input 입력 데이터
   * @return 16진수 해시 문자열
   */
  String hashToHex(byte[] input);

  /**
   * 해시 길이를 반환합니다.
   *
   * @return 해시 길이 (바이트)
   */
  int getHashLength();
}
