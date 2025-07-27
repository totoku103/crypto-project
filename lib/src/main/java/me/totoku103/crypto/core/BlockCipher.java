package me.totoku103.crypto.core;

/** 블록 암호화 알고리즘 인터페이스 */
public interface BlockCipher extends CryptoAlgorithm {

  /**
   * 암호화를 수행합니다.
   *
   * @param plaintext 평문
   * @param key 암호화 키
   * @return 암호문
   */
  byte[] encrypt(byte[] plaintext, byte[] key);

  /**
   * 복호화를 수행합니다.
   *
   * @param ciphertext 암호문
   * @param key 복호화 키
   * @return 평문
   */
  byte[] decrypt(byte[] ciphertext, byte[] key);

  /**
   * 블록 크기를 반환합니다.
   *
   * @return 블록 크기 (바이트)
   */
  int getBlockSize();

  /**
   * 키 크기를 반환합니다.
   *
   * @return 키 크기 (바이트)
   */
  int getKeySize();
}
