package me.totoku103.crypto.java.sha2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** JDK MessageDigest를 이용해 SHA-256 해시를 계산합니다. */
public class Sha256 {

  private static final String ALGORITHM_NAME = "SHA-256";
  private static final int OK = 0;
  private static final int PARAMETER_ERROR = 1;

  /** JDK에서 SHA-256 알고리즘 지원 여부를 확인합니다. */
  public static boolean isSha256Available() {
    try {
      MessageDigest.getInstance(ALGORITHM_NAME);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  /**
   * SHA-256 해시를 계산해 주어진 버퍼에 결과를 저장합니다.
   *
   * @param output 결과 버퍼
   * @param outLen 출력 길이(byte)
   * @param input 입력 데이터
   * @param inLen 입력 길이
   * @return 성공하면 0, 실패하면 1
   */
  public int sha256Hash(
      final byte[] output, final int outLen, final byte[] input, final int inLen) {
    try {
      final MessageDigest md = MessageDigest.getInstance(ALGORITHM_NAME);
      md.update(input, 0, inLen);
      final byte[] digest = md.digest();
      if (digest.length != outLen) {
        return PARAMETER_ERROR;
      }
      System.arraycopy(digest, 0, output, 0, outLen);
      return OK;
    } catch (NoSuchAlgorithmException e) {
      return PARAMETER_ERROR;
    }
  }

  /** 새 배열로 해시 값을 돌려줍니다. */
  public byte[] toHash(final byte[] input) {
    try {
      final MessageDigest md = MessageDigest.getInstance(ALGORITHM_NAME);
      return md.digest(input);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("Unsupported " + ALGORITHM_NAME, e);
    }
  }

  /**
   * 입력 데이터를 SHA-256으로 해싱하여 64자리 16진수 문자열을 반환한다.
   *
   * <p>기존 {@link me.totoku103.crypto.kisa.sha2.Sha256#encrypt(byte[])} 는 각 바이트에 0 패딩을 하지 않아 문자열 길이가
   * 달라질 수 있다. 이 메서드는 0 패딩을 적용하여 일반적인 결과와 동일한 형식을 제공한다.
   *
   * @param input 입력 데이터
   * @return 64자리 16진수 해시 문자열
   */
  public String encrypt(final byte[] input) {
    final byte[] digest = toHash(input);
    final StringBuilder sb = new StringBuilder();
    for (final byte b : digest) {
      // Sha256Vanilla는 패딩이 없으나 여기서는 두 자리로 고정한다.
      sb.append(String.format("%02x", b & 0xff));
    }
    return sb.toString();
  }
}
