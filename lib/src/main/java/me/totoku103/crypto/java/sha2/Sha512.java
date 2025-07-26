package me.totoku103.crypto.java.sha2;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-512 hashing using {@link java.security.MessageDigest}. */
public class Sha512 {
  private static final String ALGORITHM_NAME = "SHA-512";
  private static final int OK = 0;
  private static final int PARAMETER_ERROR = 1;

  /** Check whether SHA-512 algorithm is available in this JDK. */
  public static boolean isSha512Available() {
    try {
      MessageDigest.getInstance(ALGORITHM_NAME);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  /**
   * Hash the given input and store the result in the output buffer.
   *
   * @param output result buffer
   * @param outLen expected output length (64)
   * @param input input data
   * @param inLen input length
   * @return 0 if successful
   */
  public int sha512Hash(
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

  /** Return a new array with the SHA-512 digest of the input. */
  public byte[] toHash(final byte[] input) {
    try {
      final MessageDigest md = MessageDigest.getInstance(ALGORITHM_NAME);
      return md.digest(input);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException("Unsupported " + ALGORITHM_NAME, e);
    }
  }

  /** Return the digest as a hex string. */
  public String encrypt(final byte[] input) {
    final byte[] digest = toHash(input);
    final StringBuilder sb = new StringBuilder();
    for (final byte b : digest) {
      sb.append(String.format("%02x", b & 0xff));
    }
    return sb.toString();
  }
}
