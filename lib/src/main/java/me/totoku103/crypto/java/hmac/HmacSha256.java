package me.totoku103.crypto.java.hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC using SHA-256 via JDK {@link javax.crypto.Mac}. */
public class HmacSha256 {
  private static final String ALGORITHM_NAME = "HmacSHA256";
  private static final int OK = 0;
  private static final int PARAMETER_ERROR = 1;

  /** Check whether HmacSHA256 algorithm is available in this JDK. */
  public static boolean isHmacSha256Available() {
    try {
      Mac.getInstance(ALGORITHM_NAME);
      return true;
    } catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

  /**
   * Calculate HMAC-SHA256 of the input using the given key and store the result in the output
   * buffer.
   *
   * @param output result buffer
   * @param outLen expected output length (32)
   * @param key secret key
   * @param keyLen key length
   * @param input input data
   * @param inLen input length
   * @return 0 if successful
   */
  public int hmacSha256(
      final byte[] output,
      final int outLen,
      final byte[] key,
      final int keyLen,
      final byte[] input,
      final int inLen) {
    try {
      final Mac mac = Mac.getInstance(ALGORITHM_NAME);
      final SecretKeySpec keySpec = new SecretKeySpec(key, 0, keyLen, ALGORITHM_NAME);
      mac.init(keySpec);
      mac.update(input, 0, inLen);
      final byte[] result = mac.doFinal();
      System.arraycopy(result, 0, output, 0, outLen);
      return OK;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      return PARAMETER_ERROR;
    }
  }

  /** Return a new array containing the HMAC-SHA256 value of the input. */
  public byte[] toHmac(final byte[] key, final byte[] input) {
    try {
      final Mac mac = Mac.getInstance(ALGORITHM_NAME);
      mac.init(new SecretKeySpec(key, ALGORITHM_NAME));
      return mac.doFinal(input);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalArgumentException("Unsupported algorithm or invalid key", e);
    }
  }

  /** Return the HMAC as a lowercase hex string. */
  public String encrypt(final byte[] key, final byte[] input) {
    final byte[] hmac = toHmac(key, input);
    final StringBuilder sb = new StringBuilder();
    for (final byte b : hmac) {
      sb.append(String.format("%02x", b & 0xff));
    }
    return sb.toString();
  }
}
