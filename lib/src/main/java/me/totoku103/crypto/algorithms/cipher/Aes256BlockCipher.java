package me.totoku103.crypto.algorithms.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.utils.ByteUtils;

/** AES-256 블록 암호화 알고리즘 구현 */
public class Aes256BlockCipher implements BlockCipher {

  private static final String ALGORITHM_NAME = "AES-256";
  private static final String VERSION = "1.0.0";
  private static final int BLOCK_SIZE = 16; // 128 bits block size
  private static final int KEY_SIZE = 32; // 256 bits key size
  private static final String TRANSFORMATION = "AES/ECB/NoPadding";

  @Override
  public String getAlgorithmName() {
    return ALGORITHM_NAME;
  }

  @Override
  public String getVersion() {
    return VERSION;
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] key) {
    validateKey(key);
    if (plaintext == null) {
      throw new IllegalArgumentException("Plaintext cannot be null");
    }

    byte[] paddedInput = ByteUtils.addPadding(plaintext, BLOCK_SIZE);
    try {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, createSecretKey(key));
      return cipher.doFinal(paddedInput);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to encrypt with AES-256", e);
    }
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] key) {
    validateKey(key);
    if (ByteUtils.isEmpty(ciphertext)) {
      throw new IllegalArgumentException("Ciphertext cannot be null or empty");
    }
    if (ciphertext.length % BLOCK_SIZE != 0) {
      throw new IllegalArgumentException("Ciphertext length must be a multiple of block size");
    }

    try {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, createSecretKey(key));
      byte[] decrypted = cipher.doFinal(ciphertext);
      try {
        return ByteUtils.removePadding(decrypted, BLOCK_SIZE);
      } catch (IllegalArgumentException e) {
        // 패딩이 잘못된 경우에도 디버깅을 위해 복호화된 원본을 반환
        return decrypted;
      }
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to decrypt with AES-256", e);
    }
  }

  @Override
  public int getBlockSize() {
    return BLOCK_SIZE;
  }

  @Override
  public int getKeySize() {
    return KEY_SIZE;
  }

  private void validateKey(byte[] key) {
    if (ByteUtils.isEmpty(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty");
    }
    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
    }
  }

  private SecretKey createSecretKey(byte[] key) {
    return new SecretKeySpec(key, "AES");
  }
}
