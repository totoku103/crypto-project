package me.totoku103.crypto.algorithms.cipher;

import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.utils.ByteUtils;

import java.security.InvalidKeyException;

/** ARIA 블록 암호화 알고리즘 구현 */
public class AriaBlockCipher implements BlockCipher {

  private static final String ALGORITHM_NAME = "ARIA";
  private static final String VERSION = "1.0.0";
  private static final int BLOCK_SIZE = 16; // 128 bits
  private static final int KEY_SIZE = 16; // 128 bits

  private final me.totoku103.crypto.kisa.aria.AriaWrapper aria;

  public AriaBlockCipher() throws InvalidKeyException {
    this.aria = new me.totoku103.crypto.kisa.aria.AriaWrapper(128);
  }

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
    if (plaintext == null || ByteUtils.isEmpty(key)) {
      throw new IllegalArgumentException("Plaintext and key cannot be null or empty");
    }

    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
    }

    // 입력 데이터를 블록 크기에 맞춰 패딩
    byte[] paddedInput = ByteUtils.addPadding(plaintext, BLOCK_SIZE);

    try {
      aria.setKey(key);
      return aria.encrypt(paddedInput, 0);
    } catch (InvalidKeyException e) {
      throw new RuntimeException("Failed to encrypt with ARIA", e);
    }
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] key) {
    if (ByteUtils.isEmpty(ciphertext) || ByteUtils.isEmpty(key)) {
      throw new IllegalArgumentException("Ciphertext and key cannot be null or empty");
    }

    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
    }

    if (ciphertext.length != BLOCK_SIZE) {
      throw new IllegalArgumentException("Ciphertext must be " + BLOCK_SIZE + " bytes");
    }

    try {
      aria.setKey(key);
      byte[] decrypted = aria.decrypt(ciphertext, 0);

      // 패딩 제거 (안전하게 처리)
      try {
        return ByteUtils.removePadding(decrypted, BLOCK_SIZE);
      } catch (IllegalArgumentException e) {
        // 패딩이 유효하지 않으면 원본 반환
        return decrypted;
      }
    } catch (InvalidKeyException e) {
      throw new RuntimeException("Failed to decrypt with ARIA", e);
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
}
