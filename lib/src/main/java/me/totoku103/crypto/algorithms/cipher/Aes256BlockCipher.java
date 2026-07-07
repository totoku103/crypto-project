package me.totoku103.crypto.algorithms.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.utils.ByteUtils;
import me.totoku103.crypto.enums.CipherMode;

/**
 * AES-256 블록 암호화 구현. ECB/CBC 모드를 지원하며 모드는 생성자로 정한다(기본값 ECB).
 *
 * <p>CBC일 때 IV를 다루는 방법은 두 가지다.
 *
 * <ul>
 *   <li>2-arg encrypt/decrypt: IV를 랜덤으로 만들어 암호문 앞 16바이트에 붙여 준다. 복호화할 때 다시 떼어 쓰므로
 *       호출부에서 IV를 따로 신경 쓸 필요가 없다.
 *   <li>3-arg encrypt/decrypt: IV를 직접 넘긴다. 암호문에는 IV가 안 붙으니 복호화할 때 같은 IV를 넘겨야 한다.
 *       KAT 벡터 검증이나 외부 시스템과 포맷을 맞춰야 할 때 쓴다.
 * </ul>
 *
 * <p>ECB에는 IV가 없으므로 3-arg를 호출하면 {@link UnsupportedOperationException}이 난다.
 */
public class Aes256BlockCipher implements BlockCipher {

  private static final String ALGORITHM_NAME = "AES-256";
  private static final String VERSION = "1.1.0";
  private static final int BLOCK_SIZE = 16; // 128 bits block size
  private static final int KEY_SIZE = 32; // 256 bits key size
  private static final int IV_SIZE = 16; // 128 bits IV size (CBC)

  private final CipherMode mode;
  private final SecureRandom secureRandom = new SecureRandom();

  /** 기본 생성자. ECB 모드로 동작한다. */
  public Aes256BlockCipher() {
    this(CipherMode.ECB);
  }

  /**
   * 운영 모드를 지정하여 생성한다.
   *
   * @param mode 블록 암호 운영 모드 ({@link CipherMode#ECB} 또는 {@link CipherMode#CBC})
   */
  public Aes256BlockCipher(CipherMode mode) {
    if (mode == null) {
      throw new IllegalArgumentException("Cipher mode cannot be null");
    }
    this.mode = mode;
  }

  @Override
  public String getAlgorithmName() {
    return ALGORITHM_NAME;
  }

  @Override
  public String getVersion() {
    return VERSION;
  }

  /** 이 인스턴스의 운영 모드를 반환한다. */
  public CipherMode getMode() {
    return mode;
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] key) {
    validateKey(key);
    if (plaintext == null) {
      throw new IllegalArgumentException("Plaintext cannot be null");
    }

    byte[] paddedInput = ByteUtils.addPadding(plaintext, BLOCK_SIZE);
    if (mode == CipherMode.ECB) {
      return doCrypt(Cipher.ENCRYPT_MODE, paddedInput, key, null);
    }

    // CBC: 랜덤 IV 생성 후 [IV][암호문] 형태로 반환
    byte[] iv = generateIv();
    byte[] encrypted = doCrypt(Cipher.ENCRYPT_MODE, paddedInput, key, iv);
    byte[] result = new byte[IV_SIZE + encrypted.length];
    ByteUtils.copy(iv, 0, result, 0, IV_SIZE);
    ByteUtils.copy(encrypted, 0, result, IV_SIZE, encrypted.length);
    return result;
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] key) {
    validateKey(key);
    if (ByteUtils.isEmpty(ciphertext)) {
      throw new IllegalArgumentException("Ciphertext cannot be null or empty");
    }

    if (mode == CipherMode.ECB) {
      if (ciphertext.length % BLOCK_SIZE != 0) {
        throw new IllegalArgumentException("Ciphertext length must be a multiple of block size");
      }
      return unpad(doCrypt(Cipher.DECRYPT_MODE, ciphertext, key, null));
    }

    // CBC: 앞 16바이트를 IV로 분리
    if (ciphertext.length <= IV_SIZE || (ciphertext.length - IV_SIZE) % BLOCK_SIZE != 0) {
      throw new IllegalArgumentException(
          "CBC ciphertext must contain a 16-byte IV followed by a block-size multiple of data");
    }
    byte[] iv = new byte[IV_SIZE];
    byte[] body = new byte[ciphertext.length - IV_SIZE];
    ByteUtils.copy(ciphertext, 0, iv, 0, IV_SIZE);
    ByteUtils.copy(ciphertext, IV_SIZE, body, 0, body.length);
    return unpad(doCrypt(Cipher.DECRYPT_MODE, body, key, iv));
  }

  /**
   * IV를 직접 지정해 CBC로 암호화한다. 반환하는 암호문에는 IV가 붙지 않는다.
   *
   * @param plaintext 평문
   * @param key 32바이트 키
   * @param iv 16바이트 IV
   * @return 암호문 (IV 미포함)
   * @throws UnsupportedOperationException ECB 모드에서 호출한 경우
   */
  public byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv) {
    requireCbc();
    validateKey(key);
    validateIv(iv);
    if (plaintext == null) {
      throw new IllegalArgumentException("Plaintext cannot be null");
    }
    byte[] paddedInput = ByteUtils.addPadding(plaintext, BLOCK_SIZE);
    return doCrypt(Cipher.ENCRYPT_MODE, paddedInput, key, iv);
  }

  /**
   * IV를 직접 지정해 CBC로 복호화한다. 암호화 때 쓴 IV를 그대로 넘겨야 한다.
   *
   * @param ciphertext 암호문 (IV 미포함)
   * @param key 32바이트 키
   * @param iv 암호화에 사용한 16바이트 IV
   * @return 평문
   * @throws UnsupportedOperationException ECB 모드에서 호출한 경우
   */
  public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) {
    requireCbc();
    validateKey(key);
    validateIv(iv);
    if (ByteUtils.isEmpty(ciphertext)) {
      throw new IllegalArgumentException("Ciphertext cannot be null or empty");
    }
    if (ciphertext.length % BLOCK_SIZE != 0) {
      throw new IllegalArgumentException("Ciphertext length must be a multiple of block size");
    }
    return unpad(doCrypt(Cipher.DECRYPT_MODE, ciphertext, key, iv));
  }

  @Override
  public int getBlockSize() {
    return BLOCK_SIZE;
  }

  @Override
  public int getKeySize() {
    return KEY_SIZE;
  }

  /** 지정된 방향으로 AES 연산을 수행한다. iv가 null이면 ECB, 아니면 CBC 변환을 사용한다. */
  private byte[] doCrypt(int cipherMode, byte[] input, byte[] key, byte[] iv) {
    try {
      Cipher cipher = Cipher.getInstance(transformation());
      if (iv == null) {
        cipher.init(cipherMode, createSecretKey(key));
      } else {
        cipher.init(cipherMode, createSecretKey(key), new IvParameterSpec(iv));
      }
      return cipher.doFinal(input);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to " + (cipherMode == Cipher.ENCRYPT_MODE ? "encrypt" : "decrypt") + " with AES-256", e);
    }
  }

  /** PKCS7 패딩을 제거한다. 패딩이 잘못된 경우 디버깅을 위해 복호화된 원본을 반환한다. */
  private byte[] unpad(byte[] decrypted) {
    try {
      return ByteUtils.removePadding(decrypted, BLOCK_SIZE);
    } catch (IllegalArgumentException e) {
      // 패딩이 잘못된 경우에도 디버깅을 위해 복호화된 원본을 반환
      return decrypted;
    }
  }

  private String transformation() {
    return mode == CipherMode.CBC ? "AES/CBC/NoPadding" : "AES/ECB/NoPadding";
  }

  private byte[] generateIv() {
    byte[] iv = new byte[IV_SIZE];
    secureRandom.nextBytes(iv);
    return iv;
  }

  private void requireCbc() {
    if (mode != CipherMode.CBC) {
      throw new UnsupportedOperationException("Explicit IV is only supported in CBC mode");
    }
  }

  private void validateKey(byte[] key) {
    if (ByteUtils.isEmpty(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty");
    }
    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
    }
  }

  private void validateIv(byte[] iv) {
    if (ByteUtils.isEmpty(iv)) {
      throw new IllegalArgumentException("IV cannot be null or empty");
    }
    if (iv.length != IV_SIZE) {
      throw new IllegalArgumentException("IV must be " + IV_SIZE + " bytes");
    }
  }

  private SecretKey createSecretKey(byte[] key) {
    return new SecretKeySpec(key, "AES");
  }
}
