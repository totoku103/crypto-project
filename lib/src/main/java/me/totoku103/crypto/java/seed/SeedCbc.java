package me.totoku103.crypto.java.seed;

import me.totoku103.crypto.enums.SeedCbcTransformations;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Security;

/**
 * Provides SEED encryption and decryption in CBC mode.
 *
 * <p>This implementation uses the Bouncy Castle JCE provider. Ensure that the Bouncy Castle
 * provider is included in your project's dependencies and registered as a security provider.
 */
public final class SeedCbc {

  private static final String ALGORITHM = "SEED";
  private static final int IV_LENGTH = 16; // 128 bits
  private static final int KEY_LENGTH = 16; // 128 bits

  private final String TRANSFORMATION;

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public SeedCbc(SeedCbcTransformations transformations) {
    this.TRANSFORMATION = transformations.getValue();
  }

  /**
   * Encrypts data using the SEED algorithm in CBC mode with PKCS5 padding.
   *
   * @param plainText The data to encrypt.
   * @param key The 128-bit (16-byte) secret key.
   * @param iv The 128-bit (16-byte) initialization vector.
   * @return The encrypted data.
   * @throws IllegalArgumentException if the key or IV is invalid.
   * @throws IllegalStateException if an error occurs during encryption.
   */
  public byte[] encrypt(final byte[] plainText, final byte[] key, final byte[] iv) {
    if (key == null || key.length != KEY_LENGTH) {
      throw new IllegalArgumentException("Key must be 16 bytes.");
    }
    if (iv == null || iv.length != IV_LENGTH) {
      throw new IllegalArgumentException("IV must be 16 bytes.");
    }

    try {
      final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
      final IvParameterSpec ivSpec = new IvParameterSpec(iv);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
      return cipher.doFinal(plainText);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Encryption failed", e);
    }
  }

  /**
   * Decrypts data using the SEED algorithm in CBC mode with PKCS5 padding.
   *
   * @param cipherText The data to decrypt.
   * @param key The 128-bit (16-byte) secret key.
   * @param iv The 128-bit (16-byte) initialization vector.
   * @return The decrypted data.
   * @throws IllegalArgumentException if the key or IV is invalid.
   * @throws IllegalStateException if an error occurs during decryption.
   */
  public byte[] decrypt(final byte[] cipherText, final byte[] key, final byte[] iv) {
    if (key == null || key.length != KEY_LENGTH) {
      throw new IllegalArgumentException("Key must be 16 bytes.");
    }
    if (iv == null || iv.length != IV_LENGTH) {
      throw new IllegalArgumentException("IV must be 16 bytes.");
    }

    try {
      final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
      final IvParameterSpec ivSpec = new IvParameterSpec(iv);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
      return cipher.doFinal(cipherText);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Decryption failed", e);
    }
  }
}
