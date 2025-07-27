package me.totoku103.crypto.kisa.aria;

import me.totoku103.crypto.core.utils.ByteUtils;

import java.security.InvalidKeyException;

public final class SimpleAria extends Aria {

  private final byte[] key;

  public SimpleAria(final int keySize, final String key) throws InvalidKeyException {
    super(keySize);
    this.key = ByteUtils.fromHexString(key);
    super.setKey(this.key);
    super.setupRoundKeys();
  }

  public String getKey() {
    return ByteUtils.toHexString(this.key);
  }

  public String encryptEcb(final String plain) throws InvalidKeyException {
    final String hex = ByteUtils.stringToHex(plain);
    final byte[] plainBytes = ByteUtils.fromHexString(hex);
    final byte[] encrypted = encrypt(plainBytes, 0);
    return ByteUtils.toHexString(encrypted);
  }

  public String decryptEcb(final String cipher) throws InvalidKeyException {
    final byte[] cipherBytes = ByteUtils.fromHexString(cipher);
    final byte[] decrypted = decrypt(cipherBytes, 0);
    final String hex = ByteUtils.toHexString(decrypted);
    return ByteUtils.hexToString(hex);
  }
}
