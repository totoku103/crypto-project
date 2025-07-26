package me.totoku103.crypto.kisa.aria;

import java.security.InvalidKeyException;
import me.totoku103.crypto.utils.HexConverter;

public final class SimpleAria extends Aria {

  private final byte[] key;

  public SimpleAria(final int keySize, final String key) throws InvalidKeyException {
    super(keySize);
    this.key = HexConverter.toBytes(key);
    super.setKey(this.key);
    super.setupRoundKeys();
  }

  public String getKey() {
    return HexConverter.fromBytes(this.key);
  }

  public String encryptEcb(final String plain) throws InvalidKeyException {
    final String hex = HexConverter.fromString(plain);
    final byte[] plainBytes = HexConverter.toBytes(hex);
    final byte[] encrypted = encrypt(plainBytes, 0);
    return HexConverter.fromBytes(encrypted);
  }

  public String decryptEcb(final String cipher) throws InvalidKeyException {
    final byte[] cipherBytes = HexConverter.toBytes(cipher);
    final byte[] decrypted = decrypt(cipherBytes, 0);
    final String hex = HexConverter.fromBytes(decrypted);
    return HexConverter.toString(hex);
  }
}
