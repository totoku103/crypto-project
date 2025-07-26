package me.totoku103.crypto.kisa.seed.mode;

import me.totoku103.crypto.kisa.seed.Seed;
import me.totoku103.crypto.utils.PaddingUtils;

public class SeedCbc {

  private static final int BLOCK_SIZE = 16;

  public byte[] encrypt(byte[] key, byte[] iv, byte[] plainText) {
    return encrypt(key, iv, plainText, true);
  }

  public byte[] decrypt(byte[] key, byte[] iv, byte[] cipherText) {
    return decrypt(key, iv, cipherText, true);
  }

  public byte[] encrypt(byte[] key, byte[] iv, byte[] plainText, boolean usePadding) {
    byte[] target = usePadding ? PaddingUtils.addPadding(plainText, BLOCK_SIZE) : plainText;

    if (target.length % BLOCK_SIZE != 0) {
      throw new IllegalArgumentException(
          "Data length must be multiple of " + BLOCK_SIZE + " bytes");
    }

    final int[] rKey = new int[32];
    final Seed seed = new Seed();
    seed.keyShed(key, rKey);

    final int[] chain = bytesToInts(iv);
    final byte[] cipherText = new byte[target.length];
    final int[] pIn = new int[4];
    final int[] pOut = new int[4];

    for (int i = 0; i < target.length; i += BLOCK_SIZE) {
      pIn[0] = bytesToInt(target, i);
      pIn[1] = bytesToInt(target, i + 4);
      pIn[2] = bytesToInt(target, i + 8);
      pIn[3] = bytesToInt(target, i + 12);

      pIn[0] ^= chain[0];
      pIn[1] ^= chain[1];
      pIn[2] ^= chain[2];
      pIn[3] ^= chain[3];

      seed.encrypt(pOut, pIn, rKey);

      chain[0] = pOut[0];
      chain[1] = pOut[1];
      chain[2] = pOut[2];
      chain[3] = pOut[3];

      System.arraycopy(intsToBytes(pOut), 0, cipherText, i, BLOCK_SIZE);
    }
    return cipherText;
  }

  public byte[] decrypt(byte[] key, byte[] iv, byte[] cipherText, boolean usePadding) {
    if (cipherText.length % BLOCK_SIZE != 0) {
      throw new IllegalArgumentException(
          "Ciphertext length must be multiple of " + BLOCK_SIZE + " bytes");
    }

    final int[] rKey = new int[32];
    final Seed seed = new Seed();
    seed.keyShed(key, rKey);

    final int[] chain = bytesToInts(iv);
    final byte[] plainText = new byte[cipherText.length];
    final int[] pIn = new int[4];
    final int[] pOut = new int[4];
    final int[] nextChain = new int[4];

    for (int i = 0; i < cipherText.length; i += BLOCK_SIZE) {
      pIn[0] = bytesToInt(cipherText, i);
      pIn[1] = bytesToInt(cipherText, i + 4);
      pIn[2] = bytesToInt(cipherText, i + 8);
      pIn[3] = bytesToInt(cipherText, i + 12);

      nextChain[0] = pIn[0];
      nextChain[1] = pIn[1];
      nextChain[2] = pIn[2];
      nextChain[3] = pIn[3];

      seed.decrypt(pOut, pIn, rKey);

      pOut[0] ^= chain[0];
      pOut[1] ^= chain[1];
      pOut[2] ^= chain[2];
      pOut[3] ^= chain[3];

      System.arraycopy(intsToBytes(pOut), 0, plainText, i, BLOCK_SIZE);

      chain[0] = nextChain[0];
      chain[1] = nextChain[1];
      chain[2] = nextChain[2];
      chain[3] = nextChain[3];
    }

    return usePadding ? PaddingUtils.removePadding(plainText, BLOCK_SIZE) : plainText;
  }

  private int[] bytesToInts(byte[] bytes) {
    int[] ints = new int[bytes.length / 4];
    for (int i = 0; i < ints.length; i++) {
      ints[i] = bytesToInt(bytes, i * 4);
    }
    return ints;
  }

  private int bytesToInt(byte[] bytes, int offset) {
    return ((bytes[offset] & 0xff) << 24)
        | ((bytes[offset + 1] & 0xff) << 16)
        | ((bytes[offset + 2] & 0xff) << 8)
        | (bytes[offset + 3] & 0xff);
  }

  private byte[] intsToBytes(int[] ints) {
    byte[] bytes = new byte[ints.length * 4];
    for (int i = 0; i < ints.length; i++) {
      bytes[i * 4] = (byte) (ints[i] >> 24);
      bytes[i * 4 + 1] = (byte) (ints[i] >> 16);
      bytes[i * 4 + 2] = (byte) (ints[i] >> 8);
      bytes[i * 4 + 3] = (byte) ints[i];
    }
    return bytes;
  }
}
