package me.totoku103.crypto.kisa.aria.mode;

import java.util.Arrays;
import java.util.logging.Logger;
import me.totoku103.crypto.kisa.aria.AriaBcBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/** Various ARIA cipher modes implemented with BouncyCastle lightweight API. */
public final class AriaModes {
  private static final Logger log = Logger.getLogger(AriaModes.class.getName());

  private AriaModes() {}

  private static byte[] processBlocks(BlockCipher cipher, byte[] input) {
    final int blockSize = cipher.getBlockSize();
    final byte[] out = new byte[input.length];
    for (int i = 0; i < input.length; i += blockSize) {
      cipher.processBlock(input, i, out, i);
    }
    return out;
  }

  public static byte[] encryptCbc(byte[] key, byte[] iv, byte[] plaintext) {
    log.fine("encrypt CBC");
    final BlockCipher engine = new AriaBcBlockCipher();
    engine.init(true, new KeyParameter(key));
    final byte[] out = new byte[plaintext.length];
    final byte[] block = new byte[engine.getBlockSize()];

    byte[] prev = Arrays.copyOf(iv, iv.length);
    for (int i = 0; i < plaintext.length; i += block.length) {
      System.arraycopy(plaintext, i, block, 0, block.length);
      for (int j = 0; j < block.length; j++) {
        block[j] ^= prev[j];
      }
      engine.processBlock(block, 0, block, 0);
      System.arraycopy(block, 0, out, i, block.length);
      prev = block.clone();
    }
    return out;
  }

  public static byte[] decryptCbc(byte[] key, byte[] iv, byte[] ciphertext) {
    log.fine("decrypt CBC");
    final BlockCipher engine = new AriaBcBlockCipher();
    engine.init(false, new KeyParameter(key));
    final byte[] out = new byte[ciphertext.length];
    final byte[] block = new byte[engine.getBlockSize()];

    byte[] prev = Arrays.copyOf(iv, iv.length);
    for (int i = 0; i < ciphertext.length; i += block.length) {
      System.arraycopy(ciphertext, i, block, 0, block.length);
      final byte[] temp = block.clone();
      engine.processBlock(block, 0, block, 0);
      for (int j = 0; j < block.length; j++) {
        out[i + j] = (byte) (block[j] ^ prev[j]);
      }
      prev = temp;
    }
    return out;
  }

  public static byte[] processCtr(byte[] key, byte[] iv, byte[] input) {
    final BlockCipher engine = new AriaBcBlockCipher();
    final CTRModeCipher ctrModeCipher = SICBlockCipher.newInstance(engine);
    ctrModeCipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
    final byte[] out = new byte[input.length];
    ctrModeCipher.processBytes(input, 0, input.length, out, 0);
    return out;
  }

  public static byte[] encryptCfb(byte[] key, byte[] iv, byte[] plaintext) {
    return encryptCfb(key, iv, plaintext, iv.length * 8);
  }

  public static byte[] encryptCfb(byte[] key, byte[] iv, byte[] plaintext, int segmentBits) {
    final BlockCipher engine = new AriaBcBlockCipher();
    final CFBModeCipher cfbModeCipher = CFBBlockCipher.newInstance(engine, segmentBits);
    cfbModeCipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
    final byte[] out = new byte[plaintext.length];
    cfbModeCipher.processBytes(plaintext, 0, plaintext.length, out, 0);
    return out;
  }

  public static byte[] decryptCfb(byte[] key, byte[] iv, byte[] ciphertext) {
    return decryptCfb(key, iv, ciphertext, iv.length * 8);
  }

  public static byte[] decryptCfb(byte[] key, byte[] iv, byte[] ciphertext, int segmentBits) {
    final BlockCipher engine = new AriaBcBlockCipher();
    final CFBModeCipher cfbModeCipher = CFBBlockCipher.newInstance(engine, segmentBits);
    cfbModeCipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));

    final byte[] out = new byte[ciphertext.length];
    cfbModeCipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
    return out;
  }

  public static byte[] processOfb(byte[] key, byte[] iv, byte[] input) {
    return processOfb(key, iv, input, iv.length * 8);
  }

  public static byte[] processOfb(byte[] key, byte[] iv, byte[] input, int segmentBits) {
    final BlockCipher engine = new AriaBcBlockCipher();
    final OFBBlockCipher ofb = new OFBBlockCipher(engine, segmentBits);
    ofb.init(true, new ParametersWithIV(new KeyParameter(key), iv));
    final byte[] out = new byte[input.length];
    ofb.processBytes(input, 0, input.length, out, 0);
    return out;
  }

  public static class AeadResult {
    public final byte[] ciphertext;
    public final byte[] tag;

    AeadResult(byte[] c, byte[] t) {
      this.ciphertext = c;
      this.tag = t;
    }
  }

  public static AeadResult encryptGcm(
      byte[] key, byte[] iv, byte[] aad, byte[] plaintext, int tagBits) {
    log.fine("encrypt GCM");
    final BlockCipher engine = new AriaBcBlockCipher();
    final GCMModeCipher gcmModeCipher = GCMBlockCipher.newInstance(engine);
    gcmModeCipher.init(true, new AEADParameters(new KeyParameter(key), tagBits, iv, aad));
    byte[] out = new byte[gcmModeCipher.getOutputSize(plaintext.length)];
    int len = gcmModeCipher.processBytes(plaintext, 0, plaintext.length, out, 0);
    try {
      len += gcmModeCipher.doFinal(out, len);
    } catch (InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }
    int tagBytes = tagBits / 8;
    byte[] cipher = Arrays.copyOfRange(out, 0, len - tagBytes);
    byte[] tag = Arrays.copyOfRange(out, len - tagBytes, len);
    return new AeadResult(cipher, tag);
  }

  public static byte[] decryptGcm(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag)
      throws InvalidCipherTextException {
    log.fine("decrypt GCM");
    final BlockCipher engine = new AriaBcBlockCipher();
    final GCMModeCipher gcmModeCipher = GCMBlockCipher.newInstance(engine);
    gcmModeCipher.init(false, new AEADParameters(new KeyParameter(key), tag.length * 8, iv, aad));

    final byte[] in = new byte[ciphertext.length + tag.length];
    final byte[] out = new byte[gcmModeCipher.getOutputSize(in.length)];
    System.arraycopy(ciphertext, 0, in, 0, ciphertext.length);
    System.arraycopy(tag, 0, in, ciphertext.length, tag.length);

    int len = gcmModeCipher.processBytes(in, 0, in.length, out, 0);
    len += gcmModeCipher.doFinal(out, len);
    return Arrays.copyOfRange(out, 0, len);
  }

  public static AeadResult encryptCcm(
      byte[] key, byte[] iv, byte[] aad, byte[] plaintext, int tagBits) {
    log.fine("encrypt CCM");
    final BlockCipher engine = new AriaBcBlockCipher();
    final CCMModeCipher ccmModeCipher = CCMBlockCipher.newInstance(engine);
    ccmModeCipher.init(true, new AEADParameters(new KeyParameter(key), tagBits, iv, aad));
    final byte[] out = new byte[ccmModeCipher.getOutputSize(plaintext.length)];

    int len = ccmModeCipher.processBytes(plaintext, 0, plaintext.length, out, 0);
    try {
      len += ccmModeCipher.doFinal(out, len);
    } catch (InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }

    final byte[] cipher = Arrays.copyOfRange(out, 0, len - tagBits / 8);
    final byte[] tag = Arrays.copyOfRange(out, len - tagBits / 8, len);
    return new AeadResult(cipher, tag);
  }

  public static byte[] decryptCcm(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag)
      throws InvalidCipherTextException {
    log.fine("decrypt CCM");
    final BlockCipher engine = new AriaBcBlockCipher();
    final CCMModeCipher ccmModeCipher = CCMBlockCipher.newInstance(engine);
    ccmModeCipher.init(false, new AEADParameters(new KeyParameter(key), tag.length * 8, iv, aad));

    final byte[] in = new byte[ciphertext.length + tag.length];
    final byte[] out = new byte[ccmModeCipher.getOutputSize(in.length)];
    System.arraycopy(ciphertext, 0, in, 0, ciphertext.length);
    System.arraycopy(tag, 0, in, ciphertext.length, tag.length);

    int len = ccmModeCipher.processBytes(in, 0, in.length, out, 0);
    len += ccmModeCipher.doFinal(out, len);
    return Arrays.copyOfRange(out, 0, len);
  }

  public static byte[] cmac(byte[] key, byte[] data) {
    log.fine("CMAC compute");
    final BlockCipher engine = new AriaBcBlockCipher();
    final CMac cmac = new CMac(engine);
    cmac.init(new KeyParameter(key));
    cmac.update(data, 0, data.length);

    final byte[] mac = new byte[cmac.getMacSize()];
    cmac.doFinal(mac, 0);
    return mac;
  }
}
