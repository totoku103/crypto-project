package me.totoku103.crypto.kisa.aria.mode;

import me.totoku103.crypto.kisa.aria.AriaBcBlockCipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;
import java.util.logging.Logger;

/**
 * Various ARIA cipher modes implemented with BouncyCastle lightweight API.
 */
public final class AriaModes {
    private static final Logger log = Logger.getLogger(AriaModes.class.getName());
    private AriaModes() {}

    private static byte[] processBlocks(BlockCipher cipher, byte[] input) {
        int blockSize = cipher.getBlockSize();
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i += blockSize) {
            cipher.processBlock(input, i, out, i);
        }
        return out;
    }

    public static byte[] encryptCbc(byte[] key, byte[] iv, byte[] plaintext) {
        log.fine("encrypt CBC");
        BlockCipher engine = new AriaBcBlockCipher();
        engine.init(true, new KeyParameter(key));
        byte[] out = new byte[plaintext.length];
        byte[] prev = Arrays.copyOf(iv, iv.length);
        byte[] block = new byte[engine.getBlockSize()];
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
        BlockCipher engine = new AriaBcBlockCipher();
        engine.init(false, new KeyParameter(key));
        byte[] out = new byte[ciphertext.length];
        byte[] prev = Arrays.copyOf(iv, iv.length);
        byte[] block = new byte[engine.getBlockSize()];
        for (int i = 0; i < ciphertext.length; i += block.length) {
            System.arraycopy(ciphertext, i, block, 0, block.length);
            byte[] temp = block.clone();
            engine.processBlock(block, 0, block, 0);
            for (int j = 0; j < block.length; j++) {
                out[i + j] = (byte) (block[j] ^ prev[j]);
            }
            prev = temp;
        }
        return out;
    }

    public static byte[] processCtr(byte[] key, byte[] iv, byte[] input) {
        BlockCipher engine = new AriaBcBlockCipher();
        SICBlockCipher ctr = new SICBlockCipher(engine);
        ctr.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[input.length];
        ctr.processBytes(input, 0, input.length, out, 0);
        return out;
    }

    public static byte[] encryptCfb(byte[] key, byte[] iv, byte[] plaintext) {
        return encryptCfb(key, iv, plaintext, iv.length * 8);
    }

    public static byte[] encryptCfb(byte[] key, byte[] iv, byte[] plaintext, int segmentBits) {
        BlockCipher engine = new AriaBcBlockCipher();
        CFBBlockCipher cfb = new CFBBlockCipher(engine, segmentBits);
        cfb.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[plaintext.length];
        cfb.processBytes(plaintext, 0, plaintext.length, out, 0);
        return out;
    }

    public static byte[] decryptCfb(byte[] key, byte[] iv, byte[] ciphertext) {
        return decryptCfb(key, iv, ciphertext, iv.length * 8);
    }

    public static byte[] decryptCfb(byte[] key, byte[] iv, byte[] ciphertext, int segmentBits) {
        BlockCipher engine = new AriaBcBlockCipher();
        CFBBlockCipher cfb = new CFBBlockCipher(engine, segmentBits);
        cfb.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[ciphertext.length];
        cfb.processBytes(ciphertext, 0, ciphertext.length, out, 0);
        return out;
    }

    public static byte[] processOfb(byte[] key, byte[] iv, byte[] input) {
        return processOfb(key, iv, input, iv.length * 8);
    }

    public static byte[] processOfb(byte[] key, byte[] iv, byte[] input, int segmentBits) {
        BlockCipher engine = new AriaBcBlockCipher();
        OFBBlockCipher ofb = new OFBBlockCipher(engine, segmentBits);
        ofb.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[input.length];
        ofb.processBytes(input, 0, input.length, out, 0);
        return out;
    }

    public static class AeadResult {
        public final byte[] ciphertext;
        public final byte[] tag;
        AeadResult(byte[] c, byte[] t) { this.ciphertext = c; this.tag = t; }
    }

    public static AeadResult encryptGcm(byte[] key, byte[] iv, byte[] aad, byte[] plaintext, int tagBits) {
        log.fine("encrypt GCM");
        BlockCipher engine = new AriaBcBlockCipher();
        GCMBlockCipher gcm = new GCMBlockCipher(engine);
        gcm.init(true, new AEADParameters(new KeyParameter(key), tagBits, iv, aad));
        byte[] out = new byte[gcm.getOutputSize(plaintext.length)];
        int len = gcm.processBytes(plaintext, 0, plaintext.length, out, 0);
        try {
            len += gcm.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e);
        }
        int tagBytes = tagBits / 8;
        byte[] cipher = Arrays.copyOfRange(out, 0, len - tagBytes);
        byte[] tag = Arrays.copyOfRange(out, len - tagBytes, len);
        return new AeadResult(cipher, tag);
    }

    public static byte[] decryptGcm(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws InvalidCipherTextException {
        log.fine("decrypt GCM");
        BlockCipher engine = new AriaBcBlockCipher();
        GCMBlockCipher gcm = new GCMBlockCipher(engine);
        gcm.init(false, new AEADParameters(new KeyParameter(key), tag.length * 8, iv, aad));
        byte[] in = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, in, 0, ciphertext.length);
        System.arraycopy(tag, 0, in, ciphertext.length, tag.length);
        byte[] out = new byte[gcm.getOutputSize(in.length)];
        int len = gcm.processBytes(in, 0, in.length, out, 0);
        len += gcm.doFinal(out, len);
        return Arrays.copyOfRange(out, 0, len);
    }

    public static AeadResult encryptCcm(byte[] key, byte[] iv, byte[] aad, byte[] plaintext, int tagBits) {
        log.fine("encrypt CCM");
        BlockCipher engine = new AriaBcBlockCipher();
        CCMBlockCipher ccm = new CCMBlockCipher(engine);
        ccm.init(true, new AEADParameters(new KeyParameter(key), tagBits, iv, aad));
        byte[] out = new byte[ccm.getOutputSize(plaintext.length)];
        int len = ccm.processBytes(plaintext, 0, plaintext.length, out, 0);
        try {
            len += ccm.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e);
        }
        byte[] cipher = Arrays.copyOfRange(out, 0, len - tagBits / 8);
        byte[] tag = Arrays.copyOfRange(out, len - tagBits / 8, len);
        return new AeadResult(cipher, tag);
    }

    public static byte[] decryptCcm(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws InvalidCipherTextException {
        log.fine("decrypt CCM");
        BlockCipher engine = new AriaBcBlockCipher();
        CCMBlockCipher ccm = new CCMBlockCipher(engine);
        ccm.init(false, new AEADParameters(new KeyParameter(key), tag.length * 8, iv, aad));
        byte[] in = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, in, 0, ciphertext.length);
        System.arraycopy(tag, 0, in, ciphertext.length, tag.length);
        byte[] out = new byte[ccm.getOutputSize(in.length)];
        int len = ccm.processBytes(in, 0, in.length, out, 0);
        len += ccm.doFinal(out, len);
        return Arrays.copyOfRange(out, 0, len);
    }

    public static byte[] cmac(byte[] key, byte[] data) {
        log.fine("CMAC compute");
        BlockCipher engine = new AriaBcBlockCipher();
        CMac cmac = new CMac(engine);
        cmac.init(new KeyParameter(key));
        cmac.update(data, 0, data.length);
        byte[] mac = new byte[cmac.getMacSize()];
        cmac.doFinal(mac, 0);
        return mac;
    }
}
