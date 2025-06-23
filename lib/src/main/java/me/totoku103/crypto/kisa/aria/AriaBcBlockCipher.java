package me.totoku103.crypto.kisa.aria;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.InvalidKeyException;
import java.util.logging.Logger;

/**
 * BouncyCastle BlockCipher adapter for existing ARIA implementation.
 */
public class AriaBcBlockCipher implements BlockCipher {
    private static final Logger log = Logger.getLogger(AriaBcBlockCipher.class.getName());

    private Aria aria;
    private boolean forEncryption;

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        if (!(params instanceof KeyParameter kp)) {
            throw new IllegalArgumentException("KeyParameter required");
        }
        byte[] key = kp.getKey();
        int keyBits = key.length * 8;
        try {
            aria = new Aria(keyBits);
            aria.setKey(key);
            aria.setupRoundKeys();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Invalid key", e);
        }
        this.forEncryption = forEncryption;
        log.fine("ARIA cipher initialized for " + (forEncryption ? "encryption" : "decryption"));
    }

    @Override
    public String getAlgorithmName() {
        return "ARIA";
    }

    @Override
    public int getBlockSize() {
        return 16;
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws IllegalStateException {
        if (aria == null) {
            throw new IllegalStateException("Cipher not initialized");
        }
        try {
            if (forEncryption) {
                aria.encrypt(in, inOff, out, outOff);
            } else {
                aria.decrypt(in, inOff, out, outOff);
            }
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Key error", e);
        }
        return getBlockSize();
    }

    @Override
    public void reset() {
        // no internal state to reset
    }
}
