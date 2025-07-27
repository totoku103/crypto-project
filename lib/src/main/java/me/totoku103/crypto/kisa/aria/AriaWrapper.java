package me.totoku103.crypto.kisa.aria;

import java.security.InvalidKeyException;

/**
 * ARIA 클래스의 package-private 메서드들을 public으로 노출하는 래퍼 클래스
 */
public class AriaWrapper {
    
    private final Aria aria;
    
    public AriaWrapper(int keySize) throws InvalidKeyException {
        this.aria = new Aria(keySize);
    }
    
    public void setKey(byte[] masterKey) throws InvalidKeyException {
        aria.setKey(masterKey);
    }
    
    public byte[] encrypt(byte[] input, int offset) throws InvalidKeyException {
        return aria.encrypt(input, offset);
    }
    
    public byte[] decrypt(byte[] input, int offset) throws InvalidKeyException {
        return aria.decrypt(input, offset);
    }
    
    public void setupRoundKeys() throws InvalidKeyException {
        aria.setupRoundKeys();
    }
} 