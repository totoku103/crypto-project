package me.totoku103.crypto.algorithms.cipher;

import me.totoku103.crypto.core.BlockCipher;
import me.totoku103.crypto.core.utils.ByteUtils;

/**
 * SEED 블록 암호화 알고리즘 구현
 */
public class SeedBlockCipher implements BlockCipher {
    
    private static final String ALGORITHM_NAME = "SEED";
    private static final String VERSION = "1.0.0";
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int KEY_SIZE = 16;   // 128 bits
    
    private final me.totoku103.crypto.kisa.seed.Seed seed;
    
    public SeedBlockCipher() {
        this.seed = new me.totoku103.crypto.kisa.seed.Seed();
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
        if (ByteUtils.isEmpty(plaintext) || ByteUtils.isEmpty(key)) {
            throw new IllegalArgumentException("Plaintext and key cannot be null or empty");
        }
        
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
        }
        
        // SEED는 블록 단위로 처리되므로 패딩이 필요할 수 있음
        // 여기서는 간단한 구현을 위해 블록 크기에 맞춰 처리
        int[] roundKey = new int[32];
        seed.keyShed(key, roundKey);
        
        int[] input = new int[4];
        int[] output = new int[4];
        
        // 바이트 배열을 int 배열로 변환
        for (int i = 0; i < 4; i++) {
            input[i] = byteArrayToInt(plaintext, i * 4);
        }
        
        seed.encrypt(output, input, roundKey);
        
        // int 배열을 바이트 배열로 변환
        byte[] result = new byte[BLOCK_SIZE];
        for (int i = 0; i < 4; i++) {
            intToByteArray(output[i], result, i * 4);
        }
        
        return result;
    }
    
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        if (ByteUtils.isEmpty(ciphertext) || ByteUtils.isEmpty(key)) {
            throw new IllegalArgumentException("Ciphertext and key cannot be null or empty");
        }
        
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Key must be " + KEY_SIZE + " bytes");
        }
        
        int[] roundKey = new int[32];
        seed.keyShed(key, roundKey);
        
        int[] input = new int[4];
        int[] output = new int[4];
        
        // 바이트 배열을 int 배열로 변환
        for (int i = 0; i < 4; i++) {
            input[i] = byteArrayToInt(ciphertext, i * 4);
        }
        
        seed.decrypt(output, input, roundKey);
        
        // int 배열을 바이트 배열로 변환
        byte[] result = new byte[BLOCK_SIZE];
        for (int i = 0; i < 4; i++) {
            intToByteArray(output[i], result, i * 4);
        }
        
        return result;
    }
    
    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }
    
    @Override
    public int getKeySize() {
        return KEY_SIZE;
    }
    
    private int byteArrayToInt(byte[] bytes, int offset) {
        return ByteUtils.bytesToInt(bytes, offset);
    }
    
    private void intToByteArray(int value, byte[] bytes, int offset) {
        ByteUtils.intToBytes(value, bytes, offset);
    }
} 