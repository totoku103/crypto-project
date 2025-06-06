package me.totoku103.crypto.kisa.sha3.enums;

public enum BitSizeType {
    SHA3_224("SHA3-224", 224),
    SHA3_256("SHA3-256", 256),
    SHA3_384("SHA3-384", 384),
    SHA3_512("SHA3-512", 512);


    private final String algorithmName;
    private final int bitSize;

    BitSizeType(final String algorithmName, final int bitSize) {
        this.algorithmName = algorithmName;
        this.bitSize = bitSize;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public int getBitSize() {
        return bitSize;
    }
}
