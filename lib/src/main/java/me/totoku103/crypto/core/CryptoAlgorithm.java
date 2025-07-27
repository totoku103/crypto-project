package me.totoku103.crypto.core;

/**
 * 암호화 알고리즘의 공통 인터페이스
 */
public interface CryptoAlgorithm {
    
    /**
     * 알고리즘 이름을 반환합니다.
     * @return 알고리즘 이름
     */
    String getAlgorithmName();
    
    /**
     * 알고리즘 버전을 반환합니다.
     * @return 알고리즘 버전
     */
    String getVersion();
} 