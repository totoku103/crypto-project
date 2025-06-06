package me.totoku103.crypto.kisa.sha2;

/*
  @author Copyright (c) 2013 by KISA
 * @file KISA_SHA256.java
 * @brief SHA256 암호 알고리즘
 * @remarks http://seed.kisa.or.kr/
 */


/**
 * KISA에서 제공하는 SHA256 알고리즘 소스. 변수명, 메소드명 등 CodeStyle만  변경.
 */
public class Sha256 {

    // DEFAULT : JAVA = BIG_ENDIAN
    private static final int ENDIAN = Common.BIG_ENDIAN;

    private static final int SHA256_DIGEST_BLOCK_LEN = 64;
    private static final int SHA256_DIGEST_VALUE_LEN = 32;

    private static final int[] SHA256_K =
            {
                    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
                    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
                    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
                    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };


    private static int rotLULong(final int x, final int n) {
        return (x << n) | Common.shiftUR(x, 32 - n);
    }

    private static int rotRULong(final int x, final int n) {
        return Common.shiftUR(x, n) | (x << (32 - (n)));
    }

    private static int endianReverseULong(final int dwS) {
        return ((rotLULong((dwS), 8) & 0x00ff00ff) | (rotLULong((dwS), 24) & 0xff00ff00));
    }

    private static void bigD2B(int D, byte[] B, int B_offset) {
        Common.intToByteUnit(B, B_offset, D, ENDIAN);
    }

    private static int rr(int x, int n) {
        return rotRULong(x, n);
    }

    private static int ss(int x, int n) {
        return Common.shiftUR(x, n);
    }

    private static int ch(int x, int y, int z) {
        return ((x & y) ^ ((~x) & z));
    }

    private static int maj(int x, int y, int z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    private static int sigma0(int x) {
        return (rr(x, 2) ^ rr(x, 13) ^ rr(x, 22));
    }

    private static int sigma1(int x) {
        return (rr(x, 6) ^ rr(x, 11) ^ rr(x, 25));
    }

    private static int rho0(int x) {
        return (rr(x, 7) ^ rr(x, 18) ^ ss(x, 3));
    }

    private static int rho1(int x) {
        return (rr(x, 17) ^ rr(x, 19) ^ ss(x, 10));
    }

    private static final int _a = 0;
    private static final int _b = 1;
    private static final int _c = 2;
    private static final int _d = 3;
    private static final int _e = 4;
    private static final int _f = 5;
    private static final int _g = 6;
    private static final int _h = 7;

    private static void ff(int[] param, int a, int b, int c, int d, int e, int f, int g, int h, int[] X, int j) {
        long t1;

        t1 = Common.intToUnsigned(param[h]) + Common.intToUnsigned(sigma1(param[e])) + Common.intToUnsigned(ch(param[e], param[f], param[g])) + Common.intToUnsigned(SHA256_K[j]) + Common.intToUnsigned(X[j]);
        param[d] += t1;
        param[h] = (int) (t1 + Common.intToUnsigned(sigma0(param[a])) + Common.intToUnsigned(maj(param[a], param[b], param[c])));
    }

    private static int getData(byte[] x, int x_offset) {
        return Common.byteToInt(x, x_offset, ENDIAN);
    }

    //*********************************************************************************************************************************
    // o SHA256_Transform() : 512 비트 단위 블록의 메시지를 입력 받아 연쇄변수를 갱신하는 압축 함수로써
    //	                      4 라운드(64 단계)로 구성되며 8개의 연쇄변수(a, b, c, d, e, f, g, h)를 사용
    // o 입력                               : Message               - 입력 메시지의 포인터 변수
    //	                      ChainVar              - 연쇄변수의 포인터 변수
    // o 출력                               :
    //*********************************************************************************************************************************
    private static void transform(byte[] Message, int[] ChainVar) {
        int[] aHarry = new int[8];
        int[] t1 = new int[1];
        int[] x = new int[64];
        int j;

        for (j = 0; j < 16; j++)
            x[j] = getData(Message, j * 4);

        for (j = 16; j < 64; j++)
            x[j] = (int) (Common.intToUnsigned(rho1(x[j - 2])) + Common.intToUnsigned(x[j - 7]) + Common.intToUnsigned(rho0(x[j - 15])) + Common.intToUnsigned(x[j - 16]));

        aHarry[_a] = ChainVar[0];
        aHarry[_b] = ChainVar[1];
        aHarry[_c] = ChainVar[2];
        aHarry[_d] = ChainVar[3];
        aHarry[_e] = ChainVar[4];
        aHarry[_f] = ChainVar[5];
        aHarry[_g] = ChainVar[6];
        aHarry[_h] = ChainVar[7];

        for (j = 0; j < 64; j += 8) {
            ff(aHarry, _a, _b, _c, _d, _e, _f, _g, _h, x, j + 0);
            ff(aHarry, _h, _a, _b, _c, _d, _e, _f, _g, x, j + 1);
            ff(aHarry, _g, _h, _a, _b, _c, _d, _e, _f, x, j + 2);
            ff(aHarry, _f, _g, _h, _a, _b, _c, _d, _e, x, j + 3);
            ff(aHarry, _e, _f, _g, _h, _a, _b, _c, _d, x, j + 4);
            ff(aHarry, _d, _e, _f, _g, _h, _a, _b, _c, x, j + 5);
            ff(aHarry, _c, _d, _e, _f, _g, _h, _a, _b, x, j + 6);
            ff(aHarry, _b, _c, _d, _e, _f, _g, _h, _a, x, j + 7);
        }

        ChainVar[0] += aHarry[_a];
        ChainVar[1] += aHarry[_b];
        ChainVar[2] += aHarry[_c];
        ChainVar[3] += aHarry[_d];
        ChainVar[4] += aHarry[_e];
        ChainVar[5] += aHarry[_f];
        ChainVar[6] += aHarry[_g];
        ChainVar[7] += aHarry[_h];
    }

    /**
     * 연쇄변수와 길이변수를 초기화하는 함수
     *
     * @param Info : SHA256_Process 호출 시 사용되는 구조체
     */
    public static void init(Sha256Info Info) {
        Info.uChainVar[0] = 0x6a09e667;
        Info.uChainVar[1] = 0xbb67ae85;
        Info.uChainVar[2] = 0x3c6ef372;
        Info.uChainVar[3] = 0xa54ff53a;
        Info.uChainVar[4] = 0x510e527f;
        Info.uChainVar[5] = 0x9b05688c;
        Info.uChainVar[6] = 0x1f83d9ab;
        Info.uChainVar[7] = 0x5be0cd19;

        Info.uHighLength = Info.uLowLength = Info.remainNum = 0;
    }

    /**
     * 연쇄변수와 길이변수를 초기화하는 함수
     *
     * @param Info       : SHA256_Init 호출하여 초기화된 구조체(내부적으로 사용된다.)
     * @param pszMessage : 사용자 입력 평문
     * @param uDataLen   : 사용자 입력 평문 길이
     */
    public static void process(Sha256Info Info, byte[] pszMessage, int uDataLen) {
        int pszMessageOffset = Info.remainNum;

        if ((Info.uLowLength += (uDataLen << 3)) < 0) {
            Info.uHighLength++;
        }

        Info.uHighLength += Common.shiftUR(uDataLen, 29);

        while (uDataLen + pszMessageOffset >= SHA256_DIGEST_BLOCK_LEN) {
            Common.copyArrayOffset(Info.szBuffer, pszMessageOffset, pszMessage, 0, SHA256_DIGEST_BLOCK_LEN);
            transform(Info.szBuffer, Info.uChainVar);
            pszMessageOffset += SHA256_DIGEST_BLOCK_LEN - pszMessageOffset;
            uDataLen -= SHA256_DIGEST_BLOCK_LEN - pszMessageOffset;
            pszMessageOffset = 0;
        }

        Common.copyArrayOffset(Info.szBuffer, pszMessageOffset, pszMessage, 0, uDataLen);
        Info.remainNum = pszMessageOffset + uDataLen;
    }

    /**
     * 메시지 덧붙이기와 길이 덧붙이기를 수행한 후 마지막 메시지 블록을 가지고 압축함수를 호출하는 함수
     *
     * @param Info      : SHA256_Init 호출하여 초기화된 구조체(내부적으로 사용된다.)
     * @param pszDigest : 암호문
     */
    public static void close(Sha256Info Info, byte[] pszDigest) {
        int i;
        int Index;

        Index = Common.shiftUR(Info.uLowLength, 3) % SHA256_DIGEST_BLOCK_LEN;
        Info.szBuffer[Index++] = (byte) 0x80;

        if (Index > SHA256_DIGEST_BLOCK_LEN - 8) {
            Common.initArrayOffset(Info.szBuffer, Index, (byte) 0, SHA256_DIGEST_BLOCK_LEN - Index);
            transform(Info.szBuffer, Info.uChainVar);
            Common.initArray(Info.szBuffer, (byte) 0, SHA256_DIGEST_BLOCK_LEN - 8);
        } else {
            Common.initArrayOffset(Info.szBuffer, Index, (byte) 0, SHA256_DIGEST_BLOCK_LEN - Index - 8);
        }

        if (ENDIAN == Common.LITTLE_ENDIAN) {
            Info.uLowLength = endianReverseULong(Info.uLowLength);
            Info.uHighLength = endianReverseULong(Info.uHighLength);
        }

        Common.intToByteUnit(Info.szBuffer, ((int) (SHA256_DIGEST_BLOCK_LEN / 4 - 2)) * 4, Info.uHighLength, ENDIAN);
        Common.intToByteUnit(Info.szBuffer, ((int) (SHA256_DIGEST_BLOCK_LEN / 4 - 1)) * 4, Info.uLowLength, ENDIAN);

        transform(Info.szBuffer, Info.uChainVar);

        for (i = 0; i < SHA256_DIGEST_VALUE_LEN; i += 4)
            bigD2B((Info.uChainVar)[i / 4], pszDigest, i);
    }

    /**
     * 사용자 입력 평문을 한번에 처리. 내부적으로 SHA256_Init, SHA256_Process, SHA256_Close를 호출한다.
     *
     * @param pszMessage : 사용자 입력 평문
     * @param pszDigest  : 암호문
     */
    public static void encrypt(byte[] pszMessage, int uPlainTextLen, byte[] pszDigest) {
        Sha256Info info = new Sha256Info();
        init(info);
        process(info, pszMessage, uPlainTextLen);
        close(info, pszDigest);
    }

    public static String encrypt(byte[] plainText) {
        Sha256Info info = new Sha256Info();
        init(info);
        process(info, plainText, plainText.length);
        final byte[] pbCipher = new byte[32];
        close(info, pbCipher);
        final StringBuilder sb = new StringBuilder();
        for (final byte b : pbCipher) {
            sb.append(Integer.toHexString(0xff & b));
        }
        return sb.toString();
    }


    public static class Sha256Info {
        public int[] uChainVar = new int[SHA256_DIGEST_VALUE_LEN / 4];
        public int uHighLength;
        public int uLowLength;
        public int remainNum;
        public byte[] szBuffer = new byte[SHA256_DIGEST_BLOCK_LEN];
    }

    public static class Common {

        public static final int BIG_ENDIAN = 0;
        public static final int LITTLE_ENDIAN = 1;

        public static void copyArray(byte[] dst, byte[] src, int length) {
            for (int i = 0; i < length; i++) {
                dst[i] = src[i];
            }
        }

        public static void copyArrayOffset(byte[] dst, int dst_offset, byte[] src, int src_offset, int length) {
            for (int i = 0; i < length; i++) {
                dst[dst_offset + i] = src[src_offset + i];
            }
        }

        public static void initArray(byte[] dst, byte value, int length) {
            for (int i = 0; i < length; i++) {
                dst[i] = value;
            }
        }

        public static void initArrayOffset(byte[] dst, int dst_offset, byte value, int length) {
            for (int i = 0; i < length; i++) {
                dst[dst_offset + i] = value;
            }
        }

        public static void copyMem(int[] dst, byte[] src, int length, int ENDIAN) {
            int iLen = length / 4;
            for (int i = 0; i < iLen; i++) {
                byteToInt(dst, i, src, i * 4, ENDIAN);
            }
        }

        public static void copyMem(int[] dst, int[] src, int src_offset, int length) {
            int iLen = length / 4 + ((length % 4 != 0) ? 1 : 0);
            for (int i = 0; i < iLen; i++) {
                dst[i] = src[src_offset + i];
            }
        }

        public static void setByteForInt(int[] dst, int b_offset, byte value, int ENDIAN) {
            if (ENDIAN == BIG_ENDIAN) {
                int shift_value = (3 - b_offset % 4) * 8;
                int mask_value = 0x0ff << shift_value;
                int mask_value2 = ~mask_value;
                int value2 = (value & 0x0ff) << shift_value;
                dst[b_offset / 4] = (dst[b_offset / 4] & mask_value2) | (value2 & mask_value);
            } else {
                int shift_value = (b_offset % 4) * 8;
                int mask_value = 0x0ff << shift_value;
                int mask_value2 = ~mask_value;
                int value2 = (value & 0x0ff) << shift_value;
                dst[b_offset / 4] = (dst[b_offset / 4] & mask_value2) | (value2 & mask_value);
            }
        }

        public static byte getByteForInt(int[] src, int b_offset, int ENDIAN) {
            if (ENDIAN == BIG_ENDIAN) {
                int shift_value = (3 - b_offset % 4) * 8;
                int mask_value = 0x0ff << shift_value;
                int value = (src[b_offset / 4] & mask_value) >> shift_value;
                return (byte) value;
            } else {
                int shift_value = (b_offset % 4) * 8;
                int mask_value = 0x0ff << shift_value;
                int value = (src[b_offset / 4] & mask_value) >> shift_value;
                return (byte) value;
            }

        }

        public static byte[] getBytesForInts(int[] src, int offset, int ENDIAN) {
            int iLen = src.length - offset;
            byte[] result = new byte[(iLen) * 4];
            for (int i = 0; i < iLen; i++) {
                intToByte(result, i * 4, src, offset + i, ENDIAN);
            }

            return result;
        }

        public static void byteToInt(int[] dst, int dst_offset, byte[] src, int src_offset, int ENDIAN) {
            if (ENDIAN == BIG_ENDIAN) {
                dst[dst_offset] = ((0x0ff & src[src_offset]) << 24) | ((0x0ff & src[src_offset + 1]) << 16) | ((0x0ff & src[src_offset + 2]) << 8) | ((0x0ff & src[src_offset + 3]));
            } else {
                dst[dst_offset] = ((0x0ff & src[src_offset])) | ((0x0ff & src[src_offset + 1]) << 8) | ((0x0ff & src[src_offset + 2]) << 16) | ((0x0ff & src[src_offset + 3]) << 24);
            }
        }

        public static int byteToInt(byte[] src, int src_offset, int ENDIAN) {
            if (ENDIAN == BIG_ENDIAN) {
                return ((0x0ff & src[src_offset]) << 24) | ((0x0ff & src[src_offset + 1]) << 16) | ((0x0ff & src[src_offset + 2]) << 8) | ((0x0ff & src[src_offset + 3]));
            } else {
                return ((0x0ff & src[src_offset])) | ((0x0ff & src[src_offset + 1]) << 8) | ((0x0ff & src[src_offset + 2]) << 16) | ((0x0ff & src[src_offset + 3]) << 24);
            }
        }

        public static int byteToIntBigEndian(byte[] src, int src_offset) {
            return ((0x0ff & src[src_offset]) << 24) | ((0x0ff & src[src_offset + 1]) << 16) | ((0x0ff & src[src_offset + 2]) << 8) | ((0x0ff & src[src_offset + 3]));
        }

        public static void intToByte(byte[] dst, int dst_offset, int[] src, int src_offset, int ENDIAN) {
            intToByteUnit(dst, dst_offset, src[src_offset], ENDIAN);
        }

        public static void intToByteUnit(byte[] dst, int dst_offset, int src, int ENDIAN) {
            if (ENDIAN == BIG_ENDIAN) {
                dst[dst_offset] = (byte) ((src >> 24) & 0x0ff);
                dst[dst_offset + 1] = (byte) ((src >> 16) & 0x0ff);
                dst[dst_offset + 2] = (byte) ((src >> 8) & 0x0ff);
                dst[dst_offset + 3] = (byte) ((src) & 0x0ff);
            } else {
                dst[dst_offset] = (byte) ((src) & 0x0ff);
                dst[dst_offset + 1] = (byte) ((src >> 8) & 0x0ff);
                dst[dst_offset + 2] = (byte) ((src >> 16) & 0x0ff);
                dst[dst_offset + 3] = (byte) ((src >> 24) & 0x0ff);
            }

        }

        public static void intToByteUnitBigEndian(byte[] dst, int dst_offset, int src) {
            dst[dst_offset] = (byte) ((src >> 24) & 0x0ff);
            dst[dst_offset + 1] = (byte) ((src >> 16) & 0x0ff);
            dst[dst_offset + 2] = (byte) ((src >> 8) & 0x0ff);
            dst[dst_offset + 3] = (byte) ((src) & 0x0ff);
        }

        public static int shiftUR(int x, int n) {
            if (n == 0)
                return x;
            if (n >= 32)
                return 0;
            int v = x >> n;
            int v_mask = ~(0x80000000 >> (n - 1));
            return v & v_mask;
        }

        public static final long INT_RANGE_MAX = (long) Math.pow(2, 32);

        public static long intToUnsigned(int x) {
            if (x >= 0)
                return x;
            return x + INT_RANGE_MAX;
        }
    }

    public static void main(String[] args) {
        byte[] pbData = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};

        byte[] pbCipher = new byte[32];
        byte[] pbPlain = new byte[16];

        System.out.print("[ Test SHA256 reference code ]" + "\n");
        System.out.print("\n\n");
        System.out.print("[ Test HASH mode ]" + "\n");
        System.out.print("\n");

        int Plaintext_length = 1;

        for (int k = 0; k < 30; k++) {

            System.out.print("Plaintext\t: ");
            for (int i = 0; i < Plaintext_length; i++) System.out.print(Integer.toHexString(0xff & pbData[i]) + " ");
            System.out.print("\n");

            // Encryption
            encrypt(pbData, Plaintext_length, pbCipher);

            System.out.print("Ciphertext\t: ");
            for (int i = 0; i < 32; i++) System.out.print(Integer.toHexString(0xff & pbCipher[i]) + " ");
            System.out.print("\n\n");

            Plaintext_length++;

        }

    }

}
