package me.totoku103.crypto.kisa.sha2;

/**
 * Simplified SHA-512 implementation based on the FIPS 180 specification.
 * This class mirrors the interface style of {@link Sha256} but operates on
 * 64-bit words.
 */
public class Sha512 {

    private static final int BLOCK_SIZE = 128; // bytes
    private static final int DIGEST_LENGTH = 64; // bytes

    private static final long[] K = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
            0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L,
            0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L,
            0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
            0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
            0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L,
            0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL,
            0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
            0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL,
            0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L,
            0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L,
            0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
            0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L,
            0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL,
            0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL,
            0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
            0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L,
            0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL,
            0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
            0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
            0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    private static long rotr(long x, int n) {
        return (x >>> n) | (x << (64 - n));
    }

    private static long ch(long x, long y, long z) {
        return (x & y) ^ (~x & z);
    }

    private static long maj(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static long bigSigma0(long x) {
        return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
    }

    private static long bigSigma1(long x) {
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
    }

    private static long smallSigma0(long x) {
        return rotr(x, 1) ^ rotr(x, 8) ^ (x >>> 7);
    }

    private static long smallSigma1(long x) {
        return rotr(x, 19) ^ rotr(x, 61) ^ (x >>> 6);
    }

    /**
     * Compute SHA-512 digest of the given message.
     *
     * @param message input data
     * @return 64-byte digest
     */
    public static byte[] toHash(byte[] message) {
        long[] h = {
                0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
                0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
                0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
        };

        int blocks = (message.length + 17 + 127) / 128;
        byte[] padded = new byte[blocks * 128];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte) 0x80;
        long bitLen = ((long) message.length) * 8L;
        int off = padded.length - 8;
        for (int i = 7; i >= 0; i--) {
            padded[off + i] = (byte) (bitLen & 0xff);
            bitLen >>>= 8;
        }

        long[] w = new long[80];
        for (int b = 0; b < blocks; b++) {
            int base = b * 128;
            for (int t = 0; t < 16; t++) {
                int i = base + t * 8;
                w[t] = ((long) (padded[i] & 0xff) << 56)
                        | ((long) (padded[i + 1] & 0xff) << 48)
                        | ((long) (padded[i + 2] & 0xff) << 40)
                        | ((long) (padded[i + 3] & 0xff) << 32)
                        | ((long) (padded[i + 4] & 0xff) << 24)
                        | ((long) (padded[i + 5] & 0xff) << 16)
                        | ((long) (padded[i + 6] & 0xff) << 8)
                        | ((long) (padded[i + 7] & 0xff));
            }
            for (int t = 16; t < 80; t++) {
                w[t] = smallSigma1(w[t - 2]) + w[t - 7] + smallSigma0(w[t - 15]) + w[t - 16];
            }

            long a = h[0];
            long b2 = h[1];
            long c = h[2];
            long d = h[3];
            long e = h[4];
            long f = h[5];
            long g = h[6];
            long hh = h[7];

            for (int t = 0; t < 80; t++) {
                long t1 = hh + bigSigma1(e) + ch(e, f, g) + K[t] + w[t];
                long t2 = bigSigma0(a) + maj(a, b2, c);
                hh = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b2;
                b2 = a;
                a = t1 + t2;
            }

            h[0] += a;
            h[1] += b2;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hh;
        }

        byte[] out = new byte[DIGEST_LENGTH];
        for (int i = 0; i < h.length; i++) {
            long v = h[i];
            int idx = i * 8;
            out[idx] = (byte) ((v >>> 56) & 0xff);
            out[idx + 1] = (byte) ((v >>> 48) & 0xff);
            out[idx + 2] = (byte) ((v >>> 40) & 0xff);
            out[idx + 3] = (byte) ((v >>> 32) & 0xff);
            out[idx + 4] = (byte) ((v >>> 24) & 0xff);
            out[idx + 5] = (byte) ((v >>> 16) & 0xff);
            out[idx + 6] = (byte) ((v >>> 8) & 0xff);
            out[idx + 7] = (byte) (v & 0xff);
        }
        return out;
    }

    /**
     * Convenience method returning a hex string of the SHA-512 digest.
     */
    public static String encrypt(byte[] message) {
        byte[] d = toHash(message);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
