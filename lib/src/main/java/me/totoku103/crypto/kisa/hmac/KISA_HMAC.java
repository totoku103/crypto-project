package me.totoku103.crypto.kisa.hmac;

public class KISA_HMAC {
	
	//private static int ENDIAN = Common.BIG_ENDIAN;
	
	private final static byte IPAD = (byte)0x36;
    private final static byte OPAD = (byte)0x5C;
    private final static int blockLength = 64;		// for SHA256
    private final static int digestLength = 32;		// for SHA256
    
	
	public static void HMAC_SHA256_Transform(byte[] output, byte[] key, int keyLen, byte[] input, int inputLen) 
	{
		int keyLength = keyLen;
		byte[] inputPad = new byte[blockLength];
	    byte[] outputPad = new byte[blockLength];
	    byte[] firstHash = new byte[digestLength];
	    SHA256_INFO info = new SHA256_INFO();
		
	    KISA_SHA256.SHA256_Init( info );
		if(keyLength > blockLength) {
			
			KISA_SHA256.SHA256_Process( info, key, keyLength );
			KISA_SHA256.SHA256_Close( info, inputPad );
			keyLength = digestLength;
		}
		else {
			System.arraycopy(key, 0, inputPad, 0, keyLength);
		}
		
		for (int i = keyLength; i < inputPad.length; i++)
        {
            inputPad[i] = 0;
        }
		
		System.arraycopy(inputPad, 0, outputPad, 0, blockLength);

        xorPad(inputPad, blockLength, IPAD);
        xorPad(outputPad, blockLength, OPAD);
        
	    KISA_SHA256.SHA256_Init( info );
	    KISA_SHA256.SHA256_Process( info, inputPad, inputPad.length );
	    KISA_SHA256.SHA256_Process( info, input, inputLen );
	    KISA_SHA256.SHA256_Close( info, firstHash );
	    
	    KISA_SHA256.SHA256_Init( info );
	    KISA_SHA256.SHA256_Process( info, outputPad, outputPad.length );
	    KISA_SHA256.SHA256_Process( info, firstHash, digestLength );
	    KISA_SHA256.SHA256_Close( info, output );
	}
	
	private static void xorPad(byte[] pad, int len, byte n)
    {
        for (int i = 0; i < len; ++i)
        {
            pad[i] ^= n;
        }
    }
}
