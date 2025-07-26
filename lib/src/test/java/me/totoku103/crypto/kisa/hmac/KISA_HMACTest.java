package me.totoku103.crypto.kisa.hmac;

public class KISA_HMACTest {

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        System.out.println("Hello, KISA_HMACTest");

        KISA_HMACTest ins = new KISA_HMACTest();
        ins.testSHA256();
        ins.testHMAC();
    }

    public void testHMAC() {
        byte[] keybytes = new byte[256];
        byte[] msg = new byte[2048];
        byte[] kat = new byte[256];

        int keybytesLen = 0;
        int msgLen = 0;
        int outputLen = 0;
        int cnt_i;

        // set1
        keybytesLen = Utils.asc2hex(keybytes, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
        msgLen = Utils.asc2hex(msg, "548A457280851ECA0F5476AFDAC102CF6C7DBE09B3083D74FBD03DA31E9D7F27F42CD656111A7D4BB005AD2EEAED6FB62CE0B0EBE7D6933189DA0B82AD6AA8FB8E21B19AC29374462579DA0F130E3EB8DAB87F726EEB54EB5F4AE087091087ED0BAFFFC6FAB7AAC156F823DBBCEB17DD5E4E5626B10F29AA656BE73B9A57C308");
        outputLen = Utils.asc2hex(kat, "96C37F36CA0DEA3B2B3E60F1F6CDF79CFF72CA2A43A091C8105AE882A690EF2F");

        byte[] output1 = new byte[outputLen];
        KISA_HMAC.HMAC_SHA256_Transform(output1, keybytes, keybytesLen, msg, msgLen);

        Utils.print_hex("output", output1, outputLen);
        for (cnt_i = 0; cnt_i < outputLen; cnt_i++) {
            if (kat[cnt_i] != output1[cnt_i]) {
                System.out.println("FAIL: " + cnt_i);
                break;
            }
        }

        // set2
        keybytesLen = Utils.asc2hex(keybytes, "511FE863204DC8C72BCCB0194F4DA02EA0EA5B8E1609BA7783844525C8070451");
        msgLen = Utils.asc2hex(msg, "49B993F89E1E755D8C3CAA5133FC84B288D4B63206A3AE59A1DC25CEFCE7F4D2DBC4290DDBF25A8D618F390CD0C06971FF53909AEAA3AE59A7BCADBC9CC03992F08AD12A3F901E5E920E84D08E61F874EBB0114F28D2617E7D6C0579125A7B996E51B4D832C26AD90701B428D5A6D8C2363460D82AF870D00C34568DC47D63F0");
        outputLen = Utils.asc2hex(kat, "27F150ABDCBC478C83251A3F314CE609");

        byte[] output2 = new byte[outputLen];
        KISA_HMAC.HMAC_SHA256_Transform(output2, keybytes, keybytesLen, msg, msgLen);

        Utils.print_hex("output", output2, outputLen);
        for (cnt_i = 0; cnt_i < outputLen; cnt_i++) {
            if (kat[cnt_i] != output2[cnt_i]) {
                System.out.println("FAIL: " + cnt_i);
                break;
            }
        }

        // set3
        keybytesLen = Utils.asc2hex(keybytes, "3F62F99E1C4EE604A8B0F0990D58B163C624A6BD56DD82573A5CC87E1CF1989E");
        msgLen = Utils.asc2hex(msg, "4905C90565FD39E95E6261AD9E3F2D6085CB0A871648401CF02B82D6807DC3AB76814C9475970C900F602FEBF023F2C05970B5BDD103512617EAAD1C5AEB8C20AC20A9D3B5E406FFA4F381DB6BCCA88B2C5ACEE7EED45F7D95E270D911019A04D528094A8BACD04006617F067802F8CAE5D27E8DD7840F2A5458F4940D88965F");
        outputLen = Utils.asc2hex(kat, "6B964756F341B64A1A0B4BCC744DC9AB");

        byte[] output3 = new byte[outputLen];
        KISA_HMAC.HMAC_SHA256_Transform(output3, keybytes, keybytesLen, msg, msgLen);

        Utils.print_hex("output", output3, outputLen);
        for (cnt_i = 0; cnt_i < outputLen; cnt_i++) {
            if (kat[cnt_i] != output3[cnt_i]) {
                System.out.println("FAIL: " + cnt_i);
                break;
            }
        }

        // set4
        keybytesLen = Utils.asc2hex(keybytes, "96860CE5CCB1678808C9F49DD77CBFD2B6A0554EC9161EA9D0F5ED3C56E4D69C");
        msgLen = Utils.asc2hex(msg, "2BC8406115A03A2CC3AC13E802D5244F3449F1B0FD6671F03FD9A9D04907806D4BACCE0D0DC1B618E1A43665D773FCB72FB87B88144C3F0587757D599952EF2EDD79DE711DDE81564CF7859DBC1DED1391361C5B769130EE8E119261AD8ECBE7C9789A16ABBD43EEEAED29171A9D9F6A4109FCB38AFDEDB53EF5106FEF83BE9E");
        outputLen = Utils.asc2hex(kat, "CC935697032C301238D71C551337C0D38437931C85D5C6E03BDD2262F7D68F4F");

        byte[] output4 = new byte[outputLen];
        KISA_HMAC.HMAC_SHA256_Transform(output4, keybytes, keybytesLen, msg, msgLen);

        Utils.print_hex("output", output4, outputLen);
        for (cnt_i = 0; cnt_i < outputLen; cnt_i++) {
            if (kat[cnt_i] != output4[cnt_i]) {
                System.out.println("FAIL: " + cnt_i);
                break;
            }
        }

        // set5
        keybytesLen = Utils.asc2hex(keybytes, "9B45670F9C5B1A57E657D940F023F4B393852A3BBFFF07086DF47039D40B7C5BE0D9852CE0BA7FA57FFF8938F54FC2577E475E350B64F9D038232A2F7F665CE8");
        msgLen = Utils.asc2hex(msg, "AB1AD9E68F172869F747994EDF0B1E91E3DA5C10F72C029258965A07C3361E12E4518CC4113BBCAB3877320B1620B06BAA874D53EA1ECB55B495264A074269DE73C6C54FCEEEE47129D77BF602561FECBC9659874C03FC213467B67FB553E65640C1AD0D2FF748C5B2AF9D970C74131CFF4FA73384A33DFEC056332E34313C81");
        outputLen = Utils.asc2hex(kat, "47EAE43DF17515FA042F9B9A4A049336D22779D8D1FD90F01412E788340631FB");

        byte[] output5 = new byte[outputLen];
        KISA_HMAC.HMAC_SHA256_Transform(output5, keybytes, keybytesLen, msg, msgLen);

        Utils.print_hex("output", output5, outputLen);
        for (cnt_i = 0; cnt_i < outputLen; cnt_i++) {
            if (kat[cnt_i] != output5[cnt_i]) {
                System.out.println("FAIL: " + cnt_i);
                break;
            }
        }

        // set6
        keybytesLen = Utils.asc2hex(keybytes, "E4845C209CBCD1A7927EE49E5C50155698B2F6E496FD84255191B700A42F58EBBAA413B1C7A8CD72F50538EBA2FCA4F7C8E41856BC14A1AE1C03EACF02AE0D3B7E3AA9E644DB353AA1F4935EB480E8B8DAB0ACB16AD5FDB8A3813989E2E9CBAF188E45477C1DB0087D931F80FBA48BA0B65EDA7B070A414BCE53CCB5ABAA3B4E");
        msgLen = Utils.asc2hex(msg, "71E8105DD735E6E3712904D8DF3232B84536CC3EFB79146F85C0CCDBC5B705206F9032AFBEED80D365006AEFC9F087076D7FA781ADEB1F2DB011618498D8D02DFBCDD2C6970B26E0415E784B1FA83295178396CD87270A8C378FB2378CD7447EFEE91828CB587F13ED8C56764A20DB6A2C88BFA9F0F77C95027FE87C097B0A1A");
        outputLen = Utils.asc2hex(kat, "72179DF96A36AE7567CC64CE6F50149EEC01D6CA058F49856DEE52ABCA34CF47");

        byte[] output6 = new byte[outputLen];
        KISA_HMAC.HMAC_SHA256_Transform(output6, keybytes, keybytesLen, msg, msgLen);

        Utils.print_hex("output", output6, outputLen);
        for (cnt_i = 0; cnt_i < outputLen; cnt_i++) {
            if (kat[cnt_i] != output6[cnt_i]) {
                System.out.println("FAIL: " + cnt_i);
                break;
            }
        }
    }

    public void testSHA256() {
        byte pbData[] = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F};

        byte pbData1[] = {(byte) 0x61};

        byte pbCipher[] = new byte[32];
        byte pbPlain[] = new byte[16];

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
            KISA_SHA256.SHA256_Encrpyt(pbData, Plaintext_length, pbCipher);

            System.out.print("Ciphertext\t: ");
            for (int i = 0; i < 32; i++) System.out.print(Integer.toHexString(0xff & pbCipher[i]) + " ");
            System.out.print("\n\n");

            Plaintext_length++;
        }


        System.out.print("Plaintext\t: ");
        for (int i = 0; i < 1; i++) System.out.print(Integer.toHexString(0xff & pbData1[i]) + " ");
        System.out.print("\n");
        // Encryption
        KISA_SHA256.SHA256_Encrpyt(pbData1, 1, pbCipher);
        System.out.print("Ciphertext\t: ");
        for (int i = 0; i < 32; i++) System.out.print(Integer.toHexString(0xff & pbCipher[i]) + " ");
        System.out.print("\n\n");
    }
}
