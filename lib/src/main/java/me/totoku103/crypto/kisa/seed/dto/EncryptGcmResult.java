package me.totoku103.crypto.kisa.seed.dto;


public class EncryptGcmResult {
    private String cipherText;
    private String nonce;
    private String aad;

    public String getCipherText() {
        return cipherText;
    }

    public void setCipherText(final String cipherText) {
        this.cipherText = cipherText;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(final String nonce) {
        this.nonce = nonce;
    }

    public String getAad() {
        return aad;
    }

    public void setAad(final String aad) {
        this.aad = aad;
    }

    @Override
    public String toString() {
        return "EncryptGcmResult{" +
                "cipherText='" + cipherText + '\'' +
                ", nonce='" + nonce + '\'' +
                ", aad='" + aad + '\'' +
                '}';
    }

    public String toJson() {
        return "{" +
                "\"cipherText\":\"" + cipherText + "\"," +
                "\"nonce\":\"" + nonce + "\"," +
                "\"aad\":\"" + aad + "\"" +
                "}";
    }
}
