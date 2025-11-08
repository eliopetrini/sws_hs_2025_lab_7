package ch.zhaw.securitylab.slcrypt.decrypt;

import ch.zhaw.securitylab.slcrypt.decrypt.HybridDecryption.AutIntState;

/**
 * The DecryptedDocument serves to hold various information about decrypted
 * documents for informational reasons.
 */
public class DecryptedDocument {

    private byte[] document;
    private String cipherName;
    private byte[] secretKey;
    private byte[] iv;
    private char authIntType;
    private String authIntName;
    private byte[] authIntReceived;
    private byte[] authIntComp;
    private AutIntState authIntState;

    public byte[] getDocument() {
        return document;
    }

    public void setDocument(byte[] document) {
        this.document = document;
    }

    public String getCipherName() {
        return cipherName;
    }

    public void setCipherName(String cipherName) {
        this.cipherName = cipherName;
    }
    
        public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }
    
    public char getAuthIntType() {
        return authIntType;
    }

    public void setAuthIntType(char authIntType) {
        this.authIntType = authIntType;
    }

    public String getAuthIntName() {
        return authIntName;
    }

    public void setAuthIntName(String authIntName) {
        this.authIntName = authIntName;
    }

    public byte[] getAuthIntReceived() {
        return authIntReceived;
    }

    public void setAuthIntReceived(byte[] authIntReceived) {
        this.authIntReceived = authIntReceived;
    }

    public byte[] getAuthIntComp() {
        return authIntComp;
    }

    public void setAuthIntComp(byte[] authIntComp) {
        this.authIntComp = authIntComp;
    }
    
    public AutIntState getAuthIntState() {
        return authIntState;
    }

    public void setAuthIntState(AutIntState authIntState) {
        this.authIntState = authIntState;
    }


}
