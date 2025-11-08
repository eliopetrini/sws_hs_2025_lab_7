package ch.zhaw.securitylab.slcrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * The FileHeader class supports encoding and decoding of file headers. Encoding
 * means that the file header is built based on the version and encrypted
 * secret key. Decoding means that a file header is read and the version and
 * encrypted secret key are extracted.
 */
public class FileHeader {

    private static final byte[] FORMAT_STRING = {'S', 'L', 'C', 'R', 'Y', 'P', 'T'};
    private static final int VERSION = 1;
    private String cipherAlgorithm;
    private byte[] iv;
    private char authIntType;
    private String authIntAlgorithm;
    private byte[] encryptedSecretKey;
    private byte[] certificate;

    /**
     * Constructor. Empty default constructor.
     */
    public FileHeader() {
    }

    /**
     * Constructor. Decodes an existing file header that is stored in a byte
     * array. The values (version and encrypted secret key) are written to the
     * instance variables version and encryptedSecretKey.
     *
     * @param fileHeader The file header to decode
     * @throws InvalidFormatException
     */
    public FileHeader(byte[] fileHeader) throws InvalidFormatException {
        decode(new ByteArrayInputStream(fileHeader));
    }

    /**
     * Constructor. Decodes an existing file header that can be read from an
     * InputStream. The values (version and encrypted secret key) are written
     * to the instance variables version and encryptedSecretKey.
     *
     * @param fileHeaderStream The stream from which the file header can be read
     * @throws InvalidFormatException
     */
    public FileHeader(InputStream fileHeaderStream)
            throws InvalidFormatException {
        decode(fileHeaderStream);
    }

    /**
     * Decodes a file header that can be read from an InputStream. The values
     * (version and encrypted secret key) are written to the instance variables
     * version and encryptedSecretKey.
     *
     * @param is The InputStream from which file header can be read
     * @throws InvalidFormatException
     */
    private void decode(InputStream is) throws InvalidFormatException {
        int length;
        byte[] formatString = new byte[FORMAT_STRING.length];

        try {
            // Read SLCrypt file type
            is.read(formatString);
            if (!Arrays.equals(FORMAT_STRING, formatString)) {
                throw new InvalidFormatException("Not an SLCrypt file");
            }

            // Read file version
            if (is.read() != VERSION) {
                throw new InvalidFormatException("Unknown file version");
            }

            // Read cipher
            length = is.read();
            byte[] cipherBytes = new byte[length];
            is.read(cipherBytes);
            cipherAlgorithm = new String(cipherBytes, Charset.forName("UTF-8"));

            // Read IV
            length = is.read();
            iv = new byte[length];
            is.read(iv);
            
            // Read authentication/integrity algorithm type
            authIntType = (char) is.read();

            // Read authentication/integrity algorithm
            length = is.read();
            byte[] macBytes = new byte[length];
            is.read(macBytes);
            authIntAlgorithm = new String(macBytes, Charset.forName("UTF-8"));

            // Read certificate
            length = 256 * is.read() + is.read();
            certificate = new byte[length];
            is.read(certificate);
            
            // Read encrypted secret key
            length = 256 * is.read() + is.read();
            encryptedSecretKey = new byte[length];
            is.read(encryptedSecretKey);
        } catch (IOException e) {
            throw new InvalidFormatException("Invalid format");
        }
    }

    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public void setCipherAlgorithm(String cipher) {
        this.cipherAlgorithm = cipher;
    }

    public byte[] getIV() {
        return iv;
    }

    public void setIV(byte[] iv) {
        this.iv = iv;
    }
    
    public char getAuthIntType() {
        return authIntType;
    }

    public void setAuthIntType(char authIntType) {
        this.authIntType = authIntType;
    }

    public String getAuthIntAlgorithm() {
        return authIntAlgorithm;
    }

    public void setAuthIntAlgorithm(String authIntAlgorithm) {
        this.authIntAlgorithm = authIntAlgorithm;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public byte[] getEncryptedSecretKey() {
        return encryptedSecretKey;
    }

    public void setEncryptedSecretKey(byte[] secretKey) {
        this.encryptedSecretKey = secretKey;
    }

    /**
     * Encodes the file header using the currently stored values from the 
     * instance variables.
     *
     * @return The file header
     */
    public byte[] encode() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        try {
            os.write(FORMAT_STRING);
            os.write(VERSION);
            os.write(cipherAlgorithm.length() & 0xff);
            os.write(cipherAlgorithm.getBytes(Charset.forName("UTF-8")));
            os.write(iv.length & 0xff);
            os.write(iv);
            os.write(authIntType);
            os.write(authIntAlgorithm.length() & 0xff);
            os.write(authIntAlgorithm.getBytes(Charset.forName("UTF-8")));
            os.write((byte) ((certificate.length >> 8) & 0xff));
            os.write((byte) (certificate.length & 0xff));
            os.write(certificate);
            os.write((byte) ((encryptedSecretKey.length >> 8) & 0xff));
            os.write((byte) (encryptedSecretKey.length & 0xff));
            os.write(encryptedSecretKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return os.toByteArray();
    }
}
