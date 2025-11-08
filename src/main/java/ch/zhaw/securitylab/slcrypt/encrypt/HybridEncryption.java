package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import ch.zhaw.securitylab.slcrypt.FileHeader;
import ch.zhaw.securitylab.slcrypt.Helpers;

/**
 * The abstract HybridEncryption class allows encrypting a document using hybrid
 * encryption and producing a MAC over a file header and the encrypted document.
 * GCM is also supported, but in this case, no MAC is created as this is
 * integrated in GCM. To use the class, a subclass must implement the five
 * abstract methods.
 */
public abstract class HybridEncryption {

    /**
     * Encrypts a document that is available from an InputStream.
     *
     * @param document The document to encrypt
     * @param certificateEncrypt The certificate of which the public key is used
     *                           to encrypt the document
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length to use
     * @param authIntType The type to use for authentication and integrity
     *                    protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The algorithm to use for authentication and
     *                         integrity protection
     * @param macPassword The password to use for the MAC
     * @param privateKeySign The private key to create the signature
     * @param certificateVerify The certificate for signature verification
     * @return The encrypted and authenticated/integrity protected document
     * including the file header.
     */
    public byte[] encryptDocumentStream(InputStream document, 
            InputStream certificateEncrypt, String cipherAlgorithm, int keyLength, 
            char authIntType, String authIntAlgorithm, byte[] macPassword,
            InputStream privateKeySign, InputStream certificateVerify) {

        // Generate a new random secret key
        byte[] secretKey = generateSecretKey(cipherAlgorithm, keyLength);

        // Encrypt the secret key with the public key in the certificate
        byte[] encryptedSecretKey = encryptSecretKey(secretKey, certificateEncrypt);

        // Generate the file header using the encrypted secret key
        FileHeader fileHeader = generateFileHeader(cipherAlgorithm, authIntType,
                authIntAlgorithm, certificateVerify, encryptedSecretKey);

        // Encrypt the document
        byte[] encryptedDocument = encryptDocument(document, fileHeader, 
                secretKey);

        // Prepend the file header
        byte[] headerEncryptedDocument = concatByteArrays(fileHeader.encode(), 
                encryptedDocument);

        // Check authIntType in the file header
        byte[] headerEncryptedDocumentAuthInt = null;
        switch (authIntType) {
            case Helpers.MAC:
                
                // Compute the MAC and append it
                byte[] hmac = computeMAC(headerEncryptedDocument, 
                        authIntAlgorithm, macPassword);
                headerEncryptedDocumentAuthInt = 
                        concatByteArrays(headerEncryptedDocument, hmac);
                break;
            case Helpers.SIGNATURE:
                
                // Compute the Signature and append it
                byte[] signature = computeSignature(headerEncryptedDocument, 
                        authIntAlgorithm, privateKeySign);
                headerEncryptedDocumentAuthInt = 
                        concatByteArrays(headerEncryptedDocument, signature);
                break;
            case Helpers.NONE:
                
                // Don't append anything
                headerEncryptedDocumentAuthInt = headerEncryptedDocument;
                break;
            default:
                break;
        }
        
        // Return the completely protected document
        return headerEncryptedDocumentAuthInt;
    }

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    protected abstract byte[] generateSecretKey(String cipherAlgorithm, 
            int keyLength);

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificateEncrypt An input stream from which the certificate with
     *                           the public key for encryption can be read
     * @return The encrypted secret key
     */
    protected abstract byte[] encryptSecretKey(byte[] secretKey, 
            InputStream certificateEncrypt);

    /**
     * Creates a file header object and fills it with the cipher algorithm name,
     * the authentication and integrity protection type and name, and the
     * encrypted secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param authIntType The type to use for authentication and integrity
     *                    protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The algorithm to use for authentication and
     *                         integrity protection
     * @param certificateVerify An input stream from which the certificate for
     *                          signature verification can be read
     * @param encryptedSecretKey The encrypted secret key
     * @return The new file header object
     */
    protected abstract FileHeader generateFileHeader(String cipherAlgorithm, 
            char authIntType, String authIntAlgorithm, 
            InputStream certificateVerify, byte[] encryptedSecretKey);

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document The document to encrypt
     * @param fileHeader The file header that contains information for encryption
     * @param secretKey The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    protected abstract byte[] encryptDocument(InputStream document,
            FileHeader fileHeader, byte[] secretKey);

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    protected abstract byte[] computeMAC(byte[] dataToProtect, 
            String macAlgorithm, byte[] password);
    
    /**
     * Computes the signature over a byte array.
     *
     * @param dataToProtect The input over which to compute the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param privateKeySign An input stream from which the private key to sign
     *                       can be read
     * @return The byte array that contains the signature
     */
    protected abstract byte[] computeSignature(byte[] dataToProtect, 
            String signatureAlgorithm, InputStream privateKeySign);

    private byte[] concatByteArrays(byte[] first, byte[] second) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(first);
            outputStream.write(second);
            return outputStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
