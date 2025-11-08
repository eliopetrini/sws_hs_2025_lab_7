package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.InputStream;
import ch.zhaw.securitylab.slcrypt.FileHeader;

/**
 * A concrete implementation of the abstract class HybridEncryption.
 */
public class HybridEncryptionImpl extends HybridEncryption {

    /**
     * Creates a secret key.
     *
     * @param cipherAlgorithm The cipher algorithm to use
     * @param keyLength The key length in bits
     * @return The secret key
     */
    @Override
    protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {

        // To do...
        return null;
    }

    /**
     * Encrypts the secret key with a public key.
     *
     * @param secretKey The secret key to encrypt
     * @param certificateEncrypt An input stream from which the certificate with
     *                           the public key for encryption can be read
     * @return The encrypted secret key
     */
    @Override
    protected byte[] encryptSecretKey(byte[] secretKey, 
            InputStream certificateEncrypt) {

        // To do...
        return null;
    }

    /**
     * Creates a file header object and fills it with the cipher algorithm name,
     * the IV (which must first be created), the authentication and integrity 
     * protection type and algorithm name, the certificate, and the encrypted 
     * secret key.
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
    @Override
    protected FileHeader generateFileHeader(String cipherAlgorithm, 
            char authIntType, String authIntAlgorithm, 
            InputStream certificateVerify, byte[] encryptedSecretKey) {

        // To do...
        return null;
    }

    /**
     * Encrypts a document with a secret key. If GCM is used, the file header is
     * added as additionally encrypted data.
     *
     * @param document The document to encrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key used for encryption
     * @return A byte array that contains the encrypted document
     */
    @Override
    protected byte[] encryptDocument(InputStream document, 
            FileHeader fileHeader, byte[] secretKey) {

        // To do...
        return null;
    }

    /**
     * Computes the HMAC over a byte array.
     *
     * @param dataToProtect The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param password The password to use for the MAC
     * @return The byte array that contains the MAC
     */
    @Override
    protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm, 
            byte[] password) {

        // To do...
        return null;
    }
    
    /**
     * Computes the signature over a byte array.
     *
     * @param dataToProtect The input over which to compute the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param privateKeySign An input stream from which the private key to sign
     *                       can be read
     * @return The byte array that contains the signature
     */
    @Override
    protected byte[] computeSignature(byte[] dataToProtect, 
            String signatureAlgorithm, InputStream privateKeySign) {
        
        // To do...
        return null;
    }
}
