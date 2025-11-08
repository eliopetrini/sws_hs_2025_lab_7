package ch.zhaw.securitylab.slcrypt.decrypt;

import java.io.InputStream;
import java.util.Arrays;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import ch.zhaw.securitylab.slcrypt.FileHeader;
import ch.zhaw.securitylab.slcrypt.Helpers;
import ch.zhaw.securitylab.slcrypt.InvalidFormatException;
import java.security.NoSuchAlgorithmException;

/**
 * The abstract HybridDecryption class allows hybrid decryption of a document.
 * It provides implemented functionality to decrypt the document based on a
 * hybrid encrypted document and a private key (both available as InputStreams).
 * It also checks the MAC over the decrypted document. To use the class, a
 * subclass must implement the getFileHeader, getDecryptedSecretKey,
 * decryptDocument, and checkMAC methods.
 */
public abstract class HybridDecryption {

    public enum AutIntState {
        valid, invalid
    }

    /**
     * Decrypts an encrypted document that is available from an InputStream.
     *
     * @param input The document to decrypt
     * @param privateKeyDecrypt An input stream from which the private key to 
     *                          sign can be read
     * @param macPassword The password to use for the MAC
     * @return The decrypted document
     */
    public DecryptedDocument decryptDocumentStream(InputStream input, 
            InputStream privateKeyDecrypt, byte[] macPassword) 
            throws InvalidFormatException, CertificateException {
        DecryptedDocument decryptedDocument = new DecryptedDocument();

        // Get the entire encrypted data structure and the file header
        byte[] headerEncryptedDocumentAuthInt = Helpers.inputStreamToByteArray(input);
        FileHeader fileHeader = getFileHeader(headerEncryptedDocumentAuthInt);

        // Check used the authentication and integrity protection type
        char authIntType = fileHeader.getAuthIntType();
        byte[] headerEncryptedDocument = null;
        switch (authIntType) {
            case Helpers.MAC:
                decryptedDocument.setAuthIntType(Helpers.MAC);
                
                // Get the MAC algorithm
                String macAlgorithm = fileHeader.getAuthIntAlgorithm();

                // Get headerEncryptedDocument and MAC
                int macLength = Helpers.getMACSize(macAlgorithm);
                headerEncryptedDocument = Arrays.copyOfRange(headerEncryptedDocumentAuthInt, 0,
                        headerEncryptedDocumentAuthInt.length - macLength);
                byte[] macReceived = Arrays.copyOfRange(headerEncryptedDocumentAuthInt,
                        headerEncryptedDocumentAuthInt.length - macLength, headerEncryptedDocumentAuthInt.length);
                decryptedDocument.setAuthIntReceived(macReceived);
                
                // Check the MAC
                if (checkMAC(decryptedDocument, headerEncryptedDocument,
                    macAlgorithm, macReceived, macPassword)) {
                    decryptedDocument.setAuthIntState(AutIntState.valid);
                } else {
                    decryptedDocument.setAuthIntState(AutIntState.invalid);
                }
                break;
                
            case Helpers.SIGNATURE:
                decryptedDocument.setAuthIntType(Helpers.SIGNATURE);
                
                // Get the signature algorithm
                String signatureAlgorithm = fileHeader.getAuthIntAlgorithm();

                // Get the certificate from the file header, create certificate 
                // object and get public key length
                byte[] certificateRaw = fileHeader.getCertificate();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(certificateRaw);
                Certificate certificate = cf.generateCertificate(in);
                int signatureLength = ((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength()/8;
                
                // Get headerEncryptedDocument and signature and check the signature
                headerEncryptedDocument = Arrays.copyOfRange(headerEncryptedDocumentAuthInt, 0,
                        headerEncryptedDocumentAuthInt.length - signatureLength);
                byte[] signatureReceived = Arrays.copyOfRange(headerEncryptedDocumentAuthInt,
                        headerEncryptedDocumentAuthInt.length - signatureLength, headerEncryptedDocumentAuthInt.length);
                decryptedDocument.setAuthIntReceived(signatureReceived);
                
                // Check the signature
                if (checkSignature(decryptedDocument, headerEncryptedDocument,
                    signatureAlgorithm, signatureReceived, certificate)) {
                    decryptedDocument.setAuthIntState(AutIntState.valid);
                } else {
                    decryptedDocument.setAuthIntState(AutIntState.invalid);
                }
                break;
            case Helpers.NONE:
                decryptedDocument.setAuthIntType(Helpers.NONE);
                
                // No MAC
                headerEncryptedDocument = headerEncryptedDocumentAuthInt;
                break;
            default:
                throw new InvalidFormatException("[AuthIntType] AuthIntType " + authIntType + " not supported");
        }
        
        // Remove header from headerEncryptedDocument
        int headerLength = fileHeader.encode().length;
        byte[] encryptedDocument = Arrays.copyOfRange(headerEncryptedDocument,
                headerLength, headerEncryptedDocument.length);

        // Get the secret key from the file header and decrypt it
        byte[] secretKey = getDecryptedSecretKey(fileHeader, privateKeyDecrypt);

        // Decrypt the document with the secret key
        byte[] document = decryptDocument(encryptedDocument, fileHeader, secretKey);
        decryptedDocument.setDocument(document);

        // Set the fields in decryptedDocument and return it
        decryptedDocument.setCipherName(fileHeader.getCipherAlgorithm());
        decryptedDocument.setAuthIntName(fileHeader.getAuthIntAlgorithm());
        decryptedDocument.setIv(fileHeader.getIV());
        decryptedDocument.setSecretKey(secretKey);
        return decryptedDocument;
    }

    /**
     * Gets the file header object.
     *
     * @param headerEncryptedDocument The encrypted document, including the file
     * header
     * @return The file header object
     */
    protected abstract FileHeader getFileHeader(byte[] headerEncryptedDocument)
            throws InvalidFormatException;

    /**
     * Checks the HMAC over a byte array.
     *
     * @param decryptedDocument The object containing all results
     * @param input The input over which to compute the MAC
     * @param macAlgorithm The MAC algorithm to use
     * @param expectedMAC The expected MAC
     * @return true if the MAC is correct, false otherwise
     */
    public abstract boolean checkMAC(DecryptedDocument decryptedDocument, 
            byte[] input, String macAlgorithm, byte[] expectedMAC, 
            byte[] password) throws InvalidFormatException;
    
    /**
     * Checks the Signature over a byte array.
     *
     * @param decryptedDocument The object containing all results
     * @param input The input over which to check the signature
     * @param signatureAlgorithm The signature algorithm to use
     * @param signature The signature
     * @param certificate The certificate to verify the signature
     * @return true if the MAC is correct, false otherwise
     */
    public abstract boolean checkSignature(DecryptedDocument decryptedDocument, 
            byte[] input, String signatureAlgorithm, byte[] signature, 
            Certificate certificate) throws InvalidFormatException;

    /**
     * Gets the decrypted secret key.
     *
     * @param fileHeader The file header
     * @param privateKey The private key to decrypt the secret key
     * @return The decrypted secret key
     */
    protected abstract byte[] getDecryptedSecretKey(FileHeader fileHeader,
            InputStream privateKey) throws InvalidFormatException;

    /**
     * Decrypts the document.
     *
     * @param encryptedDocument The document to decrypt
     * @param fileHeader The file header that contains information for
     * encryption
     * @param secretKey The secret key to decrypt the document
     * @return The decrypted document
     */
    protected abstract byte[] decryptDocument(byte[] encryptedDocument,
            FileHeader fileHeader, byte[] secretKey) throws InvalidFormatException;
}
