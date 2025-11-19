package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import ch.zhaw.securitylab.slcrypt.FileHeader;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static ch.zhaw.securitylab.slcrypt.Helpers.*;

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
        SecretKey key = null;
        try {
            KeyGenerator kg = KeyGenerator.getInstance(getCipherName(cipherAlgorithm));
            kg.init(keyLength);
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm not supported " + e);
        }

        if (key == null) {
            throw new IllegalStateException("Failed to generate secret key.");
        }
        // To do...
        return key.getEncoded();

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
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certificateEncrypt);
            PublicKey publicKey = cert.getPublicKey();
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding"); // not sure if correct
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(secretKey);
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
        // To do...
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

        FileHeader myHeader = new FileHeader();

        SecureRandom myRandom = new SecureRandom();
        byte[] myIV = new byte[getIVLength(cipherAlgorithm)];
        myRandom.nextBytes(myIV);
        myHeader.setIV(myIV);

        myHeader.setAuthIntType(authIntType);
        if (myHeader.getAuthIntType() == 'N') {
            myHeader.setAuthIntAlgorithm("");
        } else {
            myHeader.setAuthIntAlgorithm(authIntAlgorithm);
        }
        myHeader.setCipherAlgorithm(cipherAlgorithm);

        if (!(certificateVerify == null)) {
            myHeader.setCertificate(inputStreamToByteArray(certificateVerify));
        } else {
            myHeader.setCertificate(new byte[0]);
        }

        myHeader.setEncryptedSecretKey(encryptedSecretKey);
        // To do...
        return myHeader;
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

        String algorithm = fileHeader.getCipherAlgorithm();

        try {
            SecretKeySpec kg = new SecretKeySpec(secretKey, getCipherName(algorithm));

            Cipher c1 = Cipher.getInstance(algorithm);

            if (isGCM(algorithm)) {
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, fileHeader.getIV());
                c1.init(Cipher.ENCRYPT_MODE, kg, gcmSpec);
                c1.updateAAD(fileHeader.encode());

            } else if (hasIV(algorithm)) {
                IvParameterSpec ivSpec = new IvParameterSpec(fileHeader.getIV());
                c1.init(Cipher.ENCRYPT_MODE, kg, ivSpec);
            } else {
                c1.init(Cipher.ENCRYPT_MODE, kg);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = document.read(buffer)) != -1) {
                byte[] encryptedChunk = c1.update(buffer, 0, bytesRead);
                if (encryptedChunk != null) {
                    outputStream.write(encryptedChunk);
                }
            }

            byte[] finalBytes = c1.doFinal();
            if (finalBytes != null) {
                outputStream.write(finalBytes);
            }

            return outputStream.toByteArray();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException | IOException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        // To do...
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
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            SecretKeySpec secretKeySpec = new SecretKeySpec(password, macAlgorithm);
            mac.init(secretKeySpec);
            return mac.doFinal(dataToProtect);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return null;
        }
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
        try {
            byte[] privateKeyBytes = inputStreamToByteArray(privateKeySign);
            assert privateKeyBytes != null;
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            //Signatur erstellen
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(dataToProtect);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | SignatureException e) {
            return null;
        }
        // To do...
    }
}
