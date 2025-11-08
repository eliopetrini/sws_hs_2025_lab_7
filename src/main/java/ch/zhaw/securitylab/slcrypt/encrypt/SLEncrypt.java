package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import ch.zhaw.securitylab.slcrypt.Helpers;

/**
 * The main class to produce an encrypted, authenticated and 
 * integrity-protected document.
 */
public class SLEncrypt {

    /**
     * The main method to hybrid encrypt a document.
     *
     * @param args The command line parameters
     */
    public static void main(String[] args) {
        if (args.length < 6) {
            System.out.println("Not enough arguments\n");
            usage();
        }
        int keyLength = 0;
        try {
            keyLength = Integer.parseInt(args[4]);
        } catch (Exception e) {
            System.out.println("key_length must be an integer\n");
            usage();
        }
        if (args[5].length() != 1 || !(args[5].charAt(0) == Helpers.MAC || 
                args[5].charAt(0) == Helpers.SIGNATURE || 
                args[5].charAt(0) == Helpers.NONE)) {
            System.out.println("auth_int_protection_type must be M(AC), "
                    + "S(ignature) or N(one)\n");
            usage();
        }
        char authIntType = args[5].charAt(0);
        String authIntProtectionAlgorithm = "";
        String macPassword = "";
        String privateKeyFileForSigning = "";
        String certificateFileForVerification = "";
        if (authIntType == Helpers.MAC) {
            if (args.length < 8) {
                System.out.println("Not enough arguments\n");
                usage();
            }
            authIntProtectionAlgorithm = args[6];
            macPassword = args[7];
        } else if (authIntType == Helpers.SIGNATURE) {
            if (args.length < 9) {
                System.out.println("Not enough arguments\n");
                usage();
            }
            authIntProtectionAlgorithm = args[6];
            privateKeyFileForSigning = args[7];
            certificateFileForVerification = args[8];
        }
        new SLEncrypt(args[0], args[1], args[2], args[3], keyLength, 
                authIntType, authIntProtectionAlgorithm, macPassword, 
                privateKeyFileForSigning, certificateFileForVerification);
    }
    
    /**
     * Prints the usage.
     */
    private static void usage() {
        System.out.println("Usage: java SLEncrypt plain_file encrypted_file "
                + "certificate_file_for_encryption cipher_algorithm key_length "
                + "auth_int_protection_type(M|S|N) "
                + "[auth_int_protection_algorithm] [[mac_password] |"
                + " [private_key_file_for_signing certificate_file_for_verification]]");
        System.exit(-1);
    }

    /**ß
     * Constructor. Hybrid encrypts a document.
     *
     * @param inFilename The file to encrypt
     * @param outFilename The filename to use for the encrypted document
     * @param certificateEncryptFilename The filename of the certificate for 
     *                                   encryption
     * @param cipherAlgorithm The name of the cipher algorithm to use
     * @param keyLength The key length in bits
     * @param authIntType The type to use for authentication and integrity
     *                    protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The name of the algorithm for authentication and
     *                         integrity protection to use
     * @param macPassword The password for the MAC
     * @param privateKeySignFilename The filename of the private key for signing
     * @param certificateVerifyFilename The filename of the certificate for 
     *                                  signature verification
     */
    private SLEncrypt(String inFilename, String outFilename, 
            String certificateEncryptFilename, String cipherAlgorithm, int keyLength, 
            char authIntType, String authIntAlgorithm, String macPassword, 
            String privateKeySignFilename, String certificateVerifyFilename) {
        FileInputStream in = null;
        FileOutputStream out = null;
        FileInputStream certificateEncrypt = null;
        FileInputStream privateKeySign = null;
        FileInputStream certificateVerify = null;

        try {
            // Create streams for all files to read/write
            File inFile = new File(inFilename);
            in = new FileInputStream(inFile);
            File outFile = new File(outFilename);
            out = new FileOutputStream(outFile);
            File certificateEncryptFile = new File(certificateEncryptFilename);
            certificateEncrypt = new FileInputStream(certificateEncryptFile);
            if (authIntType == Helpers.SIGNATURE) {
                privateKeySign = new FileInputStream(privateKeySignFilename);
                certificateVerify = new FileInputStream(certificateVerifyFilename);
            }

            // Encrypt the document
            encrypt(in, out, certificateEncrypt, cipherAlgorithm, keyLength, 
                    authIntType, authIntAlgorithm, macPassword, privateKeySign,
                    certificateVerify);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {

            // Close the streams
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {}
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {}
            }
            if (certificateEncrypt != null) {
                try {
                    certificateEncrypt.close();
                } catch (IOException e) {}
            }
            if (privateKeySign != null) {
                try {
                    privateKeySign.close();
                } catch (IOException e) {}
            }
            if (certificateVerify != null) {
                try {
                    certificateVerify.close();
                } catch (IOException e) {}
            }
        }
    }

    /**
     * Hybrid encrypts a document.
     *
     * @param in The InputStream from which to read the document
     * @param out The OutputStream to which to write the encrypted document
     * @param certificateEncrypt The InputStream from which to read the 
     *                           certificate for encryption
     * @param cipherAlgorithm The name of the cipher algorithm to use
     * @param keyLength The key length in bits
     * @param authIntType The type to use for authentication and integrity
     *                    protection (M for MAC, S for signature, N for none)
     * @param authIntAlgorithm The name of the algorithm for authentication and
     *                         integrity protection to use
     * @param macPassword The password for the MAC
     * @param privateKeySign The InputStream from which to read the private key 
     *                       for signing
     * @param certificateVerify The InputStream from which to read the 
     *                          certificate for signature verification
     * @throws IOException
     */
    private void encrypt(InputStream in, OutputStream out, 
            InputStream certificateEncrypt, String cipherAlgorithm, int keyLength, 
            char authIntType, String authIntAlgorithm, String macPassword, 
            InputStream privateKeySign, InputStream certificateVerify) throws IOException {

        // Hybrid encrypt the document
        HybridEncryption he = new HybridEncryptionImpl();
        byte[] macPasswordBytes = null;
        if (macPassword != null) {
            macPasswordBytes = macPassword.getBytes(Charset.forName("UTF-8"));
        }
        byte[] encrypted = he.encryptDocumentStream(in, certificateEncrypt, 
                cipherAlgorithm, keyLength, authIntType, authIntAlgorithm, 
                macPasswordBytes, privateKeySign, certificateVerify);

        // Save the encrypted document
        out.write(encrypted);
    }
}