package ch.zhaw.securitylab.slcrypt.decrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import ch.zhaw.securitylab.slcrypt.Helpers;
import ch.zhaw.securitylab.slcrypt.InvalidFormatException;
import ch.zhaw.securitylab.slcrypt.decrypt.HybridDecryption.AutIntState;

/**
 * The main class to hybrid decrypt (including checking the MAC or the
 * signature) a document.
 */
public class SLDecrypt {

    /**
     * The main method to hybrid decrypt a document.
     *
     * @param args The command line parameters
     */
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Not enough arguments\n");
            usage();
        }
        new SLDecrypt(args[0], args[1], args[2], args.length < 4 ? "" : args[3]);
    }

    /**
     * Prints the usage.
     */
    private static void usage() {
        System.out.println("Usage: java SLDecrypt encrypted_file "
                + "decrypted_file private_key_file_for_decryption [mac_password]");
        System.exit(-1);
    }

    /**
     * Constructor. Hybrid decrypts a document.
     *
     * @param inFilename The file to decrypt
     * @param outFilename The filename to use for the decrypted document
     * @param privateKeyDecryptFilename The filename of the private key for 
     *                                  decryption
     * @param macPassword The password for the MAC
     */
    private SLDecrypt(String inFilename, String outFilename, 
            String privateKeyDecryptFilename, String macPassword) {
        FileInputStream in = null;
        FileOutputStream out = null;
        FileInputStream privateKeyDecrypt = null;

        try {
            // Create streams for all files to read/write
            File inFile = new File(inFilename);
            in = new FileInputStream(inFile);
            File outFile = new File(outFilename);
            out = new FileOutputStream(outFile);
            File privateKeyDecryptFile = new File(privateKeyDecryptFilename);
            privateKeyDecrypt = new FileInputStream(privateKeyDecryptFile);

            // Decrypt the document	
            decrypt(in, out, privateKeyDecrypt, macPassword);
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
        } catch (InvalidFormatException e) {
            System.out.println("Error decrypting file! " + e.getMessage());
        } catch (IOException e) {
            System.out.println("I/O error: " + e.getMessage());
        } catch (CertificateException e) {
            System.out.println("Certificate error: " + e.getMessage());
        } finally {

            // close the streams
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
            if (privateKeyDecrypt != null) {
                try {
                    privateKeyDecrypt.close();
                } catch (IOException e) {}
            }
        }
    }

    /**
     * Hybrid decrypts a document.
     *
     * @param in The InputStream from which to read the encrypted document
     * @param out The OutputStream to which to write the decrypted document
     * @param privateKeyDecrypt The InputStream from which to read the private
     *                          key for decryption
     * @param macPassword The password to use for computing the HMAC
     * @throws IOException
     */
    private void decrypt(FileInputStream in, FileOutputStream out,
            FileInputStream privateKeyDecrypt, String macPassword)
            throws InvalidFormatException, IOException, CertificateException {

        // Hybrid decrypt the document
        HybridDecryption hd = new HybridDecryptionImpl();
        DecryptedDocument document = hd.decryptDocumentStream(in, privateKeyDecrypt,
                macPassword.getBytes(Charset.forName("UTF-8")));

        // Display information depending on authentication and integrity protection type
        System.out.println("");
        if (document.getAuthIntType() == Helpers.MAC) {
            System.out.println("MAC algorithm:        " + document.getAuthIntName());
            System.out.println("MAC received:         " + Helpers.asHex(document.getAuthIntReceived()));
            System.out.println("MAC computed:         " + Helpers.asHex(document.getAuthIntComp()));
            if (document.getAuthIntState() == AutIntState.valid) {
                System.out.println("=> MAC successfully verified");
            } else if (document.getAuthIntState() == AutIntState.invalid) {
                System.out.println("=> Error, wrong MAC!");
            }
        } else if (document.getAuthIntType() == Helpers.SIGNATURE) {
            System.out.println("Signature algorithm:  " + document.getAuthIntName());
            System.out.println("Signature received:   " + Helpers.asHex(document.getAuthIntReceived()));
            if (document.getAuthIntState() == AutIntState.valid) {
                System.out.println("=> Signature successfully verified");
            } else if (document.getAuthIntState() == AutIntState.invalid) {
                System.out.println("=> Error, signature could not be verified!");
            }
        } else if (document.getAuthIntType() == Helpers.NONE) {
            System.out.println("=> Neither MAC nor Signature included to verify authentication and integrity");
        }
        
        // Display information about algorithm, key and IV
        System.out.println("");
        System.out.println("Cipher algorithm:     " + document.getCipherName());
        System.out.println("Key length:           " + document.getSecretKey().length * 8);
        System.out.println("Key:                  " + Helpers.asHex(document.getSecretKey()));
        System.out.println("IV:                   " + Helpers.asHex(document.getIv()));

        // Display information about plaintext
        System.out.println("");
        System.out.print("Plaintext (" + document.getDocument().length + " bytes): ");
        if (document.getDocument().length <= 1000) {
            System.out.println(new String(document.getDocument()));
        } else {
            System.out.println(new String(document.getDocument(), 0, 1000));
        }

        // Save the decrypted document
        out.write(document.getDocument());
    }
}
