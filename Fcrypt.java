import java.security.MessageDigest;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * This class can be used to both encrypt and decrypt.
 *
 * In encryption mode(-e), it will use AES(Key size 256 bits) to encrypt the
 * plaintext, encrypt teh AES key with receiver's public key(RSA algorithm),
 * calculate the MD5 of the file, sign the MD5 with sender's private key
 * (RSA algorithm). Finally, it will put the signature, encrypted AES key
 * and cipher text together in the output_ciphertext_file.
 *
 * In decryption mode(-d), it first reads in the cipher text file. Then it
 * splits the file into three parts: Signature, AES Key and Contents. It
 * uses the receiver's private key to decrypt the Key file to get the AES
 * Key. Then it uses the decrypted AES key to decrypt the Contents file. At
 * last the class will sign the MD5 with sender's public key and verify the
 * signature to check if they matched.
 */
public class Fcrypt {
    // The MessageDigest is used to calculate the MD5.
    MessageDigest md;
    // Use rsaCipher and aesCipher to encrypt and decrpt files.
    Cipher rsaCipher, aesCipher;

    public File aesKeyFile = null;
    public File contentsFile = null;
    public File signatureFile = null;

    public Fcrypt() {
        try {
            this.md = MessageDigest.getInstance("MD5");
            this.rsaCipher = Cipher.getInstance("RSA");
            this.aesCipher = Cipher.getInstance("AES");
            this.aesKeyFile = new File("AES_KEY");
            this.contentsFile = new File("CONTENTS");
            this.signatureFile = new File("SIGNATURE");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    void deleteTempFiles() {
        aesKeyFile.delete();
        contentsFile.delete();
        signatureFile.delete();
    }

    String convertByteToHex(byte[] data) {
        //convert the byte to hex format
        StringBuffer sb = new StringBuffer("");
        for (int i = 0; i < data.length; i++) {
            sb.append(Integer.toString((data[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    /**
     * This method takes in the file and returns the MD5 of the file.
     */
    byte[] getMD5(File file) {
        byte[] hash = null;
        try {
            FileInputStream fis = new FileInputStream(file);

            //Using MessageDigest update() method to provide input
            byte[] buffer = new byte[8192];
            int numOfBytesRead;
            while ( (numOfBytesRead = fis.read(buffer)) != -1) {
                md.update(buffer, 0, numOfBytesRead);
            }
            hash = md.digest();

            System.out.println("Digest(in hex format): " + convertByteToHex(hash));

        } catch (IOException e) {
            e.printStackTrace();
        }

        return hash;
    }

    /**
    * Read in everything in InputSteam and write into the OutputStream.
    */
    void copy(InputStream is, OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while ((i = is.read(b)) != -1) {
            os.write(b, 0, i);
        }
    }


    public static void main(String[] args) throws IOException, InvalidKeyException, GeneralSecurityException {
        if (args.length != 5) {
            System.err.println(
                "Usage: java Fcrypt <mode> <key1> <key2> <file1> <file2>");
            System.exit(1);
        }
        String mode = args[0];
        if (mode.equals("-e")) {
            File publicKeyFile = new File(args[1]);
            File privateKeyFile = new File(args[2]);
            File plainTextFile = new File(args[3]);
            File cipherTextFile = new File(args[4]);
            Encryptor encryptor = new Encryptor(publicKeyFile, privateKeyFile, plainTextFile, cipherTextFile);
            encryptor.startEncrypting();
        } else if (mode.equals("-d")) {
            File privateKeyFile = new File(args[1]);
            File publicKeyFile = new File(args[2]);
            File cipherTextFile = new File(args[3]);
            File plainTextFile = new File(args[4]);
            Decryptor decrptor = new Decryptor(privateKeyFile, publicKeyFile, cipherTextFile, plainTextFile);
            decrptor.startDecrypting();
        } else {
            System.err.println(
                "The mode should be either encryption mode -e or decryption mode -d.");
            System.exit(1);
        }
    }
}

/**
 * This class takes care of everything related in encryption process. The
 * AES key size is 256 bits. The RSA public key and private key file should
 * be in DER format.
 */
class Encryptor extends Fcrypt {
    private final static int AES_Key_Size = 256;
    private byte[] aesKey;
    private SecretKeySpec aeskeySpec;
    private File fileToBeEncrypt = null;
    private File fileEncrypted = null;
    private File publicKeyFile = null;
    private File privateKeyFile = null;


    public Encryptor(File publicKeyFile, File privateKeyFile, File fileToBeEncrypt, File fileEncrypted) throws GeneralSecurityException {
        this.publicKeyFile = publicKeyFile;
        this.privateKeyFile = privateKeyFile;
        this.fileToBeEncrypt = fileToBeEncrypt;
        this.fileEncrypted = fileEncrypted;
    }

    /**
     * This method generate a random AES key with the given AES key size.
     */
    void generateAESKey() {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(AES_Key_Size);
            SecretKey key = kgen.generateKey();
            aesKey = key.getEncoded();
            aeskeySpec = new SecretKeySpec(aesKey, "AES");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Failed to generate a random AES key.");
            e.printStackTrace();
        }
    }

    /**
    * Use the CipherOutputStream to encrypt the file.
    */
    void encrypt(File in, File out, SecretKeySpec aeskeySpec) {
        try {
            // If the output file doens't exist. Create one.
            if (!out.exists()) {
                out.createNewFile();
            }
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);

            FileInputStream is = new FileInputStream(in);
            CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), aesCipher);

            // Read in all data from the input file and then write into the CipherOutputStream.
            copy(is, os);

            is.close();
            os.close();
        } catch (IOException e) {
            System.out.println("IOException is thrown in encryption process!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Key is not valid in encryption process.");
            e.printStackTrace();
        }
    }

    /**
     * This method takes in the contents MD5 and sign it with the sender's private
     * key using RSA algorithm. Finally it will write the signature to a temporaray
     * file.
     */
    void writeSignature(byte[] md5, File privateKeyFile, File out) {
        try {
            // read private key to be used to decrypt the AES key
            byte[] encodedKey = new byte[(int)privateKeyFile.length()];
            new FileInputStream(privateKeyFile).read(encodedKey);

            // create private key
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(privateKeySpec);

            Signature mySign = Signature.getInstance("MD5withRSA");
            mySign.initSign(pk);
            mySign.update(md5);
            byte[] byteSignedData = mySign.sign();
            System.out.println("Signature length: " + byteSignedData.length);

            FileOutputStream os = new FileOutputStream(out);

            os.write("<Signature>".getBytes());
            os.write(byteSignedData);
            os.write("</Signature>\n".getBytes());
            os.close();
        } catch (IOException e) {
            System.out.println("Cannot write signature due to IOException.");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Key is not valid when writing signature.");
            e.printStackTrace();
        } catch (SignatureException e) {
            System.out.println("Failed during generate the signature. ");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
    * Encrypts the AES key to a file using an RSA public key
    */
    private void saveKey(File publicKeyFile, File signatureFile, File aesKeyFile) {
        try {
            // If the output file doesn't exist, create one.
            if (!aesKeyFile.exists()) {
                aesKeyFile.createNewFile();
            }
            // read public key to be used to encrypt the AES key
            byte[] encodedKey = new byte[(int)publicKeyFile.length()];
            new FileInputStream(publicKeyFile).read(encodedKey);

            // create public key
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pk = kf.generatePublic(publicKeySpec);

            // write MD5 and AES key
            rsaCipher.init(Cipher.ENCRYPT_MODE, pk);
            CipherOutputStream os = new CipherOutputStream(new FileOutputStream(aesKeyFile, true), rsaCipher);

            os.write("<AES>".getBytes());
            os.write(aesKey);
            os.write("</AES>\n".getBytes());
            os.close();
        } catch (IOException e) {
            System.out.println("Cannot save AES Key to file due to IOException.");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Key is not valid when saving key to file.");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
     * This method combine the temporary files and write the data into a single output file.
     */
    void combineFiles(File a, File b, File out) {
        try {
            if (!out.exists()) {
                out.createNewFile();
            }

            FileInputStream is = new FileInputStream(a);
            FileOutputStream os = new FileOutputStream(out);
            // System.out.println("AES Key File size: " + a.length());
            os.write(String.valueOf((int) (a.length())).getBytes());
            // os.write(signature.getBytes());
            copy(is, os);
            is = new FileInputStream(b);
            copy(is, os);
            is.close();
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void startEncrypting() {
        byte[] md5OfFile = getMD5(fileToBeEncrypt);
        generateAESKey();
        encrypt(fileToBeEncrypt, contentsFile, aeskeySpec);
        writeSignature(md5OfFile, privateKeyFile, aesKeyFile);
        saveKey(publicKeyFile, signatureFile, aesKeyFile);
        combineFiles(aesKeyFile, contentsFile, fileEncrypted);
        deleteTempFiles();
    }
}

/**
 * This class takes care of everything related in decryption process. It
 * takes in the cipher text file and split them into three files: The
 * Signature file, the AES key file and the Ciphered-Contents file. Then it
 * uses its private key to decrypt the AES key file to get the AES key, then
 * use it to decrypt the contents. Finally generate the MD5 of the file and
 * sign it with the sender's public key.
 */
class Decryptor extends Fcrypt {
    private final static int AES_Key_Size = 256;
    private byte[] aesKey;
    private SecretKeySpec aeskeySpec;
    private File fileToBeDecrypt = null;
    private File fileDecrypted = null;
    private File publicKeyFile = null;
    private File privateKeyFile = null;


    public Decryptor(File privateKeyFile, File publicKeyFile, File fileToBeDecrypt, File fileDecrypted) {
        this.fileToBeDecrypt = fileToBeDecrypt;
        this.fileDecrypted = fileDecrypted;
        this.privateKeyFile = privateKeyFile;
        this.publicKeyFile = publicKeyFile;
    }

    /**
     * Split the cipher text file into 3 files.
     */
    void splitFiles(File in, File signatureFile, File aesKeyFile, File contentsFile) {
        try {
            FileInputStream is = new FileInputStream(in);
            byte[] length = new byte[3];
            is.read(length);
            String lengthStr = new String(length);
            int sigLength = Integer.parseInt(lengthStr);
            System.out.println(sigLength);

            // Write the signature to Signature file.
            FileOutputStream os = new FileOutputStream(signatureFile);
            byte[] signature = new byte[152];
            is.read(signature);
            os.write(signature);

            // Write the aes key to the AES key file.
            os = new FileOutputStream(aesKeyFile);
            byte[] aesKey = new byte[128];
            is.read(aesKey);
            os.write(aesKey);

            // Write the rest to the contents file.
            copy(is, new FileOutputStream(contentsFile));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * This method read in the signature file and verify it with the generated
     * signature using the decrypted file and sender's public key.
     */
    void loadSignature(File signatureFile, File fileDecrypted, File publicKeyFile) {
        try {
            // Read in the signature sent by the sender.
            byte[] signatureBytes = new byte[(int) signatureFile.length()];
            new FileInputStream(signatureFile).read(signatureBytes);
            byte[] receviedSig = getSignature(signatureBytes);

            // read public key to be used to decrypt the signature.
            byte[] encodedKey = new byte[(int)publicKeyFile.length()];
            new FileInputStream(publicKeyFile).read(encodedKey);

            // create public key
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pk = kf.generatePublic(publicKeySpec);

            byte[] decryptedFileMD5 = getMD5(fileDecrypted);

            Signature myVerifySign = Signature.getInstance("MD5withRSA");
            myVerifySign.initVerify(pk);
            myVerifySign.update(decryptedFileMD5);

            boolean isVerified = myVerifySign.verify(receviedSig);
            if (isVerified)
                System.out.println("Signature is verified!");
            else
                System.out.println("Error in validating Signature!");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Key is not valid when reading signature.");
            e.printStackTrace();
        } catch (SignatureException e) {
            System.out.println("Failed during generate the signature. ");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
    * Decrypts an AES key from a file using an RSA private key
    */
    void loadKey(File aesKeyFile, File privateKeyFile) {
        try {
            // read private key to be used to decrypt the AES key
            byte[] encodedKey = new byte[(int)privateKeyFile.length()];
            new FileInputStream(privateKeyFile).read(encodedKey);

            // create private key
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(privateKeySpec);

            // read AES key
            rsaCipher.init(Cipher.DECRYPT_MODE, pk);
            byte[] contents = new byte[1024];
            CipherInputStream is = new CipherInputStream(new FileInputStream(aesKeyFile), rsaCipher);
            is.read(contents);
            aesKey = getKey(contents);
            aeskeySpec = new SecretKeySpec(aesKey, "AES");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
    * Decrypts and then copies the contents of a given file.
    */
    void decrypt(File in, File out, SecretKeySpec aeskeySpec) {
        try {
            aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);

            CipherInputStream is = new CipherInputStream(new FileInputStream(in), aesCipher);
            FileOutputStream os = new FileOutputStream(out);

            copy(is, os);

            is.close();
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * Since the signature is written in a fixed format, this method take out the exact signature out
     * from all data.
     */
    byte[] getSignature(byte[] signatureAndKey) {
        String contentsString = new String(signatureAndKey);
        String signature = contentsString.substring(contentsString.indexOf("<Signature>") + 11, contentsString.indexOf("</Signature>"));
        return signature.getBytes();
    }

    /**
     * This method take out the encrypted AES Key from the AES key File.
     */
    byte[] getKey(byte[] signatureAndKey) {
        String contentsString = new String(signatureAndKey);
        String aes = contentsString.substring(contentsString.indexOf("<AES>") + 5, contentsString.indexOf("</AES>"));
        return aes.getBytes();
    }

    public void startDecrypting() {
        splitFiles(fileToBeDecrypt, signatureFile, aesKeyFile, contentsFile);
        loadKey(aesKeyFile, privateKeyFile);
        decrypt(contentsFile, fileDecrypted, aeskeySpec);
        loadSignature(signatureFile, fileDecrypted, publicKeyFile);
        deleteTempFiles();
    }
}
