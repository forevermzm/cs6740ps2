import java.security.MessageDigest;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Fcrypt {
    private MessageDigest md;
    Cipher rsaCipher, aesCipher;

    public Fcrypt() {
        try {
            this.md = MessageDigest.getInstance("MD5");
            // create RSA public key cipher
            this.rsaCipher = Cipher.getInstance("RSA");
            // create AES shared key cipher
            this.aesCipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    String convertByteToHex(byte[] data) {
        //convert the byte to hex format
        StringBuffer sb = new StringBuffer("");
        for (int i = 0; i < data.length; i++) {
            sb.append(Integer.toString((data[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

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
    * Copies a stream.
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

class Encryptor extends Fcrypt {
    private final static int AES_Key_Size = 256;
    private byte[] aesKey;
    private SecretKeySpec aeskeySpec;
    private File aesKeyFile = null;
    private File contentsFile = null;
    private File signatureFile = null;
    private File fileToBeEncrypt = null;
    private File fileEncrypted = null;
    private File publicKeyFile = null;
    private File privateKeyFile = null;


    public Encryptor(File publicKeyFile, File privateKeyFile, File fileToBeEncrypt, File fileEncrypted) throws GeneralSecurityException {
        this.publicKeyFile = publicKeyFile;
        this.privateKeyFile = privateKeyFile;
        this.fileToBeEncrypt = fileToBeEncrypt;
        this.fileEncrypted = fileEncrypted;
        this.aesKeyFile = new File("AES_KEY");
        this.contentsFile = new File("CONTENTS");
        this.signatureFile = new File("SIGNATURE");
    }

    /**
     * Creates a new AES key
     */
    void makeAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(AES_Key_Size);
        SecretKey key = kgen.generateKey();
        aesKey = key.getEncoded();
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    /**
    * Encrypts and then copies the contents of a given file.
    */
    void encrypt(File in, File out, SecretKeySpec aeskeySpec) {
        try {
            if (!out.exists()) {
                out.createNewFile();
            }
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);

            FileInputStream is = new FileInputStream(in);
            CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), aesCipher);

            copy(is, os);

            is.close();
            os.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    void writeSignature(byte[] md5, File privateKeyFile, File out) throws FileNotFoundException, IOException, GeneralSecurityException {
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
    }

    /**
    * Encrypts the AES key to a file using an RSA public key
    */
    private void saveKey(File publicKeyFile, File signatureFile, File aesKeyFile) throws IOException, GeneralSecurityException {
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
        // For later load key tag.
        //
        // os.write("<md5>".getBytes());
        // FileInputStream is = new FileInputStream(signatureFile);
        // byte[] signature = new byte[is.available()];
        // is.read(signature);
        // System.out.println("Signature file length: " + signature.length);
        // os.write(new String(signature).getBytes("UTF-8"));
        // os.write("</md5>\n".getBytes());

        os.write("<AES>".getBytes());
        os.write(aesKey);
        os.write("</AES>\n".getBytes());
        os.close();
    }

    void combineFiles(File a, File b, File out) throws FileNotFoundException, IOException {
        if (!out.exists()) {
            out.createNewFile();
        }

        FileInputStream is = new FileInputStream(a);
        FileOutputStream os = new FileOutputStream(out);
        // String signature = "<Signature>";
        System.out.println("AES Key File size: " + a.length());
        os.write(String.valueOf((int) (a.length())).getBytes());
        // os.write(signature.getBytes());
        copy(is, os);
        is = new FileInputStream(b);
        copy(is, os);
        is.close();
        os.close();
    }


    public void startEncrypting() throws IOException, InvalidKeyException, GeneralSecurityException {
        try {
            byte[] md5OfFile = getMD5(fileToBeEncrypt);
            makeAESKey();
            encrypt(fileToBeEncrypt, contentsFile, aeskeySpec);
            writeSignature(md5OfFile, privateKeyFile, aesKeyFile);
            saveKey(publicKeyFile, signatureFile, aesKeyFile);
            combineFiles(aesKeyFile, contentsFile, fileEncrypted);
            signatureFile.delete();
            aesKeyFile.delete();
            contentsFile.delete();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

class Decryptor extends Fcrypt {
    private final static int AES_Key_Size = 256;
    private byte[] aesKey;
    private SecretKeySpec aeskeySpec;
    private File fileToBeDecrypt = null;
    private File fileDecrypted = null;
    private File publicKeyFile = null;
    private File privateKeyFile = null;
    private File aesKeyFile = null;
    private File contentsFile = null;
    private File signatureFile = null;

    public Decryptor(File privateKeyFile, File publicKeyFile, File fileToBeDecrypt, File fileDecrypted) {
        this.fileToBeDecrypt = fileToBeDecrypt;
        this.fileDecrypted = fileDecrypted;
        this.privateKeyFile = privateKeyFile;
        this.publicKeyFile = publicKeyFile;
        this.aesKeyFile = new File("AES_KEY");
        this.contentsFile = new File("CONTENTS");
        this.signatureFile = new File("SIGNATURE");
    }

    void splitFiles(File in, File signatureFile, File aesKeyFile, File contentsFile) throws FileNotFoundException, IOException {
        FileInputStream is = new FileInputStream(in);
        byte[] length = new byte[3];
        is.read(length);
        String lengthStr = new String(length);
        int sigLength = Integer.parseInt(lengthStr);
        System.out.println(sigLength);

        FileOutputStream os = new FileOutputStream(signatureFile);
        byte[] signature = new byte[152];
        is.read(signature);
        os.write(signature);

        os = new FileOutputStream(aesKeyFile);
        byte[] aesKey = new byte[128];
        is.read(aesKey);
        os.write(aesKey);

        os = new FileOutputStream(contentsFile);
        int i;
        byte[] b = new byte[1024];
        while ((i = is.read(b)) != -1) {
            os.write(b, 0, i);
        }
    }

    private void loadSignature(File signatureFile, File fileDecrypted, File publicKeyFile) throws GeneralSecurityException, IOException {
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
    }

    /**
    * Decrypts an AES key from a file using an RSA private key
    */
    private void loadKey(File aesKeyFile, File privateKeyFile) throws GeneralSecurityException, IOException {
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
    }

    /**
    * Decrypts and then copies the contents of a given file.
    */
    public void decrypt(File in, File out, SecretKeySpec aeskeySpec) {
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



    private byte[] getSignature(byte[] signatureAndKey) {
        String contentsString = new String(signatureAndKey);
        String signature = contentsString.substring(contentsString.indexOf("<Signature>") + 11, contentsString.indexOf("</Signature>"));
        return signature.getBytes();
    }

    private byte[] getKey(byte[] signatureAndKey) {
        String contentsString = new String(signatureAndKey);
        String aes = contentsString.substring(contentsString.indexOf("<AES>") + 5, contentsString.indexOf("</AES>"));
        return aes.getBytes();
    }

    public void startDecrypting() throws IOException, FileNotFoundException, GeneralSecurityException {
        splitFiles(fileToBeDecrypt, signatureFile, aesKeyFile, contentsFile);
        loadKey(aesKeyFile, privateKeyFile);
        decrypt(contentsFile, fileDecrypted, aeskeySpec);
        loadSignature(signatureFile, fileDecrypted, publicKeyFile);
        signatureFile.delete();
        aesKeyFile.delete();
        contentsFile.delete();
    }
}
