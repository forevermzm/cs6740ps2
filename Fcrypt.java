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

    byte[] concatenateByteArrays(byte[] a, byte[] b) {
        return null;
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

    File getAES(File file) {
        return null;
    }

    byte[] getRSA(byte[] data, File key) {
        return null;
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
            Encryptor encryptor = new Encryptor();
            encryptor.startEncrypting();
        } else if (mode.equals("-d")) {
            Decryptor decrptor = new Decryptor();
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

    private File fileToBeEncrypt = null;
    private File fileEncrypted = null;
    private File publicKey = null;
    private File privateKey = null;
    private byte[] AESKey = null;

    Cipher pkCipher, aesCipher;

    public Encryptor() throws GeneralSecurityException {
        // create RSA public key cipher
        pkCipher = Cipher.getInstance("RSA");
        // create AES shared key cipher
        aesCipher = Cipher.getInstance("AES");
    }

    /**
     * Creates a new AES key
     */
    private void makeKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(AES_Key_Size);
        SecretKey key = kgen.generateKey();
        aesKey = key.getEncoded();
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    /**
    * Encrypts the AES key to a file using an RSA public key
    */
    private void saveKey(File out, File publicKeyFile, byte[] md5) throws IOException, GeneralSecurityException {
        if (!out.exists()) {
            out.createNewFile();
        }
        // read public key to be used to encrypt the AES key
        byte[] encodedKey = new byte[(int)publicKeyFile.length()];
        new FileInputStream(publicKeyFile).read(encodedKey);

        // create public key
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(publicKeySpec);

        // write AES key
        pkCipher.init(Cipher.ENCRYPT_MODE, pk);
        CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), pkCipher);
        os.write("<md5>".getBytes());
        os.write(md5);
        os.write("</md5>\n<AES>".getBytes());
        os.write(aesKey);
        os.write("</AES>\n".getBytes());
        os.close();
    }

    /**
    * Decrypts an AES key from a file using an RSA private key
    */
    private void loadKey(File in, File privateKeyFile) throws GeneralSecurityException, IOException {
        // read private key to be used to decrypt the AES key
        byte[] encodedKey = new byte[(int)privateKeyFile.length()];
        new FileInputStream(privateKeyFile).read(encodedKey);

        // create private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(privateKeySpec);

        // read AES key
        pkCipher.init(Cipher.DECRYPT_MODE, pk);
        byte[] contents = new byte[1024];
        CipherInputStream is = new CipherInputStream(new FileInputStream(in), pkCipher);
        is.read(contents);
        String contentsString = new String(contents);
        System.out.println(contentsString.indexOf("<md5>"));
        String md5 = contentsString.substring(contentsString.indexOf("<md5>") + 5, contentsString.indexOf("</md5>"));
        String aes = contentsString.substring(contentsString.indexOf("<AES>") + 5, contentsString.indexOf("</AES>"));
        aesKey = aes.getBytes();
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    void combineFiles(File a, File b, File out) throws FileNotFoundException, IOException {
        FileInputStream is = new FileInputStream(a);
        FileOutputStream os = new FileOutputStream(out);
        String signature = "<Signature>";
        os.write(String.valueOf((int) (a.length())).getBytes());
        os.write(signature.getBytes());
        copy(is, os);
        // os.write(signature.getBytes());
        is = new FileInputStream(b);
        copy(is, os);
        is.close();
        os.close();
    }

    void splitFiles(File in, File outA, File outB) throws FileNotFoundException, IOException{
        FileInputStream is = new FileInputStream(in);
        byte[] length = new byte[14];
        is.read(length);
        String lengthStr = new String(length);
        int sigLength = Integer.parseInt(lengthStr.substring(0, lengthStr.indexOf("<Sig")));
        System.out.println(sigLength);
        byte[] signature = new byte[sigLength];
        FileOutputStream os = new FileOutputStream(outA);
        is.read(signature);
        os.write(signature);
        os = new FileOutputStream(outB);
        int i;
        byte[] b = new byte[1024];
        while ((i = is.read(b)) != -1) {
            os.write(b, 0, i);
        }
    }


    public void startEncrypting() throws IOException, InvalidKeyException, GeneralSecurityException {
        try {
            byte[] md5OfFile = getMD5(new File("A.txt"));
            makeKey();
            encrypt(new File("A.txt"), new File("content.txt"), aeskeySpec);
            saveKey(new File("key.txt"), new File("keysFolder/public_key.der"), md5OfFile);
            combineFiles(new File("key.txt"), new File("content.txt"), new File("B.txt"));
            splitFiles(new File("B.txt"), new File("key.txt"), new File("content.txt"));
            loadKey(new File("key.txt"), new File("keysFolder/private_key.der"));
            decrypt(new File("content.txt"), new File("C.txt"), aeskeySpec);
            File encryptedFile = getAES(fileToBeEncrypt);
            byte[] signature = getRSA(md5OfFile, privateKey);

            byte[] signatureAndKey = getRSA(concatenateByteArrays(signature, AESKey), publicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

class Decryptor extends Fcrypt {
    private byte[] encryptedSignatureAndKey = null;
    private File fileToBeDecrypt = null;
    private File publicKey = null;
    private File privateKey = null;
    private byte[] AESKey = null;

    private byte[] getSignature(byte[] signatureAndKey) {
        return null;
    }

    private byte[] getKey(byte[] signatureAndKey) {
        return null;
    }

    public void startDecrypting() {

        byte[] signatureAndKey = getRSA(encryptedSignatureAndKey, privateKey);
        byte[] signature = getSignature(signatureAndKey);
        byte[] key = getKey(signatureAndKey);

        byte[] md5 = getRSA(signature, publicKey);
        File decryptedFile = getAES(fileToBeDecrypt);
        byte[] md5OfFile = getMD5(decryptedFile);

    }
}
