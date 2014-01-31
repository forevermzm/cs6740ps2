import java.security.MessageDigest;
import java.io.File;

public class Fcrypt {


    private byte[] concatenateByteArrays(byte[] a, byte[] b) {
        return null;
    }

    private byte[] getMD5(File file) {
        return null;
    }

    private File getAES(File file) {
        return null;
    }

    private byte[] getRSA(byte[] data, File key) {
        return null;
    }

    class Decryptor {
        public void start() {

        }
    }

    class Encryptor {
        public void startEncrypting() {
            File fileToBeEncrypt = null;
            File publicKey = null;
            File privateKey = null;
            byte[] AESKey = null;
            byte[] md5OfFile = getMD5(fileToBeEncrypt);
            File encryptedFile = getAES(fileToBeEncrypt);
            byte[] signature = getRSA(md5OfFile, privateKey);

            byte[] signatureAndKey = getRSA(concatenateByteArrays(signature, AESKey), publicKey);
        }
    }

    public void main(String[] args) {
        if (args.length != 5) {
            System.err.println(
                "Usage: java Fcrypt <mode> <key1> <key2> <file1> <file2>");
            System.exit(1);
        }
        String mode = args[0];
        if (mode.equals("-e")) {
            Encryptor encryptor = new Encryptor();
        } else if (mode.equals("-d")) {
            Decryptor decrptor = new Decryptor();
            decrptor.start();
        } else {
            System.err.println(
                "The mode should be either encryption mode -e or decryption mode -d.");
            System.exit(1);
        }
    }
}
