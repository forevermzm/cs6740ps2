public class Fcrypt{
    public void main(String[] args){
        if (args.length != 5) {
            System.err.println(
                "Usage: java Fcrypt <mode> <key1> <key2> <file1> <file2>");
            System.exit(1);
        }
        String mode = args[0];
        if (mode.equals("-e")){
            Encryptor encryptor = new Encryptor();
        } else if (mode.equals("-d")){
            Decryptor decrptor = new Decryptor();
        } else {
            System.err.println(
                "The mode should be either encryption mode -e or decryption mode -d.");
            System.exit(1);
        }
    }
}

class Encryptor{

}

class Decryptor{
    
}