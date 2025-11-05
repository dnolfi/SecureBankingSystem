import java.security.*;
import java.io.*;
import java.util.Base64;
import javax.crypto.SecretKey;

public class KeyGenerator {
    private static final int KEY_SIZE = 2048;
    private static final String KEY_PATH = "";

    public static void generateKeyPair(String name) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();

        saveKey(KEY_PATH + name + "_public.key", keyPair.getPublic());
        saveKey(KEY_PATH + name + "_private.key", keyPair.getPrivate());
    }

    public static void generateSecretKey(String name) throws Exception {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        saveKey(KEY_PATH + name + "_secret.key", key);
    }

    private static void saveKey(String filename, Key key) throws IOException {
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        try (FileWriter fw = new FileWriter(filename)) {
            fw.write(encodedKey);
        }
    }

    public static void main(String[] args) throws Exception {
        generateKeyPair("bank");
        generateKeyPair("ATM1");
        generateKeyPair("ATM2");
        generateKeyPair("ATM3");
        generateSecretKey("sharedSecret");
        generateSecretKey("fileEncKey");
        System.out.println("RSA key pairs and symmetric session key generated and saved.");
    }
}
