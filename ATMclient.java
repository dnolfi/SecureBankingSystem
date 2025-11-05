import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

public class ATMclient {

    private static final String KEY_PATH = ""; // Adjust if needed
    private static final String SERVER_HOST = "127.0.0.1";
    private static final int portNumber = 3000;
    private static SecretKey sharedSecretKey;
    private static SecretKey masterSecret;
    private static PrivateKey atmPrivKey;
    private static PublicKey bankPubKey;
    private static final String atmName = "ATM1";

    public static void main(String[] args) throws Exception
    {
        sharedSecretKey = loadSecretKey(KEY_PATH + "sharedSecret_secret.key");
        atmPrivKey = loadPrivateKey(KEY_PATH + "ATM1_private.key");
        bankPubKey = loadPublicKey(KEY_PATH + "bank_public.key");

        try (Socket socket = new Socket(SERVER_HOST, portNumber);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             Scanner scanner = new Scanner(System.in)) {

            // --- KEY DISTRIBUTION PROTOCOL ---
            String atmMsg = atmName + "||" + System.currentTimeMillis();
            String signature = signMessage(atmMsg, atmPrivKey);
            String encMsg = encryptAES(atmMsg, sharedSecretKey);
            String toBank = encMsg + "||" + signature;
            out.println(toBank);

            // Receive master secret from bank
            String fromBank = in.readLine();
            String[] bankParts = fromBank.split("\\|\\|");
            String encBankMsg = bankParts[0];
            String bankSig = bankParts[1];
            String decBankMsg = decryptAES(encBankMsg, sharedSecretKey);
            // --- Missing function added below ---
            boolean authenticated = authenticateSignature(decBankMsg, bankSig, bankPubKey);
            String[] bankMsgParts = decBankMsg.split("\\|\\|");
            String bankID = bankMsgParts[0];
            String masterSecretString = bankMsgParts[1];
            long bankTimeStamp = Long.parseLong(bankMsgParts[2]);
            System.out.println("Received from bank: BankID=" + bankID + ", MasterSecret=" + masterSecretString);
            if (replayCheck(System.currentTimeMillis(), bankTimeStamp)) {
                System.out.println("Replay detected. Exiting.");
                socket.close();
                return;
            }
            byte[] masterSecretBytes = Base64.getDecoder().decode(masterSecretString.getBytes());
            masterSecret = new SecretKeySpec(masterSecretBytes, 0, masterSecretBytes.length, "AES");

            // --- KEY DERIVATION ---
            byte[] salt1 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            byte[] salt2 = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
            SecretKey dataEncKey = deriveKeys(masterSecret.getEncoded(), salt1, 100);
            SecretKey macKey = deriveKeys(masterSecret.getEncoded(), salt2, 100);

            // --- CUSTOMER AUTHENTICATION PHASE ---
            System.out.println("Enter command (register or login):");
            String command = scanner.nextLine().trim().toLowerCase();
            System.out.println("Enter username:");
            String username = scanner.nextLine().trim();
            System.out.println("Enter password:");
            String password = scanner.nextLine().trim();

            String authMessage = atmName + "||" + command + "||" + username + "||" + password + "||" + System.currentTimeMillis();
            String authEnc = encryptAES(authMessage, dataEncKey);
            String authMAC = computeMAC(authMessage, macKey);
            out.println(authEnc + "||" + authMAC);
            String authResponse = in.readLine();
            System.out.println("Server response: " + authResponse);
            if(authResponse.contains("failed")) {
                socket.close();
                return;
            }

            // --- TRANSACTION PHASE ---
            while (true) {
                System.out.println("Enter operation (deposit, withdraw, balance) or 'exit' to quit:");
                String operation = scanner.nextLine().trim().toLowerCase();
                if (operation.equals("exit")) break;
                String amount = "";
                if (operation.equals("deposit") || operation.equals("withdraw")) {
                    System.out.println("Enter amount:");
                    amount = scanner.nextLine().trim();
                }
                long timestamp = System.currentTimeMillis();
                String request;
                if(operation.equals("deposit") || operation.equals("withdraw")) {
                    request = atmName + "||" + operation + "||" + amount + "||" + timestamp;
                } else {
                    request = atmName + "||" + operation + "||" + timestamp;
                }
                String reqEnc = encryptAES(request, dataEncKey);
                String reqMAC = computeMAC(request, macKey);
                out.println(reqEnc + "||" + reqMAC);
                String serverResp = in.readLine();
                String [] respParts = serverResp.split("\\|\\|");
                String decResp = decryptAES(respParts[0], dataEncKey);
                if (!MessageDigest.isEqual(computeMAC(decResp.split("\\|\\|")[0], macKey).getBytes(), respParts[1].getBytes())) {
                    System.out.println("Response MAC verification failed.");
                    socket.close();
                    return;
                }
                System.out.println("Transaction result: " + decResp.split("\\|\\|")[0]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Utility Functions (these mirror the ones in BankServer.java):

    private static String encryptAES(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encBytes);
    }

    private static String decryptAES(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    private static String computeMAC(String message, SecretKey macKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        byte[] macBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(macBytes);
    }

    // Added authenticateSignature function that was missing.
    private static boolean authenticateSignature(String message, String signature, PublicKey pubKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getDecoder().decode(signature));
    }

    private static boolean replayCheck(long currentTime, long msgTime) {
        return (Math.abs(currentTime - msgTime) > 15000);
    }

    private static String signMessage(String message, PrivateKey privKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    private static SecretKey loadSecretKey(String filename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static SecretKey deriveKeys(byte[] keyBytes, byte[] salt, int iterations) throws Exception {
        if(keyBytes.length != salt.length) {
            throw new IllegalArgumentException("KeyBytes and salt length must be same");
        }
        byte[] xord = new byte[keyBytes.length];
        for(int i = 0; i < keyBytes.length; i++){
            xord[i] = (byte)(keyBytes[i] ^ salt[i]);
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(xord);
        for(int i = 0; i < iterations; i++){
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return new SecretKeySpec(hashed, "AES");
    }
}
