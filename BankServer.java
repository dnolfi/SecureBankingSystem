import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BankServer {

    private static final String KEY_PATH = "";

    // Use a synchronized list for thread safety and persistent customer storage.
    private static List<Customer> customers = Collections.synchronizedList(new ArrayList<>());

    // Lock for file writes.
    private static final Object fileLock = new Object();

    // Keys for encryption and digital signatures.
    private static SecretKey sharedSecretKey;
    private static SecretKey masterSecret;
    private static SecretKey fileEncKey;
    private static PrivateKey bankPrivKey;
    private static PublicKey atmPubKey;
    private static String serverName;
    private static File auditFile;
    private static BufferedWriter writer;

    private static final int portNumber = 3000;

    public static void main(String args[]) throws Exception {

        // Load existing customer registrations from file.
        loadCustomers();

        serverName = "BANKSERVER";

        sharedSecretKey = loadSecretKey(KEY_PATH + "sharedSecret_secret.key");
        bankPrivKey = loadPrivateKey(KEY_PATH + "bank_private.key");

        // Key for encrypting the audit log file.
        fileEncKey = loadSecretKey(KEY_PATH + "fileEncKey_secret.key");
        //fileEncKey = generateSecretKey("fileEnc");

        // Create or open the audit log file.
        String auditLog = "auditinfo.txt";
        auditFile = new File(auditLog);
        boolean fileCreated = auditFile.createNewFile();
        writer = new BufferedWriter(new FileWriter(auditLog, true));
        if (fileCreated) {
            writer.write("Customer ID, Transaction, Time of Transaction");
            writer.newLine();
            writer.flush();
        }

        System.out.println("Listening for connections on port: " + portNumber);

        try (ServerSocket bankSocket = new ServerSocket(portNumber, 3)) {
            while (true) {
                Socket clientSocket = bankSocket.accept();
                new Thread(() -> {
                    try {
                        handleClient(clientSocket);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            }
        }
    }

    // Load customer registrations from "customers.txt".
    private static void loadCustomers() {
        File customerFile = new File("customers.txt");
        if (customerFile.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(customerFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Expected format: username||password||id
                    String[] parts = line.split("\\|\\|");
                    if (parts.length >= 3) {
                        String username = parts[0].trim();
                        String password = parts[1].trim();
                        int id = Integer.parseInt(parts[2].trim());
                        boolean exists = false;
                        for (Customer c : customers) {
                            if (c.getUsername().equals(username)) {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists) {
                            customers.add(new Customer(username, password, id));
                        }
                    }
                }
                System.out.println("Loaded " + customers.size() + " customers from file.");
            } catch (Exception e) {
                System.err.println("Error loading customers: " + e.getMessage());
            }
        }
    }

    // Handle an incoming connection from an ATM client.
    private static void handleClient(Socket clientSocket) throws Exception {
        try (Socket socket = clientSocket;
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            // --- KEY DISTRIBUTION PROTOCOL ---
            String atmMsg1 = in.readLine();
            String[] encMsgParts = atmMsg1.split("\\|\\|");
            String encFromAtm = encMsgParts[0];
            String atmSig = encMsgParts[1];
            String rcvdMsg = decryptAES(encFromAtm, sharedSecretKey);
            String[] msgParts = rcvdMsg.split("\\|\\|");
            String atmID = msgParts[0];
            long atmTimeStamp = Long.parseLong(msgParts[1]);
            long currentTime = System.currentTimeMillis();
            if (replayCheck(currentTime, atmTimeStamp)) {
                System.out.println("Replay detected. Closing connection.");
                socket.close();
                return;
            }
            atmPubKey = loadPublicKey(atmID + "_public.key");
            boolean authenticated = authenticateSignature(rcvdMsg, atmSig, atmPubKey);
            System.out.println("ATM " + atmID + " connected. Authenticated: " + authenticated);

            // Generate and send master secret.
            masterSecret = generateSecretKey(atmID);
            byte[] mKeyBytes = masterSecret.getEncoded();
            String masterString = Base64.getEncoder().encodeToString(mKeyBytes);
            String toAtm = serverName + "||" + masterString + "||" + System.currentTimeMillis();
            String signature = signMessage(toAtm, bankPrivKey);
            String encMsg = encryptAES(toAtm, sharedSecretKey);
            encMsg = encMsg + "||" + signature;
            out.println(encMsg);

            // --- KEY DERIVATION ---
            byte[] salt1 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            byte[] salt2 = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
            SecretKey dataEncKey = deriveKeys(masterSecret.getEncoded(), salt1, 100);
            SecretKey macKey = deriveKeys(masterSecret.getEncoded(), salt2, 100);

            // --- CUSTOMER REGISTRATION/LOGIN PHASE ---
            // Expected message: E(KdataEnc, [ATMID||command||username||password||timestamp]) || MAC
            String authMessage = in.readLine();
            String[] authParts = authMessage.split("\\|\\|");
            String authEnc = authParts[0];
            String authMAC = authParts[1];
            String decryptedAuth = decryptAES(authEnc, dataEncKey);
            if (!MessageDigest.isEqual(computeMAC(decryptedAuth, macKey).getBytes(), authMAC.getBytes())) {
                System.out.println("Authentication message MAC failed. Closing connection.");
                socket.close();
                return;
            }
            String[] authComponents = decryptedAuth.split("\\|\\|");
            // Format: ATMID, command (register or login), username, password, timestamp
            String command = authComponents[1].toLowerCase();
            String username = authComponents[2];
            String password = authComponents[3];
            long authTime = Long.parseLong(authComponents[4]);
            if (replayCheck(System.currentTimeMillis(), authTime)) {
                System.out.println("Replay detected in auth message. Closing connection.");
                socket.close();
                return;
            }
            Customer currentCustomer = null;
            if (command.equals("register")) {
                currentCustomer = handleRegistration(username, password);
                if (currentCustomer == null) {
                    out.println("Registration failed: Username already exists.");
                    socket.close();
                    return;
                }
                out.println("Registration successful for " + username);
            } else if (command.equals("login")) {
                currentCustomer = handleLogin(username, password);
                if (currentCustomer != null) {
                    out.println("Login successful for " + username);
                } else {
                    out.println("Login failed for " + username);
                    socket.close();
                    return;
                }
            } else {
                out.println("Invalid authentication command.");
                socket.close();
                return;
            }

            // --- TRANSACTION PHASE ---
            String clientRequest;
            while ((clientRequest = in.readLine()) != null) {
                String[] clientParts = clientRequest.split("\\|\\|");
                String decRequest = decryptAES(clientParts[0], dataEncKey);
                String reqMAC = clientParts[1];
                if (!MessageDigest.isEqual(computeMAC(decRequest, macKey).getBytes(), reqMAC.getBytes())) {
                    System.out.println("Transaction message MAC failed. Closing connection.");
                    socket.close();
                    return;
                }
                String[] reqComponents = decRequest.split("\\|\\|");
                // Format: ATMID, operation (deposit, withdraw, balance), amount(optional), timestamp
                String operation = reqComponents[1].toLowerCase();
                long reqTime = Long.parseLong(reqComponents[reqComponents.length - 1]);
                if (replayCheck(System.currentTimeMillis(), reqTime)) {
                    System.out.println("Replay detected in transaction. Closing connection.");
                    socket.close();
                    return;
                }
                String response = "";
                switch(operation) {
                    case "deposit":
                        double depositAmount = Double.parseDouble(reqComponents[2]);
                        response = handleDeposit(currentCustomer, depositAmount, reqTime);
                        break;
                    case "withdraw":
                        double withdrawAmount = Double.parseDouble(reqComponents[2]);
                        response = handleWithdrawal(currentCustomer, withdrawAmount, reqTime);
                        break;
                    case "balance":
                        response = handleBalanceInquiry(currentCustomer, reqTime);
                        break;
                    default:
                        response = "Invalid operation";
                }
                String respWithTime = response + "||" + System.currentTimeMillis();
                String encResp = encryptAES(respWithTime, dataEncKey);
                String respMAC = computeMAC(response, macKey);
                out.println(encResp + "||" + respMAC);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Create and register a new customer.
    private static Customer handleRegistration(String username, String password) throws IOException {
        // Check for duplicate username.
        for (Customer cust : customers) {
            if (cust.getUsername().equals(username)) {
                System.out.println("Registration failed: Username already exists: " + username);
                return null;
            }
        }
        int newID = customers.size() + 1;
        Customer newCustomer = new Customer(username, password, newID);
        customers.add(newCustomer);
        synchronized(fileLock) {
            try (BufferedWriter regWriter = new BufferedWriter(new FileWriter("customers.txt", true))) {
                regWriter.write(username + "||" + password + "||" + newID);
                regWriter.newLine();
            }
        }
        System.out.println("Registered new customer: " + username);
        return newCustomer;
    }

    // Verify login credentials.
    private static Customer handleLogin(String username, String password) {
        for (Customer cust : customers) {
            if (cust.getUsername().equals(username) && cust.getPassword().equals(password)) {
                System.out.println("Customer " + username + " logged in successfully.");
                return cust;
            }
        }
        System.out.println("Login failed for " + username);
        return null;
    }

    private static String handleDeposit(Customer customer, double amount, long time) throws Exception {
        customer.deposit(amount);
        String dateTime = convertToDateTime(time);
        String logEntry = customer.getUsername() + ", Deposited: " + amount + ", " + dateTime;
        String encLog = encryptAES(logEntry, fileEncKey);
        synchronized(fileLock) {
            writer.write(encLog);
            writer.newLine();
            writer.flush();
        }
        return "Deposit successful. New balance: " + customer.getBalance();
    }

    private static String handleWithdrawal(Customer customer, double amount, long time) throws Exception {
        String dateTime = convertToDateTime(time);
        if (amount > customer.getBalance()) {
            return "Withdrawal failed: insufficient funds.";
        }
        customer.withdraw(amount);
        String logEntry = customer.getUsername() + ", Withdrew: " + amount + ", " + dateTime;
        String encLog = encryptAES(logEntry, fileEncKey);
        synchronized(fileLock) {
            writer.write(encLog);
            writer.newLine();
            writer.flush();
        }
        return "Withdrawal successful. New balance: " + customer.getBalance();
    }

    private static String handleBalanceInquiry(Customer customer, long time) throws Exception {
        String dateTime = convertToDateTime(time);
        String logEntry = customer.getUsername() + ", Balance inquiry: " + customer.getBalance() + ", " + dateTime;
        String encLog = encryptAES(logEntry, fileEncKey);
        synchronized(fileLock) {
            writer.write(encLog);
            writer.newLine();
            writer.flush();
        }
        return "Current balance: " + customer.getBalance();
    }

    private static String convertToDateTime(long time) {
        LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault());
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
        return dateTime.format(formatter);
    }

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

    private static boolean authenticateSignature(String message, String signature, PublicKey pubKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getDecoder().decode(signature));
    }

    private static String signMessage(String message, PrivateKey privKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    private static SecretKey generateSecretKey(String name) throws Exception {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        saveKey(name + "_masterSecret.key", key);
        return key;
    }

    private static SecretKey loadSecretKey(String filename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void saveKey(String filename, Key key) throws IOException {
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        try (FileWriter fw = new FileWriter(filename)) {
            fw.write(encodedKey);
        }
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

    private static boolean replayCheck(long currentTime, long msgTime) {
        return (Math.abs(currentTime - msgTime) > 15000);
    }

    private static SecretKey deriveKeys(byte[] keyBytes, byte[] salt, int iterations) throws Exception {
        if (keyBytes.length != salt.length) {
            throw new IllegalArgumentException("KeyBytes and salt length must be same");
        }
        byte[] xord = new byte[keyBytes.length];
        for (int i = 0; i < keyBytes.length; i++) {
            xord[i] = (byte) (keyBytes[i] ^ salt[i]);
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(xord);
        for (int i = 0; i < iterations; i++) {
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return new SecretKeySpec(hashed, "AES");
    }
}
