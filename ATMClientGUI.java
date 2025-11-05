

import javax.swing.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ATMClientGUI extends JFrame
{
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JComboBox<String> authCommandCombo; // "login" or "register"
    private JTextArea outputArea;
    private JButton authButton, depositButton, withdrawButton, balanceButton;

    // Networking and crypto fields
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private SecretKey sharedSecretKey, masterSecret, dataEncKey, macKey;
    private PrivateKey atmPrivKey;
    private PublicKey bankPubKey;
    private final String atmName = "ATM1";
    private final String KEY_PATH = "";
    private final String SERVER_HOST = "127.0.0.1";
    private final int portNumber = 3000;

    public ATMClientGUI()
    {
        setTitle("ATM Client");
        setSize(500, 450);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(null);

        JLabel userLabel = new JLabel("Username:");
        userLabel.setBounds(20, 20, 80, 25);
        add(userLabel);

        usernameField = new JTextField();
        usernameField.setBounds(100, 20, 160, 25);
        add(usernameField);

        JLabel passLabel = new JLabel("Password:");
        passLabel.setBounds(20, 60, 80, 25);
        add(passLabel);


        passwordField = new JPasswordField();
        passwordField.setBounds(100, 60, 160, 25);
        add(passwordField);

        JLabel authLabel = new JLabel("Action:");
        authLabel.setBounds(20, 100, 80, 25);
        add(authLabel);

        authCommandCombo = new JComboBox<>(new String[] {"login", "register"});
        authCommandCombo.setBounds(100, 100, 160, 25);
        add(authCommandCombo);

        //btn to submit
        authButton = new JButton("Submit");
        authButton.setBounds(20, 190, 150, 35);
        add(authButton);

        // btn to deposit cash
        depositButton = new JButton("Deposit");
        depositButton.setBounds(20, 150, 100, 25);
        depositButton.setEnabled(false);
        add(depositButton);

        // btn to witdraw cash
        withdrawButton = new JButton("Withdraw");
        withdrawButton.setBounds(130, 150, 100, 25);
        withdrawButton.setEnabled(false);
        add(withdrawButton);

        // button for the balance
        balanceButton = new JButton("Balance");
        balanceButton.setBounds(240, 150, 100, 25);
        balanceButton.setEnabled(false);
        add(balanceButton);

        // output box
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setBounds(20, 250, 440, 160);
        add(scrollPane);

        // Authentication button event.
        authButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    initializeConnection();
                    String username = usernameField.getText().trim();
                    String password = new String(passwordField.getPassword()).trim();
                    String command = authCommandCombo.getSelectedItem().toString().trim();
                    sendAuthentication(command, username, password);
                } catch(Exception ex) {
                    outputArea.append("Error: " + ex.getMessage() + "\n");
                }
            }
        });

        depositButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String amount = JOptionPane.showInputDialog("Enter deposit amount:");
                if (amount == null) return; // User pressed cancel, do nothing
                sendTransaction("deposit", amount);
            }
        });

        withdrawButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String amount = JOptionPane.showInputDialog("Enter withdraw amount:");
                if (amount == null) return; // User pressed cancel, do nothing
                sendTransaction("withdraw", amount);
            }
        });

        balanceButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendTransaction("balance", "");
            }
        });
    }

    private void initializeConnection() throws Exception {
        sharedSecretKey = loadSecretKey(KEY_PATH + "sharedSecret_secret.key");
        atmPrivKey = loadPrivateKey(KEY_PATH + "ATM1_private.key");
        bankPubKey = loadPublicKey(KEY_PATH + "bank_public.key");
        socket = new Socket(SERVER_HOST, portNumber);
        out = new PrintWriter(socket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        // --- KEY DISTRIBUTION PROTOCOL ---
        String atmMsg = atmName + "||" + System.currentTimeMillis();
        String sig = signMessage(atmMsg, atmPrivKey);
        String encMsg = encryptAES(atmMsg, sharedSecretKey);
        out.println(encMsg + "||" + sig);
        String bankResponse = in.readLine();
        String[] parts = bankResponse.split("\\|\\|");
        String decBankMsg = decryptAES(parts[0], sharedSecretKey);
        String[] bankMsgParts = decBankMsg.split("\\|\\|");
        String masterSecretStr = bankMsgParts[1];
        byte[] masterBytes = Base64.getDecoder().decode(masterSecretStr.getBytes());
        masterSecret = new SecretKeySpec(masterBytes, 0, masterBytes.length, "AES");

        byte[] salt1 = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte[] salt2 = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
        dataEncKey = deriveKeys(masterSecret.getEncoded(), salt1, 100);
        macKey = deriveKeys(masterSecret.getEncoded(), salt2, 100);
    }

    private void sendAuthentication(String command, String username, String password) throws Exception {
        String authMsg = atmName + "||" + command + "||" + username + "||" + password + "||" + System.currentTimeMillis();
        String authEnc = encryptAES(authMsg, dataEncKey);
        String authMAC = computeMAC(authMsg, macKey);
        out.println(authEnc + "||" + authMAC);
        String response = in.readLine();
        outputArea.append("Server: " + response + "\n");
        if(response.contains("successful")) {
            depositButton.setEnabled(true);
            withdrawButton.setEnabled(true);
            balanceButton.setEnabled(true);
        }
    }

    private void sendTransaction(String operation, String amount) {
        try {
            String txn;
            if(operation.equals("deposit") || operation.equals("withdraw")) {
                txn = atmName + "||" + operation + "||" + amount + "||" + System.currentTimeMillis();
            } else {
                txn = atmName + "||" + operation + "||" + System.currentTimeMillis();
            }
            String encTxn = encryptAES(txn, dataEncKey);
            String txnMAC = computeMAC(txn, macKey);
            out.println(encTxn + "||" + txnMAC);
            String response = in.readLine();
            String[] parts = response.split("\\|\\|");
            String decResp = decryptAES(parts[0], dataEncKey);
            outputArea.append("Transaction result: " + decResp.split("\\|\\|")[0] + "\n");
        } catch(Exception ex) {
            outputArea.append("Transaction error: " + ex.getMessage() + "\n");
        }
    }

    private String encryptAES(String message, SecretKey key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encBytes = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encBytes);
    }

    private String decryptAES(String encrypted, SecretKey key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decBytes = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    private String computeMAC(String message, SecretKey macKey) throws Exception
    {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        byte[] macBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(macBytes);
    }

    private boolean replayCheck(long currentTime, long msgTime) {
        return (Math.abs(currentTime - msgTime) > 15000);
    }

    private String signMessage(String message, PrivateKey privKey) throws Exception
    {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    private SecretKey loadSecretKey(String filename) throws Exception
    {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        return new SecretKeySpec(keyBytes, "AES");
    }

    private PrivateKey loadPrivateKey(String filename) throws Exception
    {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private SecretKey deriveKeys(byte[] keyBytes, byte[] salt, int iterations) throws Exception
    {
        if(keyBytes.length != salt.length) {
            throw new IllegalArgumentException("Key and salt length must be same");
        }
        byte[] xord = new byte[keyBytes.length];
        for(int i = 0; i < keyBytes.length; i++){
            xord[i] = (byte)(keyBytes[i] ^ salt[i]);
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashed = digest.digest(xord);
        for(int i=0; i<iterations; i++){
            digest.reset();
            hashed = digest.digest(hashed);
        }
        return new SecretKeySpec(hashed, "AES");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new ATMClientGUI().setVisible(true);
        });
    }
}
