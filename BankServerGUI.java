import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;

public class BankServerGUI extends JFrame
{
    private static final String KEY_PATH = "";
    private JTextArea log;
    private JButton refreshBtn;
    private JButton decryptBtn;
    private static SecretKey fileEncKey;

    public BankServerGUI()
    {
        setTitle("Bank Server Dashboard");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(2, 1));

        log = new JTextArea();
        log.setEditable(false);
        add(new JScrollPane(log), BorderLayout.CENTER);

        refreshBtn = new JButton("Refresh Audit Log");
        refreshBtn.addActionListener(e -> loadAuditLog());
        buttonPanel.add(refreshBtn);

        decryptBtn = new JButton("Decrypt Audit Log");
        decryptBtn.addActionListener(e -> decryptAuditLog());
        buttonPanel.add(decryptBtn);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void loadAuditLog() {
        try {
            String content = new String(Files.readAllBytes(Paths.get("auditinfo.txt")));
            log.setText(content);
        } catch(Exception e) {
            log.setText("Error loading audit log: " + e.getMessage());
        }
    }

    private void decryptAuditLog() {
        try {
            fileEncKey = loadSecretKey(KEY_PATH + "fileEncKey_secret.key");

            // Read all lines from the file
            ArrayList<String> encLines = new ArrayList<>(Files.readAllLines(Paths.get("auditinfo.txt")));

            if (encLines.isEmpty()) {
                log.setText("Audit log is empty.");
                return;
            }

            // The first line should remain unchanged
            String firstLine = encLines.get(0);
            ArrayList<String> decLines = new ArrayList<>();
            decLines.add(firstLine);

            // Process the remaining lines
            for (int i = 1; i < encLines.size(); i++) {
                String trimmedLine = encLines.get(i).trim();
                if (!trimmedLine.isEmpty()) {
                    try {
                        String decLine = decryptAES(trimmedLine, fileEncKey);
                        decLines.add(decLine);
                    } catch (Exception ex) {
                        decLines.add("[ERROR] Unable to decrypt line: " + encLines.get(i));
                        ex.printStackTrace();
                    }
                }
            }

            // Display decrypted content in the log
            log.setText(String.join("\n", decLines));

        } catch (Exception e) {
            log.setText("Error loading audit log: " + e.getMessage());
        }
    }

    private static SecretKey loadSecretKey(String filename) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename))).trim());
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static String decryptAES(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception
    {
        SwingUtilities.invokeLater(() ->
        {
            new BankServerGUI().setVisible(true);
        });
    }
}
