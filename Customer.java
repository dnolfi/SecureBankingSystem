public class Customer {

    private String username;
    private String password;
    private int id;
    private double balance;

    public Customer(String username, String password, int id) {
        this.username = username;
        this.password = password;
        this.id = id;
        this.balance = 0.0;
    }

    public String getUsername() {
        return username;
    }

    // For simplicity, storing plaintext passwords. In practice, store hashed passwords.
    public String getPassword() {
        return password;
    }

    public double getBalance() {
        return balance;
    }

    public int getID() {
        return id;
    }

    public void setBalance(double balance) {
        this.balance = balance;
    }

    public void withdraw(double amount) {
        if (amount <= balance) {
            balance = balance - amount;
        }
    }

    public void deposit(double amount) {
        balance += amount;
    }
}
