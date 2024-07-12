import java.util.Scanner;

public class RSAEncryption {
    private int[] privateKey;
    private int[] publicKey;

    public RSAEncryption (int p, int q) {
        privateKey = new int[2];
        publicKey = new int[2];
        setKeys(p, q);
    }

    private void setKeys(int p, int q) {
        int n = p*q;
        publicKey[1] = n;
        privateKey[1] = n;

        int e = 2;
        int rel_prime = (p-1)*(q-1);

        // Find e where e < n & is a relative prime of rel_prime
        while (rel_prime % e == 0 && e < n) e++;
        publicKey[0] = e;

        // Find d where e*d mod rel_prime = 1
        while((rel_prime + 1) % e != 0) rel_prime+= rel_prime;
        privateKey[0] = (rel_prime + 1) / e;
    }

    // Recursively encrypt or decrypt a message
    private int mod_exponential(int m, int e, int n) {
        if(e == 0)
            return 1;
        else if(e == 1)
            return m % n;
        else
            return ((m % n)*mod_exponential(m, e-1, n)) % n;
    }

    public int encrypt(int m) {
        return mod_exponential(m, publicKey[0], publicKey[1]);
    }

    public int decrypt(int c) {
        return mod_exponential(c, privateKey[0], privateKey[1]);
    }

    public void printKeys() {
        System.out.println("Public key: [" + publicKey[0] + ", " + publicKey[1] + "]");
        System.out.println("Private key: [" + privateKey[0] + ", " + privateKey[1] + "]");
    }

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        System.out.print("Enter the prime numbers p and q: ");
        RSAEncryption rsa = new RSAEncryption(in.nextInt(), in.nextInt());
        rsa.printKeys();

        System.out.print("Enter the plaintext message m (an integer): ");
        int m = in.nextInt();
        int c = rsa.encrypt(m);
        System.out.println("Ciphertext c is: " + c);
        System.out.println("Plaintext m is: " + rsa.decrypt(c));
    }
}
