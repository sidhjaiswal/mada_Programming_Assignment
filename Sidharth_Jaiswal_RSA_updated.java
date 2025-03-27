import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * Author: Sidharth Jaiswal
 * Modul: mada FS25
 * Programming assignment RSA
 */
public class Sidharth_Jaiswal_RSA {

    private static final Random RANDOM = new Random();
    private static final List<BigInteger> ENCRYPTED_NUMBERS = new ArrayList<>();
    private static final List<BigInteger> DECRYPTED_NUMBERS = new ArrayList<>();

    //Task 1
    public static void generateKeyPair() {
        // different primes
        BigInteger p, q;
        do {
            p = new BigInteger(127, RANDOM);
            q = new BigInteger(127, RANDOM);
        } while (!p.isProbablePrime(100) && q.isProbablePrime(100)); // randomize value till it's a prime

        // product of the primes
        BigInteger n = p.multiply(q);

        //define phi of n
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        //find out e
        BigInteger e = BigInteger.TWO.add(BigInteger.ONE);
        while (e.compareTo(phi) < 0) {
            if (phi.gcd(e).equals(BigInteger.ONE)) {
                break;
            }
            e = e.add(BigInteger.TWO);
        }
        //compute d with extended euclid algorithm (BigInteger has that method built in)
        BigInteger d = extendedEuclidAlgorithm(phi, e);
        //save key pairs
        saveKeyPair("Sidhs_sk.txt", n, d);
        saveKeyPair("Sidhs_pk.txt", n, e);

        System.out.println("p: " + p);
        System.out.println("q: " + q);
        System.out.println("n: " + n);
        System.out.println("phi: " + phi);
        System.out.println("e: " + e);
        System.out.println("d: " + d);
        System.out.println(
            e.multiply(d).mod(phi).equals(BigInteger.ONE)); //To verify my extended euclid algorithm works
    }

    public static BigInteger extendedEuclidAlgorithm(BigInteger phi, BigInteger e) {
        // init variables
        BigInteger a = phi, b = e, r, q, x0 = BigInteger.ONE, y0 = BigInteger.ZERO, x1 = BigInteger.ZERO,
            y1 =
                BigInteger.ONE, temp;
        // while b is not 0
        while (!b.equals(BigInteger.ZERO)) {
            q = a.divide(b);
            r = a.mod(b);

            a = b;
            b = r;

            temp = x0;
            x0 = x1;
            x1 = temp.subtract(x1.multiply(q));

            temp = y0;
            y0 = y1;
            y1 = temp.subtract(y1.multiply(q));
        }
        // in case y0 is negative
        if (y0.compareTo(BigInteger.ZERO) < 0) {
            y0 = y0.add(phi);
        }
        return y0;
    }

    public static void saveKeyPair(String filename, BigInteger n, BigInteger x) {
        try {
            String key = n.toString() + "," + x.toString();

            FileWriter writer = new FileWriter(filename, false);
            writer.write(key);
            writer.close();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    //Task 2
    public static void encryption() {
        try {
            //get public key from Sidhs_pk.txt
            var publicReader = new BufferedReader(new FileReader("Sidhs_pk.txt"));
            String[] keys = publicReader.readLine().split(",", 2);
            BigInteger n = new BigInteger(keys[0]);
            BigInteger e = new BigInteger(keys[1]);

            //reading text file
            File text = new File("Sidhs_text.txt");
            FileWriter textWriter = new FileWriter(text);
            textWriter.write("Hallo");
            textWriter.close();
            var reader = new FileReader(text);
            int character;
            while ((character = reader.read()) != -1) {
                var value = BigInteger.valueOf(character);
                ENCRYPTED_NUMBERS.add(fastExponentationAlgorithm(value, e, n));
                System.out.println("Character: " + (char) character + " (ASCII: " + character + ") Encrypted value: " +
                    fastExponentationAlgorithm(value, e, n));
            }
            //stores encrypted numbers to Sidhs_cipher.txt
            saveEncryptedMessage("Sidhs_cipher.txt");
        } catch (Exception exception) {
            System.out.println(exception.getMessage());
        }
    }

    public static BigInteger fastExponentationAlgorithm(BigInteger x, BigInteger e, BigInteger n) {
        //convert e to binary string
        String binaryString = e.toString(2);
        //initialisation
        int i = binaryString.length() - 1;
        BigInteger h = BigInteger.ONE;
        BigInteger k = x;
        //while loop
        while (i >= 0) {
            if (binaryString.charAt(i) == '1') {
                h = k.multiply(h).mod(n);
            }
            k = k.pow(2).mod(n);
            i--;
        }
        return h;
    }

    public static void saveEncryptedMessage(String filename) {
        StringBuilder EncryptedMessage = new StringBuilder();
        for (var i : ENCRYPTED_NUMBERS) {
            EncryptedMessage.append(i.toString());
            EncryptedMessage.append(",");
        }
        try {
            FileWriter writer = new FileWriter(filename, false);
            writer.append(EncryptedMessage.toString());
            writer.close();
            System.out.println("Saved message in cipher file");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    //Task 3
    public static void decryption() {
        try {
            //get private key from Sidhs_sk.txt
            var privateReader = new BufferedReader(new FileReader("Sidhs_sk.txt"));
            String[] keys = privateReader.readLine().split(",", 2);
            BigInteger n = new BigInteger(keys[0]);
            BigInteger d = new BigInteger(keys[1]);

            //reading ciphered text and storing decrypted numbers
            var cipherReader = new BufferedReader(new FileReader("Sidhs_cipher.txt"));
            String[] encryptedValues = cipherReader.readLine().split(",");
            for (var i : encryptedValues) {
                var encryptedNumber = new BigInteger(i);
                System.out.println("Encrypted value: " + i + " Decrypted value: " +
                    fastExponentationAlgorithm(encryptedNumber, d, n));
                DECRYPTED_NUMBERS.add(fastExponentationAlgorithm(encryptedNumber, d, n));
            }
            saveDecryption("Sidhs_text-d.txt");
            System.out.println("Saved decrypted message in text-d file");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public static void saveDecryption(String filename) {
        StringBuilder decryptedMessage = new StringBuilder();
        try {
            var writer = new FileWriter(filename, false);
            for (var i : DECRYPTED_NUMBERS) {
                char character = (char) i.intValue();
                decryptedMessage.append(character);
            }
            writer.write(decryptedMessage.toString());
            writer.close();
            System.out.println("Decrypted message: " + decryptedMessage);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public static String decryptVogtsText() {
        String message = "";
        try {
            var privateReader = new BufferedReader(new FileReader("sk.txt"));
            var cipherReader = new BufferedReader(new FileReader("cipher.txt"));

            //get key pair from sk text
            String keypair = privateReader.readLine();
            privateReader.close();

            keypair = keypair.replaceAll("[()]", "");
            String[] keys = keypair.split(",", 2);

            BigInteger n = new BigInteger(keys[0]);
            BigInteger d = new BigInteger(keys[1]);

            String[] cipherValues = cipherReader.readLine().split(",");
            cipherReader.close();

            StringBuilder decryptedMessage = new StringBuilder();

            for (var i : cipherValues) {
                BigInteger cipher = new BigInteger(i);
                BigInteger decryptedValue = fastExponentationAlgorithm(cipher, d, n);
                DECRYPTED_NUMBERS.add(decryptedValue);

                char decryptedChar = (char) decryptedValue.intValue();
                decryptedMessage.append(decryptedChar);
            }

            FileWriter writer = new FileWriter("Vogts_text-d.txt", false);
            writer.write(decryptedMessage.toString());
            writer.close();

            System.out.println("Decrypted Message: " + decryptedMessage);
            System.out.println("Saved decrypted message in Vogts_text-d.txt");

            message = String.valueOf(decryptedMessage);

        } catch (Exception exception) {
            System.out.println("Error during decryption: " + exception.getMessage());

        }
        return message;
    }

    public static void main(String[] args) {
        generateKeyPair();
        encryption();
        decryption();
        decryptVogtsText();
    }
}

