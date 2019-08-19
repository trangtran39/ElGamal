
import java.math.*;
import java.util.*;

/**
 * Paillier Cryptosystem <br><br>
 * References: <br>
 * [1] Pascal Paillier, "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes," EUROCRYPT'99.
 *    URL: <a href="http://www.gemplus.com/smart/rd/publications/pdf/Pai99pai.pdf">http://www.gemplus.com/smart/rd/publications/pdf/Pai99pai.pdf</a><br>
 * 
 * [2] Paillier cryptosystem from Wikipedia. 
 *    URL: <a href="http://en.wikipedia.org/wiki/Paillier_cryptosystem">http://en.wikipedia.org/wiki/Paillier_cryptosystem</a>
 * @author Kun Liu (kunliu1@cs.umbc.edu)
 * @version 1.0
 */
public class Paillier {

    /**
     * p and q are two large primes. 
     * lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1).
     */
    private BigInteger p,  q,  lambda;
    /**
     * n = p*q, where p and q are two large primes.
     */
    public BigInteger n;
    /**
     * nsquare = n*n
     */
    public BigInteger nsquare;
    /**
     * a random integer in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
     */
    private BigInteger g;
    /**
     * number of bits of modulus
     */
    private int bitLength;

    /**
     * Constructs an instance of the Paillier cryptosystem.
     * @param bitLengthVal number of bits of modulus
     * @param certainty The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
     */
    public Paillier(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier cryptosystem with 512 bits of modulus and at least 1-2^(-64) certainty of primes generation.
     */
    public Paillier() {
        KeyGeneration(512, 64);
    }

    /**
     * Sets up the public key and private key.
     * @param bitLengthVal number of bits of modulus.
     * @param certainty The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
     */
    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        /*Constructs two randomly generated positive BigIntegers that are probably prime, with the specified bitLength and certainty.*/
        p = new BigInteger(bitLength / 2, certainty, new Random());
        System.out.println("p is: \n" + p);
        q = new BigInteger(bitLength / 2, certainty, new Random());
        System.out.println("q is: \n" + q);

        n = p.multiply(q);
        nsquare = n.multiply(n);

        g = new BigInteger("2");
        // lamda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1).
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
                p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        /* check whether g is good.*/
        /* check if gcd(L(g^lamda mod nsquare),n) == 1. Also, L(x) = (x-1)/n */
        if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g is not good. Choose g again.");
            System.exit(1);
        }
    }

    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function explicitly requires random input r to help with encryption.
     * @param m plaintext as a BigInteger
     * @param r random plaintext to help with encryption
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m, BigInteger r) {
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function automatically generates random input r (to help with encryption).
     * @param m plaintext as a BigInteger
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m) {
    	// select random r
        BigInteger r = new BigInteger(bitLength, new Random());
        // g = (g^m * r^n) mod nsquare = (g^m mod nsquare * r^n mod nsquare) mod nsquare
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

    }

    /**
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where u = (L(g^lambda mod n^2))^(-1) mod n.
     * @param c ciphertext as a BigInteger
     * @return plaintext as a BigInteger
     */
    public BigInteger Decryption(BigInteger c) {
        BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
    }

    /**
     * main function
     * @param str intput string
     */
    public static void main(String[] str) {
        /* instantiating an object of Paillier cryptosystem*/
        Paillier paillier = new Paillier(); // bitLengthVal = 512, certainty= 64
        /* instantiating two plaintext msgs*/
        Scanner keyboard = new Scanner(System.in);
        System.out.print("Enter plaintext 1: ");
        int message1 = keyboard.nextInt();
        BigInteger m1 = new BigInteger(Integer.toString(message1));
        System.out.print("Enter plaintext 2: ");
        int message2 = keyboard.nextInt();
        BigInteger m2 = new BigInteger(Integer.toString(message2));
        System.out.println("\n");
        
        /* encryption*/
        BigInteger c1 = paillier.Encryption(m1);
        BigInteger c2 = paillier.Encryption(m2);
        
        /* printout encrypted text*/
        System.out.println("Processing Encryption....");
        System.out.println("Ciphertext 1 is: " + c1);
        System.out.println("Ciphertext 2 is: " + c2);
        System.out.println("\n");
        
        /* printout decrypted text */
        System.out.println("Processing Decryption....");
        System.out.println("Plaintext 1 is :" + paillier.Decryption(c1).toString());
        System.out.println("Plaintext 2 is :" + paillier.Decryption(c2).toString());
        System.out.println("\n");
        
        /* test homomorphic properties -> D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n */
        System.out.println("Testing Additive Properties.....");
        BigInteger product_c1c2 = c1.multiply(c2).mod(paillier.nsquare);
        BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
        System.out.println("Original sum: " + sum_m1m2.toString());
        System.out.println("Decrypted sum: " + paillier.Decryption(product_c1c2).toString());
        System.out.println("\n");
        
        /* test homomorphic properties -> D(E(m1)^m2 mod n^2) = (m1*m2) mod n */
        System.out.println("Testing Multiply Properties.....");
        BigInteger expo_c1m2 = c1.modPow(m2, paillier.nsquare);
        BigInteger product_m1m2 = m1.multiply(m2).mod(paillier.n);
        System.out.println("Original product: " + product_m1m2.toString());
        System.out.println("Decrypted product: " + paillier.Decryption(expo_c1m2).toString());
        /* test homomorphic properties --> D(E(m2)^m1 mod n^2) = (m1*m2) mod n */
        BigInteger expo_c2m1 = c2.modPow(m1, paillier.nsquare);
        System.out.println("Original product: " + product_m1m2.toString());
        System.out.println("Decrypted product: " + paillier.Decryption(expo_c2m1).toString());
        
        keyboard.close();
    }
}