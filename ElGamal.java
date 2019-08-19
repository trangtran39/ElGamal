import java.util.*;
import java.math.BigInteger;

public class ElGamal {
		
	public static void main(String[] args) {
	
		Scanner keyboard = new Scanner(System.in);
		Random r = new Random();
		
		System.out.println("Enter the approximate value of the prime number for your El Gamal key.");
		BigInteger p = getNextPrime(keyboard.next());

        System.out.println("p is: " + p);
		// Calculate a generator.
		BigInteger g = getGenerator(p, r);
		System.out.println("g is : "+ g);
		
		// We found a generator, so let's do the rest of it.
		if (g != null) {
		
			// Pick a secret a.
			BigInteger a = new BigInteger(p.bitCount()-1, r);
			
			// Calculate the corresponding public b.
			BigInteger b = g.modPow(a, p);
		
			// Print out our public keys.
			System.out.println("Post p = "+p+" g = "+g+" b = "+b);
		
			// When we send a message, the sender picks a random k.
			BigInteger k = new BigInteger(p.bitCount()-1, r);
			
			// Here, the sender starts calculating parts of the ciphertext that
			// don't involve the actual message.
			BigInteger c1 = g.modPow(k, p);
			BigInteger c2 = b.modPow(k, p);
		
			// Here we get the message from the user.
			System.out.println("Please enter your message. It should be in between 1 and "+p);
			BigInteger m = new BigInteger(keyboard.next());
		
			// Now, we can calculate the rest of the second ciphertext.
			c2 = c2.multiply(m);
			c2 = c2.mod(p);
		
			// Print out the two ciphertexts.
			System.out.println("The corresponding cipher texts are c1 = "+c1+", c2 = "+c2);
		
			// First, determine the inverse of c1 raised to the a power mod p.
			BigInteger temp = c1.modPow(a,p);
			temp = temp.modInverse(p);
	
			// Print this out.
			System.out.println("Here is c1^ -a = "+temp);
	
			// Now, just multiply this by the second ciphertext
			BigInteger recover = temp.multiply(c2);
			recover = recover.mod(p);
		
			// And this will give us our original message back!
			System.out.println("The original message = "+recover);
		}
		
		// My sorry message!
		else
			System.out.println("Sorry, a generator for your prime couldn't be found.");
			
	keyboard.close();
	}
	
	
	// Incrementally tries each BigInteger starting at the value passed
	// in as a parameter until one of them is tests as being prime.
	public static BigInteger getNextPrime(String ans) {
		
		BigInteger test = new BigInteger(ans);
		while (!test.isProbablePrime(64))
			test = test.add(BigInteger.ONE);
			System.out.println("Next prime is: " + test);
		return test;		
	}
	
	
	// Precondition - p is prime and it's reasonably small, say, no more than 
	//				  5,000,000. If it's larger, this method will be quite
	//                time-consuming.
	// Postcondition - if a generator for p can be found, then it is returned
	//                 if no generator is found after 1000 tries, null is 
	//                 returned.
	public static BigInteger getGenerator(BigInteger p, Random r) {

		int numtries = 0;
		
		// Try finding a generator at random 100 times.
		while (numtries < 10) {
		
    		// Here's what we're trying as the generator this time.
    		BigInteger rand = new BigInteger(p.bitCount()-1,r);
    		//System.out.println("rand is: " + rand);
    		int count = 1;
    		while (rand.equals(BigInteger.ZERO) && count < 10){
    			rand = new BigInteger(p.bitCount()-1,r);
    			count ++;
        		System.out.println("rand is: " + rand);
    		}
    		if (count == 11)
    		{
    			System.out.println("NULL");
    			return null;
    		}
    		BigInteger exp = BigInteger.ONE;
    		BigInteger next = rand.mod(p);
    		
			// We exponentiate our generator until we get 1 mod p.
    		while (!next.equals(BigInteger.ONE)) {
    			exp = exp.add(BigInteger.ONE);
      			next = rand.modPow(exp, p);
    		}

			// If the first time we hit 1 is the exponent p-1, then we have
			// a generator.
    		if (exp.equals(p.subtract(BigInteger.ONE)))
      			return rand;
      	}
      	
      	// None of the 1000 values we tried was a generator.
      	return null;

  }

}