
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author flame
 */
public class DiffieHelmanGen {
    public static void main(String[] args) throws Exception {
        BigInteger number = new BigInteger(32,new Random());
        BigInteger prime = number.nextProbablePrime();
        
        PrimitiveRootSearch prs = new PrimitiveRootSearch();
        BigInteger generator = prs.primitiveRootSearch(prime);

        System.out.println("Generated prime number value is : "+ prime);
        System.out.println("Generated primitive root value is : " + generator );
        
        GFG gg = new GFG();
        
        RandomString rando = new RandomString();
        System.out.println("HashCode Generated by SHA-1 for: "); 
        
        String AlphaNumStr = rando.nextString(); 
        String HashedAlpha = gg.encryptThisString(AlphaNumStr);
        System.out.println("\n" + AlphaNumStr + " : " + HashedAlpha); 
        
       try {
	    
			String localDir = System.getProperty("user.dir");
            File myObj = new File(localDir + "\\Alice\\Parameters.txt");
            File myObj2 = new File(localDir + "\\Bob\\BobPW.txt");
            if (myObj.createNewFile()) {
              System.out.println("File created: " + myObj.getName());
            } else {
              System.out.println("File already exists.");
            }
            if (myObj2.createNewFile()) {
              System.out.println("File created: " + myObj2.getName());
            } else {
              System.out.println("File already exists.");
            }
            
            Formatter writer = new Formatter(localDir + "\\Alice\\Parameters.txt");
            writer.format("%s\n",prime.toString());
            writer.format("%s\n",generator.toString());
            writer.format("%s",HashedAlpha);
            writer.close();
            
            Formatter bob = new Formatter(localDir + "\\Bob\\BobPW.txt");
            bob.format("%s",AlphaNumStr);
            bob.close();
            
            
       } 
       
       catch (IOException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }
        
    }
    
}
class GFG { 
    public static String encryptThisString(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
  
            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            // Add preceding 0s to make it 32 bit 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
  
            // return the HashText 
            return hashtext; 
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
 
} 

class RandomString {

    /**
     * Generate a random string.
     */
    public String nextString() {
        for (int idx = 0; idx < buf.length; ++idx)
            buf[idx] = symbols[random.nextInt(symbols.length)];
        return new String(buf);
    }

    public static final String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final String lower = upper.toLowerCase(Locale.ROOT);

    public static final String digits = "0123456789";

    public static final String alphanum = upper + lower + digits;

    private final Random random;

    private final char[] symbols;

    private final char[] buf;

    public RandomString(int length, Random random, String symbols) {
        if (length < 1) throw new IllegalArgumentException();
        if (symbols.length() < 2) throw new IllegalArgumentException();
        this.random = Objects.requireNonNull(random);
        this.symbols = symbols.toCharArray();
        this.buf = new char[length];
    }

    /**
     * Create an alphanumeric string generator.
     */
    public RandomString(int length, Random random) {
        this(length, random, alphanum);
    }

    /**
     * Create an alphanumeric strings from a secure generator.
     */
    public RandomString(int length) {
        this(length, new SecureRandom());
    }

    /**
     * Create session identifiers.
     */
    public RandomString() {
        this(6);
    }

}

class FastExponentiation {

	public static BigInteger fastExponentiation(BigInteger base,
			BigInteger exponent, BigInteger modulus) {
		return recurseFastExponentiation(base, exponent, modulus,
				BigInteger.ONE);
	}

	private static BigInteger recurseFastExponentiation(BigInteger base,
			BigInteger exponent, BigInteger modulus, BigInteger result) {

		if (exponent.equals(BigInteger.ZERO)) {
			return result;
		} else if (exponent.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE)) {
			return recurseFastExponentiation(base,
					exponent.subtract(BigInteger.ONE), modulus,
					base.multiply(result).mod(modulus));
		} else {
			return recurseFastExponentiation(base.multiply(base).mod(modulus),
					exponent.divide(BigInteger.valueOf(2)), modulus, result);
		}
	}
}

class MillerRabin {

	private static int attempts = 20;

	public static boolean testStrongPrime(BigInteger n) {
		// If p is 0, 1, or an event number return false
		if (n.equals(BigInteger.ZERO) || n.equals(BigInteger.ONE)
				|| n.mod(Util.TWO).equals(BigInteger.ZERO))
			return false;

		// 2 is prime so return true
		if (n.equals(Util.TWO))
			return true;

		// Generate 2 ^ r * m
		int r = 0;
		BigInteger m = n.subtract(BigInteger.ONE);
		BigInteger nMinusOne = n.subtract(BigInteger.ONE);
		while (m.mod(Util.TWO).equals(BigInteger.ZERO)) {
			m = m.divide(Util.TWO);
			r++;
		}

		for (int i = 0; i < attempts; i++) {
			// Pick a random number
			BigInteger b = Util.randomBigInteger(BigInteger.ONE,
					n.subtract(BigInteger.ONE));

			// Compute b ^ m mod n
			BigInteger z = FastExponentiation.fastExponentiation(b, m, n);

			// If y = 1 mod n or -1 mod n skip and try next random number
			if (!z.equals(BigInteger.ONE) && !z.equals(nMinusOne)) {
				boolean isWitness = false;
				for (int j = 0; j < r; j++) {
					z = FastExponentiation.fastExponentiation(b, Util.TWO
							.pow(j).multiply(m), n);

					// n is a composite
					if (z.equals(BigInteger.ONE))
						return false;

					// b is a witness to n primality
					if (z.equals(nMinusOne)) {
						isWitness = true;
						break;
					}
				}
				if (!isWitness) {
					return false;
				}
			}
		}
		return true;
	}

}

class PrimitiveRootSearch {

	public static BigInteger primitiveRootSearch(BigInteger p) throws Exception {
		if (p == null || !MillerRabin.testStrongPrime(p))
			throw new Exception("Invalid p for primitive root search");

		// Find prime factors of p-1 once
		BigInteger n = p.subtract(BigInteger.ONE);
		Set<BigInteger> factors = findPrimeFactors(n);

		// Try to find the primitive root by starting at random number
		BigInteger g = Util.randomBigInteger(Util.TWO,
				n.subtract(BigInteger.ONE));
		while (!checkPrimitiveRoot(g, p, n, factors)) {
			g = g.add(BigInteger.ONE);
		}
		return g;
	}

	private static boolean checkPrimitiveRoot(BigInteger g, BigInteger p,
			BigInteger n, Set<BigInteger> factors) {
		// Run g^(n / "each factor) mod p
		// If the is 1 mod p then g is not a primitive root
		Iterator<BigInteger> i = factors.iterator();
		while (i.hasNext()) {
			if (FastExponentiation.fastExponentiation(g, n.divide(i.next()), p)
					.equals(BigInteger.ONE)) {
				return false;
			}
		}
		return true;
	}

	private static Set<BigInteger> findPrimeFactors(BigInteger n) {
		// Set is unique
		Set<BigInteger> factors = new HashSet<BigInteger>();
		for (BigInteger i = BigInteger.valueOf(2); i.compareTo(n) <= 0; i = i
				.add(BigInteger.ONE)) {
			while (n.mod(i).equals(BigInteger.ZERO)) {
				// Add y to factors and decrease n
				factors.add(i);
				n = n.divide(i);
				// This should speed things up a bit for very large numbers!
				if (MillerRabin.testStrongPrime(n))
					return factors;
			}
		}
		return factors;
	}
}

class Util {

	public static final BigInteger TWO = BigInteger.valueOf(2);
	public static final BigInteger THREE = BigInteger.valueOf(3);
	public static final BigInteger FOUR = BigInteger.valueOf(4);
	public static final BigDecimal TWO_DEC = BigDecimal.valueOf(2);

	private static final SecureRandom rand = new SecureRandom();

	public static BigInteger convertStringToBigInt(String message) {
		BigInteger retVal = BigInteger.valueOf(0);
		for (int i = 0; i < message.length(); i++) {
			int charVal = message.charAt(message.length() - (i + 1));
			// Add the value by offsetting by 3 decminal places
			retVal = retVal.add(BigInteger.valueOf(charVal).multiply(
					BigInteger.TEN.pow(i * 3)));
		}
		return retVal;
	}

	public static String convertBigIntToString(BigInteger value) {
		StringBuffer result = new StringBuffer();
		String val = value.toString();
		for (int i = 0; i < Math.ceil((double) val.length() / (double) 3); i++) {
			int end = val.length() - (i * 3);
			int start = (end - 3 < 0) ? 0 : end - 3;
			result.insert(0, (char) Integer.valueOf(val.substring(start, end))
					.intValue());
		}

		return result.toString();
	}

	public static BigInteger randomBigInteger(BigInteger min, BigInteger max) {
		BigInteger n;
		do {
			n = randomBigInteger(min.bitLength(), max.bitLength());
		} while (n.compareTo(min) <= 0 || n.compareTo(max) >= 0);
		return n;
	}

	public static BigInteger randomBigInteger(int minBits, int maxBits) {
		// Chose a random length
		int bits = rand.nextInt(maxBits - minBits + 1) + minBits;
		BigInteger n = new BigInteger(bits, rand);
		// Make sure we didn't get a random bigint outside range
		while (n.bitLength() <= minBits && n.bitLength() >= maxBits) {
			n = new BigInteger(bits, rand);
		}
		return n;
	}

	// Taken from http://www.merriampark.com/bigsqrt.htm
	public static BigInteger getSqRoot(BigInteger bigint) {
		BigDecimal n = new BigDecimal(bigint);
		int scale = bigint.toString().length() / 2;
		int length = bigint.toString().length();
		if ((length % 2) == 0)
			length--;
		length /= 2;

		BigDecimal guess = BigDecimal.ONE.movePointRight(length);
		BigDecimal lastGuess = BigDecimal.ZERO;
		BigDecimal error = BigDecimal.ZERO;

		boolean more = true;
		int iterations = 0;
		while (more) {
			lastGuess = guess;
			guess = n.divide(guess, scale, BigDecimal.ROUND_HALF_UP);
			guess = guess.add(lastGuess);
			guess = guess.divide(TWO_DEC, scale, BigDecimal.ROUND_HALF_UP);
			error = n.subtract(guess.multiply(guess));
			if (++iterations >= 50) {
				more = false;
			} else if (lastGuess.equals(guess)) {
				more = error.abs().compareTo(BigDecimal.ONE) >= 0;
			}
		}
		return guess.toBigInteger();
	}
}

