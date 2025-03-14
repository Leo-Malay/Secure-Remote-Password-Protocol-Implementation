import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SRP_Utility {
    public static final BigInteger N = new BigInteger(
            "E9E3C8013CF43E080378D682F58D784EB6A9D7A0A2E9A17D8F0A1C9B8BB9B149", 16); // N a large prime (N = 2q + 1
                                                                                     // where q: prime)
    public static final BigInteger g = BigInteger.valueOf(2); // g: generator

    /**
     * Computes multiplier paramter: k
     * 
     * @return BigInteger k
     * @throws NoSuchAlgorithmException
     */
    public static BigInteger computeK() throws NoSuchAlgorithmException {
        byte[] n_bytes = N.toByteArray();
        byte[] g_bytes = g.toByteArray();

        byte[] temp = new byte[n_bytes.length + g_bytes.length];
        System.arraycopy(n_bytes, 0, temp, 0, n_bytes.length);
        System.arraycopy(g_bytes, 0, temp, n_bytes.length, g_bytes.length);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(temp);

        return new BigInteger(1, hash);
    }

    /**
     * Computes SHA-256 Hash for given string input
     * 
     * @param input String random string
     * @return BigInteger hash of string input
     * @throws NoSuchAlgorithmException
     */
    public static BigInteger hash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest(input.getBytes());
        return new BigInteger(1, bytes);
    }

    /**
     * Computes Exponent and Mods it with given modulus value
     * 
     * @param base     BigInteger used as base
     * @param exponent BigInteger used as exponent
     * @param modulus  BigInteger used as modulus
     * @return
     */
    public static BigInteger modularExponent(BigInteger base, BigInteger exponent, BigInteger modulus) {
        return base.modPow(exponent, modulus);
    }

    /**
     * Generates and return a random BigInteger mod N
     * 
     * @param max BigInteger used for modulo with randomly generated number
     * @return BigInteger random number
     */
    public static BigInteger generateRandomBigInteger(BigInteger max) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(max.bitLength(), random).mod(max);
    }
}
