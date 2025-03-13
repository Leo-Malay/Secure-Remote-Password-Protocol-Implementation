import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SRP_Utility {
    public static final BigInteger N = new BigInteger(
            "E9E3C8013CF43E080378D682F58D784EB6A9D7A0A2E9A17D8F0A1C9B8BB9B149", 16);
    public static final BigInteger g = BigInteger.valueOf(2);

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

    public static BigInteger hash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest(input.getBytes());
        return new BigInteger(1, bytes);
    }

    public static BigInteger modularExponent(BigInteger base, BigInteger exponent, BigInteger modulus) {
        return base.modPow(exponent, modulus);
    }

    public static BigInteger generateRandomBigInteger(BigInteger max) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(max.bitLength(), random).mod(max);
    }
}
