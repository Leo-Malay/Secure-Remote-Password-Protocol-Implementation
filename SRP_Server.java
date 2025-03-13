
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class SRP_Server extends SRP_Utility {
    public String username; // I: pulled from database
    public BigInteger salt; // salt: pulled from database

    private BigInteger k; // k: H(N, g)
    private BigInteger u; // u: H(A, B)
    private BigInteger v; // v: g^H(salt || password)
    private BigInteger b; // b: random value
    public BigInteger A; // A: g^a mod N (sent by client)
    public BigInteger B; // B: (g^b + kv) mod N
    public BigInteger sessionKey; // S: H((Av^u)^(b))

    public SRP_Server() {
        try {
            this.k = SRP_Utility.computeK();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public BigInteger genSalt() {
        return SRP_Utility.generateRandomBigInteger(SRP_Utility.N);
    }

    public BigInteger genVerifier(BigInteger salt, String password) {
        try {
            BigInteger x = SRP_Utility.hash(salt.toString().concat(password));
            return SRP_Utility.modularExponent(SRP_Utility.g, x, SRP_Utility.N);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void computePublicPrivatePair() {
        try {
            this.b = SRP_Utility.generateRandomBigInteger(SRP_Utility.N);
            this.B = SRP_Utility.modularExponent(SRP_Utility.g, this.b, SRP_Utility.N).add(this.k.multiply(this.v));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setUser(String username, BigInteger salt, BigInteger verifier) {
        this.username = username;
        this.salt = salt;
        this.v = verifier;
    }

    public void setClientPublic(BigInteger A) {
        try {
            this.A = A;
            this.u = SRP_Utility.hash(A.toString().concat(this.B.toString()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void computeSessionKey() {
        try {
            BigInteger temp = SRP_Utility.modularExponent(
                    this.A.multiply(SRP_Utility.modularExponent(this.v, this.u, SRP_Utility.N)), this.b,
                    SRP_Utility.N);
            this.sessionKey = SRP_Utility.hash(temp.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}