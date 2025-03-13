
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Server extends SRP {
    private String username; // I: pulled from database
    public BigInteger salt; // salt: pulled from database

    private BigInteger k; // k: H(N, g)
    private BigInteger u; // u: H(A, B)
    private BigInteger v; // v: g^H(salt || password)
    private BigInteger b; // b: random value
    public BigInteger A; // A: g^a mod N (sent by client)
    public BigInteger B; // B: (g^b + kv) mod N
    public BigInteger sessionKey; // S: H((Av^u)^(b))

    public Server() {
        try {
            this.k = SRP.hash(SRP.N.add(SRP.g).toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public BigInteger genSalt() {
        return SRP.generateRandomBigInteger(SRP.N);
    }

    public BigInteger genVerifier(BigInteger salt, String password) {
        try {
            BigInteger temp = new BigInteger(password.getBytes());
            BigInteger x = SRP.hash(salt.add(temp).toString());
            return SRP.modularExponent(SRP.g, x, SRP.N);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void computePublicPrivatePair() {
        try {
            this.b = SRP.generateRandomBigInteger(SRP.N);
            this.B = SRP.modularExponent(SRP.g, this.b, SRP.N).add(this.k.multiply(this.v));
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
            this.u = SRP.hash(A.add(this.B).toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void computeSessionKey() {
        try {
            BigInteger temp = SRP.modularExponent(this.A.multiply(SRP.modularExponent(this.v, this.u, SRP.N)), this.b,
                    SRP.N);
            this.sessionKey = SRP.hash(temp.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}