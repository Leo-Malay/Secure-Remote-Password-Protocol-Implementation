import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class Client extends SRP {
    public String username; // I
    private String password; // p

    private BigInteger k; // k: H(g || N)
    private BigInteger u; // u: H(A, B)
    private BigInteger x; // x: H(salt || password)
    private BigInteger a; // a: random value
    public BigInteger A; // A: g^a mod N
    public BigInteger B; // B: (g^b + kv) mod N (sent by server)
    public BigInteger salt; // salt: random value (sent by server)
    public BigInteger sessionKey; // S: H((B-kv)^(a + ux))

    public Client() {
        try {
            this.k = SRP.hash(SRP.N.add(SRP.g).toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void computePublicPrivatePair() {
        try {
            this.a = SRP.generateRandomBigInteger(SRP.N);
            this.A = SRP.modularExponent(SRP.g, this.a, SRP.N);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setUser(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void setSalt(BigInteger salt) {
        try {
            this.salt = salt;
            BigInteger temp = new BigInteger(this.password.getBytes());
            this.x = SRP.hash(this.salt.add(temp).toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void setServerPublic(BigInteger B) {
        try {
            this.B = B;
            this.u = SRP.hash(this.A.add(B).toString());

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void computeSessionKey() {
        try {
            BigInteger v = SRP.modularExponent(SRP.g, this.x, SRP.N);
            BigInteger temp = SRP.modularExponent(this.B.subtract(this.k.multiply(v)),
                    this.a.add(this.u.multiply(this.x)), SRP.N);
            this.sessionKey = SRP.hash(temp.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}