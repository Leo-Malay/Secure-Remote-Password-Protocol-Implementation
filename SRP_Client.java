import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class SRP_Client extends SRP_Utility {
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

    public SRP_Client() {
        try {
            this.k = SRP_Utility.computeK();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void computePublicPrivatePair() {
        try {
            this.a = SRP_Utility.generateRandomBigInteger(SRP_Utility.N);
            this.A = SRP_Utility.modularExponent(SRP_Utility.g, this.a, SRP_Utility.N);
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
            this.x = SRP_Utility.hash(this.salt.toString().concat(this.password));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void setServerPublic(BigInteger B) {
        try {
            this.B = B;
            this.u = SRP_Utility.hash(this.A.toString().concat(B.toString()));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void computeSessionKey() {
        try {
            BigInteger v = SRP_Utility.modularExponent(SRP_Utility.g, this.x, SRP_Utility.N);
            BigInteger temp = SRP_Utility.modularExponent(this.B.subtract(this.k.multiply(v)),
                    this.a.add(this.u.multiply(this.x)), SRP_Utility.N);
            this.sessionKey = SRP_Utility.hash(temp.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}