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
    public BigInteger M; // M: H(H(N) xor H(g), H(I), s, A, B, S)

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

    public void computeSessionKeyVerifier() {
        StringBuilder result = new StringBuilder();

        try {
            BigInteger N_xor_G = SRP_Utility.hash(SRP_Utility.N.toString())
                    .xor(SRP_Utility.hash(SRP_Utility.g.toString()));
            result.append(N_xor_G.toString());

            result.append(SRP_Utility.hash(this.username).toString());
            result.append(this.salt.toString());
            result.append(this.A.toString());
            result.append(this.B.toString());
            result.append(this.sessionKey.toString());

            this.M = new BigInteger(result.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public Boolean verifySessionKey(BigInteger M) {
        try {
            BigInteger client_hash = SRP_Utility
                    .hash(this.A.toString().concat(this.M.toString().concat(this.sessionKey.toString())));
            return client_hash.compareTo(M) == 0;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }
}