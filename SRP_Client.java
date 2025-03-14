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

    /**
     * Constructor class which calculates k upon initiation
     * 
     * @throws NoSuchAlgorithmException
     */
    public SRP_Client() throws NoSuchAlgorithmException {
        this.k = SRP_Utility.computeK();
    }

    /**
     * Computes Public and Private values for server: (a, A)
     */
    public void computePublicPrivatePair() {
        this.a = SRP_Utility.generateRandomBigInteger(SRP_Utility.N);
        this.A = SRP_Utility.modularExponent(SRP_Utility.g, this.a, SRP_Utility.N);
    }

    /**
     * Loads users into the class for authentication process
     * 
     * @param username String username entered by user
     * @param password String password entered by user
     * @throws Exception
     */
    public void setUser(String username, String password) throws Exception {
        if (username.length() == 0)
            throw new Exception("Username must be non-empty");
        if (password.length() == 0)
            throw new Exception("Password must be non-empty");
        this.username = username;
        this.password = password;
    }

    /**
     * Set salt sent by server for particular user I
     * 
     * @param salt BigInteger salt sent by server
     * @throws NoSuchAlgorithmException
     */
    public void setSalt(BigInteger salt) throws NoSuchAlgorithmException {
        this.salt = salt;
        this.x = SRP_Utility.hash(this.salt.toString().concat(this.password));
    }

    /**
     * Set servers public value: B
     * 
     * @param B BigInteger B provided by server
     * @throws NoSuchAlgorithmException
     * @throws Exception
     */
    public void setServerPublic(BigInteger B) throws NoSuchAlgorithmException, Exception {
        if (B.mod(SRP_Utility.N).equals(BigInteger.ZERO))
            throw new Exception("B mod N must not be zero");

        this.B = B;
        this.u = SRP_Utility.hash(this.A.toString().concat(B.toString()));
    }

    /**
     * Compute shared session key: sessionKey
     * 
     * @throws NoSuchAlgorithmException
     */
    public void computeSessionKey() throws NoSuchAlgorithmException {
        BigInteger v = SRP_Utility.modularExponent(SRP_Utility.g, this.x, SRP_Utility.N);
        BigInteger temp = SRP_Utility.modularExponent(this.B.subtract(this.k.multiply(v)),
                this.a.add(this.u.multiply(this.x)), SRP_Utility.N);
        this.sessionKey = SRP_Utility.hash(temp.toString());
    }

    /**
     * Computes session key verifier: M
     * 
     * @throws NoSuchAlgorithmException
     */
    public void computeSessionKeyVerifier() throws NoSuchAlgorithmException {
        StringBuilder result = new StringBuilder();

        BigInteger N_xor_G = SRP_Utility.hash(SRP_Utility.N.toString())
                .xor(SRP_Utility.hash(SRP_Utility.g.toString()));
        result.append(N_xor_G.toString());

        result.append(SRP_Utility.hash(this.username).toString());
        result.append(this.salt.toString());
        result.append(this.A.toString());
        result.append(this.B.toString());
        result.append(this.sessionKey.toString());

        this.M = new BigInteger(result.toString());
    }

    /**
     * Verifies session key verifier sent by client
     * 
     * @param M BigIntger M sent by server
     * @return Boolean Verified or not?
     * @throws NoSuchAlgorithmException
     */
    public Boolean verifySessionKey(BigInteger M) throws NoSuchAlgorithmException {
        BigInteger client_hash = SRP_Utility
                .hash(this.A.toString().concat(this.M.toString().concat(this.sessionKey.toString())));
        return client_hash.compareTo(M) == 0;
    }
}