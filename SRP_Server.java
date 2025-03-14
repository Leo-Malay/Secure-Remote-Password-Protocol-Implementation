
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
    public BigInteger M; // M: H(A, M, S); temp: H(H(N) xor H(g), H(I), s, A, B, S)

    public SRP_Server() throws NoSuchAlgorithmException {
        this.k = SRP_Utility.computeK();
    }

    public BigInteger genSalt() {
        return SRP_Utility.generateRandomBigInteger(SRP_Utility.N);
    }

    public BigInteger genVerifier(BigInteger salt, String password) throws NoSuchAlgorithmException {
        BigInteger x = SRP_Utility.hash(salt.toString().concat(password));
        return SRP_Utility.modularExponent(SRP_Utility.g, x, SRP_Utility.N);
    }

    public void computePublicPrivatePair() {
        this.b = SRP_Utility.generateRandomBigInteger(SRP_Utility.N);
        this.B = SRP_Utility.modularExponent(SRP_Utility.g, this.b, SRP_Utility.N).add(this.k.multiply(this.v));
    }

    public void setUser(String username, BigInteger salt, BigInteger verifier) throws Exception {
        if (username.length() == 0)
            throw new Exception("Username must be non-empty");
        if (salt.equals(BigInteger.ZERO))
            throw new Exception("Salt must be a non-zero");
        if (verifier.equals(BigInteger.ZERO))
            throw new Exception("Verifier must be a non-zero");

        this.username = username;
        this.salt = salt;
        this.v = verifier;
    }

    public void setClientPublic(BigInteger A) throws Exception, NoSuchAlgorithmException {
        if (A.mod(SRP_Utility.N).equals(BigInteger.ZERO))
            throw new Exception("A mod N must not be zero");

        this.A = A;
        this.u = SRP_Utility.hash(A.toString().concat(this.B.toString()));
    }

    public void computeSessionKey() throws NoSuchAlgorithmException {
        BigInteger temp = SRP_Utility.modularExponent(
                this.A.multiply(SRP_Utility.modularExponent(this.v, this.u, SRP_Utility.N)), this.b,
                SRP_Utility.N);
        this.sessionKey = SRP_Utility.hash(temp.toString());
    }

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

        this.M = SRP_Utility
                .hash(this.A.toString().concat(result.toString().concat(this.sessionKey.toString())));

    }

    public Boolean verifySessionKey(BigInteger M) throws NoSuchAlgorithmException {
        BigInteger client_hash = SRP_Utility
                .hash(this.A.toString().concat(M.toString().concat(this.sessionKey.toString())));
        return client_hash.compareTo(this.M) == 0;
    }
}