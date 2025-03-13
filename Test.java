import java.math.BigInteger;

public class Test {
    public static void main(String[] args) {
        SRP_Client client = new SRP_Client();
        SRP_Server server = new SRP_Server();

        String password = "Password";
        // Generating User
        String username = "Alex";
        BigInteger salt = server.genSalt();
        BigInteger verifier = server.genVerifier(salt, password);

        // Server will contain {username, salt, verifier} and compute public private
        // value
        server.setUser(username, salt, verifier);
        server.computePublicPrivatePair();

        // Client will enter {username, passwoord} and compute public private value
        client.setUser(username, password);
        client.computePublicPrivatePair();

        // Client will send username and public value to server
        server.setClientPublic(client.A);

        // Server in response will send salt and it's public value
        client.setSalt(server.salt);
        client.setServerPublic(server.B);

        // Both will now compute their sessionKey.
        server.computeSessionKey();
        client.computeSessionKey();

        // Both client and server will compute key verifier
        client.computeSessionKeyVerifier();
        server.computeSessionKeyVerifier();

        // Client will send his key verifier to Server
        boolean server_response = server.verifySessionKey(client.M);
        if (server_response) {
            // Server will send his key verifer to Client
            boolean client_response = client.verifySessionKey(server.M);
            if (client_response) {
                System.out.println("Client and Server are mutually authenticated.");
            } else {
                System.out.println("Client found Server's proof to be incorrect. Client will reject authentication.");
            }
        } else {
            System.out.println(" Server found Client's proof to be incorrect. Server will reject authentication.");
        }
    }
}