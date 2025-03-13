import java.math.BigInteger;

public class Test {
    public static void main(String[] args) {
        Client client = new Client();
        Server server = new Server();

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

        // Check if both have the same key
        if (server.sessionKey.equals(client.sessionKey)) {

            System.out.println("Authenticated");
            System.out.println("Server: " + server.sessionKey.toString());
            System.out.println("Client: " + client.sessionKey.toString());
        } else {
            System.out.println("Not Authenticated");
        }
    }
}