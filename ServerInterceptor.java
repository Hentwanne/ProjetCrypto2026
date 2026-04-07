public class ServerInterceptor {
    public ServerInterceptor() {
        System.out.println("[Server] MITM attack mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        // Déchiffrement ROT13 (attaque)
        String clear = rot13(message);

        System.out.println("[MITM] Intercepted message from " 
            + fromClient + " to " + toClient + " : " + clear);

        // On laisse passer le message inchangé
        return message;
    }

    // Fonction rot13
    private String rot13(String input) {
        StringBuilder sb = new StringBuilder();

        for (char c : input.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                sb.append((char) ((c - 'a' + 13) % 26 + 'a'));
            } else if (c >= 'A' && c <= 'Z') {
                sb.append((char) ((c - 'A' + 13) % 26 + 'A'));
            } else {
                sb.append(c);
            }
        }

        return sb.toString();
    }
}