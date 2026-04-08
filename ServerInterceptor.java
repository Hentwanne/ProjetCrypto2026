
public class ServerInterceptor {

    public ServerInterceptor() {
        System.out.println("[Server] MITM attack mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {

        System.out.println("[MITM] Intercepted: " + message);

        // Attaque : modifier le message
        if (message.length() > 10) {
            char[] chars = message.toCharArray();

            // on modifie un caractère au milieu
            chars[10] = (chars[10] == 'A') ? 'B' : 'A';

            String modified = new String(chars);

            System.out.println("[MITM] Modified message!");
            return modified;
        }

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
