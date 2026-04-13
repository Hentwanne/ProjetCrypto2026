

public class ServerInterceptor {

    // Pour l'attaque de rejeu
    private String replayMessageForClient2 = null;
    private boolean replayAlreadyDone = false;

    public ServerInterceptor() {
        System.out.println("[Server] Replay attack mode");
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        System.out.println("[Server] Relaying from " + fromClient + " to client " + toClient + " : " + message);

        // Le handshake passe normalement
        if (isHandshakeMessage(message)) {
            return message;
        }

        // Attaque de rejeu seulement sur les messages applicatifs
        if (fromClient == 1 && toClient == 2) {

            // On mémorise le premier message envoyé de 1 vers 2
            if (replayMessageForClient2 == null) {
                replayMessageForClient2 = message;
                System.out.println("[Replay] First encrypted message stored");
                return message;
            }

            // Une seule fois, on rejoue le message précédent au lieu du nouveau
            if (!replayAlreadyDone) {
                replayAlreadyDone = true;
                System.out.println("[Replay] Replaying previous encrypted message!");
                return replayMessageForClient2;
            }

            return message;
        }

        return message;
    }

    private boolean isHandshakeMessage(String message) {
        String[] parts = message.split(":");
        return parts.length == 3;
    }
}
