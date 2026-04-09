import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Interceptor {

    private SecretKeySpec aesKey;

    public Interceptor() {
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            // 1. Génération d'une paire de clés ECDH éphémère
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair keyPair = kpg.generateKeyPair();

            // 2. Envoi de la clé publique au pair
            String myPublicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            output.println(myPublicKeyBase64);

            // 3. Réception de la clé publique du pair
            String otherPublicKeyBase64 = input.readLine();
            byte[] otherPublicKeyBytes = Base64.getDecoder().decode(otherPublicKeyBase64);

            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(otherPublicKeyBytes);
            PublicKey otherPublicKey = kf.generatePublic(keySpec);

            // 4. Calcul du secret partagé ECDH
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(otherPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // 5. Dérivation de la clé AES-128 à partir du secret partagé
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha.digest(sharedSecret);
            byte[] keyBytes = Arrays.copyOf(hash, 16);
            aesKey = new SecretKeySpec(keyBytes, "AES");

            System.out.println("[Interceptor] Handshake complete!");
        } catch (Exception e) {
            throw new IOException("Handshake failed", e);
        }
    }

    public String beforeSend(String plainText) {
        try {
            System.out.println("[Interceptor] Encrypting message: " + plainText);

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

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String afterReceive(String encryptedText) {
        try {
            System.out.println("[Interceptor] Decrypting message...");

            String[] parts = encryptedText.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

            byte[] decrypted = cipher.doFinal(cipherBytes);

            return new String(decrypted, "UTF-8");

        } catch (Exception e) {
            return "[Decryption failed: message integrity check failed]";
        }
    }
}