
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Interceptor {

    private SecretKeySpec aesKey;
    private PrivateKey ecdsaPrivateKey;
    private PublicKey ecdsaPublicKey;

    public Interceptor(String privateKeyPath, String publicKeyPath) {
        try {
            this.ecdsaPrivateKey = loadPrivateKey(privateKeyPath);
            this.ecdsaPublicKey = loadPublicKey(publicKeyPath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load ECDSA keys", e);
        }
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(pem);

        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Unsupported private key format. Convert it to PKCS#8 with OpenSSL.", e);
        }
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(pem);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(spec);
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
    try {
        System.out.println("[Interceptor] Starting handshake");

        // 1. Génération d'une paire de clés ECDH éphémère
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] myECDHPublicKeyBytes = keyPair.getPublic().getEncoded();
        String myECDHPublicKeyBase64 = Base64.getEncoder().encodeToString(myECDHPublicKeyBytes);

        // 2. Signature de la clé publique ECDH avec la clé privée ECDSA long terme
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(ecdsaPrivateKey);
        signature.update(myECDHPublicKeyBytes);
        byte[] signatureBytes = signature.sign();
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

        // 3. Envoi de : clé_publique_ECDH : signature : clé_publique_ECDSA
        String myECDSAPublicKeyBase64 = Base64.getEncoder().encodeToString(ecdsaPublicKey.getEncoded());
        output.println(myECDHPublicKeyBase64 + ":" + signatureBase64 + ":" + myECDSAPublicKeyBase64);

        // 4. Réception des données de l'autre client
        String received = input.readLine();
        String[] parts = received.split(":");

        String otherECDHPublicKeyBase64 = parts[0];
        String otherSignatureBase64 = parts[1];
        String otherECDSAPublicKeyBase64 = parts[2];

        byte[] otherECDHPublicKeyBytes = Base64.getDecoder().decode(otherECDHPublicKeyBase64);
        byte[] otherSignatureBytes = Base64.getDecoder().decode(otherSignatureBase64);
        byte[] otherECDSAPublicKeyBytes = Base64.getDecoder().decode(otherECDSAPublicKeyBase64);

        // 5. Reconstruction de la clé publique ECDH de l'autre client
        KeyFactory kf = KeyFactory.getInstance("EC");

        X509EncodedKeySpec ecdhKeySpec = new X509EncodedKeySpec(otherECDHPublicKeyBytes);
        PublicKey otherECDHPublicKey = kf.generatePublic(ecdhKeySpec);

        // 6. Reconstruction de la clé publique ECDSA de l'autre client
        X509EncodedKeySpec ecdsaKeySpec = new X509EncodedKeySpec(otherECDSAPublicKeyBytes);
        PublicKey otherECDSAPublicKey = kf.generatePublic(ecdsaKeySpec);

        // 7. Vérification de la signature
        Signature verifySig = Signature.getInstance("SHA256withECDSA");
        verifySig.initVerify(otherECDSAPublicKey);
        verifySig.update(otherECDHPublicKeyBytes);

        boolean valid = verifySig.verify(otherSignatureBytes);

        if (!valid) {
            throw new IOException("Invalid ECDH public key signature");
        }

        // 8. Calcul du secret partagé ECDH
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(keyPair.getPrivate());
        ka.doPhase(otherECDHPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // 9. Dérivation de la clé AES-128
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
