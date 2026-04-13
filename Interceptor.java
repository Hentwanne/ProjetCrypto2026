
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
    private X509Certificate myCertificate;
    private X509Certificate caCertificate;

    public Interceptor(String privateKeyPath, String certificatePath, String caCertificatePath) {
        try {
            this.ecdsaPrivateKey = loadPrivateKey(privateKeyPath);
            this.myCertificate = loadCertificate(certificatePath);
            this.caCertificate = loadCertificate(caCertificatePath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load keys/certificates", e);
        }
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(pem);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(spec);
    }

    private X509Certificate loadCertificate(String path) throws Exception {
        try (FileInputStream fis = new FileInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    public void onHandshake(BufferedReader input, PrintWriter output) throws IOException {
        try {
            System.out.println("[Interceptor] Starting handshake");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair keyPair = kpg.generateKeyPair();

            byte[] myECDHPublicKeyBytes = keyPair.getPublic().getEncoded();
            String myECDHPublicKeyBase64 = Base64.getEncoder().encodeToString(myECDHPublicKeyBytes);

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(ecdsaPrivateKey);
            sig.update(myECDHPublicKeyBytes);
            byte[] signatureBytes = sig.sign();
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

            String certBase64 = Base64.getEncoder().encodeToString(myCertificate.getEncoded());

            // Format : ecdhPub:signature:certificate
            output.println(myECDHPublicKeyBase64 + ":" + signatureBase64 + ":" + certBase64);

            String received = input.readLine();
            String[] parts = received.split(":", 3);
            if (parts.length != 3) {
                throw new IOException("MITM DETECTE : format de handshake invalide");
            }

            byte[] otherECDHPublicKeyBytes = Base64.getDecoder().decode(parts[0]);
            byte[] otherSignatureBytes = Base64.getDecoder().decode(parts[1]);
            byte[] otherCertBytes = Base64.getDecoder().decode(parts[2]);

            X509Certificate otherCertificate;
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                otherCertificate = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(otherCertBytes));
            } catch (Exception e) {
                throw new IOException("MITM DETECTE : certificat invalide ou falsifie");
            }

            try {
                otherCertificate.checkValidity();
                otherCertificate.verify(caCertificate.getPublicKey());
            } catch (Exception e) {
                throw new IOException("MITM DETECTE : certificat non signe par l'AC");
            }

            String identity = otherCertificate.getSubjectX500Principal().getName();
            System.out.println("[Interceptor] Identite du client distant : " + identity);

            PublicKey otherECDSAPublicKey = otherCertificate.getPublicKey();

            Signature verifySig = Signature.getInstance("SHA256withECDSA");
            verifySig.initVerify(otherECDSAPublicKey);
            verifySig.update(otherECDHPublicKeyBytes);

            boolean valid = verifySig.verify(otherSignatureBytes);
            if (!valid) {
                throw new IOException("MITM DETECTE : signature de la cle ECDH invalide");
            }

            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec ecdhSpec = new X509EncodedKeySpec(otherECDHPublicKeyBytes);
            PublicKey otherECDHPublicKey = kf.generatePublic(ecdhSpec);

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(otherECDHPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha.digest(sharedSecret);
            byte[] keyBytes = Arrays.copyOf(hash, 16);
            aesKey = new SecretKeySpec(keyBytes, "AES");

            System.out.println("[Interceptor] Handshake complete!");
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("MITM DETECTE : echec du handshake");
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
