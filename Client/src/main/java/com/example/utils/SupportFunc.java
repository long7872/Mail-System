package com.example.utils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class SupportFunc {
    // --- Generate RSA key pair ---
    public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    // --- Save keys to PEM format files ---
    public static void savePrivateKeyToPem(PrivateKey privateKey, Path path) throws Exception {
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + chunkBase64(Base64.getEncoder().encodeToString(privateKey.getEncoded()))
                + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(path, pem);
    }

    public static void savePublicKeyToPem(PublicKey publicKey, Path path) throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + chunkBase64(Base64.getEncoder().encodeToString(publicKey.getEncoded()))
                + "\n-----END PUBLIC KEY-----\n";
        Files.writeString(path, pem);
    }

    // --- Load keys from PEM files ---
    public static PrivateKey loadPrivateKeyFromPem(Path path) throws Exception {
        String pem = Files.readString(path);
        PrivateKey pvk = loadPrivateKeyFromString(pem);
        return pvk;
    }

    public static PublicKey loadPublicKeyFromPem(Path path) throws Exception {
        String pem = Files.readString(path);
        PublicKey pbk = loadPublicKeyFromString(pem);
        return pbk;
    }

    public static PublicKey loadPublicKeyFromString(String pem) throws Exception {
        pem = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\r", "")
                .replace("\n", "")
                .trim();

        byte[] encoded = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }

    public static PrivateKey loadPrivateKeyFromString(String pem) throws Exception {
        pem = pem
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replace("\r", "")
                .replace("\n", "")
                .trim();

        byte[] decoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    // --- Utility: wrap base64 every 64 chars for PEM readability ---
    private static String chunkBase64(String base64) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < base64.length()) {
            int end = Math.min(i + 64, base64.length());
            sb.append(base64, i, end).append('\n');
            i = end;
        }
        return sb.toString().trim();
    }

    public static String hashMD5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b)); // convert to hex
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        return signed;
    }

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public static AESResult encryptAES(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return new AESResult(iv, encrypted);
    }

    public static byte[] encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            new MGF1ParameterSpec("SHA-256"),
            PSource.PSpecified.DEFAULT
        );

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        return encryptedKey;
    }

    public static SecretKey decryptAESKeyWithRSA(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        try {
        System.out.println(">>> SUPPORTFUNC: Starting RSA decryption...");
        System.out.println(">>> SUPPORTFUNC: encryptedKey length = " + encryptedKey.length);
        System.out.println(">>> SUPPORTFUNC: privateKey algorithm = " + privateKey.getAlgorithm());
        System.out.println(">>> SUPPORTFUNC: privateKey format = " + privateKey.getFormat());

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        System.out.println(">>> SUPPORTFUNC: Cipher instance created");

        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            new MGF1ParameterSpec("SHA-256"),
            PSource.PSpecified.DEFAULT
        );
        System.out.println(">>> SUPPORTFUNC: OAEP params created");

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        System.out.println(">>> SUPPORTFUNC: Cipher initialized successfully");

        System.out.println(">>> SUPPORTFUNC: About to call cipher.doFinal()...");
        byte[] decodedKey = cipher.doFinal(encryptedKey);

        System.out.println(">>> SUPPORTFUNC: SUCCESS! Decoded key length = " + decodedKey.length);
        return new SecretKeySpec(decodedKey, "AES");
            } catch (javax.crypto.BadPaddingException e) {
        System.err.println(">>> SUPPORTFUNC ERROR: BadPaddingException - Wrong key or corrupted data");
        e.printStackTrace();
        throw new Exception("RSA decryption failed: Wrong private key or corrupted encrypted key", e);
    } catch (javax.crypto.IllegalBlockSizeException e) {
        System.err.println(">>> SUPPORTFUNC ERROR: IllegalBlockSizeException - Block size mismatch");
        e.printStackTrace();
        throw new Exception("RSA decryption failed: Invalid block size", e);
    } catch (Exception e) {
        System.err.println(">>> SUPPORTFUNC ERROR: Unexpected exception");
        e.printStackTrace();
        throw new Exception("RSA decryption failed: " + e.getMessage(), e);
    }
    }

    public static byte[] decryptAES(byte[] ciphertext, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        byte[] decrypted = cipher.doFinal(ciphertext);
        return decrypted;
    }

    public static boolean verifySignature(String message, byte[] signature, PublicKey senderPubKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(senderPubKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(signature);
    }


    public static void showAlert(AlertType alertType, String title, String header, String content) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(content);

        alert.show();
    }
}
