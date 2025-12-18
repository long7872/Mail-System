package com.example.controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;

import java.io.*;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;
import org.json.JSONObject;

import com.example.App;
import com.example.enums.Screen;
import com.example.utils.HttpClientUtil;
import com.example.utils.SupportFunc;
import com.example.utils.UserSession;

public class AuthController {

    @FXML
    private TextField emailField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private PasswordField confirmPasswordField;
    @FXML
    private CheckBox rememberCheck;

    private final String BASE_URL = "http://localhost:3000/";

    private final String SIGNUP_URL = BASE_URL + "auth/signup";
    private final String LOGIN_URL = BASE_URL + "auth/login";

    private final Path appDir = Paths.get(System.getProperty("user.home"), "email_app");
    private final Path configPath = appDir.resolve("email_app.properties");
    private final Path keyDir = appDir.resolve("keys");
    private final Properties props = new Properties();

    @FXML
    public void initialize() {
        try {
            if (!Files.exists(appDir)) 
                Files.createDirectories(appDir);
            if (!Files.exists(keyDir)) 
                Files.createDirectories(keyDir);

            if (Files.exists(configPath)) {
                try (InputStream in = Files.newInputStream(configPath)) {
                    props.load(in);
                    String savedEmail = props.getProperty("email", "");
                    boolean remember = Boolean.parseBoolean(props.getProperty("remember", "false"));
                    emailField.setText(savedEmail);
                    rememberCheck.setSelected(remember);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private KeyPair saveKey(String email) {
        try {
            Path privateKeyPath = keyDir.resolve(email + "-private.pem");
            Path publicKeyPath = keyDir.resolve(email + "-public.pem");
            
            PrivateKey privateKey;
            PublicKey publicKey;
            // Nếu chưa có key, tạo mới
            if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
                System.out.println("🔑 Generating new key pair for " + email);
                KeyPair kp = SupportFunc.generateRSAKeyPair(2048);
                
                SupportFunc.savePrivateKeyToPem(kp.getPrivate(), privateKeyPath);
                SupportFunc.savePublicKeyToPem(kp.getPublic(), publicKeyPath);

                privateKey = kp.getPrivate();
                publicKey = kp.getPublic();
            } else {
                System.out.println("✅ Existing key pair found for " + email);
                // System.out.println("PubKey: " + Files.readString(publicKeyPath).replace("-----BEGIN PUBLIC KEY-----", "")
                // .replace("-----END PUBLIC KEY-----", "")
                // .replace("\r", "")
                // .replace("\n", "")
                // .trim());
                // System.out.println("PriKey: " + Files.readString(privateKeyPath));
                privateKey = SupportFunc.loadPrivateKeyFromPem(privateKeyPath);
                publicKey = SupportFunc.loadPublicKeyFromPem(publicKeyPath);
            }

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
 
    private void rememberLogin(String email, boolean remember) {
        try (OutputStream out = Files.newOutputStream(configPath)) {
            if (remember) {
                props.setProperty("email", email);
                props.setProperty("remember", "true");
            } else {
                props.remove("email");
                props.setProperty("remember", "false");
            }
            props.store(out, "Email App Preferences");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    void onLogin(ActionEvent event) {
        try {
            String email = emailField.getText();
            String password = passwordField.getText();

            String hashPassword = SupportFunc.hashMD5(password);

            saveKey(email);
            Path publicKeyPath = keyDir.resolve(email + "-public.pem");
            String publicKeyPem = Files.readString(publicKeyPath);

            JSONObject body = new JSONObject();
            body.put("email", email);
            body.put("password_hash", hashPassword);
            body.put("public_key", publicKeyPem);
            

            HttpResponse<String> response = HttpClientUtil.post(
                    LOGIN_URL, body.toString(), null);

            if (response.statusCode() == 200) {
                JSONObject obj = new JSONObject(response.body());
                String token = obj.getString("token");

                KeyPair kp = saveKey(email);
                PrivateKey privateKey = kp.getPrivate();
                PublicKey publicKey = kp.getPublic();

                UserSession.setSession(token, email, privateKey, publicKey);

                rememberLogin(email, rememberCheck.isSelected());

                SupportFunc.showAlert(
                    AlertType.INFORMATION,
                    "Status",
                    "Succeed!",
                    "Login Successful!"
                );
                System.out.println("JWT: " + token);

                App.switchToScene(Screen.MAILBOX.value(), "Mailbox");
            } else {
                SupportFunc.showAlert(
                    AlertType.ERROR,
                    "Status",
                    "Server Error!",
                    "Invalid email or password!"
                );
            }
        } catch (Exception e) {
            SupportFunc.showAlert(
                AlertType.ERROR,
                "Status",
                "Error!",
                e.getMessage()
            );
        }
    }

    @FXML
    void onRegister(ActionEvent event) {
        try {
            String email = emailField.getText();
            String password = passwordField.getText();
            String confirmPassword = confirmPasswordField.getText();

            if (!password.equals(confirmPassword)) {
                SupportFunc.showAlert(
                    AlertType.ERROR,
                    "Status",
                    "Wrong!",
                    "Password not match."
                );
                return;
            }

            String hashPassword = SupportFunc.hashMD5(password);

            saveKey(email);
            rememberLogin(email, rememberCheck.isSelected());
            Path publicKeyPath = keyDir.resolve(email + "-public.pem");
            String publicKeyPem = Files.readString(publicKeyPath);

            JSONObject body = new JSONObject();
            body.put("email", email);
            body.put("password_hash", hashPassword);
            body.put("public_key", publicKeyPem);
            

            HttpResponse<String> response = HttpClientUtil.post(
                    SIGNUP_URL, body.toString(), null);

            if (response.statusCode() == 201) {
                SupportFunc.showAlert(
                    AlertType.INFORMATION,
                    "Status",
                    "Succeed!",
                    "Account created successfully!"
                );

            } else {
                SupportFunc.showAlert(
                    AlertType.ERROR,
                    "Status",
                    "Server Error!",
                    response.body()
                );
            }
        } catch (Exception e) {
            SupportFunc.showAlert(
                AlertType.ERROR,
                "Status",
                "Error!",
                e.getMessage()
            );
        }
    }
}
