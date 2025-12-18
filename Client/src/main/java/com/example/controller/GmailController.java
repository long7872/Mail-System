package com.example.controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.json.JSONArray;
import org.json.JSONObject;

import com.example.enums.MLScanStatus;
import com.example.enums.MLSentimentResult;
import com.example.enums.MLSpamResult;
import com.example.utils.AESResult;
import com.example.utils.EmailItem;
import com.example.utils.HttpClientUtil;
import com.example.utils.SupportFunc;
import com.example.utils.UserSession;

public class GmailController {

    @FXML
    private VBox contentArea;

    @FXML
    private Label nameLbl;

    private final String BASE_URL = "http://localhost:3000/";
    private final String PUBLIC_KEY_USER_URL = BASE_URL + "user/public_key";
    private final String PUBLIC_KEY_SERVICE_URL = BASE_URL + "system/public_key";
    private final String ML_NAME = "ML_SERVICE";
    private final String SEND_URL = BASE_URL + "email/send";
    private final String RECEIVED_URL = BASE_URL + "email/received";
    private final String SENT_URL = BASE_URL + "email/sent";

    private final String currentUser = UserSession.getEmail(); 

    @FXML
    void initialize() {
        nameLbl.setText(currentUser);
        loadInbox();
    }

    @FXML
    void onAllClick(ActionEvent event) {
        loadAll();
    }

    private void loadAll() {
        try {
            HttpResponse<String> res = HttpClientUtil.get(RECEIVED_URL + "?type=" + MLSpamResult.ALL, UserSession.getToken());
            if (res.statusCode() != 200) return;

            JSONArray arr = new JSONArray(res.body());

            contentArea.getChildren().clear(); // clear UI list

            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                System.out.println("Json Object inbox received: "+obj);

                EmailItem item = new EmailItem(
                    obj.getInt("id"),
                    obj.getString("sender_email"),
                    UserSession.getEmail(),
                    obj.getString("encrypted_key_recipient"),
                    obj.getString("ciphertext"),
                    obj.getString("iv"),
                    obj.getString("created_at")
                );

                item.setML(
                    MLScanStatus.valueOf(obj.getString("ml_scan_status").toUpperCase()),
                    MLSpamResult.valueOf(obj.getString("ml_spam_result").toUpperCase()),
                    obj.optDouble("ml_spam_score", 0.0),
                    MLSentimentResult.valueOf(obj.getString("ml_sentiment_result").toUpperCase()),
                    obj.optDouble("ml_sentiment_score", 0.0)
                );

                contentArea.getChildren().add(createEmailRow(item, MLSpamResult.ALL));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @FXML
    void onInboxClick(ActionEvent event) {
        loadInbox();
    }

    private void loadInbox() {
        try {
            HttpResponse<String> res = HttpClientUtil.get(RECEIVED_URL + "?type=" + MLSpamResult.HAM, UserSession.getToken());
            if (res.statusCode() != 200) return;

            JSONArray arr = new JSONArray(res.body());

            contentArea.getChildren().clear(); // clear UI list

            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                System.out.println("Json Object inbox received: "+obj);

                EmailItem item = new EmailItem(
                    obj.getInt("id"),
                    obj.getString("sender_email"),
                    UserSession.getEmail(),
                    obj.getString("encrypted_key_recipient"),
                    obj.getString("ciphertext"),
                    obj.getString("iv"),
                    obj.getString("created_at")
                );

                item.setML(
                    MLScanStatus.valueOf(obj.getString("ml_scan_status").toUpperCase()),
                    MLSpamResult.valueOf(obj.getString("ml_spam_result").toUpperCase()),
                    obj.optDouble("ml_spam_score", 0.0),
                    MLSentimentResult.valueOf(obj.getString("ml_sentiment_result").toUpperCase()),
                    obj.optDouble("ml_sentiment_score", 0.0)
                );

                contentArea.getChildren().add(createEmailRow(item, MLSpamResult.HAM));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @FXML
    void onSpamClick(ActionEvent event) {
        loadSpam();
    }

    private void loadSpam() {
        try {
            HttpResponse<String> res = HttpClientUtil.get(RECEIVED_URL + "?type=" + MLSpamResult.SPAM, UserSession.getToken());
            if (res.statusCode() != 200) return;

            JSONArray arr = new JSONArray(res.body());

            contentArea.getChildren().clear(); // clear UI list

            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                System.out.println("Json Object inbox received: "+obj);

                EmailItem item = new EmailItem(
                    obj.getInt("id"),
                    obj.getString("sender_email"),
                    UserSession.getEmail(),
                    obj.getString("encrypted_key_recipient"),
                    obj.getString("ciphertext"),
                    obj.getString("iv"),
                    obj.getString("created_at")
                );

                contentArea.getChildren().add(createEmailRow(item, MLSpamResult.SPAM));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @FXML
    void onSentClick(ActionEvent event) {
        loadSent();
    }

    private void loadSent() {
        try {
            HttpResponse<String> res = HttpClientUtil.get(SENT_URL, UserSession.getToken());
            if (res.statusCode() != 200) return;

            JSONArray arr = new JSONArray(res.body());

            contentArea.getChildren().clear(); // clear UI list

            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                System.out.println("Json Object sent received: "+obj);

                EmailItem item = new EmailItem(
                    obj.getInt("id"),
                    UserSession.getEmail(),
                    obj.getString("recipient_email"),
                    obj.getString("encrypted_key_sender"),
                    obj.getString("ciphertext"),
                    obj.getString("iv"),
                    obj.getString("created_at")
                );

                contentArea.getChildren().add(createEmailRow(item, MLSpamResult.SPAM));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private VBox createEmailRow(EmailItem item, MLSpamResult type) {
        VBox col = new VBox();
        col.setOnMouseClicked(e -> openEmail(item)); // click to open

        Label lblFrom = new Label("From: " + item.from);
        Label lblTo = new Label("To: " + item.to);
        lblFrom.setStyle("-fx-font-size: 14px; -fx-padding: 10;");
        lblTo.setStyle("-fx-font-size: 14px; -fx-padding: 10;");

        HBox lblRow = new HBox(lblFrom, lblTo);
        lblRow.setStyle("-fx-padding: 8; -fx-cursor: hand;");
        Separator hSeparator = new Separator();

        col.getChildren().add(lblRow);

        if (type == MLSpamResult.SPAM) {
            Label lblDate = new Label("Date: " + item.dateString);
            lblDate.setStyle("-fx-font-size: 14px; -fx-padding: 10;");
            HBox row = new HBox(lblDate);
            col.getChildren().add(row);
            col.getChildren().add(hSeparator);
        } else {
            Label lblSpam = new Label(item.spamResult + ": " + item.spamScore);
            Label lblSentiment = new Label(item.sentimentResult.name() + ": " + item.sentimentScore);
            Label lblDate = new Label("Date: " + item.dateString);
            lblSpam.setStyle("-fx-font-size: 14px; -fx-padding: 10;");
            lblSentiment.setStyle("-fx-font-size: 14px; -fx-padding: 10;");
            lblDate.setStyle("-fx-font-size: 14px; -fx-padding: 10;");
            HBox mlRow = new HBox(lblSpam, lblSentiment, lblDate);
            mlRow.setStyle("-fx-padding: 8; -fx-cursor: hand;");
            
            col.getChildren().add(mlRow);
            col.getChildren().add(hSeparator);
        }

        return col;
    }

    @FXML
    void onComposeClick(ActionEvent event) {
        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Compose Email");

        TextField toField = new TextField();
        toField.setPromptText("Recipient");
        TextField subjectField = new TextField();
        subjectField.setPromptText("Subject");
        TextArea contentField = new TextArea();
        contentField.setPromptText("Message content");

        VBox box = new VBox(10, new Label("To:"), toField,
                new Label("Subject:"), subjectField,
                new Label("Content:"), contentField);
        dialog.getDialogPane().setContent(box);

        ButtonType sendBtn = new ButtonType("Send", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(sendBtn, ButtonType.CANCEL);

        dialog.setResultConverter(button -> {
            if (button == sendBtn) {
                sendEmail(toField.getText(), subjectField.getText(), contentField.getText());
            }
            return null;
        });

        dialog.showAndWait();
    }

    private void sendEmail(String to, String subject, String content) {
        System.out.println("Encrypting AES key using RECIPIENT PUBLIC KEY: " + to);
        System.out.println("UserSession private key belongs to: " + UserSession.getEmail());
        try {
            // Recipient Public key
            HttpResponse<String> publicKeyUserResponse = HttpClientUtil.get(
                PUBLIC_KEY_USER_URL + "?email=" + to, UserSession.getToken()
            );

            if (publicKeyUserResponse.statusCode() != 200) {
                SupportFunc.showAlert(
                    AlertType.ERROR, 
                    "Status", 
                    "Server Error!", 
                    "Recipient not found."
                );
                return;
            }

            JSONObject userPubKeyObj = new JSONObject(publicKeyUserResponse.body());
            String recipientPublicKeyPem = userPubKeyObj.getString("public_key");

            System.out.println("RecipientPublicKey PEM:\n" + recipientPublicKeyPem);

            // ML Service Public key
            HttpResponse<String> publicKeyServiceResponse = HttpClientUtil.get(
                PUBLIC_KEY_SERVICE_URL + "?service=" + ML_NAME, UserSession.getToken()
            );

            if (publicKeyServiceResponse.statusCode() != 200) {
                SupportFunc.showAlert(
                    AlertType.ERROR, 
                    "Status", 
                    "Server Error!", 
                    "Recipient not found."
                );
                return;
            }

            JSONObject mlServicePubKeyObj = new JSONObject(publicKeyServiceResponse.body());
            String mlPublicKeyPem = mlServicePubKeyObj.getString("public_key");

            // Convert PEM → PublicKey
            PublicKey recipientPublicKey = SupportFunc.loadPublicKeyFromString(recipientPublicKeyPem);
            PublicKey mlPublicKey = SupportFunc.loadPublicKeyFromString(mlPublicKeyPem);

            // 1) Create message JSON BEFORE signing
            JSONObject messageObject = new JSONObject();
            messageObject.put("subject", subject);
            messageObject.put("content", content);

            // 2) Sign (sign only plaintext fields, NOT encrypted)
            byte[] sign = SupportFunc.signMessage(subject + content, UserSession.getPrivateKey());
            String signature = Base64.getEncoder().encodeToString(sign);
            messageObject.put("signature", signature);

            String jsonStr = messageObject.toString();

            // 3) Generate AES key
            SecretKey aesKey = SupportFunc.generateAESKey();

            // 4) AES encrypt JSON
            AESResult result = SupportFunc.encryptAES(jsonStr, aesKey);
            byte[] iv = result.iv();
            byte[] ciphertext = result.ciphertext();

            String iv64 = Base64.getEncoder().encodeToString(iv);
            String ciphertext64 = Base64.getEncoder().encodeToString(ciphertext);

            // 5) RSA encrypt AES key
            byte[] encryptedKeySender = SupportFunc.encryptAESKeyWithRSA(aesKey, UserSession.getPublicKey());
            byte[] encryptedKeyRecipient = SupportFunc.encryptAESKeyWithRSA(aesKey, recipientPublicKey);
            byte[] encryptedKeyML = SupportFunc.encryptAESKeyWithRSA(aesKey, mlPublicKey);

            String encryptedKeySender64 = Base64.getEncoder().encodeToString(encryptedKeySender);
            String encryptedKeyRecipient64 = Base64.getEncoder().encodeToString(encryptedKeyRecipient);
            String encryptedKeyML64 = Base64.getEncoder().encodeToString(encryptedKeyML);

            // 5) Send both
            JSONObject sendObj = new JSONObject();
            sendObj.put("to", to);
            sendObj.put("encrypted_key_sender", encryptedKeySender64);
            sendObj.put("encrypted_key_recipient", encryptedKeyRecipient64);
            sendObj.put("encrypted_key_ml", encryptedKeyML64);
            sendObj.put("ciphertext", ciphertext64);
            sendObj.put("iv", iv64);

            HttpResponse<String> sendResponse = HttpClientUtil.post(
                SEND_URL,
                sendObj.toString(),
                UserSession.getToken()
            );

            System.out.println("Client encrypted_key_sender: " + encryptedKeySender64);
            System.out.println("Client encrypted_key_recipient: " + encryptedKeyRecipient64);
            System.out.println("Client encrypted_key_ml: " + encryptedKeyML64);
            System.out.println("Client encrypted_iv: " + iv64);
            JSONObject json = new JSONObject(sendResponse.body());
            System.out.println("Server returned recipient: " + json.getJSONObject("email").getString("to"));
            System.out.println("Server returned sender key: " + json.getJSONObject("email").getString("encrypted_key_sender"));
            System.out.println("Server returned recipient key: " + json.getJSONObject("email").getString("encrypted_key_recipient"));
            System.out.println("Server returned ml key: " + json.getJSONObject("email").getString("encrypted_key_ml"));
            System.out.println("Server returned iv: " + json.getJSONObject("email").getString("iv"));

            if (sendResponse.statusCode() == 201) {
                SupportFunc.showAlert(
                    AlertType.INFORMATION, 
                    "Status", 
                    "Success!", 
                    "Encrypted Email Sent!"
                );

                System.out.println("Server returned ml_scan_status: " + json.getJSONObject("email").getString("ml_scan_status"));
                System.out.println("Server returned ml_spam_result: " + json.getJSONObject("email").getString("ml_spam_result"));
                System.out.println("Server returned ml_spam_score: " + json.getJSONObject("email").getString("ml_spam_score"));
                System.out.println("Server returned ml_sentiment_result: " + json.getJSONObject("email").getString("ml_sentiment_result"));
                System.out.println("Server returned ml_sentiment_score: " + json.getJSONObject("email").getString("ml_sentiment_score"));
            } else {
                SupportFunc.showAlert(
                    AlertType.ERROR, 
                    "Status", 
                    "Send Failed!", 
                    sendResponse.body()
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

    private void openEmail(EmailItem email) {
        try {
            System.out.println("User Session: " + UserSession.getEmail() + ", email from: " + email.from);
            PrivateKey pvk1 = UserSession.getPrivateKey();
            System.out.println(pvk1);
            boolean isSent = (UserSession.getEmail().equals(email.from));
            if (isSent) 
                System.out.println("Decrypting using private key of sender: " + email.from);
            else 
                System.out.println("Decrypting using private key of recipient: " + email.to);


             // --- Decode what we received from DB/email item ---
            String encryptedKey64 = email.encryptedKey64;
            String ciphertext64 = email.ciphertext64;
            String iv64 = email.iv64;

            System.out.println("CLIENT LOG: encrypted_key (len=" + encryptedKey64.length() + "): " + encryptedKey64.substring(0, Math.min(64, encryptedKey64.length())) + "...");
            System.out.println("CLIENT LOG: ciphertext (len=" + ciphertext64.length() + "): " + ciphertext64.substring(0, Math.min(64, ciphertext64.length())) + "...");
            System.out.println("CLIENT LOG: iv (len=" + iv64.length() + "): " + iv64);

            // Basic sanity checks
            if (encryptedKey64 == null || encryptedKey64.isEmpty()) throw new IllegalStateException("encrypted_key missing");
            if (iv64 == null || iv64.isEmpty()) throw new IllegalStateException("iv missing");
            if (ciphertext64 == null || ciphertext64.isEmpty()) throw new IllegalStateException("ciphertext missing");

            byte[] encryptedKey = Base64.getDecoder().decode(encryptedKey64);
            byte[] ciphertext = Base64.getDecoder().decode(ciphertext64);
            byte[] iv = Base64.getDecoder().decode(iv64);

            // Confirm iv length
            System.out.println("CLIENT LOG: IV bytes length = " + iv.length);
            if (iv.length != 12) {
                throw new IllegalStateException("IV length != 12 bytes: " + iv.length);
            }

            // 1) Decrypt AES key
            System.out.println("Check PrivateKey in UserSession");
            PrivateKey pvk = UserSession.getPrivateKey();
            if (pvk == null) {
                System.out.println("No PrivateKey in UserSession");
                throw new IllegalStateException("No PrivateKey in UserSession — user didn't load their key");
            }

            SecretKey aesKey = SupportFunc.decryptAESKeyWithRSA(encryptedKey, UserSession.getPrivateKey());
            System.out.println("CLIENT LOG: AES key unwrapped, length=" + aesKey.getEncoded().length);

            // 2) Decrypt ciphertext
            byte[] json = SupportFunc.decryptAES(ciphertext, aesKey, iv);
            String jsonStr = new String(json, StandardCharsets.UTF_8);
            System.out.println("CLIENT LOG: decrypted JSON: " + jsonStr);

            JSONObject msg = new JSONObject(jsonStr);
            String subject = msg.getString("subject");
            String content = msg.getString("content");
            String signature = msg.getString("signature");

            // 3) Get sender or recipient public key
            PublicKey pubKey;
            if (!isSent) {
                HttpResponse<String> senderKeyRes = HttpClientUtil.get(
                    PUBLIC_KEY_USER_URL + "?email=" + email.from,
                    UserSession.getToken()
                );
                String senderPubKeyPem = new JSONObject(senderKeyRes.body()).getString("public_key");
                pubKey = SupportFunc.loadPublicKeyFromString(senderPubKeyPem);
            } else {
                pubKey = UserSession.getPublicKey();
            }

            // 4) Verify signature
            byte[] signature64 = Base64.getDecoder().decode(signature);
            boolean ok = SupportFunc.verifySignature(subject + content, signature64, pubKey);
            if (!ok) {
                SupportFunc.showAlert(Alert.AlertType.ERROR, "Security Warning", "Signature Invalid!", "Message may be tampered!");
                return;
            }

            // 5) Display result
            SupportFunc.showAlert(Alert.AlertType.INFORMATION, subject, "Verified Sender: " + email.from, content);

        } catch (javax.crypto.AEADBadTagException e) {
            SupportFunc.showAlert(Alert.AlertType.ERROR, "Decrypt Error",
                "Auth failed", "Ciphertext or key/iv mismatch (AEAD tag).");
        } catch (javax.crypto.BadPaddingException e) { // Often RSA OAEP wrong key
            SupportFunc.showAlert(Alert.AlertType.ERROR, "Decrypt Error",
                "RSA OAEP decryption error", e.getMessage());
        } catch (Exception e) {
            SupportFunc.showAlert(Alert.AlertType.ERROR, "Decrypt Error",
                "Failed to decrypt message.", e.toString());
        }
    }
}
