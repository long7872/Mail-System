package com.example.utils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class UserSession {
    private static String jwtToken;
    private static String userEmail;
    private static PrivateKey userPriKey;
    private static PublicKey userPubKey;

    public static void setSession(String token, String email, PrivateKey privateKey, PublicKey publicKey) {
        jwtToken = token;
        userEmail = email;
        userPriKey = privateKey;
        userPubKey = publicKey;
    }

    public static String getToken() {
        return jwtToken;
    }

    public static String getEmail() {
        return userEmail;
    }

    public static PrivateKey getPrivateKey() {
        return userPriKey;
    }

    public static PublicKey getPublicKey() {
        return userPubKey;
    }

    public static void clear() {
        jwtToken = null;
        userEmail = null;
        userPriKey = null;
        userPubKey = null;
    }
}
