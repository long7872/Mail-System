package com.example.utils;

import com.example.enums.MLScanStatus;
import com.example.enums.MLSentimentResult;
import com.example.enums.MLSpamResult;

public class EmailItem {
    public int id;
    public String from = "";
    public String to = "";
    public String encryptedKey64;
    public String ciphertext64;
    public String iv64;
    public String dateString;
    public MLScanStatus scanStatus = MLScanStatus.PENDING;
    public MLSpamResult spamResult = MLSpamResult.HAM;
    public double spamScore;
    public MLSentimentResult sentimentResult = MLSentimentResult.NEUTRAL;
    public double sentimentScore;

    // Constructor for Inbox (recipient)
    public EmailItem(int id, String from, String to, String encryptedKey64, String ciphertext64, String iv64, String dateString) {
        this.id = id;
        this.from = from;
        this.to = to;
        this.encryptedKey64 = encryptedKey64;
        this.ciphertext64 = ciphertext64;
        this.iv64 = iv64;
        this.dateString = dateString;
    }

    public void setML(MLScanStatus scanStatus, MLSpamResult spamResult, double spamScore, 
                MLSentimentResult sentimentResult, double sentimentScore) {
        this.scanStatus = scanStatus;
        this.spamResult = spamResult;
        this.spamScore = spamScore;
        this.sentimentResult = sentimentResult;
        this.sentimentScore = sentimentScore;
    }
}
