package com.example.utils;

public record AESResult(byte[] iv, byte[] ciphertext) {}