package com.example.enums;

public enum Screen {
    AUTH("auth"),
    MAILBOX("mailbox");

    private final String name;

    private Screen(String name) {
        this.name = name;
    }

    public String value() {
        return name;
    }
}
