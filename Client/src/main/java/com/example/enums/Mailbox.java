package com.example.enums;

public enum Mailbox {
    INBOX("inbox"),
    SENT("sent");

    private final String name;

    private Mailbox(String name) {
        this.name = name;
    }

    public String value() {
        return name;
    }
}
