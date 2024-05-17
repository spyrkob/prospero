package org.wildfly.prospero.cli.commands.certificate;

import org.wildfly.channel.Keyring;

import java.io.PrintStream;

class KeyPrinter {

    private final PrintStream writer;

    KeyPrinter(PrintStream writer) {
        this.writer = writer;
    }

    void print(Keyring.KeyInfo key) {
        System.out.println("Key ID: " + key.getKeyID());
        System.out.println("Fingerprint: " + key.getFingerprint());
        System.out.println("Trust status: " + key.getStatus());
        if (!key.getIdentity().isEmpty()) {
            System.out.println("User IDs: ");
            for (String userId : key.getIdentity()) {
                System.out.println(" * " + userId);
            }
        }
        System.out.println("Created: " + key.getIssueDate());
        if (key.getExpiryDate() != null) {
            System.out.println("Valid until: " + key.getExpiryDate());
        }
    }
}
