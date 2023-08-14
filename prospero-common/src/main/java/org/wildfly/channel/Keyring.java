package org.wildfly.channel;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

public class Keyring {

    private final Path keyStoreFile;
    private PGPPublicKeyRingCollection publicKeyRingCollection;

    public Keyring(Path keyStoreFile) throws IOException, PGPException {
        this.keyStoreFile = keyStoreFile;

        if (!Files.exists(keyStoreFile)) {
            publicKeyRingCollection = new PGPPublicKeyRingCollection(Collections.emptyList());
            try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
                publicKeyRingCollection.encode(outStream);
            }
        } else {
            publicKeyRingCollection = new PGPPublicKeyRingCollection(new FileInputStream(keyStoreFile.toFile()), new JcaKeyFingerprintCalculator());
        }
    }

    public void importKey(File keyFile) throws IOException {
        final PGPPublicKeyRing pgpPublicKeys = new PGPPublicKeyRing(new FileInputStream(keyFile), new JcaKeyFingerprintCalculator());
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, pgpPublicKeys);
        try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
            publicKeyRingCollection.encode(outStream);
        }
    }

    public PGPPublicKeyRing getKeyRing() {
        // TODO: handle multiple keyrings
        return publicKeyRingCollection.getKeyRings().next();
    }
}
