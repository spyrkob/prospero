package org.wildfly.channel;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.jboss.logging.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class Keyring {

    private final Logger log = Logger.getLogger(Keyring.class.getName());

    private final Path keyStoreFile;

    private synchronized PGPPublicKeyRingCollection getPublicKeyRingCollection() {
        if (publicKeyRingCollection == null) {
            publicKeyRingCollection = new PGPPublicKeyRingCollection(Collections.emptyList());
        }
        return publicKeyRingCollection;
    }

    private PGPPublicKeyRingCollection publicKeyRingCollection;

    public Keyring(Path keyStoreFile) throws IOException, PGPException {
        this.keyStoreFile = keyStoreFile;

        if (Files.exists(keyStoreFile)) {
            publicKeyRingCollection = new PGPPublicKeyRingCollection(new FileInputStream(keyStoreFile.toFile()), new JcaKeyFingerprintCalculator());
        }
    }

    public void importArmoredKey(File keyFile) throws IOException {
        final PGPPublicKeyRing pgpPublicKeys = new PGPPublicKeyRing(new ArmoredInputStream(new FileInputStream(keyFile)), new JcaKeyFingerprintCalculator());
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(getPublicKeyRingCollection(), pgpPublicKeys);
        try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
            getPublicKeyRingCollection().encode(outStream);
        }
    }

    public PGPPublicKey getKey(PGPSignature pgpSignature) {
        // TODO: handle multiple keyrings;
        final Iterator<PGPPublicKeyRing> keyRings = getPublicKeyRingCollection().getKeyRings();
        while (keyRings.hasNext()) {
            final PGPPublicKey publicKey = getPublicKey(pgpSignature, keyRings.next());
            if (publicKey == null) {
                return null;
            }
            if (publicKey.hasRevocation()) {
                throw new RuntimeException("The key has been revoked");
            }
            return publicKey;
        }

        return null;
    }

    public PGPPublicKey getPublicKey(PGPSignature pgpSignature, PGPPublicKeyRing pgpPublicKeyRing) {

        final Iterator<PGPPublicKey> publicKeys = pgpPublicKeyRing.getPublicKeys();

        if (log.isTraceEnabled()) {
            log.tracef("Public keys in key ring%n");
            while (publicKeys.hasNext()) {
                final PGPPublicKey pubKey = publicKeys.next();
                if (pubKey.getUserIDs().hasNext()) {
                    log.tracef("%s %X\n", pubKey.getUserIDs().next(), pubKey.getKeyID());
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debugf("KeyID used in signature: %X\n", pgpSignature.getKeyID());
        }

        return pgpPublicKeyRing.getPublicKey(pgpSignature.getKeyID());
    }

    public void importArmoredKey(List<PGPPublicKey> pgpPublicKeys) throws IOException {
        final PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(pgpPublicKeys);
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(getPublicKeyRingCollection(), pgpPublicKeyRing);
        try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
            getPublicKeyRingCollection().encode(outStream);
        }
    }
}
