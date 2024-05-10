package org.wildfly.channel;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
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
        final Iterator<PGPPublicKeyRing> keyRings = getPublicKeyRingCollection().getKeyRings();
        while (keyRings.hasNext()) {
            return getPublicKey(pgpSignature, keyRings.next());
        }

        return null;
    }

    private PGPPublicKey getPublicKey(PGPSignature pgpSignature, PGPPublicKeyRing pgpPublicKeyRing) {

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

    public void importCertificate(File certificateFile) throws IOException, PGPException {
        final PGPSignature pgpSignature = new PGPSignature(new BCPGInputStream(new ArmoredInputStream(new FileInputStream(certificateFile))));
        final long keyId = pgpSignature.getKeyID();

        final PGPPublicKeyRingCollection publicKeyRingCollection = getPublicKeyRingCollection();
        final Iterator<PGPPublicKeyRing> keyRings = publicKeyRingCollection.getKeyRings();
        PGPPublicKeyRing keyRing = null;
        PGPPublicKey publicKey = null;
        while (keyRings.hasNext()) {
            keyRing = keyRings.next();
            publicKey = keyRing.getPublicKey(keyId);
            if (publicKey != null) {
                break;
            }
        }



        final PGPPublicKey pgpPublicKey = PGPPublicKey.addCertification(publicKey, pgpSignature);
        // TODO: see if possible to use just a keyRing instead of collection for storage
        PGPPublicKeyRing newKeyRing = PGPPublicKeyRing.insertPublicKey(keyRing, pgpPublicKey);

        PGPPublicKeyRingCollection collection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection, keyRing);
        collection = PGPPublicKeyRingCollection.addPublicKeyRing(collection, newKeyRing);

        this.publicKeyRingCollection = collection;
        try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
            getPublicKeyRingCollection().encode(outStream);
        }

    }

    public PGPPublicKey getKey(long keyID) {
        final Iterator<PGPPublicKeyRing> keyRings = getPublicKeyRingCollection().getKeyRings();
        while (keyRings.hasNext()) {
            final PGPPublicKeyRing keyRing = keyRings.next();
            final PGPPublicKey publicKey = keyRing.getPublicKey(keyID);
            if (publicKey != null) {
                return publicKey;
            }
        }
        return null;
    }
}
