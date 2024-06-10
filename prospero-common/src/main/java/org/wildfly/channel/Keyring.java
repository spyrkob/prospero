package org.wildfly.channel;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.eclipse.jgit.util.Hex;
import org.jboss.logging.Logger;
import org.wildfly.prospero.api.exceptions.OperationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

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

    public PGPPublicKey getKey(PGPSignature pgpSignature) {
        final Iterator<PGPPublicKeyRing> keyRings = getPublicKeyRingCollection().getKeyRings();
        while (keyRings.hasNext()) {
            final PGPPublicKey publicKey = getPublicKey(pgpSignature, keyRings.next());
            if (publicKey != null) {
                return publicKey;
            }
        }

        return null;
    }


    // used in test
    public Keyring(Path keyStoreFile) throws IOException, PGPException {
        this.keyStoreFile = keyStoreFile;

        if (Files.exists(keyStoreFile)) {
            publicKeyRingCollection = new PGPPublicKeyRingCollection(new FileInputStream(keyStoreFile.toFile()), new JcaKeyFingerprintCalculator());
        }
    }

    public boolean removeKey(String keyId) throws IOException {
        final Iterator<PGPPublicKeyRing> keyRings = getPublicKeyRingCollection().getKeyRings();
        while (keyRings.hasNext()) {
            final PGPPublicKeyRing keyRing = keyRings.next();
            final Iterator<PGPPublicKey> publicKeys = keyRing.getPublicKeys();
            while (publicKeys.hasNext()) {
                final PGPPublicKey next = publicKeys.next();
                if (Long.toHexString(next.getKeyID()).equalsIgnoreCase(keyId)) {
                    this.publicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRingCollection, keyRing);

                    try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
                        getPublicKeyRingCollection().encode(outStream);
                    }
                    return true;
                }
            }
        }
        return false;
    }

    public void revokeCertificate(InputStream contentStream) throws IOException, PGPException {
        final PGPSignature pgpSignature = new PGPSignature(new BCPGInputStream(new ArmoredInputStream(contentStream)));
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

    public void importCertificate(InputStream certificateStream) throws IOException, OperationException {
        final PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(new ArmoredInputStream(certificateStream), new JcaKeyFingerprintCalculator());
        if (getKey(pgpPublicKeyRing.getPublicKey().getKeyID()) != null) {
            throw new DuplicatedCertificateException("The certificate with key ID " + pgpPublicKeyRing.getPublicKey().getKeyID() + " is already imported.",
                    pgpPublicKeyRing.getPublicKey().getKeyID());
        }
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(getPublicKeyRingCollection(), pgpPublicKeyRing);
        try(FileOutputStream outStream = new FileOutputStream(keyStoreFile.toFile())) {
            getPublicKeyRingCollection().encode(outStream);
        }
    }

    // not used in test

    @Deprecated
    public void importCertificate(List<PGPPublicKey> pgpPublicKeys) throws IOException {
        final PGPPublicKeyRing pgpPublicKeyRing = new PGPPublicKeyRing(pgpPublicKeys);
        publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(getPublicKeyRingCollection(), pgpPublicKeyRing);
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

    public Collection<KeyInfo> listKeys() {
        final Iterator<PGPPublicKeyRing> keyRings = getPublicKeyRingCollection().getKeyRings();
        final ArrayList<KeyInfo> keyInfos = new ArrayList<>();
        while (keyRings.hasNext()) {
            final PGPPublicKeyRing keyRing = keyRings.next();
            final Iterator<PGPPublicKey> publicKeys = keyRing.getPublicKeys();
            while (publicKeys.hasNext()) {
                final PGPPublicKey key = publicKeys.next();
                final String keyID = Long.toHexString(key.getKeyID()).toUpperCase(Locale.ROOT);
                final String fingerprint = Hex.toHexString(key.getFingerprint()).toUpperCase(Locale.ROOT);
                final Iterator<String> userIDs = key.getUserIDs();
                final ArrayList<String> tmpUserIds = new ArrayList<>();
                while (userIDs.hasNext()) {
                    tmpUserIds.add(userIDs.next());
                }
                final List<String> identities = Collections.unmodifiableList(tmpUserIds);
                final KeyInfo.Status status = key.hasRevocation() ? KeyInfo.Status.REVOKED : KeyInfo.Status.TRUSTED;
                final LocalDateTime creationDate = key.getCreationTime().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
                final LocalDateTime expiryDate = key.getValidSeconds() == 0?null:creationDate.plusSeconds(key.getValidSeconds());
                keyInfos.add(new KeyInfo(keyID, status, fingerprint, identities, creationDate, expiryDate));
            }
        }

        return keyInfos;
    }

    public KeyInfo readKey(File file) throws IOException {
        final PGPPublicKeyRing pgpPublicKeys = new PGPPublicKeyRing(new ArmoredInputStream(new FileInputStream(file)), new JcaKeyFingerprintCalculator());
        final PGPPublicKey key = pgpPublicKeys.getPublicKey();
        final String keyID = Long.toHexString(key.getKeyID()).toUpperCase(Locale.ROOT);
        final String fingerprint = Hex.toHexString(key.getFingerprint()).toUpperCase(Locale.ROOT);
        final Iterator<String> userIDs = key.getUserIDs();
        final ArrayList<String> tmpUserIds = new ArrayList<>();
        while (userIDs.hasNext()) {
            tmpUserIds.add(userIDs.next());
        }
        final List<String> identities = Collections.unmodifiableList(tmpUserIds);
        final KeyInfo.Status status = key.hasRevocation() ? KeyInfo.Status.REVOKED : KeyInfo.Status.TRUSTED;
        final LocalDateTime creationDate = key.getCreationTime().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        final LocalDateTime expiryDate = key.getValidSeconds() == 0?null:creationDate.plusSeconds(key.getValidSeconds());

        return new KeyInfo(keyID, status, fingerprint, identities, creationDate, expiryDate);
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

    // TODO move out
    public static class KeyInfo {

        private final String keyID;

        enum Status { TRUSTED, REVOKED }
        private Status status;
        private String fingerprint;
        private List<String> identity;
        private LocalDateTime issueDate;
        private LocalDateTime expiryDate;

        public KeyInfo(String keyID, Status status, String fingerprint, List<String> identity, LocalDateTime issueDate, LocalDateTime expiryDate) {
            this.keyID = keyID;
            this.status = status;
            this.fingerprint = fingerprint;
            this.identity = identity;
            this.issueDate = issueDate;
            this.expiryDate = expiryDate;
        }

        public String getKeyID() {
            return keyID;
        }

        public Status getStatus() {
            return status;
        }

        public String getFingerprint() {
            return fingerprint;
        }

        public Collection<String> getIdentity() {
            return identity;
        }

        public LocalDateTime getIssueDate() {
            return issueDate;
        }

        public LocalDateTime getExpiryDate() {
            return expiryDate;
        }

        @Override
        public String toString() {
            return "KeyInfo{" +
                    "keyID='" + keyID + '\'' +
                    ", status=" + status +
                    ", fingerprint='" + fingerprint + '\'' +
                    ", identity=" + identity +
                    ", issueDate=" + issueDate +
                    ", expiryDate=" + expiryDate +
                    '}';
        }
    }
}
