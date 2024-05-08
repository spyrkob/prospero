package org.wildfly.prospero.utils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class SignatureUtils {

    /**
     * Generate key ring with private/public key pair
     *
     * @return
     * @throws Exception
     * @param userId
     * @param password
     */
    public static PGPSecretKeyRing generateSecretKey(String userId, String password) throws Exception {
        return PGPainless.generateKeyRing().modernKeyRing(userId, password);
    }

    /**
     * Sign {@code originalFile} using private key found in the {@code keyRing}. The detached signature is stored
     * next to {@code originalFile} with ".asc" suffix.
     *
     * @param keyRing
     * @param originalFile
     * @param pass
     * @return
     * @throws Exception
     */
    public static Long signFile(PGPSecretKeyRing keyRing, Path originalFile, String pass) throws Exception {
        EncryptionStream encryptionStream = null;
        try {
            encryptionStream = getEncryptionStreamWithSigning(keyRing, pass);
            try (InputStream fIn = new FileInputStream(originalFile.toFile())) {
                Streams.pipeAll(fIn, encryptionStream);
            }
        } finally {
            // can't use try-with-resources - the encryptionStream has to be close before next step, but we still need access to it
            if (encryptionStream != null) {
                encryptionStream.close();
            }
        }

        final Path signatureFilePath = originalFile.getParent().resolve(originalFile.getFileName().toString() + ".asc");

        try(FileOutputStream fos = new FileOutputStream(signatureFilePath.toFile());
            ArmoredOutputStream aos = new ArmoredOutputStream(fos)) {
            for (SubkeyIdentifier subkeyIdentifier : encryptionStream.getResult().getDetachedSignatures().keySet()) {
                final Set<PGPSignature> pgpSignatures = encryptionStream.getResult().getDetachedSignatures().get(subkeyIdentifier);
                for (PGPSignature pgpSignature : pgpSignatures) {
                    pgpSignature.encode(aos);
                    return pgpSignature.getKeyID();
                }
            }
        }
        return null;
    }

    private static EncryptionStream getEncryptionStreamWithSigning(PGPSecretKeyRing keyRing, String pass) throws PGPException, IOException {
        return PGPainless.encryptAndOrSign()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                        .addDetachedSignature(
                                SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(pass)),
                                keyRing)));
    }

    public static void exportPublicKeys(PGPSecretKeyRing pgpSecretKey, File targetFile) throws IOException {
        final List<PGPPublicKey> pubKeyList = new ArrayList<>();
        final Iterator<PGPPublicKey> publicKeys = pgpSecretKey.getPublicKeys();
        publicKeys.forEachRemaining(pubKeyList::add);
        final PGPPublicKeyRing pubKeyRing = new PGPPublicKeyRing(pubKeyList);
        try (OutputStream outStream = new ArmoredOutputStream(new FileOutputStream(targetFile))) {
            pubKeyRing.encode(outStream, true);
        }
    }
}
