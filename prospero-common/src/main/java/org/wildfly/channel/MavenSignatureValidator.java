/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.channel;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.jboss.logging.Logger;
import org.wildfly.channel.spi.SignatureValidator;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

public class MavenSignatureValidator implements SignatureValidator {

    private final Logger log = Logger.getLogger(MavenSignatureValidator.class.getName());
    private Function<String, Boolean> acceptor;

    private Keyring keyring;

    public MavenSignatureValidator(Function<String, Boolean> acceptor, Keyring keyring) throws IOException, PGPException {
        this.keyring = keyring;

        this.acceptor = acceptor;
    }

    @Override
    public void validateSignature(MavenArtifact artifact, File signature, String gpgUrl) {
        if (log.isDebugEnabled()) {
            log.debugf("Verifying %s with signature %s", artifact, signature);
        }

        PGPSignature pgpSignature = readSignatureFile(signature);


        PGPPublicKey publicKey = keyring.getKey(pgpSignature);

        if (publicKey == null && gpgUrl != null) {
            final List<PGPPublicKey> pgpPublicKeys = downloadPublicKey(gpgUrl);
            final String description = describeImportedKeys(pgpPublicKeys);
            // TODO: verify that the key matches required signature
            if (acceptor.apply(description)) {
                try {
                    keyring.importCertificate(pgpPublicKeys);
                    publicKey = keyring.getKey(pgpSignature);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        final String artifactGav = String.format("%s:%s:%s", artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());
        final String keyID = Long.toHexString(pgpSignature.getKeyID()).toUpperCase(Locale.ROOT);
        if (publicKey == null) {
            throw new UntrustedArtifactException(String.format("No matching trusted certificate found to verify signature of artifact %s. Required key ID %s",
                    artifactGav, keyID)
                    , artifact, keyID);
        }

        final Iterator<PGPSignature> subKeys = publicKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
        while (subKeys.hasNext()) {
            final PGPSignature subKey = subKeys.next();
            final PGPPublicKey masterKey = keyring.getKey(subKey.getKeyID());
            if (masterKey.hasRevocation()) {
                throw new UntrustedArtifactException(String.format("The certificate (key ID %s) used to sign artifact %s has been revoked with message:%n%s.",
                        artifactGav, keyID, getRevocationReason(masterKey)),
                        artifact, keyID);
            }
        }

        if (publicKey.hasRevocation()) {
            throw new UntrustedArtifactException(String.format("The certificate (key ID %s) used to sign artifact %s has been revoked with message:%n%s.",
                    artifactGav, keyID, getRevocationReason(publicKey)),
                    artifact, keyID);
        }

        if (log.isDebugEnabled()) {
            log.debugf("The ID of the selected key is %s\n", keyID);
        }
        try {
            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }

        verifyFile(artifact, pgpSignature);
    }

    private static String getRevocationReason(PGPPublicKey publicKey) {
        Iterator<PGPSignature> keySignatures = publicKey.getSignaturesOfType(PGPSignature.KEY_REVOCATION);
        String revocationDescription = null;
        while (keySignatures.hasNext()) {
            final PGPSignature sign = keySignatures.next();
            if (sign.getSignatureType() == PGPSignature.KEY_REVOCATION) {
                final PGPSignatureSubpacketVector hashedSubPackets = sign.getHashedSubPackets();
                revocationDescription = hashedSubPackets.getRevocationReason().getRevocationDescription();
            }
        }
        return revocationDescription;
    }

    static String describeImportedKeys(List<PGPPublicKey> pgpPublicKeys) {
        final StringBuilder sb = new StringBuilder();
        for (PGPPublicKey pgpPublicKey : pgpPublicKeys) {
            final Iterator<String> userIDs = pgpPublicKey.getUserIDs();
            while (userIDs.hasNext()) {
                sb.append(userIDs.next());
            }
            sb.append(": ").append(Hex.toHexString(pgpPublicKey.getFingerprint()));
        }
        return sb.toString();
    }

    private static void verifyFile(MavenArtifact mavenArtifact, PGPSignature pgpSignature) {
        // Read file to verify
        byte[] data = new byte[1024];
        InputStream inputStream = null;
        try {
            inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(mavenArtifact.getFile())));
            while (true) {
                int bytesRead = inputStream.read(data, 0, 1024);
                if (bytesRead == -1)
                    break;
                pgpSignature.update(data, 0, bytesRead);
            }
            inputStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Verify the signature
        try {
            if (!pgpSignature.verify()) {
                throw new SignatureException(String.format("The signature for artifact %s:%s:%s is invalid. The artifact might be corrupted or tampered with.",
                        mavenArtifact.getGroupId(), mavenArtifact.getArtifactId(), mavenArtifact.getVersion()));
            }
        } catch (PGPException e) {
            throw new SignatureException("Unable to verify the file signature", e);
        }
    }

    private static PGPSignature readSignatureFile(File signatureFile) {
        PGPSignature pgpSignature = null;
        try {

            try (InputStream decoderStream = PGPUtil.getDecoderStream(new FileInputStream(signatureFile))) {
                PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
                Object o = pgpObjectFactory.nextObject();
                if (o instanceof PGPSignatureList) {
                    PGPSignatureList signatureList = (PGPSignatureList) o;
                    if (signatureList.isEmpty()) {
                        throw new RuntimeException("signatureList must not be empty");
                    }
                    pgpSignature = signatureList.get(0);
                } else if (o instanceof PGPSignature) {
                    pgpSignature = (PGPSignature) o;
                } else {
                    throw new SignatureException("Could not find signature in provided signature file");
                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return pgpSignature;
    }

    private static List<PGPPublicKey> downloadPublicKey(String signatureUrl) {
        try {
            final URI uri = URI.create(signatureUrl);
            final InputStream inputStream;
            if (uri.getScheme().equals("classpath")) {
                final String keyPath = uri.getSchemeSpecificPart();
                inputStream = MavenSignatureValidator.class.getClassLoader().getResourceAsStream(keyPath);
            } else {
                final URLConnection urlConnection = uri.toURL().openConnection();
                urlConnection.connect();
                inputStream = urlConnection.getInputStream();
            }
            try (InputStream decoderStream = new ArmoredInputStream(inputStream)) {
                final PGPPublicKeyRing pgpPublicKeys = new PGPPublicKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
                final ArrayList<PGPPublicKey> res = new ArrayList<>();
                final Iterator<PGPPublicKey> publicKeys = pgpPublicKeys.getPublicKeys();
                while (publicKeys.hasNext()) {
                    res.add(publicKeys.next());
                }
                return res;
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
