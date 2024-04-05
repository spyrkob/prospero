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
import java.net.URL;
import java.net.URLConnection;
import java.util.Iterator;
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
    public void validateSignature(File artifact, File signature, String gpgUrl) {
        if (log.isDebugEnabled()) {
            log.debugf("Verifying %s with signature %s", artifact, signature);
        }

        PGPSignature pgpSignature = readSignatureFile(signature);


        PGPPublicKey publicKey = keyring.getKey(pgpSignature);

        if (publicKey == null) {
            final PGPPublicKey pgpPublicKey = downloadPublicKey(gpgUrl);
            final Iterator<String> userIDs = pgpPublicKey.getUserIDs();
            final StringBuilder sb = new StringBuilder();
            while (userIDs.hasNext()) {
                sb.append(userIDs.next());
            }
            // TODO: verify that the key matches required signature
            if (acceptor.apply(sb + ": " +  Hex.toHexString(pgpPublicKey.getFingerprint()))) {
                try {
                    keyring.importArmoredKey(pgpPublicKey);
                    publicKey = keyring.getKey(pgpSignature);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            if (publicKey == null) {
                throw new SignatureValidator.SignatureException("No matching public key found");
            }
        }

        if (log.isDebugEnabled()) {
            log.debugf("The ID of the selected key is %X\n", publicKey.getKeyID());
        }
        try {
            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }

        verifyFile(artifact, pgpSignature);
    }

    private static void verifyFile(File mavenArtifact, PGPSignature pgpSignature) {
        // Read file to verify
        byte[] data = new byte[1024];
        InputStream inputStream = null;
        try {
            inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(mavenArtifact)));
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
                throw new SignatureException("The file and its signature don't match");
            }
        } catch (PGPException e) {
            throw new SignatureException("Unable to verify the file signature", e);
        }
    }

    private static String getSignatureFileUrl(MavenArtifact mavenArtifact, Repository repository) {
        final String classifier = mavenArtifact.getClassifier()==null || mavenArtifact.getClassifier().isEmpty() ?"" : "-" + mavenArtifact.getClassifier();
        final String signatureUrl = repository.getUrl() + "/" + mavenArtifact.getGroupId().replaceAll("\\.", "/") +
                "/" + mavenArtifact.getArtifactId() +
                "/" + mavenArtifact.getVersion() + "/" + mavenArtifact.getArtifactId() + "-" + mavenArtifact.getVersion() + classifier + "." +
                mavenArtifact.getExtension() + ".asc";
        return signatureUrl;
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

    private static PGPPublicKey downloadPublicKey(String signatureUrl) {
        try {
            final URLConnection urlConnection = new URL(signatureUrl).openConnection();
            urlConnection.connect();
            try (InputStream decoderStream = new ArmoredInputStream(urlConnection.getInputStream())) {
                final PGPPublicKeyRing pgpPublicKeys = new PGPPublicKeyRing(decoderStream, new JcaKeyFingerprintCalculator());
                return pgpPublicKeys.getPublicKey();
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
