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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.jboss.logging.Logger;
import org.wildfly.channel.spi.SignatureValidator;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Iterator;
import java.util.function.Function;

public class MavenSignatureValidator implements SignatureValidator {

    private final Logger log = Logger.getLogger(MavenSignatureValidator.class.getName());

//    private final PGPPublicKeyRingCollection publicKeyRingCollection;
    private Function<String, Boolean> acceptor;

    private Keyring keyring;


    public MavenSignatureValidator(File publicKeyFolder) throws IOException, PGPException {
        this(publicKeyFolder, (s)->true);
    }

    private static boolean loaded = false;
    public MavenSignatureValidator(File publicKeyFolder, Function<String, Boolean> acceptor) throws IOException, PGPException {
//        PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(Collections.emptyList());
//
//        final File[] children = publicKeyFolder.listFiles();
//        if (children == null) {
//            throw new RuntimeException("Unable to list certificates in " + publicKeyFolder);
//        }
//
//        for (File file : children) {
//            try (InputStream inputStream = PGPUtil.getDecoderStream(new FileInputStream(file))) {
//                final PGPPublicKeyRing keyRing = new PGPPublicKeyRing(inputStream, new JcaKeyFingerprintCalculator());
//                publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection, keyRing);
//            }
//        }
//        this.publicKeyRingCollection = publicKeyRingCollection;
        keyring = new Keyring(publicKeyFolder.toPath().resolve("keyring.gpg"));
        if (!loaded) {
            keyring.importKey(publicKeyFolder.toPath().resolve("test_pub.gpg").toFile());
            loaded = true;
        }
        this.acceptor = acceptor;
    }

    @Override
    public void validateSignature(MavenArtifact mavenArtifact, Repository repository) throws SignatureException {
        if (log.isDebugEnabled()) {
            log.debugf("Verifying %s from %s", mavenArtifact, repository);
        }

        final String signatureUrl = getSignatureFileUrl(mavenArtifact, repository);
        PGPSignature pgpSignature = downloadSignatureFile(signatureUrl);

//        final PGPPublicKeyRing pgpPublicKeyRing = publicKeyRingCollection.getKeyRings().next();
        final PGPPublicKeyRing pgpPublicKeyRing = keyring.getKeyRing();

        PGPPublicKey publicKey = getPublicKey(pgpSignature, pgpPublicKeyRing);

//        if (acceptor.apply(String.format("%X", pgpSignature.getKeyID()))) {
//            keyring.importKey();
//        }

        if (log.isDebugEnabled()) {
            log.debugf("The ID of the selected key is %X\n", publicKey.getKeyID());
        }
        try {
            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }

        verifyFile(mavenArtifact, pgpSignature);
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
        PGPPublicKey publicKey = pgpPublicKeyRing.getPublicKey(pgpSignature.getKeyID());

        // If signature is not matching the key used for signing we fail
        if (publicKey == null) {
            throw new SignatureException("No matching public key found");
        }
        return publicKey;
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

    private static PGPSignature downloadSignatureFile(String signatureUrl) {
        PGPSignature pgpSignature = null;
        try {
            final URLConnection urlConnection = new URL(signatureUrl).openConnection();
            urlConnection.connect();
            try (InputStream inputStream = urlConnection.getInputStream()) {
                final InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);
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
                decoderStream.close();
            }

        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return pgpSignature;
    }
}
