package org.wildfly.channel;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.gpg.keybox.jcajce.JcaBlobVerifierBuilder;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRingCollection;
import org.wildfly.prospero.utils.SignatureUtils;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeyringTest {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void creatingKeyringWithoutKeyDoesntCreateFile() throws Exception {
        final Path file = temp.newFolder("keyring-test-folder").toPath();

        new Keyring(file.resolve("store.gpg"));

        assertThat(file.resolve("store.gpg"))
                .doesNotExist();
    }

    @Test
    public void addKeyToKeyring() throws Exception {
        final Path file = temp.newFolder("keyring-test-folder").toPath();

        final Keyring keyring = new Keyring(file.resolve("store.gpg"));

        final File keyFile = temp.newFile("key.gpg");
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        SignatureUtils.exportPublicKeys(generatedKey, keyFile);


        keyring.importArmoredKey(keyFile);

        final Iterator<PGPPublicKey> publicKeys = PGPainless.readKeyRing().keyRing(new FileInputStream(file.resolve("store.gpg").toFile())).getPublicKeys();
        assertTrue("New store should contain a key",
                publicKeys.hasNext());
        assertEquals(Hex.toHexString(generatedKey.getPublicKey().getFingerprint()), Hex.toHexString(publicKeys.next().getFingerprint()));
    }

    @Test
    public void addKeyToExistingKeyring() throws Exception {
        final Path file = temp.newFolder("keyring-test-folder").toPath();

        final Keyring keyring = new Keyring(file.resolve("store.gpg"));
        // add initial key
        final File keyFile = temp.newFile("key.gpg");
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        SignatureUtils.exportPublicKeys(generatedKey, keyFile);
        keyring.importArmoredKey(keyFile);

        // add new key
        final Keyring keyringTwo = new Keyring(file.resolve("store.gpg"));
        final File keyFileTwo = temp.newFile("key-two.gpg");
        final PGPSecretKeyRing generatedKeyTwo = SignatureUtils.generateSecretKey("Test 2", "test");
        SignatureUtils.exportPublicKeys(generatedKeyTwo, keyFileTwo);
        keyringTwo.importArmoredKey(keyFileTwo);


        final PGPPublicKeyRingCollection pgpPublicKeyRings = PGPainless.readKeyRing().publicKeyRingCollection(new FileInputStream(file.resolve("store.gpg").toFile()));
        assertTrue("New store should contain a key",
                pgpPublicKeyRings.getKeyRings().hasNext());

        final ArrayList<PGPPublicKey> pgpPublicKeys = new ArrayList<>();
        pgpPublicKeyRings.getKeyRings().forEachRemaining(kr->kr.getPublicKeys().forEachRemaining(pgpPublicKeys::add));
//        final Iterator<PGPPublicKey> publicKeys = (Iterator<PGPPublicKey>) pgpPublicKeyRings;();
//        publicKeys.forEachRemaining(pgpPublicKeys::add);
        assertThat(pgpPublicKeys)
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .contains(
                        Hex.toHexString(generatedKey.getPublicKey().getFingerprint()),
                        Hex.toHexString(generatedKeyTwo.getPublicKey().getFingerprint()));
    }

    @Test
    @Ignore
    public void createTestKeystore() throws Exception {
        final File keyFile = new File("/Users/spyrkob/workspaces/set/prospero/tmp/sig_validate/verifier/RH.gpg");
        final Keyring keyring = new Keyring(Path.of("/Users/spyrkob/workspaces/set/prospero/tmp/verify-sign/test-keys/keyring.gpg"));

        keyring.importArmoredKey(keyFile);
    }

    @Test
    public void checkRevocations() throws Exception {
        final Path keyPath = Path.of("/Users/spyrkob/workspaces/set/prospero/tmp/sig_validate/verifier/mount/exported.gpg");
//        final Path keyPath = Path.of("/Users/spyrkob/workspaces/set/prospero/tmp/sig_validate/verifier/mount/keyring.gpg");
//        PGPKeyRingCollection
//        final KeyBox keyBox = new KeyBox(new FileInputStream(keyPath.toFile()), new JcaKeyFingerprintCalculator(), new JcaBlobVerifierBuilder().build());
//        System.out.println(keyBox.getKeyBlobs().get(0).getNumberOfSignatures());
        PGPKeyRingCollection publicKeyRingCollection = new PGPKeyRingCollection(new FileInputStream(keyPath.toFile()), false);
        final Iterator<PGPPublicKeyRing> keyRings = publicKeyRingCollection.getPgpPublicKeyRingCollection().getKeyRings();
        int i = 0;
        while (keyRings.hasNext()) {
            System.out.println("keyring: " + i++);
            final PGPPublicKeyRing ring = keyRings.next();
            final Iterator<PGPPublicKey> publicKeys = ring.getPublicKeys();
            while (publicKeys.hasNext()) {
                final PGPPublicKey key = publicKeys.next();
                System.out.println(key.getKeyID() + " " + key.hasRevocation());
                if (key.hasRevocation()) {
                    final Iterator<PGPUserAttributeSubpacketVector> userAttributes = key.getUserAttributes();
                    while (userAttributes.hasNext()) {
                        System.out.println(userAttributes.next());
                    }
                    final PublicKeyPacket publicKeyPacket = key.getPublicKeyPacket();
                    System.out.println(publicKeyPacket);
                    final Iterator<PGPSignature> keySignatures = key.getKeySignatures();
                    while (keySignatures.hasNext()) {
                        System.out.println("signature");
                        final PGPSignature sign = keySignatures.next();
                        if (sign.getSignatureType() == PGPSignature.KEY_REVOCATION) {
                            System.out.println(sign);
                        }
                    }
                }
            }
        }
    }

}