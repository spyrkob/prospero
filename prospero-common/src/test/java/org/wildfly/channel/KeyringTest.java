package org.wildfly.channel;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.pgpainless.PGPainless;
import org.wildfly.prospero.utils.SignatureUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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

        assertThat(pgpPublicKeys)
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .contains(
                        Hex.toHexString(generatedKey.getPublicKey().getFingerprint()),
                        Hex.toHexString(generatedKeyTwo.getPublicKey().getFingerprint()));
    }

    @Test
    public void importRevocations() throws Exception {
        final Path file = temp.newFolder("keyring-test-folder").toPath();

        final Keyring keyring = new Keyring(file.resolve("store.gpg"));

        final File keyFile = temp.newFile("key.gpg");
        final File revokeFile = temp.newFile("revoke.gpg");
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        SignatureUtils.exportPublicKeys(generatedKey, keyFile);

        keyring.importArmoredKey(keyFile);

        final Long revokedKeyId = SignatureUtils.exportRevocationKeys(generatedKey, revokeFile, "test");

        keyring.importCertificate(revokeFile);

        final PGPPublicKeyRingCollection pgpPublicKeyRings = PGPainless.readKeyRing().publicKeyRingCollection(new FileInputStream(file.resolve("store.gpg").toFile()));
        final ArrayList<PGPPublicKey> pgpPublicKeys = new ArrayList<>();
        pgpPublicKeyRings.getKeyRings().forEachRemaining(kr->{if (pgpPublicKeyRings.contains(revokedKeyId)) { pgpPublicKeys.add(kr.getPublicKey(revokedKeyId)); }});
        assertThat(pgpPublicKeys)
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .contains(
                        Hex.toHexString(generatedKey.getPublicKey().getFingerprint()));

        assertThat(pgpPublicKeys).allMatch(PGPPublicKey::hasRevocation);
    }

    @Test
    public void testMe() throws Exception {
        final Path file = temp.newFolder("keyring-test-folder").toPath();

        final Keyring keyring = new Keyring(file.resolve("store.gpg"));
        final File cert = new File("/Users/spyrkob/workspaces/set/prospero/tmp/sig_validate/verifier/RH.gpg");
        try {
            System.out.println(keyring.readKey(cert));
        } catch (IOException e) {
            keyring.importArmoredKey(cert);
        }
    }
}