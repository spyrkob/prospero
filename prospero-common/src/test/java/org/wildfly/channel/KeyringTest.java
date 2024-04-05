package org.wildfly.channel;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.pgpainless.PGPainless;
import org.wildfly.prospero.utils.SignatureUtils;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.util.Iterator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class KeyringTest {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    @Test
    public void createEmptyKeyring() throws Exception {
        final Path file = temp.newFolder("keyring-test-folder").toPath();

        new Keyring(file.resolve("store.gpg"));

        assertThat(file.resolve("store.gpg"))
                .exists();
        assertNull("New store should be empty",
                PGPainless.readKeyRing().keyRing(new FileInputStream(file.resolve("store.gpg").toFile())));
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
    @Ignore
    public void createTestKeystore() throws Exception {
        final File keyFile = new File("/Users/spyrkob/workspaces/set/prospero/tmp/sig_validate/verifier/RH.gpg");
        final Keyring keyring = new Keyring(Path.of("/Users/spyrkob/workspaces/set/prospero/tmp/verify-sign/test-keys/keyring.gpg"));

        keyring.importArmoredKey(keyFile);
    }

}