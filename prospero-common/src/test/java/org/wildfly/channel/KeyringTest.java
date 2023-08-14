package org.wildfly.channel;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.pgpainless.PGPainless;
import org.wildfly.prospero.utils.SignatureUtils;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
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
        SignatureUtils.exportPublicKeys(SignatureUtils.generateSecretKey("Test", "test"), keyFile);

        keyring.importKey(keyFile);

        assertTrue("New store should be empty",
                PGPainless.readKeyRing().keyRing(new FileInputStream(file.resolve("store.gpg").toFile())).getPublicKeys().hasNext());
    }

}