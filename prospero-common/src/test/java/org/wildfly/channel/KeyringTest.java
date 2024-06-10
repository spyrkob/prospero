package org.wildfly.channel;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.pgpainless.PGPainless;
import org.wildfly.prospero.api.exceptions.OperationException;
import org.wildfly.prospero.utils.SignatureUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

public class KeyringTest {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();
    private Keyring keyring;
    private Path file;

    @Before
    public void setUp() throws Exception {
        file = temp.newFolder("keyring-test-folder").toPath();
        keyring = new Keyring(file.resolve("store.gpg"));
    }

    // start of initialization tests

    @Test
    public void creatingKeyringWithoutKeyDoesntCreateFile() throws Exception {
        assertThat(file.resolve("store.gpg"))
                .doesNotExist();
    }

    // end of initialization tests

    /*
     * start of add key tests
     */
    @Test
    public void addKeyToKeyring() throws Exception {
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        importKeyRing(generatedKey);

        assertThat(readPublicKeys())
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .containsExactlyElementsOf(getFingerPrints(generatedKey));
    }

    @Test
    public void addKeyToExistingKeyring() throws Exception {
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        final PGPSecretKeyRing generatedKeyTwo = SignatureUtils.generateSecretKey("Test 2", "test");

        // add initial key
        importKeyRing(generatedKey);

        // re-create Keyring to check that no caching happens
        this.keyring = new Keyring(file.resolve("store.gpg"));
        // and add another key
        importKeyRing(generatedKeyTwo);

        assertThat(readPublicKeys())
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .containsExactlyInAnyOrderElementsOf(getFingerPrints(generatedKey, generatedKeyTwo));
    }

    @Test
    public void addExistingKeyAgain_ThrowsException() throws Exception {
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");

        // add initial key
        importKeyRing(generatedKey);

        // try to add another key
        assertThatThrownBy(()-> importKeyRing(generatedKey))
                .isInstanceOf(DuplicatedCertificateException.class);

        assertThat(readPublicKeys())
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .containsExactlyInAnyOrderElementsOf(getFingerPrints(generatedKey));
    }

    /*
     * end of add key tests
     */

    /*
     * start of remove key tests
     */
    @Test
    public void removeKeyFromKeyring() throws Exception {
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        importKeyRing(generatedKey);

        keyring.removeKey(Long.toHexString(generatedKey.getPublicKey().getKeyID()));

        assertNull("Expected the keystore file to not be present",
                PGPainless.readKeyRing().keyRing(new FileInputStream(file.resolve("store.gpg").toFile())));
    }

    @Test
    public void removeKeyFromKeyringWithTwoKeys() throws Exception {
        final PGPSecretKeyRing generatedKey1 = SignatureUtils.generateSecretKey("Test", "test");
        importKeyRing(generatedKey1);

        // and import another key
        final PGPSecretKeyRing generatedKey2 = SignatureUtils.generateSecretKey("Test", "test");
        importKeyRing(generatedKey2);

        keyring.removeKey(Long.toHexString(generatedKey1.getPublicKey().getKeyID()));

        assertThat(readPublicKeys())
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .containsExactlyElementsOf(getFingerPrints(generatedKey2));
    }

    @Test
    public void removeKeyFromEmptyStore_ReturnsFalse() throws Exception {
        final PGPSecretKeyRing generatedKey1 = SignatureUtils.generateSecretKey("Test", "test");

        assertFalse("Removing non-existing cert should return false",
                keyring.removeKey(Long.toHexString(generatedKey1.getPublicKey().getKeyID())));

        assertThat(readPublicKeys())
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .isEmpty();
    }

    @Test
    public void removeNonExistingKey_ReturnsFalse() throws Exception {
        final PGPSecretKeyRing generatedKey1 = SignatureUtils.generateSecretKey("Test", "test");

        importKeyRing(generatedKey1);

        // and import another key
        final PGPSecretKeyRing generatedKey2 = SignatureUtils.generateSecretKey("Test", "test");

        assertFalse("Removing non-existing cert should return false",
                keyring.removeKey(Long.toHexString(generatedKey2.getPublicKey().getKeyID())));

        assertThat(readPublicKeys())
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .containsExactlyInAnyOrderElementsOf(getFingerPrints(generatedKey1));
    }

    // TODO: remove subkey throws exception

    /*
     * end of remove key tests
     */

    /*
     * start of import certificate tests
     */
    @Test
    public void importRevocations() throws Exception {
        final File revokeFile = temp.newFile("revoke.gpg");
        final PGPSecretKeyRing generatedKey = SignatureUtils.generateSecretKey("Test", "test");
        SignatureUtils.exportRevocationKeys(generatedKey, revokeFile, "test");

        importKeyRing(generatedKey);
        keyring.revokeCertificate(new FileInputStream(revokeFile));

        final List<PGPPublicKey> publicKeys = readPublicKeys();
        assertThat(publicKeys)
                .map(PGPPublicKey::getFingerprint)
                .map(Hex::toHexString)
                .containsExactlyInAnyOrderElementsOf(getFingerPrints(generatedKey));

        assertThat(publicKeys).allMatch(KeyringTest::isRevoked);
    }

    // TODO: import revocation on non-existing certificate throws exception

    /*
     * end of import certificate tests
     */

    /*
     * start of get certificate tests
     */

    // TODO: get existing certificate
    // TODO: return null when trying to get non existing certificate
    // TODO: get subkey returns subkey

    /*
     * end of get certificate tests
     */

    /*
     * start of list certificate tests
     */

    // TODO: get one key
    // TODO: get multiple keys
    // TODO: empty list if there are no keys

    /*
     * end of list certificate tests
     */

    /*
     * start of read certificate tests
     */

    // TODO: read a certificate (key)
    // TODO: invalid input throws exception

    /*
     * end of read certificate tests
     */

    private List<PGPPublicKey> readPublicKeys() throws IOException {
        final List<PGPPublicKey> keyList = new ArrayList<>();
        if (!Files.exists(file.resolve("store.gpg"))) {
            return Collections.emptyList();
        }
        final PGPPublicKeyRingCollection pgpKeyRing = PGPainless.readKeyRing().publicKeyRingCollection(new FileInputStream(file.resolve("store.gpg").toFile()));
        final Iterator<PGPPublicKeyRing> keyRings = pgpKeyRing.getKeyRings();
        while (keyRings.hasNext()) {
            final PGPPublicKeyRing keyRing = keyRings.next();
            final Iterator<PGPPublicKey> publicKeys = keyRing.getPublicKeys();
            while (publicKeys.hasNext()) {
                final PGPPublicKey key = publicKeys.next();
                keyList.add(key);
            }
        }
        return keyList;
    }

    private static List<String> getFingerPrints(PGPSecretKeyRing... generatedKeys) {
        final List<String> fingerprintList = new ArrayList<>();
        for (PGPSecretKeyRing generatedKey : generatedKeys) {
            final Iterator<PGPPublicKey> publicKeys = generatedKey.getPublicKeys();
            while (publicKeys.hasNext()) {
                final PGPPublicKey key = publicKeys.next();
                fingerprintList.add(Hex.toHexString(key.getFingerprint()));
            }
        }
        return fingerprintList;
    }

    private static boolean isRevoked(PGPPublicKey key) {
        // only check master keys not subkeys
        return !key.isMasterKey() || key.hasRevocation();

    }

    private void importKeyRing(PGPSecretKeyRing generatedKey) throws IOException, OperationException {
        final File keyFile = temp.newFile();
        SignatureUtils.exportPublicKeys(generatedKey, keyFile);
        keyring.importCertificate(new FileInputStream(keyFile));
    }
}