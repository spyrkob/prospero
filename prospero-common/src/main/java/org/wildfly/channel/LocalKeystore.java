package org.wildfly.channel;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.encoders.Hex;
import org.wildfly.channel.gpg.GpgKeystore;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;

public class LocalKeystore implements GpgKeystore {

    private final Keyring keyring;
    private final Function<String, Boolean> acceptor;

    public LocalKeystore(Function<String, Boolean> acceptor, Keyring keyring) {
        this.keyring = keyring;
        this.acceptor = acceptor;
    }

    @Override
    public PGPPublicKey get(String keyIdHex) {
        final BigInteger bi = new BigInteger(keyIdHex, 16);

        final long keyID = bi.longValue();
        return keyring.getKey(keyID);
    }

    @Override
    public boolean add(List<PGPPublicKey> publicKey) {
        final String description = describeImportedKeys(publicKey);
        if (acceptor.apply(description)) {
            try {
                keyring.importCertificate(publicKey);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return true;
        } else {
            return false;
        }
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
}
