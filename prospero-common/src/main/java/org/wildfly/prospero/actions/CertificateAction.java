package org.wildfly.prospero.actions;

import org.bouncycastle.openpgp.PGPException;
import org.wildfly.channel.Keyring;
import org.wildfly.prospero.api.certificate.RevokeCertificate;
import org.wildfly.prospero.api.certificate.TrustCertificate;
import org.wildfly.prospero.api.certificate.TrustedCertificateStore;
import org.wildfly.prospero.metadata.ProsperoMetadataUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;

public class CertificateAction implements TrustedCertificateStore {

    private final Path installationDir;
    private final Keyring keyring;

    public CertificateAction(Path installationDir) throws PGPException, IOException {
        this.installationDir = installationDir;
        // TODO: wrap PGPException
        keyring = new Keyring(installationDir.resolve(ProsperoMetadataUtils.METADATA_DIR).resolve("keyring.gpg"));
    }

    public void importCertificate(TrustCertificate trustCertificate) {
        try {
            keyring.importCertificate(trustCertificate.getContentStream());
        } catch (IOException e) {
            // TODO: wrap the exceptions
            throw new RuntimeException(e);
        }
    }

    public void removeCertificate(String certificateId) {
        // TODO: implement me
    }

    public void revokeCertificate(RevokeCertificate revokeCertificate) {
        try {
            keyring.revokeCertificate(revokeCertificate.getContentStream());
        } catch (IOException | PGPException e) {
            throw new RuntimeException(e);
        }
    }

    public Collection<Keyring.KeyInfo> getCertificates() {
        return keyring.listKeys();
    }

}
