package org.wildfly.prospero.api.certificate;

import org.wildfly.channel.Keyring;
import org.wildfly.prospero.api.exceptions.OperationException;

import java.util.Collection;

public interface TrustedCertificateStore {

    void importCertificate(TrustCertificate trustCertificate) throws OperationException;

    void removeCertificate(String certificateId);
    void revokeCertificate(RevokeCertificate revokeCertificate);

    Collection<Keyring.KeyInfo> getCertificates();
}
