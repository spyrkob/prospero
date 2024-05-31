package org.wildfly.prospero.api.certificate;

import org.wildfly.channel.Keyring;

import java.util.Collection;

public interface TrustedCertificateStore {

    void importCertificate(TrustCertificate trustCertificate);

    void removeCertificate(String certificateId);
    void revokeCertificate(RevokeCertificate revokeCertificate);

    Collection<Keyring.KeyInfo> getCertificates();
}
