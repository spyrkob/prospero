package org.wildfly.prospero.api.certificate;

import java.util.List;

public interface TrustedCertificateStore {

    void importCertificate(TrustCertificate trustCertificate);

    void removeCertificate(String certificateId);
    void revokeCertificate(RevokeCertificate revokeCertificate);

    List<TrustCertificate> getCertificates();
}
