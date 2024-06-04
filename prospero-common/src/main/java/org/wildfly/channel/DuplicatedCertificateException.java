package org.wildfly.channel;

import org.wildfly.prospero.api.exceptions.OperationException;

public class DuplicatedCertificateException extends OperationException {

    private final long keyID;

    public DuplicatedCertificateException(String msg, long keyID) {
        super(msg);
        this.keyID = keyID;
    }

    public String getKeyID() {
        return String.format("%Xd", keyID);
    }
}
