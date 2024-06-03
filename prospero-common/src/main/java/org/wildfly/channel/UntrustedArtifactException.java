package org.wildfly.channel;

import org.wildfly.channel.spi.SignatureValidator;

public class UntrustedArtifactException extends SignatureValidator.SignatureException {

    private final ArtifactCoordinate artifact;
    private final String keyID;

    public UntrustedArtifactException(String message, ArtifactCoordinate artifact, String keyID) {
        super(message);
        this.artifact = artifact;
        this.keyID = keyID;
    }

    public ArtifactCoordinate getArtifact() {
        return artifact;
    }

    public String getKeyID() {
        return keyID;
    }
}
