package org.wildfly.prospero.api;

public class ChannelVersions {

    private final String mavenCoord;

    public enum Status {FULL, PARTIAL, NONE, UNKNOWN}
    private String name;
    private String version;
    private Status status;

    public ChannelVersions(String name, String mavenCoord, String version, Status status) {
        this.name = name;
        this.version = version;
        this.status = status;
        this.mavenCoord = mavenCoord;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public Status getStatus() {
        return status;
    }

    public String getMavenCoord() {
        return mavenCoord;
    }

    @Override
    public String toString() {
        return "ChannelVersions{" +
                "name='" + name + '\'' +
                ", version='" + version + '\'' +
                ", status=" + status +
                '}';
    }
}
