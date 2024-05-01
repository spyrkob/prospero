package org.wildfly.prospero.actions;

import org.jboss.galleon.ProvisioningException;
import org.wildfly.channel.Channel;
import org.wildfly.channel.ChannelManifest;
import org.wildfly.channel.ChannelManifestMapper;
import org.wildfly.channel.ChannelSession;
import org.wildfly.channel.MavenArtifact;
import org.wildfly.channel.MavenCoordinate;
import org.wildfly.channel.Stream;
import org.wildfly.prospero.api.ChannelVersions;
import org.wildfly.prospero.api.InstallationMetadata;
import org.wildfly.prospero.api.MavenOptions;
import org.wildfly.prospero.api.exceptions.OperationException;
import org.wildfly.prospero.galleon.GalleonEnvironment;
import org.wildfly.prospero.metadata.ManifestVersionRecord;
import org.wildfly.prospero.wfchannel.MavenSessionManager;

import java.net.MalformedURLException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class ChannelStatusAction {


    private final InstallationMetadata installationMetadata;
    private final ChannelSession channelSession;

    public ChannelStatusAction(Path installation) throws OperationException, ProvisioningException {
        this.installationMetadata = InstallationMetadata.loadInstallation(installation);
        final List<Channel> channels = installationMetadata.getProsperoConfig().getChannels();
        final MavenSessionManager msm = new MavenSessionManager(MavenOptions.DEFAULT_OPTIONS);
        final GalleonEnvironment env = GalleonEnvironment.builder(installation, channels, msm, true).build();
        this.channelSession = env.getChannelSession();
    }

    public List<ChannelVersions> getChannelsStatus() throws MalformedURLException {
        final ChannelManifest installedManifest = this.installationMetadata.getManifest();

        final Optional<ManifestVersionRecord> manifestVersions = this.installationMetadata.getManifestVersions();
        if (manifestVersions.isEmpty()) {
            return Collections.emptyList();
        }

        final List<Channel> channels = this.installationMetadata.getProsperoConfig().getChannels();


        final List<ChannelVersions> channelVersions = new ArrayList<>();
        for (ManifestVersionRecord.MavenManifest mavenManifest : manifestVersions.get().getMavenManifests()) {
            Channel channel = mapToChannel(mavenManifest, channels);

            // resolve this manifest
            final MavenArtifact artifact = channelSession.resolveDirectMavenArtifact(mavenManifest.getGroupId(), mavenManifest.getArtifactId(), "yaml", "manifest", mavenManifest.getVersion());

            final ChannelManifest manifest = ChannelManifestMapper.from(artifact.getFile().toURI().toURL());

            ChannelVersions.Status status = ChannelVersions.Status.NONE;
            boolean found = false;
            for (Stream stream : manifest.getStreams()) {
                final Optional<Stream> installedArtifact = installedManifest.findStreamFor(stream.getGroupId(), stream.getArtifactId());
                if (installedArtifact.isEmpty()) {
                    continue;
                }

                if (!installedArtifact.get().getVersion().equals(stream.getVersion())) {
                    if (status != ChannelVersions.Status.NONE) {
                        status = ChannelVersions.Status.PARTIAL;
                    }
                    found = true;
                } else {
                    if (status != ChannelVersions.Status.PARTIAL) {
                        status = ChannelVersions.Status.FULL;
                    }
                }
            }
            if (status == ChannelVersions.Status.FULL && found) {
                status = ChannelVersions.Status.PARTIAL;
            }
            channelVersions.add(new ChannelVersions(channel==null?"":channel.getName(), mavenManifest.getGroupId() + ":" + mavenManifest.getArtifactId(), mavenManifest.getVersion(), status));
        }

        return channelVersions;
    }

    private Channel mapToChannel(ManifestVersionRecord.MavenManifest mavenManifest, List<Channel> channels) {
        for (Channel channel : channels) {
            if (channel.getManifestCoordinate() == null || channel.getManifestCoordinate().getMaven() == null) {
                return null;
            }

            final MavenCoordinate mavenCoord = channel.getManifestCoordinate().getMaven();
            if (mavenCoord.getGroupId().equals(mavenManifest.getGroupId()) && mavenCoord.getArtifactId().equals(mavenManifest.getArtifactId())) {
                return channel;
            }
        }
        return null;
    }
}
