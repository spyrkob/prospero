/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.prospero.galleon;

import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.jboss.galleon.ProvisioningException;
import org.jboss.galleon.ProvisioningManager;
import org.jboss.galleon.layout.ProvisioningLayoutFactory;
import org.wildfly.channel.Channel;
import org.wildfly.channel.ChannelSession;
import org.wildfly.channel.maven.VersionResolverFactory;
import org.wildfly.channel.spi.MavenVersionsResolver;
import org.wildfly.prospero.actions.Console;
import org.wildfly.prospero.api.exceptions.OperationException;
import org.wildfly.prospero.model.ChannelRef;
import org.wildfly.prospero.model.ProsperoConfig;
import org.wildfly.prospero.wfchannel.ChannelRefMapper;
import org.wildfly.prospero.wfchannel.MavenSessionManager;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

public class GalleonEnvironment {

    private final ProvisioningManager provisioningManager;
    private final ChannelMavenArtifactRepositoryManager repositoryManager;
    private final ChannelSession channelSession;
    private final List<ChannelRef> channelRefs;

    private GalleonEnvironment(Builder builder) throws ProvisioningException, OperationException {
        Optional<Console> console = Optional.ofNullable(builder.console);
        Optional<Channel> restoreManifest = Optional.ofNullable(builder.manifest);
        channelRefs = builder.prosperoConfig.getChannels();

        final RepositorySystem system = builder.mavenSessionManager.newRepositorySystem();
        final DefaultRepositorySystemSession session = builder.mavenSessionManager.newRepositorySystemSession(system);
        final VersionResolverFactory wrappedFactory = new VersionResolverFactory(system, session, builder.prosperoConfig.getRemoteRepositories());
        final List<Channel> channels = new ChannelRefMapper(wrappedFactory).mapToChannel(builder.prosperoConfig.getChannels());
        final MavenVersionsResolver.Factory factory = new CachedVersionResolverFactory(wrappedFactory, builder.installDir, system, session);
        channelSession = new ChannelSession(channels, factory);
        if (restoreManifest.isEmpty()) {
            repositoryManager = new ChannelMavenArtifactRepositoryManager(channelSession);
        } else {
            repositoryManager = new ChannelMavenArtifactRepositoryManager(channelSession, restoreManifest.get());
        }
        provisioningManager = GalleonUtils.getProvisioningManager(builder.installDir, repositoryManager, builder.fpTracker);

        final ProvisioningLayoutFactory layoutFactory = provisioningManager.getLayoutFactory();
        if (console.isPresent()) {
            layoutFactory.setProgressCallback("LAYOUT_BUILD", console.get().getProgressCallback("LAYOUT_BUILD"));
            layoutFactory.setProgressCallback("PACKAGES", console.get().getProgressCallback("PACKAGES"));
            layoutFactory.setProgressCallback("CONFIGS", console.get().getProgressCallback("CONFIGS"));
            layoutFactory.setProgressCallback("JBMODULES", console.get().getProgressCallback("JBMODULES"));
        }
    }

    public ProvisioningManager getProvisioningManager() {
        return provisioningManager;
    }

    public ChannelMavenArtifactRepositoryManager getRepositoryManager() {
        return repositoryManager;
    }

    public ChannelSession getChannelSession() {
        return channelSession;
    }

    public List<ChannelRef> getChannelRefs() {
        return channelRefs;
    }

    public static Builder builder(Path installDir, ProsperoConfig prosperoConfig, MavenSessionManager mavenSessionManager) {
        Objects.requireNonNull(installDir);
        Objects.requireNonNull(prosperoConfig);
        Objects.requireNonNull(mavenSessionManager);

        return new Builder(installDir, prosperoConfig, mavenSessionManager);
    }

    public static class Builder {

        private final Path installDir;
        private final ProsperoConfig prosperoConfig;
        private final MavenSessionManager mavenSessionManager;
        public Consumer<String> fpTracker;
        private Console console;
        private Channel manifest;

        private Builder(Path installDir, ProsperoConfig prosperoConfig, MavenSessionManager mavenSessionManager) {
            this.installDir = installDir;
            this.prosperoConfig = prosperoConfig;
            this.mavenSessionManager = mavenSessionManager;
        }

        public Builder setConsole(Console console) {
            this.console = console;
            return this;
        }

        public Builder setRestoreManifest(Channel manifest) {
            this.manifest = manifest;
            return this;
        }

        public Builder setResolvedFpTracker(Consumer<String> fpTracker) {
            this.fpTracker = fpTracker;
            return this;
        }

        public GalleonEnvironment build() throws ProvisioningException, OperationException {
            return new GalleonEnvironment(this);
        }
    }
}
