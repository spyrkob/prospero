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

package org.wildfly.prospero.api;

import java.io.IOException;
import java.nio.file.Files;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.wildfly.channel.Channel;
import org.wildfly.channel.ChannelMapper;
import org.wildfly.channel.ChannelManifestCoordinate;
import org.wildfly.channel.Repository;
import org.wildfly.prospero.Messages;
import org.wildfly.prospero.api.exceptions.ArtifactResolutionException;
import org.wildfly.prospero.api.exceptions.NoChannelException;
import org.wildfly.prospero.model.ChannelRef;
import org.wildfly.prospero.model.KnownFeaturePack;
import org.wildfly.prospero.model.ProsperoConfig;

public class ProvisioningDefinition {

    private static final String REPO_TYPE = "default";
    public static final RepositoryPolicy DEFAULT_REPOSITORY_POLICY = new RepositoryPolicy(true, RepositoryPolicy.UPDATE_POLICY_ALWAYS, RepositoryPolicy.CHECKSUM_POLICY_FAIL);

    private final String fpl;
    private final List<Channel> channels = new ArrayList<>();
    private final Set<String> includedPackages = new HashSet<>();
    private final List<RemoteRepository> repositories = new ArrayList<>();
    private final Path definition;

    private ProvisioningDefinition(Builder builder) throws ArtifactResolutionException, NoChannelException {
        final Optional<String> fpl = Optional.ofNullable(builder.fpl);
        final Optional<Path> definition = Optional.ofNullable(builder.definitionFile);
        final List<String> overrideRemoteRepos = builder.remoteRepositories;
        final Optional<Path> provisionConfigFile = Optional.ofNullable(builder.provisionConfigFile);
        final Optional<ChannelRef> channel = Optional.ofNullable(builder.channel);
        final Optional<Set<String>> includedPackages = Optional.ofNullable(builder.includedPackages);

        this.includedPackages.addAll(includedPackages.orElse(Collections.emptySet()));

        try {
            if (fpl.isPresent() && KnownFeaturePacks.isWellKnownName(fpl.get())) {
                KnownFeaturePack featurePackInfo = KnownFeaturePacks.getByName(fpl.get());
                this.fpl = featurePackInfo.getLocation();
                this.definition = null;
                this.includedPackages.addAll(featurePackInfo.getPackages());
                this.repositories.addAll(featurePackInfo.getRemoteRepositories());
                setUpBuildEnv(overrideRemoteRepos, provisionConfigFile, channel, featurePackInfo.getChannelGavs());
            } else if (provisionConfigFile.isPresent()) {
                this.fpl = fpl.orElse(null);
                this.definition = definition.orElse(null);
                this.channels.addAll(ChannelMapper.fromString(Files.readString(provisionConfigFile.get())));
                this.repositories.clear();
                this.repositories.addAll(Collections.emptyList());
            } else {
                // TODO: provisionConfigFile needn't be mandatory, we could still collect all required data from the
                //  other options (channel, channelRepo - perhaps both should be made collections)
                throw new IllegalArgumentException(
                        String.format("Incomplete configuration: either a predefined fpl (%s) or a provisionConfigFile must be given.",
                                String.join(", ", KnownFeaturePacks.getNames())));
            }
        } catch (IOException e) {
            throw new ArtifactResolutionException("Unable to resolve channel definition: " + e.getMessage(), e);
        }

        if (channels.isEmpty()) {
            if (fpl.isPresent() && KnownFeaturePacks.isWellKnownName(fpl.get())) {
                throw Messages.MESSAGES.fplDefinitionDoesntContainChannel(fpl.get());
            } else {
                throw Messages.MESSAGES.noChannelReference();
            }
        }
    }

    private void setUpBuildEnv(List<String> overrideRemoteRepos, Optional<Path> provisionConfigFile,
                               Optional<ChannelRef> channelRef, List<String> channelGAs) throws IOException {
        if (!provisionConfigFile.isPresent() && !channelRef.isPresent()) {
            if (!overrideRemoteRepos.isEmpty()) {
                this.repositories.clear();
                int i = 0;
                for (String url : overrideRemoteRepos) {
                    String channelRepoId = "channel-" + (i++);
                    this.repositories.add(new RemoteRepository.Builder(channelRepoId, REPO_TYPE, url)
                                    .setPolicy(DEFAULT_REPOSITORY_POLICY)
                                    .build());
                }
            }
            if (channelGAs != null) {
                channelGAs.forEach(c -> {
                    try {
                        this.channels.add(new Channel("", "", null, null,
                                this.repositories.stream().map(r->new Repository(r.getId(), r.getUrl())).collect(Collectors.toList()),
                                ChannelManifestCoordinate.create(null, c)));
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                });
            }
        } else if (channelRef.isPresent()) {
            this.channels.add(new Channel("", "", null, null,
                    this.repositories.stream().map(r->new Repository(r.getId(), r.getUrl())).collect(Collectors.toList()),
                    channelRef.get().toManifest()));
        } else {
            this.channels.addAll(ChannelMapper.fromString(Files.readString(provisionConfigFile.get())));
            this.repositories.clear();
            this.repositories.addAll(Collections.emptyList());
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public Set<String> getIncludedPackages() {
        return includedPackages;
    }

    public String getFpl() {
        return fpl;
    }

    public List<ChannelRef> getChannelRefs() {
        return null;
    }

    public List<Channel> getChannels() {
        return channels;
    }

    public List<RemoteRepository> getRepositories() {
        return repositories;
    }

    public Path getDefinition() {
        return definition;
    }

    public ProsperoConfig getProsperoConfig() {
        return new ProsperoConfig(channels);
    }

    public static class Builder {
        private String fpl;
        private Path provisionConfigFile;
        private Path definitionFile;
        private List<String> remoteRepositories = Collections.emptyList();
        private Set<String> includedPackages;
        private ChannelRef channel;

        public ProvisioningDefinition build() throws ArtifactResolutionException, NoChannelException {
            return new ProvisioningDefinition(this);
        }

        public Builder setFpl(String fpl) {

            this.fpl = fpl;
            return this;
        }

        public Builder setProvisionConfig(Path provisionConfigFile) {
            this.provisionConfigFile = provisionConfigFile;
            return this;
        }

        public Builder setRemoteRepositories(List<String> remoteRepositories) {
            this.remoteRepositories = remoteRepositories;
            return this;
        }

        public Builder setIncludedPackages(Set<String> includedPackages) {
            this.includedPackages = includedPackages;
            return this;
        }

        public Builder setChannel(String channel) {
            if (channel != null) {
                this.channel = ChannelRef.fromString(channel);
            }
            return this;
        }

        public Builder setDefinitionFile(Path provisionDefinition) {
            this.definitionFile = provisionDefinition;
            return this;
        }
    }
}
