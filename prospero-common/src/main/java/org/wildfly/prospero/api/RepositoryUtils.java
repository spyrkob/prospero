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

import org.eclipse.aether.repository.RemoteRepository;
import org.wildfly.channel.Repository;

import static org.wildfly.prospero.api.ProvisioningDefinition.DEFAULT_REPOSITORY_POLICY;

public class RepositoryUtils {
    public static Repository toChannelRepository(RemoteRepository r) {
        return new Repository(r.getId(), r.getUrl());
    }

    public static RemoteRepository toRemoteRepository(String id, String url) {
        return new RemoteRepository.Builder(id, "default", url)
                .setPolicy(DEFAULT_REPOSITORY_POLICY)
                .build();
    }
}
