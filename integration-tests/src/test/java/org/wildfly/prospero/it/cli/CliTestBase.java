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

package org.wildfly.prospero.it.cli;

import org.wildfly.channel.Stream;
import org.wildfly.prospero.cli.ReturnCodes;
import org.wildfly.prospero.cli.commands.CliConstants;
import org.wildfly.prospero.it.ExecutionUtils;
import org.wildfly.prospero.it.commonapi.WfCoreTestBase;
import org.wildfly.prospero.model.ManifestYamlSupport;
import org.wildfly.prospero.test.MetadataTestUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public abstract class CliTestBase extends WfCoreTestBase {

    protected void install(Path provisionConfig, Path targetDir) throws Exception {
        ExecutionUtils.prosperoExecution(CliConstants.Commands.INSTALL,
                        CliConstants.CHANNELS, provisionConfig.toString(),
                        CliConstants.FPL, "org.wildfly.core:wildfly-core-galleon-pack::zip",
                        CliConstants.DIR, targetDir.toAbsolutePath().toString())
                .withTimeLimit(10, TimeUnit.MINUTES)
                .execute()
                .assertReturnCode(ReturnCodes.SUCCESS_LOCAL_CHANGES);
    }

    protected static Optional<Stream> getInstalledArtifact(String artifactId, Path serverPath) throws IOException {
        return ManifestYamlSupport.parse(serverPath.resolve(MetadataTestUtils.MANIFEST_FILE_PATH).toFile())
                .getStreams().stream()
                .filter(s -> s.getArtifactId().equals(artifactId))
                .findFirst();
    }
}
