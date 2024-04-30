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

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.prospero.cli.ReturnCodes;
import org.wildfly.prospero.cli.commands.CliConstants;
import org.wildfly.prospero.it.ExecutionUtils;
import org.wildfly.prospero.test.MetadataTestUtils;

import static org.wildfly.prospero.test.MetadataTestUtils.upgradeStreamInManifest;

public class InstallTest extends CliTestBase {

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    private File targetDir;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        targetDir = tempDir.newFolder();
    }

    @Test
    public void testInstallWithProvisionConfig() throws Exception {
        Path channelsFile = MetadataTestUtils.prepareChannel("manifests/wfcore-base.yaml");

        ExecutionUtils.prosperoExecution(CliConstants.Commands.INSTALL,
                        CliConstants.CHANNELS, channelsFile.toString(),
                        CliConstants.FPL, "org.wildfly.core:wildfly-core-galleon-pack::zip",
                        CliConstants.DIR, targetDir.getAbsolutePath())
                .withTimeLimit(10, TimeUnit.MINUTES)
                .execute()
                .assertReturnCode(ReturnCodes.SUCCESS);
    }

    @Test
    public void testInstallWithLocalRepositories() throws Exception {
        final Path manifestPath = tempDir.newFile().toPath();
        final Path provisionConfig = tempDir.newFile().toPath();
        MetadataTestUtils.copyManifest("manifests/wfcore-base.yaml", manifestPath);
        MetadataTestUtils.prepareChannel(provisionConfig, List.of(manifestPath.toUri().toURL()));

        install(provisionConfig, targetDir.toPath());

        upgradeStreamInManifest(manifestPath, resolvedUpgradeArtifact);

        final URL temporaryRepo = mockTemporaryRepo(true);

        ExecutionUtils.prosperoExecution(CliConstants.Commands.UPDATE, CliConstants.Commands.PERFORM,
                        CliConstants.REPOSITORIES, temporaryRepo.toString(),
                        CliConstants.Y,
                        CliConstants.NO_LOCAL_MAVEN_CACHE,
                        CliConstants.DIR, targetDir.getAbsolutePath())
                .execute()
                .assertReturnCode(ReturnCodes.SUCCESS);
    }
}
