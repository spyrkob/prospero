/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package org.wildfly.channel;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.channel.maven.VersionResolverFactory;
import org.wildfly.channel.spi.SignatureValidator;
import org.wildfly.prospero.api.MavenOptions;
import org.wildfly.prospero.test.MetadataTestUtils;
import org.wildfly.prospero.utils.MavenUtils;
import org.wildfly.prospero.utils.SignatureUtils;
import org.wildfly.prospero.wfchannel.MavenSessionManager;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.wildfly.channel.MavenSignatureValidator.describeImportedKeys;

public class SignatureTest {

    @Rule
    public TemporaryFolder temp = new TemporaryFolder();
    private MavenSessionManager msm;
    private RepositorySystem repositorySystem;
    private DefaultRepositorySystemSession repositorySession;

    @Before
    public void setUp() throws Exception {
        msm = new MavenSessionManager(MavenOptions.OFFLINE_NO_CACHE);
        repositorySystem = msm.newRepositorySystem();
        repositorySession = msm.newRepositorySystemSession(repositorySystem);
    }

    @Test
    public void testValidArtifact() throws Exception {
        final ChannelManifest manifest = MetadataTestUtils.createManifest(List.of(new Stream("com.test.sign", "test-app", "1.0.0")));
        final File manifestFile = temp.newFile("test-manifest.yaml");
        FileUtils.write(manifestFile, ChannelManifestMapper.toYaml(manifest), StandardCharsets.UTF_8);

        final File jarFile = temp.newFile("test.jar");

        final Path testRepo = temp.newFolder("test-repo").toPath();
        new MavenUtils(MavenOptions.OFFLINE_NO_CACHE).deployFile("com.test.sign", "test-app", "1.0.0", null, "jar",
                jarFile, testRepo.toUri().toURL());

        final PGPSecretKeyRing pgpSecretKey = SignatureUtils.generateSecretKey("test@test.org", "TestPassword");

        final Path artifactPath = MavenUtils.pathOf(testRepo, "com.test.sign", "test-app", "1.0.0");
        SignatureUtils.signFile(pgpSecretKey, artifactPath, "TestPassword");
        final Path publicKeyFolder = temp.newFolder("public-keys").toPath();

        List<Channel> channels = List.of(new Channel.Builder()
                .setManifestUrl(new URL(manifestFile.toURI().toURL().toExternalForm()))
                .addRepository("test-repo", testRepo.toUri().toURL().toExternalForm())
                .setGpgCheck(true)
                .setGpgUrl(publicKeyFolder.resolve("test-key.gpg").toUri().toString())
                .build());

        SignatureUtils.exportPublicKeys(pgpSecretKey, publicKeyFolder.resolve("test-key.gpg").toFile());

        final MavenSignatureValidator signatureValidator = new MavenSignatureValidator((s)->true, new Keyring(publicKeyFolder.resolve("keyring.gpg")));
        final ChannelSession session = new ChannelSession(channels, new VersionResolverFactory(repositorySystem, repositorySession,
                VersionResolverFactory.DEFAULT_REPOSITORY_MAPPER), signatureValidator);

        session.resolveMavenArtifact("com.test.sign", "test-app", "jar", null, "");
    }

    @Test
    public void testCorruptedArtifact() throws Exception {
        final ChannelManifest manifest = MetadataTestUtils.createManifest(List.of(new Stream("com.test.sign", "test-app", "1.0.0")));
        final File manifestFile = temp.newFile("test-manifest.yaml");
        FileUtils.write(manifestFile, ChannelManifestMapper.toYaml(manifest), StandardCharsets.UTF_8);

        final File jarFile = temp.newFile("test.jar");

        final Path testRepo = temp.newFolder("test-repo").toPath();
        final MavenUtils mavenUtils = new MavenUtils(MavenOptions.OFFLINE_NO_CACHE);
        mavenUtils.deployFile("com.test.sign", "test-app", "1.0.0", null, "jar",
                jarFile, testRepo.toUri().toURL());

        final PGPSecretKeyRing pgpSecretKey = SignatureUtils.generateSecretKey("test@test.org", "TestPassword");

        final Path artifactPath = MavenUtils.pathOf(testRepo, "com.test.sign", "test-app", "1.0.0");
        SignatureUtils.signFile(pgpSecretKey, artifactPath, "TestPassword");

        List<Channel> channels = List.of(new Channel.Builder()
                .setManifestUrl(new URL(manifestFile.toURI().toURL().toExternalForm()))
                .addRepository("test-repo", testRepo.toUri().toURL().toExternalForm())
                .setGpgCheck(true)
                .build());

        final Path publicKeyFolder = temp.newFolder("public-keys").toPath();
        SignatureUtils.exportPublicKeys(pgpSecretKey, publicKeyFolder.resolve("test-key.gpg").toFile());

        final MavenSignatureValidator signatureValidator = new MavenSignatureValidator((s)->true, new Keyring(publicKeyFolder.resolve("keyring.gpg")));
        final ChannelSession session = new ChannelSession(channels, new VersionResolverFactory(repositorySystem, repositorySession,
                VersionResolverFactory.DEFAULT_REPOSITORY_MAPPER), signatureValidator);

        // corrupt the artifact
        final File corruptedJarFile = temp.newFile("corrupted-test.jar");
        Files.writeString(corruptedJarFile.toPath(), "foobar");
        mavenUtils.deployFile("com.test.sign", "test-app", "1.0.0", null, "jar",
                corruptedJarFile, testRepo.toUri().toURL());

        assertThatThrownBy(()-> session.resolveMavenArtifact("com.test.sign", "test-app", "jar", null, ""))
                .isInstanceOf(SignatureValidator.SignatureException.class);
    }

    @Test
    public void requireAcceptingNewCert() throws Exception {
        final ChannelManifest manifest = MetadataTestUtils.createManifest(List.of(new Stream("com.test.sign", "test-app", "1.0.0")));
        final File manifestFile = temp.newFile("test-manifest.yaml");
        FileUtils.write(manifestFile, ChannelManifestMapper.toYaml(manifest), StandardCharsets.UTF_8);

        final File jarFile = temp.newFile("test.jar");

        final Path testRepo = temp.newFolder("test-repo").toPath();
        new MavenUtils(MavenOptions.OFFLINE_NO_CACHE).deployFile("com.test.sign", "test-app", "1.0.0", null, "jar",
                jarFile, testRepo.toUri().toURL());

        final PGPSecretKeyRing pgpSecretKey = SignatureUtils.generateSecretKey("test@test.org", "TestPassword");

        final Path artifactPath = MavenUtils.pathOf(testRepo, "com.test.sign", "test-app", "1.0.0");
        SignatureUtils.signFile(pgpSecretKey, artifactPath, "TestPassword");

        final Path publicKeyFolder = temp.newFolder("public-keys").toPath();
        SignatureUtils.exportPublicKeys(pgpSecretKey, publicKeyFolder.resolve("test-key.gpg").toFile());

        List<Channel> channels = List.of(new Channel.Builder()
                .setManifestUrl(manifestFile.toURI().toURL())
                .addRepository("test-repo", testRepo.toUri().toURL().toExternalForm())
                .setGpgCheck(true)
                .setGpgUrl(publicKeyFolder.resolve("test-key.gpg").toUri().toString())
                .build());


        final ArrayList<String> signatures = new ArrayList<>();
        final MavenSignatureValidator signatureValidator = new MavenSignatureValidator((s)->{
            signatures.add(s);
            return true;
        }, new Keyring(publicKeyFolder.resolve("keyring.gpg")));
        final ChannelSession session = new ChannelSession(channels, new VersionResolverFactory(repositorySystem, repositorySession,
                VersionResolverFactory.DEFAULT_REPOSITORY_MAPPER), signatureValidator);

        session.resolveMavenArtifact("com.test.sign", "test-app", "jar", null, "");

        assertThat(signatures)
                .containsExactly(describeImportedKeys(toList(pgpSecretKey.getPublicKeys())));
    }

    @Test
    public void dontRequireTrustedCert() throws Exception {
        final ChannelManifest manifest = MetadataTestUtils.createManifest(List.of(new Stream("com.test.sign", "test-app", "1.0.0")));
        final File manifestFile = temp.newFile("test-manifest.yaml");
        FileUtils.write(manifestFile, ChannelManifestMapper.toYaml(manifest), StandardCharsets.UTF_8);

        final File jarFile = temp.newFile("test.jar");

        final Path testRepo = temp.newFolder("test-repo").toPath();
        new MavenUtils(MavenOptions.OFFLINE_NO_CACHE).deployFile("com.test.sign", "test-app", "1.0.0", null, "jar",
                jarFile, testRepo.toUri().toURL());

        final PGPSecretKeyRing pgpSecretKey = SignatureUtils.generateSecretKey("test@test.org", "TestPassword");

        final Path artifactPath = MavenUtils.pathOf(testRepo, "com.test.sign", "test-app", "1.0.0");
        SignatureUtils.signFile(pgpSecretKey, artifactPath, "TestPassword");

        List<Channel> channels = List.of(new Channel.Builder()
                .setManifestUrl(new URL(manifestFile.toURI().toURL().toExternalForm()))
                .addRepository("test-repo", testRepo.toUri().toURL().toExternalForm())
                .setGpgCheck(true)
                .build());

        final Path publicKeyFolder = temp.newFolder("public-keys").toPath();
        SignatureUtils.exportPublicKeys(pgpSecretKey, publicKeyFolder.resolve("test-key.gpg").toFile());

        final ArrayList<String> addedSignatures = new ArrayList<>();
        final Keyring keyring = new Keyring(publicKeyFolder.resolve("keyring.gpg"));
        keyring.importArmoredKey(toList(pgpSecretKey.getPublicKeys()));

        final MavenSignatureValidator signatureValidator = new MavenSignatureValidator((s)->{
            addedSignatures.add(s);
            return true;
        }, keyring);
        final ChannelSession session = new ChannelSession(channels, new VersionResolverFactory(repositorySystem, repositorySession,
                VersionResolverFactory.DEFAULT_REPOSITORY_MAPPER), signatureValidator);

        session.resolveMavenArtifact("com.test.sign", "test-app", "jar", null, "");

        assertThat(addedSignatures)
                .isEmpty();
    }

    @Test
    public void failOnRevokedCert() throws Exception {
        final ChannelManifest manifest = MetadataTestUtils.createManifest(List.of(new Stream("com.test.sign", "test-app", "1.0.0")));
        final File manifestFile = temp.newFile("test-manifest.yaml");
        FileUtils.write(manifestFile, ChannelManifestMapper.toYaml(manifest), StandardCharsets.UTF_8);

        final File jarFile = temp.newFile("test.jar");

        final Path testRepo = temp.newFolder("test-repo").toPath();
        new MavenUtils(MavenOptions.OFFLINE_NO_CACHE).deployFile("com.test.sign", "test-app", "1.0.0", null, "jar",
                jarFile, testRepo.toUri().toURL());

        final PGPSecretKeyRing pgpSecretKey = SignatureUtils.generateSecretKey("test@test.org", "TestPassword");

        final Path artifactPath = MavenUtils.pathOf(testRepo, "com.test.sign", "test-app", "1.0.0");
        SignatureUtils.signFile(pgpSecretKey, artifactPath, "TestPassword");

        List<Channel> channels = List.of(new Channel.Builder()
                .setManifestUrl(new URL(manifestFile.toURI().toURL().toExternalForm()))
                .addRepository("test-repo", testRepo.toUri().toURL().toExternalForm())
                .setGpgCheck(true)
                .build());

        final Path publicKeyFolder = temp.newFolder("public-keys").toPath();
        SignatureUtils.exportPublicKeys(pgpSecretKey, publicKeyFolder.resolve("test-key.gpg").toFile());
        SignatureUtils.exportRevocationKeys(pgpSecretKey, publicKeyFolder.resolve("revoke.gpg").toFile(), "TestPassword");

        final ArrayList<String> addedSignatures = new ArrayList<>();
        final Keyring keyring = new Keyring(publicKeyFolder.resolve("keyring.gpg"));
        keyring.importArmoredKey(toList(pgpSecretKey.getPublicKeys()));
        keyring.importCertificate(publicKeyFolder.resolve("revoke.gpg").toFile());

        final MavenSignatureValidator signatureValidator = new MavenSignatureValidator((s)->{
            addedSignatures.add(s);
            return true;
        }, keyring);
        final ChannelSession session = new ChannelSession(channels, new VersionResolverFactory(repositorySystem, repositorySession,
                VersionResolverFactory.DEFAULT_REPOSITORY_MAPPER), signatureValidator);

        assertThatThrownBy(()->session.resolveMavenArtifact("com.test.sign", "test-app", "jar", null, ""))
                .hasMessageContaining("has been revoked");

        assertThat(addedSignatures)
                .isEmpty();
    }

    private List<PGPPublicKey> toList(Iterator<PGPPublicKey> publicKeys) {
        final ArrayList<PGPPublicKey> res = new ArrayList<>();
        while (publicKeys.hasNext()) {
            res.add(publicKeys.next());
        }
        return res;
    }
}
