package org.wildfly.prospero.cli.commands.certificate;

import org.wildfly.channel.Keyring;
import org.wildfly.prospero.cli.ActionFactory;
import org.wildfly.prospero.cli.CliConsole;
import org.wildfly.prospero.cli.ReturnCodes;
import org.wildfly.prospero.cli.commands.AbstractCommand;
import org.wildfly.prospero.cli.commands.CliConstants;
import org.wildfly.prospero.metadata.ProsperoMetadataUtils;
import picocli.CommandLine;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.util.Optional;

@CommandLine.Command(name = "add")
public class CertificateAddCommand extends AbstractCommand {

    @CommandLine.Option(names = CliConstants.DIR)
    private Optional<Path> installationDir;

    @CommandLine.Option(names = "--certificate", required = true)
    private Path certificateFile;

    public CertificateAddCommand(CliConsole console, ActionFactory actionFactory) {
        super(console, actionFactory);
    }

    @Override
    public Integer call() throws Exception {
        final Path serverDir = determineInstallationDirectory(installationDir);
        final Keyring keyring = new Keyring(serverDir.resolve(ProsperoMetadataUtils.METADATA_DIR).resolve("keyring.gpg"));

        keyring.readKey(certificateFile.toAbsolutePath().toFile());

        keyring.importCertificate(new FileInputStream(certificateFile.toAbsolutePath().toFile()));
        return ReturnCodes.SUCCESS;
    }
}
