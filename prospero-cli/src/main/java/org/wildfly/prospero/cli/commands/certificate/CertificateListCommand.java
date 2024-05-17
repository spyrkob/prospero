package org.wildfly.prospero.cli.commands.certificate;

import org.wildfly.channel.Keyring;
import org.wildfly.prospero.cli.ActionFactory;
import org.wildfly.prospero.cli.CliConsole;
import org.wildfly.prospero.cli.ReturnCodes;
import org.wildfly.prospero.cli.commands.AbstractCommand;
import org.wildfly.prospero.cli.commands.CliConstants;
import org.wildfly.prospero.metadata.ProsperoMetadataUtils;
import picocli.CommandLine;

import java.nio.file.Path;
import java.util.Collection;
import java.util.Optional;

@CommandLine.Command(name="list")
public class CertificateListCommand extends AbstractCommand {

    @CommandLine.Option(names = CliConstants.DIR)
    private Optional<Path> installationDir;

    public CertificateListCommand(CliConsole console, ActionFactory actionFactory) {
        super(console, actionFactory);
    }

    @Override
    public Integer call() throws Exception {
        final Path serverDir = determineInstallationDirectory(installationDir);
        final Keyring keyring = new Keyring(serverDir.resolve(ProsperoMetadataUtils.METADATA_DIR).resolve("keyring.gpg"));
        final Collection<Keyring.KeyInfo> keys = keyring.listKeys();

        if (keys.isEmpty()) {
            System.out.println("No keys imported into the the truststore.");
        } else {
            final KeyPrinter keyPrinter = new KeyPrinter(System.out);
            for (Keyring.KeyInfo key : keys) {
                System.out.println("-------");
                keyPrinter.print(key);
            }
        }
        return ReturnCodes.SUCCESS;
    }
}
