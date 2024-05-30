package org.wildfly.prospero.cli.commands.certificate;

import org.wildfly.prospero.cli.ActionFactory;
import org.wildfly.prospero.cli.CliConsole;
import org.wildfly.prospero.cli.commands.AbstractCommand;
import org.wildfly.prospero.cli.commands.CliConstants;
import picocli.CommandLine;

import java.nio.file.Path;
import java.util.Optional;

@CommandLine.Command(name = "remove")
public class CertificateRemoveCommand  extends AbstractCommand {

    @CommandLine.Option(names = CliConstants.DIR)
    private Optional<Path> installationDir;

    @CommandLine.ArgGroup(exclusive = true, multiplicity = "1")
    private CertificateOptions certificateOptions;

    static class CertificateOptions {
        @CommandLine.Option(names = "name")
        private String certificateName;

        @CommandLine.Option(names = "revoke-certificate")
        private Path revokeCertificatePath;
    }

    public CertificateRemoveCommand(CliConsole console, ActionFactory actionFactory) {
        super(console, actionFactory);
    }

    @Override
    public Integer call() throws Exception {
        return null;
    }
}
