package org.wildfly.prospero.cli.commands.certificate;

import org.wildfly.prospero.cli.ActionFactory;
import org.wildfly.prospero.cli.CliConsole;
import org.wildfly.prospero.cli.commands.AbstractParentCommand;
import picocli.CommandLine;

import java.util.List;

@CommandLine.Command(name="certificate")
public class CertificatesCommand extends AbstractParentCommand {
    public CertificatesCommand(CliConsole console, ActionFactory actionFactory) {
        super(console, actionFactory, "certificate", List.of(
                new CertificateAddCommand(console, actionFactory),
                new CertificateRemoveCommand(console, actionFactory),
                new CertificateListCommand(console, actionFactory))
        );
    }
}
