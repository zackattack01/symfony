<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Secrets\JweHandler;
use Symfony\Component\DependencyInjection\Exception\SecretsOverwriteRequiredException;

/**
 * Console command to set up encrypted secrets files
 * Usage: php bin/console secrets:init.
 */
final class SecretsInitCommand extends Command
{
    protected static $defaultName = 'secrets:init';
    private $io;
    private $secretsHandler;

    public function __construct(JweHandler $secretsHandler)
    {
        $this->secretsHandler = $secretsHandler;
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setDescription('Set up encrypted_secrets public/private key pair and encrypted secrets file')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command creates an empty secrets file based on the location configured encrypted_secrets.secrets_file,
and generates a key pair based on the values set in encrypted_secrets.private_key_file and encrypted_secrets.public_key_file.

After running this command, use

  <info>php bin/console secrets:add</info> or <info>php bin/console secrets:edit</info> to modify your secrets.

Always store your private key in a secure location outside of version control; you will not be able to recover your secrets without it.
HELP
            )
        ;
    }

    /**
     * {@inheritdoc}
     */
    protected function initialize(InputInterface $input, OutputInterface $output)
    {
        $this->io = new SymfonyStyle($input, $output);
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            $this->secretsHandler->initSecretsFiles($overwriteExisting = false);
            $this->io->success('Secrets files have been initialized.');
        } catch (SecretsOverwriteRequiredException $e) {
            $permissionToOverwrite = $this->io->ask(
                sprintf(
                    'Secrets files already exist at: %s. Do you wish to overwrite these files? (y/n)',
                    implode(', ', $e->getExistingFileLocations())
                ),
                'n',
                function ($choice): bool {
                    return !empty($choice) && 'y' === strtolower($choice);
                }
            );

            if ($permissionToOverwrite) {
                $this->secretsHandler->initSecretsFiles($overwriteExisting = true);
                $this->io->success('Secrets files have been initialized. Existing files were overwritten.');
            } else {
                $this->io->warning(sprintf(
                    'Secrets files were previously created. %s aborted.',
                    self::getDefaultName()
                ));
            }
        }
    }
}
