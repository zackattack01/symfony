<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

/**
 * Console command to add an encrypted secret
 * Usage: php bin/console secrets:add
 */
class SecretsAddCommand extends Command
{
    protected static $defaultName = 'secrets:add';
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
            ->setDescription('Encrypt and add a secret key value pair to the specified secrets file')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command adds an encrypted secret to the secrets-file configured in encrypted_secrets.secrets_file

encrypted_secrets.enabled must set to true in your yaml config for the environment you are running this in.

  <info>php %command.full_name% DATABASE_URL mysql://db_user:db_password@127.0.0.1:3306/db_name</info>

will encrypt the value for DATABASE_URL using the public key file specified in encrypted_secrets.public_key_file, and
add the pair to the json secrets file configured by encrypted_secrets.secrets_file.

Always store your private key in a secure location outside of version control; you will not be able to recover your secrets without it.
HELP
            )
            ->addArgument('secret-name', InputArgument::REQUIRED, 'The variable name of the secret (e.g., DATABASE_URL).')
            ->addArgument('secret-value', InputArgument::REQUIRED, 'The secret to be encrypted.')
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
        $name = $input->getArgument('secret-name');
        $secretValue = $input->getArgument('secret-value');

        $this->secretsHandler->validateConfig()
                             ->addEntry($name, $secretValue)
                             ->writeEncrypted();

        //TODO- $this->secretsHandler->validateEncryptedSecrets();
        $this->io->success(sprintf(
            'Secret for %s has been successfully added.',
            $name
        ));
    }
}

