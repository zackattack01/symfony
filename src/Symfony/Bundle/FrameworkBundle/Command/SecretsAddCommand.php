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
use Symfony\Component\DependencyInjection\SecretVarProcessor;

/**
 * Console command to add an encrypted secret
 * Usage: php bin/console secrets:add
 */
class SecretsAddCommand extends Command
{
    protected static $defaultName = 'secrets:add';
    private $io;
    private $secretsProcessor;

    public function __construct(SecretVarProcessor $secretsProcessor)
    {
        $this->secretsProcessor = $secretsProcessor;
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
The <info>%command.name%</info> command adds an encrypted secret to the specified secrets-file

If encrypted_secrets.enabled is set to true in your yaml config,

  <info>php %command.full_name% DATABASE_URL mysql://db_user:db_password@127.0.0.1:3306/db_name</info>

will encrypt the value for DATABASE_URL using the public key file specified in encrypted_secrets.public_key_file, and
add the pair to the json secrets file configured by encrypted_secrets.secrets_file. If you haven't configured encrypted_secrets or wish to override these values,
you can provide the required information via the public-key-file and secrets-file options:

<info>php %command.full_name% DATABASE_URL mysql://db_user:db_password@127.0.0.1:3306/db_name --public-key-file ./config/secrets.pub --secrets-file ./config/secrets.jwe</info>

If this is the first time you've run <info>%command.name%</info> and no secrets-file exists in the specified location, one will be created for you.

Always store the companion private key in a secure location; you will not be able to recover your secrets without them.
HELP
            )
            ->addArgument('secret-name', InputArgument::REQUIRED, 'The variable name of the secret (e.g., DATABASE_URL).')
            ->addArgument('secret-value', InputArgument::REQUIRED, 'The secret to be encrypted.')
            ->addOption('public-key-file', 'p', InputOption::VALUE_REQUIRED, 'The public key file to be used for encryption.')
            ->addOption('secrets-file', 's', InputOption::VALUE_REQUIRED, 'The file to write encrypted secrets to')
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
        $pubKeyLocation = $input->getOption('public-key-file');
        $secretsLocation = $input->getOption('secrets-file');

        if (isset($secretsLocation) && !file_exists($secretsLocation)) {
            JweHandler::initSecretsFile($secretsLocation);
        }

        if ($this->secretsProcessor->isSecretsLookupEnabled()) {
            $secretsHandler = $this->secretsProcessor->getSecretsHandler();
            if (isset($pubKeyLocation)) {
                $secretsHandler->setPublicKeyFromLocation($pubKeyLocation);
            }

            if (isset($secretsLocation)) {
                $secretsHandler->setSecretsLocation($secretsLocation);
            }
        } elseif (is_null($pubKeyLocation) || is_null($secretsLocation)) {
            throw new RuntimeException("Provide a public-key-file and secrets-file to read from or pre-configure one by setting encrypted_secrets.enabled to true and configuring encrypted_secrets.public_key_file and encrypted_secrets.secrets_file in your config");
        } else {
            $secretsHandler = new JweHandler($secretsLocation, $pubKeyLocation);
        }

        $secretsHandler->addEntry($name, $secretValue)
                       ->writeEncrypted();

        //TODO add verification that key decrypts all existing values
        $this->io->success(sprintf(
            'Secret for %s has been successfully added.',
            $name
        ));
    }
}

