<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

final class SecretsAddCommand extends Command
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
            ->setDescription('Encrypt and add a secret key value pair to the configured secrets file')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command adds an encrypted secret to the file configured in encrypted_secrets.secrets_file

  <info>php %command.full_name% DATABASE_URL mysql://db_user:db_password@127.0.0.1:3306/db_name</info>

will encrypt the value for DATABASE_URL using the public key file specified in encrypted_secrets.public_key_file. The private key is not required to add or overwrite secrets.
If the secret name and value are not provided, you will be prompted to provide one. Secret names should follow the same structure as env variables used in your config.
They cannot be empty, and should contain only word characters.

Always store your private key in a secure location outside of version control; you will not be able to recover your secrets without it.
HELP
            )
            ->addArgument('secret-name', InputArgument::OPTIONAL, 'The variable name of the secret (e.g., DATABASE_URL).')
            ->addArgument('secret-value', InputArgument::OPTIONAL, 'The secret to be encrypted.')
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

        if (null === $name || null === $secretValue) {
            $name = $this->io->ask('Enter the variable name for the secret', $default = null, function ($nameGiven) {
                return $this->validateUserInput($nameGiven);
            });

            $secretValue = $this->io->ask('Enter the secret value', $default = null, function ($valueGiven) {
                return $this->validateUserInput($valueGiven, $restrictToWords = false);
            });
        }

        $this->secretsHandler->addEntry($name, $secretValue);

        $this->io->success(sprintf(
            'Secret for %s has been successfully added.',
            $name
        ));
    }

    private function validateUserInput($value, bool $restrictToWords = true)
    {
        $trimmed = trim($value, " \t\n\r\0\x0B\"\'");
        if (empty($value) || 0 === \strlen($trimmed)) {
            throw new \InvalidArgumentException('The value provided cannot be empty');
        }

        if ($restrictToWords && !preg_match('/^(?:\w++:)*+\w++$/', $trimmed)) {
            throw new \InvalidArgumentException('Only "word" characters are allowed.');
        }

        return $trimmed;
    }
}
