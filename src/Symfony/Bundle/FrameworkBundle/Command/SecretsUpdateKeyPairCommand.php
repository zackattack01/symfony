<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

/**
 * Console command to update your encrypted_secrets public/private key pair
 * Usage: php bin/console secrets:update-keypair.
 */
final class SecretsUpdateKeyPairCommand extends Command
{
    protected static $defaultName = 'secrets:update-keypair';
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
            ->setDescription('Update your encrypted_secrets public/private key pair')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> updates your encrypted_secrets public/private key pair.

  <info>php %command.full_name%</info>

will temporarily decrypt the values from the json secrets file set by encrypted_secrets.secrets_file using the public and private key pair specified by
encrypted_secrets.public_key_file and encrypted_secrets.private_key_file. It will then generate a new key pair, re-encrypt your secrets, and update the public and private key files.

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
        $this->secretsHandler->updateKeyPair();
        $this->io->success('Secrets have been successfully encrypted. Be sure to store the private key used in a secure location.');
    }
}
