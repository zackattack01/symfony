<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Output\Output;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Bundle\FrameworkBundle\Secrets\SecretsWriter;

/**
 * Console command to decrypt an encrypted secrets file based on the contents of config/secrets_{env}.enc.json
 * Usage: php bin/console secrets:decrypt
 */
class SecretsDecryptCommand extends Command
{
    protected static $defaultName = 'secrets:decrypt';
    private $io;
    private $secretsWriter;

    public function __construct(SecretsWriter $secretsWriter)
    {
        $this->secretsWriter = $secretsWriter;
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setDescription('Decrypt config/secrets.enc and write contents to config/secrets.json')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command decrypts an encrypted secrets file in config/secrets.enc and writes the content to config/secrets.json:

  <info>php %command.full_name%</info>

Ensure that secrets.json is included in .gitignore. Be sure to add this command to your deploy process to ensure the application will have
access to your latest secrets.

HELP
            )
            ->addArgument('master-key', InputArgument::REQUIRED, 'The master key to be used for decryption.')
            ->addArgument('iv', InputArgument::REQUIRED, 'The 16 byte initialization vector to be used for decryption.');
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
        $masterKey = $input->getArgument('master-key');
        $iv = $input->getArgument('iv');

        $this->secretsWriter->writeSecrets($masterKey, $iv, SecretsWriter::DECRYPT_ACTION);
        $this->io->success('Secrets have been decrypted. Make sure this file is not committed to version control.');
    }
}

