<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\Output;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Bundle\FrameworkBundle\Secrets\SecretsWriter;

/**
 * TODO update this to be an edit command or remove entirely and have people only use the add command
 * Console command to generate an encrypted secrets file based on the contents of /var/cache/{env}/secrets.json
 * Usage: php bin/console secrets:encrypt
 */
class SecretsEncryptCommand extends Command
{
    protected static $defaultName = 'secrets:encrypt';
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
            ->setDescription('Generate encrypted config/packages/{env}/secrets.enc.json from var/cache/{env}/secrets.json')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command generates an encrypted secrets file based on your existing secrets.json file:

  <info>php %command.full_name%</info>

To decrypt this file based on the encrypted file generated here,
add <info>php bin/console secrets:decrypt [master-key]</info> to your deploy process.

After updating any values in secrets.json, rerun this command and commit the encrypted file to version control.
Always store your master key in a secure location; you will not be able to recover your secrets without them.

HELP
            )
            ->addArgument('master-key', InputArgument::OPTIONAL, 'The master key to be used for encryption.')
            ->addOption('from-file', 'f', InputOption::VALUE_REQUIRED, 'Read the master key and IV from secrets file');
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
        $keyFileLocation = $input->getOption('from-file');

        if (is_null($keyFileLocation)) {
            if (is_null($masterKey)) {
                throw new RuntimeException("Either provide a master key or specify a file to read it from with --from-file.");
            }
        } else {
            $secretKeyInfo = $this->secretsWriter->readSecretKeyFile($keyFileLocation);
            $masterKey = $secretKeyInfo['master_key'];
        }

        $this->secretsWriter->writeEncryptedSecrets($masterKey);
        $this->io->success('Secrets have been successfully encrypted. Be sure to securely store the master key used.');
    }
}

