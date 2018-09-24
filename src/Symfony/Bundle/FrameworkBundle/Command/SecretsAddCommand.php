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
 * Console command to add an encrypted secret
 * Usage: php bin/console secrets:add
 */
class SecretsAddCommand extends Command
{
    protected static $defaultName = 'secrets:add';
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
            ->setDescription('Add a secret to config/packages/{env}/secrets.enc.json')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command adds an encrypted secret to config/packages/{env}/secrets.enc.json:

  <info>php %command.full_name% [secret-name] [secret-value] [master-key] </info>

To decrypt this file based on the encrypted file generated here,
add <info>php bin/console secrets:decrypt [master-key]</info> to your deploy process.

Always store your master key and iv in a secure location; you will not be able to recover your secrets without them.

HELP
            )
            ->addArgument('secret-name', InputArgument::REQUIRED, 'The variable name of the secret (e.g., DATABASE_URL).')
            ->addArgument('secret-value', InputArgument::REQUIRED, 'The secret to be encrypted.')
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
        $secretName = $input->getArgument('secret-name');
        $secretValue = $input->getArgument('secret-value');
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

        //TODO add verification that key decrypts all existing values
        $this->secretsWriter->writeSingleSecret($secretName, $secretValue, $masterKey);
        $this->io->success(sprintf(
            'Secret for %s has been successfully added. Be sure to securely store the master key used.',
            $secretName
        ));
    }
}

