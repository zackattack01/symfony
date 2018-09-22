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
 * Console command to generate an encrypted secrets file based on the contents of config/secrets_{env}.json
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
            ->setDescription('Generate config/secrets.enc from config/secrets.json')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command generates an encrypted secrets file based on your existing secrets.json file:

  <info>php %command.full_name%</info>

Secrets.json has been included in your .gitignore by default. Ensure that this file is not committed to version control.
To decrypt this file based on the encrypted file generated here,
add <info>php bin/console secrets:decrypt</info> to your deploy process.

After updating any values in secrets.json, rerun this command and commit the encrypted file to version control.
Always store your master key and iv in a secure location; you will not be able to recover your secrets without them.

HELP
            )
            ->addArgument('master-key', InputArgument::REQUIRED, 'The master key to be used for encryption.')
            ->addArgument('iv', InputArgument::OPTIONAL, 'A 16 byte initialization vector to be used for encryption.')
            ->addOption('generate-iv', null, InputOption::VALUE_NONE, 'Randomly generate an initialization vector for encryption.');
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
        $generateIv = $input->getOption('generate-iv');

        //TODO validate iv is 16 bytes

        if ((!$generateIv && is_null($iv)) || ($generateIv && !is_null($iv))) {
            throw new RuntimeException("Either provide a 16-byte initialization vector or use the --generate-iv flag to have one randomly generated.");
        }

        if ($generateIv) {
            $iv = base64_encode(random_bytes(12));
            $this->io->note(sprintf('Generated IV: %s', $iv));
        }

        $this->secretsWriter->writeSecrets($masterKey, $iv, SecretsWriter::ENCRYPTION_CONFIG);
        $this->io->success('Secrets have been successfully encrypted. Be sure to securely store the password and iv used.');
    }
}

