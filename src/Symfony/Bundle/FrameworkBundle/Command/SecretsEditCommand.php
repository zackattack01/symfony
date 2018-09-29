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
 * Console command to temporarily decrypt and allow editing of encrypted secrets file
 * Usage: php bin/console secrets:edit
 */
class SecretsEditCommand extends Command
{
    const DEFAULT_EDITOR = 'vi';
    const SUPPORTED_EDITORS = [
        'nano',
        'emacs',
        'vi',
        'vim'
    ];

    protected static $defaultName = 'secrets:edit';
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
        $supportedEditorsLine = implode(", ", array_slice(self::SUPPORTED_EDITORS, 0, -1));
        $supportedEditorsLine .= ", and ".array_values(array_slice(self::SUPPORTED_EDITORS, -1))[0];
        $this
            ->setDescription('Opens an editor session with decrypted secrets and re-encrypts file to the provided location')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> opens an editor session with decrypted secrets and re-encrypts file to the provided location.

  <info>php %command.full_name%</info>

To decrypt this file based on the encrypted file generated here,
add <info>php bin/console secrets:decrypt [master-key]</info> to your deploy process.

Always store your master key in a secure location; you will not be able to recover your secrets without them.

HELP
            )
            ->addArgument('master-key', InputArgument::OPTIONAL, 'The master key to be used for encryption.')
            ->addOption('master-key-file', 'm', InputOption::VALUE_REQUIRED, 'Read the master key and IV from secrets file')
            ->addOption('encrypted-secrets-file', 's', InputOption::VALUE_REQUIRED, 'The file to decrypt secrets from')
            ->addOption(
                'editor',
                null,
                InputOption::VALUE_REQUIRED,
                "Preferred text editor. Supported editors include $supportedEditorsLine. Defaults to ".self::DEFAULT_EDITOR
            );
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
        $keyFileLocation = $input->getOption('master-key-file');
        $encryptedSecretsLocation = $input->getOption('encrypted-secrets-file');
        $editor = $input->getOption('editor') ?? self::DEFAULT_EDITOR;

        if (is_null($keyFileLocation)) {
            if (is_null($masterKey)) {
                throw new RuntimeException("Either provide a master key or specify a file to read it from with --master-key-file.");
            }
        } else {
            $masterKey = $this->secretsWriter->readMasterKey($keyFileLocation);
        }

        $tempDecryptedSecrets = $this->secretsWriter->writePlaintextSecrets($masterKey, $encryptedSecretsLocation);

        system("$editor $tempDecryptedSecrets > `tty`");

        $this->secretsWriter->writeEncryptedSecrets($masterKey, $tempDecryptedSecrets, $encryptedSecretsLocation);

        unlink($tempDecryptedSecrets);
        // require_once('/usr/local/bin/psysh'); eval(\Psy\sh());

        $this->io->success('Secrets have been successfully encrypted. Be sure to securely store the master key used.');
    }

    //php bin/console secrets:edit masterpass -s ./config/secrets.enc.json --editor vim
}

