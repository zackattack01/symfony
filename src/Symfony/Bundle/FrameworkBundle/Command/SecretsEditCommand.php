<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\DependencyInjection\SecretVarProcessor;

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
    private $secretsProcessor;

    /**
     * @param SecretVarProcessor $secretsProcessor
     */
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
        $supportedEditorsLine = implode(", ", array_slice(self::SUPPORTED_EDITORS, 0, -1));
        $supportedEditorsLine .= ", and ".array_values(array_slice(self::SUPPORTED_EDITORS, -1))[0];
        $this
            ->setDescription('Opens an editor session with decrypted secrets and re-encrypts file to the provided location')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> opens an editor session with decrypted secrets and re-encrypts file to the provided location.

  <info>php %command.full_name% [master-key] </info>

Run <info>php bin/console secrets:decrypt [master-key]</info> to decrypt this file based on the encrypted file generated here.

Always store your master key in a secure location; you will not be able to recover your secrets without them.
HELP
            )
            ->addOption('master-key', 'k', InputOption::VALUE_REQUIRED, 'The master key to be used for encryption.')
            ->addOption('master-key-file', 'm', InputOption::VALUE_REQUIRED, 'Read the master key from a specified file')
            ->addOption('encrypted-secrets-file', 's', InputOption::VALUE_REQUIRED, 'Read the encrypted JSON secrets from specified file')
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
        $masterKey = $input->getOption('master-key');
        $keyFileLocation = $input->getOption('master-key-file');

        if (isset($masterKey) && isset($masterFileLocation)) {
            throw new RuntimeException("Specify either the master key itself or the location of a file containing it.");
        }
        $encryptedSecretsLocation = $input->getOption('encrypted-secrets-file');

        $editor = $input->getOption('editor') ?? self::DEFAULT_EDITOR;

        $secretsHelper = new SecretsCommandHelper($this->secretsProcessor);
        $existingConfig = $this->secretsProcessor->getConfiguration();
        //setting master-key always overrides existing config
        if (isset($masterKey)) {
            $keyFileLocation = $secretsHelper->writeContentToTempFile($masterKey);
            //TODO figure out how to ensure file is unlinked/removed in php
        }

        if (is_null($keyFileLocation)) {
            if (isset($existingConfig['master_key_file'])) {
                $keyFileLocation = $existingConfig['master_key_file'];
            } else {
                throw new RuntimeException("You must provide the configuration for a master key and secrets file if encrypted_secrets have not been enabled in framework.yaml");
            }
        }

        if (is_null($encryptedSecretsLocation)) {
            if (isset($existingConfig['secrets_file'])) {
                $encryptedSecretsLocation = $existingConfig['secrets_file'];
            } else {
                throw new RuntimeException("You must provide the configuration for the encrypted secrets file location if encrypted_secrets have not been enabled in framework.yaml");
            }
        }

        $this->secretsProcessor->configureEncryptedSecrets($keyFileLocation, $encryptedSecretsLocation);
        $tempDecryptedSecretsFile = $secretsHelper->writePlaintextSecretsToTempFile();

        system("$editor $tempDecryptedSecretsFile > `tty`");
        $secretsHelper->writeEncryptedSecretsToTempFile($tempDecryptedSecretsFile);

        if (isset($masterKey)) {
            unlink($keyFileLocation);
        }
        $this->io->success('Secrets have been successfully encrypted. Be sure to securely store the master key used.');
    }
}

