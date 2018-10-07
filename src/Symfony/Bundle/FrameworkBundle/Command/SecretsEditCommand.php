<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\DependencyInjection\SecretVarProcessor;
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

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
The <info>%command.name%</info> opens an editor session with decrypted secrets and re-encrypts the file to the provided location.

If encrypted_secrets.enabled is set to true in your yaml config,

  <info>php %command.full_name%</info>
  
will temporarily decrypt the values from the json secrets file set by encrypted_secrets.secrets_file, using the public and private key pair specified by
encrypted_secrets.public_key_file and encrypted_secrets.private_key_file. After you've finished editing, the values will be re-encrypted.
If you haven't configured encrypted_secrets or wish to override these values, you can provide the required information via the public-key-file,
private-key-file, and secrets-file options:

  <info>php %command.full_name% --secrets-file ./config/secrets.jwe --public-key-file ./config/secrets.pub --private-key-file /etc/app-name/secret-key</info>
  
Always store your private key in a secure location; you will not be able to recover your secrets without it.
HELP
            )
            ->addOption('secrets-file', 's', InputOption::VALUE_REQUIRED, 'The file to edit encrypted secrets from')
            ->addOption('public-key-file', 'p', InputOption::VALUE_REQUIRED, 'The 32 byte public key file to be used for encryption.')
            ->addOption('private-key-file', 'x', InputOption::VALUE_REQUIRED, 'The 32 byte private key file to be used for decryption.')
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
        $secretsLocation = $input->getOption('secrets-file');
        $pubKeyLocation = $input->getOption('public-key-file');
        $privateKeyLocation = $input->getOption('private-key-file');
        $editor = $input->getOption('editor') ?? self::DEFAULT_EDITOR;

        if (isset($secretsLocation) && !file_exists($secretsLocation)) {
            JweHandler::initSecretsFile($secretsLocation);
        }

        if ($this->secretsProcessor->isSecretsLookupEnabled()) {
            $secretsHandler = $this->secretsProcessor->getSecretsHandler();
            if (isset($pubKeyLocation)) {
                $secretsHandler->setPublicKeyFromLocation($pubKeyLocation);
            }

            if (isset($privateKeyLocation)) {
                $secretsHandler->setPrivateKeyLocation($privateKeyLocation);
            }

            if (isset($secretsLocation)) {
                $secretsHandler->setSecretsLocation($secretsLocation);
            }
        } elseif (is_null($pubKeyLocation) || is_null($secretsLocation) || is_null($privateKeyLocation)) {
            throw new RuntimeException("Provide a secrets-file, public-key-file, and private-key-file to read from or pre-configure them by setting encrypted_secrets.enabled to true and setting up encrypted_secrets.secrets_file, encrypted_secrets.public_key_file, and encrypted_secrets.private_key_file in your config");
        } else {
            $secretsHandler = new JweHandler($secretsLocation, $pubKeyLocation, $privateKeyLocation);
        }

        $tempFileName = tempnam(sys_get_temp_dir(), "");
        try {
            $secretsHandler->writePlaintext($tempFileName);
            system("$editor $tempFileName > `tty`");
            $secretsHandler->regenerateEncryptedEntries($tempFileName)
                           ->writeEncrypted();
        } finally {
            unlink($tempFileName);
        }

        $this->io->success('Secrets have been successfully encrypted. Be sure to store the private key used in a secure location.');
    }
}

