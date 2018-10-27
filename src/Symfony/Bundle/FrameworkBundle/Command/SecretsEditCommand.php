<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

/**
 * Console command to temporarily decrypt and allow editing of encrypted secrets file
 * Usage: php bin/console secrets:edit.
 */
class SecretsEditCommand extends Command
{
    const DEFAULT_EDITOR = 'vi';
    const SUPPORTED_EDITORS = array(
        'nano',
        'emacs',
        'vi',
        'vim',
    );

    protected static $defaultName = 'secrets:edit';
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
        $supportedEditorsLine = implode(', ', \array_slice(self::SUPPORTED_EDITORS, 0, -1));
        $supportedEditorsLine .= ', and '.array_values(\array_slice(self::SUPPORTED_EDITORS, -1))[0];
        $this
            ->setDescription('Opens an editor session with decrypted secrets and re-encrypts file to the provided location')
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> opens an editor session with decrypted secrets and re-encrypts the file to the configured location.

encrypted_secrets.enabled must set to true in your yaml config for the environment you are running this in.

  <info>php %command.full_name%</info>

will temporarily decrypt the values from the json secrets file set by encrypted_secrets.secrets_file, using the public and private key pair specified by
encrypted_secrets.public_key_file and encrypted_secrets.private_key_file. After you've finished editing, the values will be re-encrypted.

Always store your private key in a secure location outside of version control; you will not be able to recover your secrets without it.
HELP
            )
            ->addOption(
                'editor',
                null,
                InputOption::VALUE_REQUIRED,
                "Preferred text editor. Supported editors include $supportedEditorsLine. Defaults to ".self::DEFAULT_EDITOR
            );
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
        $editor = $input->getOption('editor') ?? self::DEFAULT_EDITOR;

        $tempFileName = tempnam(sys_get_temp_dir(), '');
        try {
            $this->secretsHandler->writePlaintext($tempFileName);
            system("$editor $tempFileName > `tty`");
            $this->secretsHandler->regenerateEncryptedEntries($tempFileName);
        } finally {
            unlink($tempFileName);
        }

        $this->io->success('Secrets have been successfully encrypted. Be sure to store the private key used in a secure location.');
    }
}
