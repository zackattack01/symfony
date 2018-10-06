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
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

/**
 * Console command to add an encrypted secret
 * Usage: php bin/console secrets:add
 */
class SecretsAddCommand extends Command
{
    protected static $defaultName = 'secrets:add';
    private $io;
//    private $secretsWriter;

//    public function __construct(SecretsWriter $secretsWriter)
//    {
//        $this->secretsWriter = $secretsWriter;
//        parent::__construct();
//    }

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
            ->addArgument('public-key-file', InputArgument::OPTIONAL, 'The public key file to be used for encryption.')
            ->addArgument('secrets-file', InputArgument::OPTIONAL, 'The file to write encrypted secrets to')
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
        $pubKeyLocation = $input->getArgument('public-key-file');
        $secretsLocation = $input->getArgument('secrets-file');

        //TODO check if already configured in framework.yaml
        if (is_null($pubKeyLocation)) {
            throw new RuntimeException("Provide a public key file to read from or pre-configure one in framework.yaml");
        }

        if (!file_exists($secretsLocation)) {
            JweHandler::initSecretsFile($secretsLocation);
        }

        $secretsWriter = new JweHandler($secretsLocation, $pubKeyLocation);
        $secretsWriter->addEntry($name, $secretValue)
                      ->write();

        //TODO add verification that key decrypts all existing values
        $this->io->success(sprintf(
            'Secret for %s has been successfully added.',
            $name
        ));
    }
}

