<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

use Symfony\Bundle\FrameworkBundle\Secrets\Exception\SecretsMissingException;
use Symfony\Bundle\FrameworkBundle\Secrets\Exception\InvalidSecretsFormatException;
use Symfony\Component\HttpKernel\KernelInterface;

class BaseSecretsHandler
{
    const ENCRYPTION_METHOD = "aes-256-cfb";
    const PLAINTEXT_SECRETS = "/config/secrets_{env}.json";
    const ENCRYPTED_SECRETS = "/config/secrets_{env}.enc.json";

    private $kernel;

    public function __construct(KernelInterface $kernel)
    {
        $this->kernel = $kernel;
    }

    protected function readSecrets(string $rawSecretsLocation)
    {
        $formattedSecretsLocation = $this->formattedSecretsLocation($rawSecretsLocation);

        if (!file_exists($formattedSecretsLocation)) {
            throw new SecretsMissingException($formattedSecretsLocation);
        }

        $secrets = json_decode(file_get_contents($formattedSecretsLocation), true);
        
        if (is_null($secrets)) {
            throw new InvalidSecretsFormatException($formattedSecretsLocation);
        }

        return $secrets;
    }

    protected function formattedSecretsLocation(string $locationTemplate)
    {
        $filename = str_replace("{env}", $this->kernel->getEnvironment(), $locationTemplate);
        $baseLocation = $this->kernel->getRootDir().'/..';
        return $baseLocation.$filename;
    }
}
