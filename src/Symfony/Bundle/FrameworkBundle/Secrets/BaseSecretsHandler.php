<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

use Symfony\Bundle\FrameworkBundle\Secrets\Exception\SecretsMissingException;
use Symfony\Bundle\FrameworkBundle\Secrets\Exception\InvalidSecretsFormatException;

class BaseSecretsHandler
{
    const ENCRYPTION_METHOD = "aes-256-cbc";
    const DECRYPT_ACTION = "decrypt";
    const ENCRYPT_ACTION = "encrypt";

    protected $encryptedSecretsLocation;
    protected $plaintextSecretsLocation;

    public function __construct(string $projectRoot, string $environment)
    {
        $this->encryptedSecretsLocation = "$projectRoot/config/packages/$environment/secrets.enc.json";
        $this->plaintextSecretsLocation = "$projectRoot/var/cache/$environment/secrets.json";
    }

    protected function readSecrets(string $secretsLocation)
    {
        if (!file_exists($secretsLocation)) {
            throw new SecretsMissingException($secretsLocation);
        }

        $secrets = json_decode(file_get_contents($secretsLocation), true);
        
        if (is_null($secrets)) {
            throw new InvalidSecretsFormatException($secretsLocation);
        }

        return $secrets;
    }

    protected function cipherSecretValue(string $secretValue, string $masterKey, string $iv, string $transformationType)
    {
        if (self::ENCRYPT_ACTION === $transformationType) {
            return openssl_encrypt($secretValue, self::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
        } elseif (self::DECRYPT_ACTION === $transformationType) {
            return openssl_decrypt($secretValue, self::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
        } else {
            throw new \RuntimeException(sprintf('transformationType "%s" not supported by %s', $transformationType, get_class($this)));
        }
    }
}
