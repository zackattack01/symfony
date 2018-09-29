<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

use Symfony\Bundle\FrameworkBundle\Secrets\Exception\SecretsMissingException;
use Symfony\Bundle\FrameworkBundle\Secrets\Exception\InvalidSecretsFormatException;

trait SecretsHandlerTrait
{
    protected function readEncryptedSecrets(string $secretsLocation, $allowEmptySecrets = false)
    {
        if (!file_exists($secretsLocation)) {
            throw new SecretsMissingException($secretsLocation);
        }

        $secrets = json_decode(file_get_contents($secretsLocation), true);
        if (is_null($secrets)) {
            if ($allowEmptySecrets) {
                $secrets = [];
            } else {
                throw new InvalidSecretsFormatException($secretsLocation." does not contain valid json.");
            }
        } else {
            foreach ($secrets as $secretKey => $secretValues) {
                if (!array_key_exists(SecretsWriter::CIPHERTEXT_KEY, $secretValues)) {
                    throw new InvalidSecretsFormatException("Each value must contain a ".SecretsWriter::CIPHERTEXT_KEY." key in ".$secretsLocation);
                }

                if (!array_key_exists(SecretsWriter::IV_KEY, $secretValues)) {
                    throw new InvalidSecretsFormatException("Each value must contain a ".SecretsWriter::IV_KEY." key in ".$secretsLocation);
                }
            }
        }

        return $secrets;
    }

    protected function readMasterKey(string $fileLocation)
    {
        if (file_exists($fileLocation)) {
            return trim(file_get_contents($fileLocation));
        } else {
            throw new RuntimeException(sprintf('No master key file found at "%s".', $fileLocation));
        }
    }

    protected function fetchSingleSecret(string $secretsLocation, string $secretKey)
    {
        return json_decode(file_get_contents($secretsLocation), true)[$secretKey];
    }

    protected function decryptSecretValue(string $secretValue, string $masterKey, string $iv)
    {
        return openssl_decrypt($secretValue, SecretsWriter::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
    }
}
