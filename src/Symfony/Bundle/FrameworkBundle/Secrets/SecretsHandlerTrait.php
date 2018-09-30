<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

use Symfony\Bundle\FrameworkBundle\Secrets\Exception\SecretsMissingException;
use Symfony\Bundle\FrameworkBundle\Secrets\Exception\InvalidSecretsFormatException;

trait SecretsHandlerTrait
{
    protected function validateEncryptedSecrets(string $secretsLocation)
    {
        if (!file_exists($secretsLocation)) {
            throw new SecretsMissingException($secretsLocation);
        }

        $secrets = json_decode(file_get_contents($secretsLocation), true);
        if (is_null($secrets)) {
            throw new InvalidSecretsFormatException($secretsLocation." does not contain valid json.");
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



    protected function fetchSingleSecret(string $secretsLocation, string $secretKey)
    {
        return json_decode(file_get_contents($secretsLocation), true)['secrets'][$secretKey];
    }

    protected function decryptSecretValue(string $secretValue, string $masterKey, string $iv)
    {
        return openssl_decrypt($secretValue, SecretsWriter::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
    }
}
