<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

class SecretsWriter extends BaseSecretsHandler
{
    public function writeSecrets(string $masterKey, string $iv, string $transformationAction)
    {
        if (parent::ENCRYPT_ACTION === $transformationAction) {
            $sourceSecretsLocation = $this->plaintextSecretsLocation;
            $destinationFile = $this->encryptedSecretsLocation;
        } elseif (parent::DECRYPT_ACTION === $transformationAction) {
            $sourceSecretsLocation = $this->encryptedSecretsLocation;
            $destinationFile = $this->plaintextSecretsLocation;
        }
        $secrets = $this->readSecrets($sourceSecretsLocation);
        $transformedSecrets = $this->transformSecrets($masterKey, $iv, $secrets, $transformationAction);
        $formattedSecrets = json_encode($transformedSecrets, JSON_PRETTY_PRINT);
        return file_put_contents($destinationFile, $formattedSecrets) > 0;
    }

    public function writeSecretKeyFile(string $fileLocation)
    {
        //TODO
    }


    public function readSecretKeyFile(string $fileLocation)
    {
        //TODO
    }

    public function transformSecrets(string $masterKey, string $iv, array $secrets, string $transformationAction)
    {
        $transformedSecrets = [];
        //TODO remove recursive calls and array support
        foreach ($secrets as $secretName => $secret) {
            if (is_array($secret)) {
                // to support non-associative arrays as values (e.g., a set of tokens)
                if (array_values($secret) === $secret) {
                    foreach ($secret as $singleValue) {
                        $transformedSecrets[$secretName][] = $this->cipherSecretValue($singleValue, $masterKey, $iv, $transformationAction);
                    }
                } else {
                    $transformedSecrets[$secretName] = $this->transformSecrets($masterKey, $iv, $secret, $transformationAction);
                }
            } else {
                $transformedSecrets[$secretName] = $this->cipherSecretValue($secret, $masterKey, $iv, $transformationAction);
            }
        }

        return $transformedSecrets;
    }
}
