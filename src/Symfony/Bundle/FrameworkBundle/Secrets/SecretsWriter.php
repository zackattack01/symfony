<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

class SecretsWriter extends BaseSecretsHandler
{
    const ENCRYPTION_CONFIG = [
        "action" => "encrypt",
        "source_file" => parent::PLAINTEXT_SECRETS,
        "destination_file" => parent::ENCRYPTED_SECRETS
    ];

    const DECRYPTION_CONFIG = [
        "action" => "decrypt",
        "source_file" => parent::ENCRYPTED_SECRETS,
        "destination_file" => parent::PLAINTEXT_SECRETS
    ];

    public function writeSecrets(string $masterKey, string $iv, array $transformationTypeConfig)
    {
        $secretsLocation = $transformationTypeConfig["source_file"];
        $secrets = $this->readSecrets($secretsLocation);
        $transformedSecrets = $this->transformSecrets($masterKey, $iv, $secrets, $transformationTypeConfig['action']);
        $formattedSecrets = json_encode($transformedSecrets, JSON_PRETTY_PRINT);
        $destinationFile = $this->formattedSecretsLocation($transformationTypeConfig["destination_file"]);
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

    public function transformSecrets(string $masterKey, string $iv, array $secrets, string $transformationType)
    {
        $transformedSecrets = [];

        foreach ($secrets as $secretName => $secret) {
            if (is_array($secret)) {
                // to support non-associative arrays as values (e.g., a set of tokens)
                if (array_values($secret) === $secret) {
                    foreach ($secret as $singleValue) {
                        $transformedSecrets[$secretName][] = $this->cipherSecretValue($singleValue, $masterKey, $iv, $transformationType);
                    }
                } else {
                    $transformedSecrets[$secretName] = $this->transformSecrets($masterKey, $iv, $secret, $transformationType);
                }
            } else {
                $transformedSecrets[$secretName] = $this->cipherSecretValue($secret, $masterKey, $iv, $transformationType);
            }
        }

        return $transformedSecrets;
    }

    private function cipherSecretValue(string $secretValue, string $masterKey, string $iv, string $transformationType)
    {
        if (self::ENCRYPTION_CONFIG['action'] === $transformationType) {
            return openssl_encrypt($secretValue, parent::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
        } elseif (self::DECRYPTION_CONFIG['action'] === $transformationType) {
            return openssl_decrypt($secretValue, parent::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
        } else {
            throw new \RuntimeException(sprintf('transformationType "%s" not supported by %s', $transformationType, get_class($this)));
        }
    }
}
