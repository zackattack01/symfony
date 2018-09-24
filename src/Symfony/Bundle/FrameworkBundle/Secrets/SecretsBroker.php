<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

class SecretsBroker extends BaseSecretsHandler
{
    private $checkCachedSecrets;
    private $decryptedSecrets;

    public function __construct(string $projectRoot, string $environment, bool $checkCachedSecrets = true)
    {
        $this->checkCachedSecrets = $checkCachedSecrets;
        parent::__construct($projectRoot, $environment);
    }

    public function fetchSecret(string $name)
    {
        if ($this->checkCachedSecrets) {
            $this->decryptedSecrets = $this->decryptedSecrets ?? $this->readSecrets($this->plaintextSecretsLocation);
            return $this->decryptedSecrets[$name];
        } else {
            $encryptedSecrets = $this->readSecrets($this->encryptedSecretsLocation);
            $masterKey = ""; //TODO figure out how key should be stored for runtime decryption
            $secret = $encryptedSecrets[$name]["ciphertext"]; //TODO add presence check and missing error class
            $iv = $encryptedSecrets[$name]["iv"];
            return $this->cipherSecretValue($secret, $masterKey, $iv, parent::DECRYPT_ACTION);
        }
    }
}