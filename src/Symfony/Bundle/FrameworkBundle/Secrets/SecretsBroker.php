<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

use Symfony\Component\HttpKernel\KernelInterface;

class SecretsBroker extends BaseSecretsHandler
{
    private $checkCachedSecrets;
    private $decryptedSecrets;
    private $encryptedSecrets;

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
            $this->encryptedSecrets = $this->encryptedSecrets ?? $this->readSecrets($this->encryptedSecretsLocation);
            $masterKey = ""; //TODO figure out how key and iv should be stored for runtime decryption
            $iv = "";
            $secret = $this->encryptedSecrets[$name]; //TODO add presence check and missing error class
            return $this->cipherSecretValue($secret, $masterKey, $iv, parent::DECRYPT_ACTION);
        }
    }
}