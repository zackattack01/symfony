<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

class SecretsWriter extends BaseSecretsHandler
{
    public function writeEncryptedSecrets(string $masterKey)
    {
        $encryptedSecrets = $this->generateEncryptedSecrets($masterKey);
        $formattedSecrets = json_encode($encryptedSecrets, JSON_PRETTY_PRINT);
        return file_put_contents($this->encryptedSecretsLocation, $formattedSecrets) > 0;
    }

    public function writePlaintextSecrets(string $masterKey)
    {
        $decryptedSecrets = $this->generatePlaintextSecrets($masterKey);
        $formattedSecrets = json_encode($decryptedSecrets);
        return file_put_contents($this->plaintextSecretsLocation, $formattedSecrets) > 0;
    }

    public function writeSingleSecret(string $secretName, string $secretValue, string $masterKey)
    {
        $encryptedSecrets = $this->readSecrets($this->encryptedSecretsLocation);
        $this->addSingleSecret($secretName, $secretValue, $masterKey, $encryptedSecrets);
        $formattedSecrets = json_encode($encryptedSecrets, JSON_PRETTY_PRINT);
        return file_put_contents($this->encryptedSecretsLocation, $formattedSecrets) > 0;
    }


    public function writeSecretKeyFile(string $fileLocation)
    {
        //TODO
    }


    public function readSecretKeyFile(string $fileLocation)
    {
        //TODO
    }

    public function generateEncryptedSecrets(string $masterKey)
    {
        $plaintextSecrets = $this->readSecrets($this->plaintextSecretsLocation);
        $encryptedSecrets = [];
        foreach ($plaintextSecrets as $secretName => $secretValue) {
            $this->addSingleSecret($secretName, $secretValue, $masterKey, $encryptedSecrets);
        }

        return $encryptedSecrets;
    }

    public function generatePlaintextSecrets(string $masterKey)
    {
        $encryptedSecrets = $this->readSecrets($this->encryptedSecretsLocation);
        $plaintextSecrets = [];
        foreach ($encryptedSecrets as $secretName => $secretValue) {
            $iv = $secretValue[parent::IV_KEY];
            $ciphertext = $secretValue[parent::CIPHERTEXT_KEY];
            $plaintextSecrets[$secretName] = $this->decryptSecretValue($ciphertext, $masterKey, $iv);
        }

        return $plaintextSecrets;
    }

    public function addSingleSecret(string $secretName, string $secretValue, string $masterKey, array &$secrets)
    {
        $iv = $this->generateIv();
        $secrets[$secretName][parent::IV_KEY] = $iv;
        $secrets[$secretName][parent::CIPHERTEXT_KEY] = $this->encryptSecretValue($secretValue, $masterKey, $iv);
    }

    private function encryptSecretValue(string $secretValue, string $masterKey, string $iv)
    {
        return openssl_encrypt($secretValue, parent::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
    }

    private function generateIv()
    {
        return base64_encode(random_bytes(12));
    }
}
