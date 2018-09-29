<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets;

class SecretsWriter
{
    use SecretsHandlerTrait;

    const ENCRYPTION_METHOD = "aes-256-cbc";

    const CIPHERTEXT_KEY = "ciphertext";

    const IV_KEY = "iv";

    private $container;

    public function __construct(ContainerInterface $container)
    {
        //TODO: add support for defaulting to values configured in framework.yaml
        $this->container = $container;
    }

    public function writeEncryptedSecrets(string $masterKey, string $plaintextLocation, string $encryptedLocation)
    {
        $encryptedSecrets = $this->generateEncryptedSecrets($masterKey, $plaintextLocation);
        $formattedSecrets = json_encode($encryptedSecrets, JSON_PRETTY_PRINT, JSON_UNESCAPED_SLASHES);
        return file_put_contents($encryptedLocation, $formattedSecrets) > 0;
    }

    public function writePlaintextSecrets(string $masterKey, string $encryptedSecretsLocation)
    {
        $decryptedSecrets = $this->generatePlaintextSecrets($masterKey, $encryptedSecretsLocation);
        $formattedSecrets = json_encode($decryptedSecrets, JSON_PRETTY_PRINT, JSON_UNESCAPED_SLASHES);
        $tmpfname = tempnam("/tmp", "");
        $handle = fopen($tmpfname, "w");
        fwrite($handle, $formattedSecrets);
        fclose($handle);
        return $tmpfname;
    }

    public function writeSingleSecret(string $secretName, string $secretValue, string $masterKey)
    {
        $encryptedSecrets = $this->readSecrets($this->encryptedSecretsLocation, $allowEmptySecrets = true);
        $this->addSingleSecret($secretName, $secretValue, $masterKey, $encryptedSecrets);
        $formattedSecrets = json_encode($encryptedSecrets, JSON_PRETTY_PRINT, JSON_UNESCAPED_SLASHES);
        return file_put_contents($this->encryptedSecretsLocation, $formattedSecrets) > 0;
    }


    public function readPlaintextSecrets(string $secretsLocation)
    {
        if (!file_exists($secretsLocation)) {
            throw new SecretsMissingException($secretsLocation);
        }

        $secrets = json_decode(file_get_contents($secretsLocation), true);
        if (is_null($secrets)) {
            throw new InvalidSecretsFormatException($secretsLocation." does not contain valid json.");
        }

        return $secrets;
    }

    public function generateEncryptedSecrets(string $masterKey, string $secretsLocation)
    {
        $plaintextSecrets = $this->readPlaintextSecrets($secretsLocation);
        $encryptedSecrets = [];
        foreach ($plaintextSecrets as $secretName => $secretValue) {
            $this->addSingleSecret($secretName, $secretValue, $masterKey, $encryptedSecrets);
        }

        return $encryptedSecrets;
    }

    public function generatePlaintextSecrets(string $masterKey, string $encryptedSecretsLocation)
    {
        $encryptedSecrets = $this->readEncryptedSecrets($encryptedSecretsLocation);
        $plaintextSecrets = [];
        foreach ($encryptedSecrets as $secretName => $secretValue) {
            $iv = $secretValue[self::IV_KEY];
            $ciphertext = $secretValue[self::CIPHERTEXT_KEY];
            $plaintextSecrets[$secretName] = $this->decryptSecretValue($ciphertext, $masterKey, $iv);
        }

        return $plaintextSecrets;
    }

    public function addSingleSecret(string $secretName, string $secretValue, string $masterKey, array &$secrets)
    {
        $iv = $this->generateIv();
        $secrets[$secretName][self::CIPHERTEXT_KEY] = $this->encryptSecretValue($secretValue, $masterKey, $iv);
        $secrets[$secretName][self::IV_KEY] = $iv;
    }

    private function encryptSecretValue(string $secretValue, string $masterKey, string $iv)
    {
        return openssl_encrypt($secretValue, self::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
    }

    private function generateIv()
    {
        return base64_encode(random_bytes(12));
    }
}
