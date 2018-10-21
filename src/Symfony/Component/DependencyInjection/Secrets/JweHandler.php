<?php

namespace Symfony\Component\DependencyInjection\Secrets;

use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

final class JweHandler
{
    const JSON_ENCODE_OPTIONS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_FORCE_OBJECT;

    private $secretsLocation;

    private $privateKeyLocation;

    private $publicKeyLocation;

    private $secrets;

    public function __construct(string $secretsLocation, string $publicKeyLocation, string $privateKeyLocation = null)
    {
        $this->secretsLocation = $secretsLocation;
        $this->publicKeyLocation = $publicKeyLocation;
        $this->privateKeyLocation = $privateKeyLocation;
        if ($this->isValidSecretsFile($this->secretsLocation) && $secrets = $this->readSecrets($this->secretsLocation)) {
            $this->secrets = $secrets;
        }
    }

    /**
     * @return $this
     */
    public function addEntry(string $key, string $secret)
    {
        $this->secrets[$key] = JweEntry::encrypt($secret, $this->getPublicKey());
        $this->writeEncrypted();
        return $this;
    }

    /**
     * @return string
     *
     * @throws RuntimeException if the privateKeyLocation is not configured, or a value does not exist for the required key
     */
    public function decrypt(string $key)
    {
        if (!isset($this->privateKeyLocation)) {
            throw new RuntimeException('encrypted_secrets must be configured with an private_key_file location to read secrets.');
        }

        if (!isset($this->secrets[$key])) {
            throw new RuntimeException(sprintf(
                'Secret value for %s does not exist in %s',
                $key,
                $this->secretsLocation
            ));
        }

        return JweEntry::decrypt($this->secrets[$key], $this->collectKeyPair());
    }

    /**
     * @return $this
     *
     * @throws InvalidArgumentException if the plaintext file does not contain valid secrets
     */
    public function regenerateEncryptedEntries(string $plaintextLocation)
    {
        if ($this->isValidSecretsFile($plaintextLocation) && $plaintextSecrets = $this->readSecrets($plaintextLocation)) {
            $this->secrets = [];
            foreach ($plaintextSecrets as $key => $secret) {
                $this->addEntry($key, $secret);
            }
        } else {
            throw new InvalidArgumentException(sprintf(
                'plaintext key location %s must point to a file with valid json secrets',
                $plaintextLocation
            ));
        }

        $this->writeEncrypted();
        return $this;
    }

    /**
     * generates a new key pair, and writes it to the configured public and private key locations after re-encrypting secrets
     *
     * @throws InvalidArgumentException if the $publicKeyLocation or $privateKeyLocation cannot be written
     */
    public function updateKeyPair()
    {
        $tempSecretsLocation = tempnam(sys_get_temp_dir(), "");
        try {
            //TODO should probably add a temp backup and make this behave like a transaction
            $this->writePlaintext($tempSecretsLocation)
                 ->writeNewKeyPair()
                 ->regenerateEncryptedEntries($tempSecretsLocation)
                 ->writeEncrypted();
        } finally {
            unlink($tempSecretsLocation);
        }
    }

    /**
     * @throws InvalidArgumentException if the secretsLocation does not point to a readable secrets file with valid json,
     * or if the public and private key files do not point to existing, readable files with 32 byte key values
     */
    public function validateConfig(bool $decryptRequired = false)
    {
        if (!$this->isValidSecretsFile($this->secretsLocation) || !$this->readSecrets($this->secretsLocation)) {
             throw new InvalidArgumentException(sprintf(
                'secretsLocation %s must point to an existing, readable file with valid json secrets',
                $this->secretsLocation
            ));
        }

        if (!$this->isValidKeyLocation($this->publicKeyLocation)) {
            throw new InvalidArgumentException(sprintf(
                'publicKeyLocation %s must point to an existing %u byte file',
                $this->publicKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }

        if ($decryptRequired && (!isset($this->privateKeyLocation) || !$this->isValidKeyLocation($this->privateKeyLocation))) {
            throw new InvalidArgumentException(sprintf(
                'the configuration for encrypted_secrets.private_key_file (%s) must point to an existing %u byte file',
                $this->privateKeyLocation ?? "not set",
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }

        return $this;
    }

    /**
     * Decrypts all populated secrets and writes the plaintext to the provided $fileLocation
     * @return $this
     */
    public function writePlaintext(string $fileLocation)
    {
        $plaintextSecrets = [];
        $this->populateSecrets();
        foreach (array_keys($this->secrets) as $key) {
            $plaintextSecrets[$key] = $this->decrypt($key);
        }

        $this->writeFile($fileLocation, json_encode($plaintextSecrets, self::JSON_ENCODE_OPTIONS));
        return $this;
    }

    /**
     * helper method to format a sodium crypto box keypair from the configured public and private key values
     * @return string
     */
    private function collectKeyPair()
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $this->getPrivateKey(),
            $this->getPublicKey()
        );
    }

    /**
     * @return string
     */
    private function getPrivateKey()
    {
        return $this->readKey($this->privateKeyLocation);
    }

    /**
     * @return string
     */
    private function getPublicKey()
    {
        return $this->readKey($this->publicKeyLocation);
    }

    /**
     * @throws InvalidArgumentException if the fileLocation does not exist in a writable directory or
     * if the file already exists and $overwriteExisting is set to false
     */
    public function initSecretsFiles(bool $overwriteExisting)
    {
        if (!$overwriteExisting) {
            if (file_exists($this->secretsLocation)) {
                throw new InvalidArgumentException(sprintf(
                    'secrets file at %s already exists',
                    $this->secretsLocation
                ));
            }

            if (file_exists($this->publicKeyLocation)) {
                throw new InvalidArgumentException(sprintf(
                    'public key file at %s already exists',
                    $this->publicKeyLocation
                ));
            }

            if (file_exists($this->privateKeyLocation)) {
                throw new InvalidArgumentException(sprintf(
                    'private key file at %s already exists',
                    $this->privateKeyLocation
                ));
            }
        }

        $this->writeFile($this->secretsLocation, json_encode([], self::JSON_ENCODE_OPTIONS));
        $this->writeNewKeyPair();
        return $this;
    }

    /**
     * @return bool
     */
    private function isValidKeyLocation(string $filePath)
    {
        return $this->isValidSecretsFile($filePath) &&
            (SODIUM_CRYPTO_BOX_SECRETKEYBYTES === filesize($filePath));
    }

    /**
     * @return bool
     */
    private function isValidSecretsFile(string $filePath)
    {
        return (stream_is_local($filePath) && is_readable($filePath));
    }

    /**
     * @return array
     */
    private function populateSecrets()
    {
        $this->secrets = $this->readSecrets($this->secretsLocation);
        return $this;
    }

    private function readKey(string $keyLocation)
    {
        return trim(file_get_contents($keyLocation));
    }

    /**
     * returns the decoded json secrets from $secretsLocation or false if the file does not contain valid json
     * @return array|false
     */
    private function readSecrets(string $secretsLocation)
    {
        $rawSecrets = trim(file_get_contents($secretsLocation));

        return json_decode($rawSecrets, true);
    }

    /**
     * @return $this
     */
    private function writeEncrypted()
    {
        $this->writeFile($this->secretsLocation, json_encode($this->secrets, self::JSON_ENCODE_OPTIONS));
        return $this;
    }

    private function writeFile(string $fileLocation, string $content)
    {
        $fileDir = pathinfo($fileLocation, PATHINFO_DIRNAME);
        if (!is_dir($fileDir) || !is_writeable($fileLocation)) {
            throw new InvalidArgumentException(sprintf(
                'file location for secrets at %s must exist in a writable directory',
                $fileLocation
            ));
        }

        return file_put_contents($fileLocation, $content) > 0;
    }

    private function writeNewKeyPair()
    {
        $newKeyPair = sodium_crypto_box_keypair();
        $this->writeFile($this->privateKeyLocation, sodium_crypto_box_secretkey($newKeyPair));
        $this->writeFile($this->publicKeyLocation, sodium_crypto_box_publickey($newKeyPair));

        return $this;
    }
}
