<?php

namespace Symfony\Component\DependencyInjection\Secrets;

use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

final class JweHandler
{
    private $secretsLocation;

    private $publicKey;

    private $privateKeyLocation;

    private $publicKeyLocation;

    private $secrets;

    /**
     * @param string $fileLocation
     *
     * @throws InvalidArgumentException if the fileLocation does not exist in a writable directory
     */
    public static function initSecretsFile(string $fileLocation)
    {
        if (is_writeable(pathinfo($fileLocation, PATHINFO_DIRNAME))) {
            file_put_contents($fileLocation, json_encode([], JSON_FORCE_OBJECT));
        } else {
            throw new InvalidArgumentException(sprintf(
                'fileLocation for secrets at %s must exist in a writable directory',
                $fileLocation
            ));
        }
    }

    /**
     * JweHandler constructor.
     * @param string $secretsLocation
     * @param string $publicKeyLocation
     * @param string|null $privateKeyLocation
     */
    public function __construct(string $secretsLocation, string $publicKeyLocation, string $privateKeyLocation = null)
    {
        $this->setPublicKeyInfo($publicKeyLocation);
        $this->setSecretsFromLocation($secretsLocation);
        if (isset($privateKeyLocation)) {
            $this->setPrivateKeyLocation($privateKeyLocation);
        }
    }

    /**
     * @return string
     */
    public function getSecretsLocation(): string
    {
        return $this->secretsLocation;
    }

    /**
     * @param string $secretsLocation
     *
     * @throws InvalidArgumentException if the secretsLocation does not point to a readable secrets file with valid json
     */
    public function setSecretsFromLocation(string $secretsLocation): void
    {
        if ($this->isValidSecretsFile($secretsLocation)) {
            $this->secrets = $this->readSecrets($secretsLocation);
            $this->secretsLocation = $secretsLocation;
        } else {
            throw new InvalidArgumentException(sprintf(
                'secretsLocation %s must point to an existing, readable file',
                $secretsLocation
            ));
        }
    }

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * sets publicKeyLocation and caches publicKey if publicKeyLocation is a readable, 32 byte key file
     * @param string $publicKeyLocation
     *
     * @throws InvalidArgumentException if the publicKeyLocation does not point to a readable, 32 byte key file
     */
    public function setPublicKeyInfo(string $publicKeyLocation): void
    {
        if ($this->isValidKeyLocation($publicKeyLocation)) {
            $this->publicKey = trim(file_get_contents($publicKeyLocation));
            $this->publicKeyLocation = $publicKeyLocation;
        } else {
            throw new InvalidArgumentException(sprintf(
                'publicKeyLocation %s must point to an existing %u byte file',
                $publicKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }
    }

    /**
     * sets privateKeyLocation
     * @param string $privateKeyLocation
     *
     * @throws InvalidArgumentException if the privateKeyLocation does not point to a readable, 32 byte key file
     */
    public function setPrivateKeyLocation(string $privateKeyLocation): void
    {
        if ($this->isValidKeyLocation($privateKeyLocation)) {
            $this->privateKeyLocation = $privateKeyLocation;
        } else {
            throw new InvalidArgumentException(sprintf(
                'privateKeyLocation %s must point to an existing %u byte file',
                $privateKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }
    }

    /**
     * @param string $key
     * @param string $secret
     * @return $this
     */
    public function addEntry(string $key, string $secret)
    {
        $this->secrets[$key] = JweEntry::encrypt($secret, $this->publicKey);
        return $this;
    }

    /**
     * @param string $plaintextLocation
     * @return $this
     *
     * @throws InvalidArgumentException if the plaintext file does not contain valid secrets
     */
    public function regenerateEncryptedEntries(string $plaintextLocation)
    {
        if ($this->isValidSecretsFile($plaintextLocation)) {
            $plaintextSecrets = $this->readSecrets($plaintextLocation);
            $this->secrets = [];
            foreach ($plaintextSecrets as $key => $secret) {
                $this->addEntry($key, $secret);
            }
        } else {
            throw new InvalidArgumentException(sprintf(
                'plaintextLocation %s must point to a file with valid json secrets',
                $plaintextLocation
            ));
        }

        return $this;
    }

    /**
     * @return $this
     */
    public function writeEncrypted()
    {
        file_put_contents($this->secretsLocation, json_encode($this->secrets, JSON_PRETTY_PRINT));
        return $this;
    }

    /**
     * Decrypts all populated secrets and writes the plaintext to the provided $fileLocation
     * @param string $fileLocation
     * @return $this
     */
    public function writePlaintext(string $fileLocation)
    {
        $plaintextSecrets = [];
        foreach (array_keys($this->secrets) as $key) {
            $plaintextSecrets[$key] = $this->decrypt($key);
        }

        file_put_contents($fileLocation, json_encode($plaintextSecrets, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        return $this;
    }

    /**
     * @param string $key
     * @return string
     *
     * @throws RuntimeException if the privateKeyLocation is not configured, or a value does not exist for the required key
     */
    public function decrypt(string $key)
    {
        if (!isset($this->privateKeyLocation)) {
            throw new RuntimeException(sprintf(
                '%s must be initialized with a secret key file location to read secrets.',
                get_class($this)
            ));
        }

        if (!isset($this->secrets[$key])) {
            throw new RuntimeException(sprintf(
                'Secret value for %s does not exist in %s',
                $key,
                $this->secretsLocation
            ));
        }

        $keyPair = $this->collectKeyPair();

        return JweEntry::decrypt($this->secrets[$key], $keyPair);
    }

    /**
     * helper method to format a sodium crypto box keypair from the configured public and private key values
     * @return string
     */
    private function collectKeyPair()
    {
        $secretKey = trim(file_get_contents($this->privateKeyLocation));
        return sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $secretKey,
            $this->publicKey
        );
    }

    /**
     * @param string $filePath
     * @return bool
     */
    private function isValidSecretsFile(string $filePath)
    {
        return (stream_is_local($filePath) && is_readable($filePath));
    }

    /**
     * @param string $filePath
     * @return bool
     */
    private function isValidKeyLocation(string $filePath)
    {
        return $this->isValidSecretsFile($filePath) &&
            (SODIUM_CRYPTO_BOX_SECRETKEYBYTES === filesize($filePath));
    }


    /**
     * @param string $secretsLocation
     * @return array
     *
     * @throws InvalidArgumentException if the $secretsLocation file does not contain valid json secrets
     */
    private function readSecrets(string $secretsLocation)
    {
        $rawSecrets = trim(file_get_contents($secretsLocation));
        $secrets = json_decode($rawSecrets, true);
        if (false === $secrets) {
            throw new InvalidArgumentException(sprintf(
                'secretsLocation %s must point to a file with valid json secrets',
                $secretsLocation
            ));
        }

        return $secrets;
    }

    /**
     * generates a new key pair and writes it to the configured public and private key locations
     * @return $this
     *
     * @throws InvalidArgumentException if the $publicKeyLocation or $privateKeyLocation cannot be written
     */
    public function updateKeyPair()
    {
        if (is_writeable(pathinfo($this->privateKeyLocation, PATHINFO_DIRNAME)) &&
            is_writeable(pathinfo($this->publicKeyLocation, PATHINFO_DIRNAME))) {

            $newKeyPair = sodium_crypto_box_keypair();
            file_put_contents($this->publicKeyLocation, sodium_crypto_box_publickey($newKeyPair));
            file_put_contents($this->privateKeyLocation, sodium_crypto_box_secretkey($newKeyPair));
        } else {
            throw new InvalidArgumentException(sprintf(
                'File locations for public and private keys at %s and %s must exist in writable directories',
                $this->publicKeyLocation,
                $this->privateKeyLocation
            ));
        }

        return $this;
    }

    /**
     * @return string
     */
    public function getPublicKeyLocation()
    {
        return $this->publicKeyLocation;
    }
}
