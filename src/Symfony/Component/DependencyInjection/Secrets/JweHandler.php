<?php

namespace Symfony\Component\DependencyInjection\Secrets;

use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

final class JweHandler
{
    private $secretsLocation;

    private $publicKey;

    private $privateKeyLocation;

    private $secrets;

    public static function initSecretsFile(string $fileLocation)
    {
        if (is_writable(pathinfo($fileLocation, PATHINFO_DIRNAME))) {
            file_put_contents($fileLocation, json_encode([]));
        } else {
            throw new InvalidArgumentException(sprintf(
                'fileLocation for secrets at %s must exist in a writable directory',
                $fileLocation
            ));
        }
    }

    public function __construct(string $secretsLocation, string $publicKeyLocation, string $privateKeyLocation = null)
    {
        $this->setPublicKeyFromLocation($publicKeyLocation);
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
     * @param string $publicKeyLocation
     */
    public function setPublicKeyFromLocation(string $publicKeyLocation): void
    {
        if ($this->isValidKeyLocation($publicKeyLocation)) {
            $this->publicKey = trim(file_get_contents($publicKeyLocation));
        } else {
            throw new InvalidArgumentException(sprintf(
                'publicKeyLocation %s must point to an existing %u byte file',
                $publicKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }
    }

    /**
     * @param string $privateKeyLocation
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

    public function addEntry(string $key, string $secret)
    {
        $this->secrets[$key] = JweEntry::encrypt($secret, $this->publicKey);
        return $this;
    }

    public function regenerateEncryptedEntries(string $plaintextLocation)
    {
        if ($this->isValidSecretsFile($plaintextLocation)) {
            $plaintextSecrets = $this->readSecrets($plaintextLocation);
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

    public function writeEncrypted()
    {
        return file_put_contents($this->secretsLocation, json_encode($this->secrets, JSON_PRETTY_PRINT));
    }

    public function writePlaintext(string $fileLocation)
    {
        $plaintextSecrets = [];
        foreach (array_keys($this->secrets) as $key) {
            $plaintextSecrets[$key] = $this->decrypt($key);
        }

        return file_put_contents($fileLocation, json_encode($plaintextSecrets, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

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

    private function collectKeyPair()
    {
        $secretKey = trim(file_get_contents($this->privateKeyLocation));
        return sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $secretKey,
            $this->publicKey
        );
    }

    private function isValidSecretsFile(string $filePath)
    {
        return (stream_is_local($filePath) && is_readable($filePath));
    }

    private function isValidKeyLocation(string $filePath)
    {
        return $this->isValidSecretsFile($filePath) &&
            (SODIUM_CRYPTO_BOX_SECRETKEYBYTES === filesize($filePath));
    }

    private function readSecrets($secretsLocation)
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

    //TODO will be for a setup command, figure out where this should live
    public static function generateKeyPair()
    {
        return sodium_crypto_box_keypair();
    }
}
