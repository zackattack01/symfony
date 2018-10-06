<?php

namespace Symfony\Component\DependencyInjection\Secrets;

use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

class JweHandler
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
        if ($this->isValidKeyLocation($publicKeyLocation)) {
            $this->publicKey = trim(file_get_contents($publicKeyLocation));
        } else {
            throw new InvalidArgumentException(sprintf(
                'publicKeyLocation %s must point to an existing %u byte file',
                [$publicKeyLocation, SODIUM_CRYPTO_BOX_SECRETKEYBYTES]
            ));
        }

        if (is_null($privateKeyLocation) || $this->isValidKeyLocation($privateKeyLocation)) {
            $this->privateKeyLocation = $privateKeyLocation;
        } else {
            throw new InvalidArgumentException(sprintf(
                'privateKeyLocation %s must point to an existing %u byte file',
                $privateKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }

        if ($this->isValidSecretsFile($secretsLocation) &&
            (false !== $this->populateSecrets($secretsLocation))) {
            $this->secretsLocation = $secretsLocation;
        } else {
            throw new InvalidArgumentException(sprintf(
                'secretsLocation %s must point to an existing file with valid json secrets',
                $secretsLocation
            ));
        }
    }

    public function addEntry(string $key, string $secret)
    {
        $this->secrets[$key] = JweEntry::encrypt($secret, $this->publicKey);
        return $this;
    }

    public function write()
    {
        return file_put_contents($this->secretsLocation, json_encode($this->secrets, JSON_PRETTY_PRINT));
    }

    public function read()
    {
        if (!isset($this->privateKeyLocation)) {
            throw new RuntimeException(sprintf(
               '%s must be initialized with a secret key file location to read secrets.',
               get_class($this)
            ));
        }

        $keyPair = $this->collectKeyPair();

        $decrypted = [];
        foreach($this->secrets as $key => $value) {
            $decrypted[$key] = JweEntry::decrypt($value, $keyPair);
        }

        return $decrypted;
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

    private function populateSecrets($secretsLocation)
    {
        $rawSecrets = trim(file_get_contents($secretsLocation));
        return $this->secrets = json_decode($rawSecrets, true);
    }

    //TODO will be for a setup command, figure out where this should live
    public static function generateKeyPair()
    {
        return sodium_crypto_box_keypair();
    }
}