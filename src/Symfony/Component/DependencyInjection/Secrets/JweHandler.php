<?php

namespace Symfony\Component\DependencyInjection\Secrets;

use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;
use Symfony\Component\DependencyInjection\Exception\SecretsOverwriteRequiredException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\KernelInterface;

final class JweHandler
{
    const JSON_ENCODE_OPTIONS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_FORCE_OBJECT;

    private $secretsLocation;

    private $privateKeyLocation;

    private $publicKeyLocation;

    private $secrets;

    private $filesystem;

    private $configDir;

    public function __construct(string $projectDir, string $secretsLocation, string $publicKeyLocation, string $privateKeyLocation = null)
    {
        $this->configDir = $projectDir . '/config';
        $this->secretsLocation = $secretsLocation;
        $this->publicKeyLocation = $publicKeyLocation;
        $this->privateKeyLocation = $privateKeyLocation;
        $this->filesystem = new Filesystem();
    }

    public function addEntry(string $key, string $secret): void
    {
        $this->validateConfig();
        $this->secrets[$key] = JweEntry::encrypt($secret, $this->getPublicKey());
        $this->writeEncrypted();
    }

    /**
     * @throws RuntimeException if the privateKeyLocation is not configured, or a value does not exist for the required key
     */
    public function decrypt(string $key): string
    {
        $this->validateConfig($decryptRequired = true);

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
     * @throws InvalidArgumentException if the fileLocation does not exist in a writable directory or
     *                                  if the file already exists and $overwriteExisting is set to false
     */
    public function initSecretsFiles(bool $overwriteExisting): void
    {
        if (!$overwriteExisting) {
            $requiredOverwrites = array();
            if (file_exists($this->secretsLocation)) {
                $requiredOverwrites[] = $this->secretsLocation;
            }

            if (file_exists($this->publicKeyLocation)) {
                $requiredOverwrites[] = $this->publicKeyLocation;
            }

            if (file_exists($this->privateKeyLocation)) {
                $requiredOverwrites[] = $this->privateKeyLocation;
            }

            if (!empty($requiredOverwrites)) {
                throw new SecretsOverwriteRequiredException(sprintf(
                    'secrets files at %s already exist',
                    implode(', ', $requiredOverwrites)
                ), $requiredOverwrites);
            }
        }

        $this->writeFile(
            $this->secretsLocation,
            json_encode(array(), self::JSON_ENCODE_OPTIONS),
            true
        );

        $this->writeNewKeyPair(true);
    }

    /**
     * @throws InvalidArgumentException if the plaintext file does not contain valid secrets
     */
    public function regenerateEncryptedEntries(string $plaintextLocation): void
    {
        $this->validateConfig();
        if ($this->isValidSecretsFile($plaintextLocation) &&
            false !== $plaintextSecrets = $this->readSecrets($plaintextLocation)) {
            $this->secrets = array();
            foreach ($plaintextSecrets as $key => $secret) {
                if (!preg_match('/^(?:\w++:)*+\w++$/', $key)) {
                    throw new \InvalidArgumentException(sprintf(
                        'The name for %s is invalid, secrets cannot be updated. Only "word" characters can be used in variable names.',
                        $key
                    ));
                }

                $this->secrets[$key] = JweEntry::encrypt($secret, $this->getPublicKey());
            }
        } else {
            throw new InvalidArgumentException(sprintf(
                'plaintext key location %s must point to a file with valid json secrets',
                $plaintextLocation
            ));
        }

        $this->writeEncrypted();
    }

    /**
     * generates a new key pair, and writes it to the configured public and private key locations after re-encrypting secrets.
     *
     * @throws InvalidArgumentException if the $publicKeyLocation or $privateKeyLocation cannot be written
     */
    public function updateKeyPair(): void
    {
        $tempSecretsLocation = tempnam(sys_get_temp_dir(), '');
        try {
            //TODO should probably add a temp backup and make this behave like a transaction
            $this->writePlaintext($tempSecretsLocation);
            $this->writeNewKeyPair();
            $this->regenerateEncryptedEntries($tempSecretsLocation);
        } finally {
            unlink($tempSecretsLocation);
        }
    }

    /**
     * @throws InvalidArgumentException if the secretsLocation does not point to a readable secrets file with valid json,
     *                                  or if the public and private key files do not point to existing, readable files with 32 byte key values
     */
    public function validateConfig(bool $decryptRequired = false): void
    {
        if (!$this->isValidSecretsFile($this->secretsLocation)) {
            throw new InvalidArgumentException(sprintf(
                'encrypted_secrets.secrets_file location %s must point to an existing, readable file',
                $this->secretsLocation
            ));
        }

        if (false === $this->populateSecrets()) {
            throw new InvalidArgumentException(sprintf(
                'encrypted_secrets.secrets_file location %s must contain valid json secrets',
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

        if ($decryptRequired && !isset($this->privateKeyLocation)) {
            throw new InvalidArgumentException('encrypted_secrets must be configured with a private_key_file location to read secrets.');
        }

        if ($decryptRequired && !$this->isValidKeyLocation($this->privateKeyLocation)) {
            throw new InvalidArgumentException(sprintf(
                'the configuration for encrypted_secrets.private_key_file (%s) must point to an existing %u byte file',
                $this->privateKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }
    }

    /**
     * Decrypts all populated secrets and writes the plaintext to the provided $fileLocation.
     */
    public function writePlaintext(string $fileLocation): void
    {
        $this->validateConfig($decryptRequired = true);
        $plaintextSecrets = array();
        foreach (array_keys($this->secrets) as $key) {
            $plaintextSecrets[$key] = $this->decrypt($key);
        }

        $this->writeFile($fileLocation, json_encode($plaintextSecrets, self::JSON_ENCODE_OPTIONS));
    }

    /**
     * helper method to format a sodium crypto box keypair from the configured public and private key values.
     *
     * @return string
     */
    private function collectKeyPair()
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $this->getPrivateKey(),
            $this->getPublicKey()
        );
    }

    private function getPrivateKey(): string
    {
        return $this->readKey($this->privateKeyLocation);
    }

    private function getPublicKey(): string
    {
        return $this->readKey($this->publicKeyLocation);
    }

    private function isValidKeyLocation(string $filePath): bool
    {
        return $this->isValidSecretsFile($filePath) &&
            (SODIUM_CRYPTO_BOX_SECRETKEYBYTES === filesize($filePath));
    }

    private function isValidSecretsFile(string $filePath): bool
    {
        return stream_is_local($filePath) && is_readable($filePath);
    }

    /**
     * @return array|false
     */
    private function populateSecrets()
    {
        return $this->secrets = $this->readSecrets($this->secretsLocation);
    }

    private function readKey(string $keyLocation)
    {
        return file_get_contents($keyLocation);
    }

    /**
     * returns the decoded json secrets from $secretsLocation or false if the file does not contain valid json.
     *
     * @return array|false
     */
    private function readSecrets(string $secretsLocation)
    {
        $rawSecrets = file_get_contents($secretsLocation);

        return json_decode($rawSecrets, true);
    }

    private function writeEncrypted(): void
    {
        $this->writeFile($this->secretsLocation, json_encode($this->secrets, self::JSON_ENCODE_OPTIONS));
    }

    private function writeFile(string $fileLocation, string $content, $makeConfigDir = false): void
    {
        $dir = \dirname($fileLocation);

        if (!is_dir($dir)) {
            if ($makeConfigDir && (\dirname($dir) === $this->configDir)) {
                $this->filesystem->mkdir($dir);
            } else {
                throw new InvalidArgumentException(sprintf(
                    'directory %s for %s does not exist',
                    $dir,
                    $fileLocation
                ));
            }
        }

        if (!file_exists($fileLocation) && is_writable($dir)) {
            $this->filesystem->touch($fileLocation);
        }

        if (!is_writable($fileLocation)) {
            throw new InvalidArgumentException(sprintf(
                'file location for encrypted secrets at %s must exist in a writable directory',
                $fileLocation
            ));
        }

        file_put_contents($fileLocation, $content);
    }

    private function writeNewKeyPair($makeConfigDir = false): void
    {
        $newKeyPair = sodium_crypto_box_keypair();
        $this->writeFile($this->privateKeyLocation, sodium_crypto_box_secretkey($newKeyPair), $makeConfigDir);
        $this->writeFile($this->publicKeyLocation, sodium_crypto_box_publickey($newKeyPair), $makeConfigDir);
    }
}
