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

    private $configDir;

    private $filesystem;

    private $encryptedSecrets;

    private $encryptedLocation;

    private $plaintextLocation;

    private $privateKeyLocation;

    private $publicKeyLocation;


    public function __construct(string $projectDir, string $encryptedLocation, string $publicKeyLocation, string $privateKeyLocation = null)
    {
        $this->configDir = $projectDir . '/config';
        $this->encryptedLocation = $encryptedLocation;
        $this->publicKeyLocation = $publicKeyLocation;
        $this->privateKeyLocation = $privateKeyLocation;
        $this->filesystem = new Filesystem();
    }

    public function addEntry(string $key, string $secret): void
    {
        $secrets = $this->getEncryptedSecrets();
        $secrets[$key] = JweEntry::encrypt($secret, $this->getPublicKey());
        $this->setSecrets($secrets);
        $this->writeEncrypted();
    }

    /**
     * @throws RuntimeException if the privateKeyLocation is not configured, or a value does not exist for the required key
     */
    public function decrypt(string $key): string
    {
        $secrets = $this->getEncryptedSecrets();

        if (!isset($secrets[$key])) {
            throw new RuntimeException(sprintf(
                'Secret value for %s does not exist in %s',
                $key,
                $this->encryptedLocation
            ));
        }

        $keyPair = $this->collectKeyPair();

        return JweEntry::decrypt($secrets[$key], $keyPair);
    }

    /**
     * @throws InvalidArgumentException if the fileLocation does not exist in a writable directory or
     *                                  if the file already exists and $overwriteExisting is set to false
     */
    public function initSecretsFiles(bool $overwriteExisting): void
    {
        if (!$overwriteExisting) {
            $requiredOverwrites = array();
            if (file_exists($this->encryptedLocation)) {
                $requiredOverwrites[] = $this->encryptedLocation;
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
            $this->encryptedLocation,
            json_encode(array(), self::JSON_ENCODE_OPTIONS),
            true
        );

        $this->writeKeyPair();
    }

    /**
     * @throws InvalidArgumentException if the plaintext file does not contain valid secrets
     */
    public function regenerateEncryptedEntries(): void
    {
        $plaintextSecrets = $this->getPlaintextSecrets();
        $encryptedSecrets = array();
        foreach ($plaintextSecrets as $key => $secret) {
            if (!preg_match('/^(?:\w++:)*+\w++$/', $key)) {
                throw new \InvalidArgumentException(sprintf(
                    'The name for %s is invalid, secrets cannot be updated. Only "word" characters can be used in variable names.',
                    $key
                ));
            }

            $encryptedSecrets[$key] = JweEntry::encrypt($secret, $this->getPublicKey());
        }

        $this->setSecrets($encryptedSecrets);
        $this->writeEncrypted();
    }

    /**
     * generates a new key pair, and writes it to the configured public and private key locations after re-encrypting secrets.
     *
     * @throws InvalidArgumentException if the $publicKeyLocation or $privateKeyLocation cannot be written
     */
    public function updateKeyPair(): void
    {
        $backupSecrets = $this->getEncryptedSecrets();
        $backupKeyPair = $this->collectKeyPair();
        $tempSecretsLocation = tempnam(sys_get_temp_dir(), '');
        try {
            $this->writePlaintext($tempSecretsLocation);
            $this->writeKeyPair();
            $this->regenerateEncryptedEntries();
        } catch (\Exception $e) {
            $this->setSecrets($backupSecrets);
            $this->writeEncrypted();
            $this->writeKeyPair($backupKeyPair);

            throw new RuntimeException(sprintf(
                "Unable to update keypair (%s). The existing keypair and secrets have been restored.",
                $e->getMessage()
            ));
        } finally {
            unlink($tempSecretsLocation);
        }
    }

    /**
     * Decrypts all populated secrets and writes the plaintext to the provided $fileLocation.
     */
    public function writePlaintext(string $fileLocation): void
    {
        $encryptedSecrets = $this->getEncryptedSecrets();
        $plaintextSecrets = array();
        foreach (array_keys($encryptedSecrets) as $key) {
            $plaintextSecrets[$key] = $this->decrypt($key);
        }

        $this->writeFile($fileLocation, json_encode($plaintextSecrets, self::JSON_ENCODE_OPTIONS));
        $this->plaintextLocation = $fileLocation;
    }

    /**
     * helper method to format a sodium crypto box keypair from the configured public and private key values.
     */
    private function collectKeyPair(): string
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $this->getPrivateKey(),
            $this->getPublicKey()
        );
    }

    /**
     * @throws RuntimeException if the secretsLocation is not set
     */
    private function getEncryptedSecrets(): array
    {
        if (isset($this->encryptedSecrets)) {
            return $this->encryptedSecrets;
        }

        if (!isset($this->encryptedLocation)) {
            throw new RuntimeException('Encrypted secrets location must be set to read secrets');
        }

        return $this->readSecrets($this->encryptedLocation);
    }

    private function getPlaintextSecrets()
    {
        if (!isset($this->plaintextLocation)) {
            throw new RuntimeException('Plaintext secrets location must be set to read decrypted secrets');
        }

        return $this->readSecrets($this->plaintextLocation);
    }

    private function getPrivateKey(): string
    {
        if (!isset($this->privateKeyLocation)) {
            throw new InvalidArgumentException('encrypted_secrets must be configured with a private_key_file location to read secrets.');
        }

        if (!$this->isValidKeyLocation($this->privateKeyLocation)) {
            throw new InvalidArgumentException(sprintf(
                'the configuration for encrypted_secrets.private_key_file (%s) must point to an existing %u byte file',
                $this->privateKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }

        return $this->readKey($this->privateKeyLocation);
    }

    private function getPublicKey(): string
    {
        if (!$this->isValidKeyLocation($this->publicKeyLocation)) {
            throw new InvalidArgumentException(sprintf(
                'publicKeyLocation %s must point to an existing %u byte file',
                $this->publicKeyLocation,
                SODIUM_CRYPTO_BOX_SECRETKEYBYTES
            ));
        }

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

    private function readKey(string $keyLocation)
    {
        return file_get_contents($keyLocation);
    }

    /**
     * returns the decoded json secrets from $secretsLocation
     *
     * @throws InvalidArgumentException if the secrets file does not exist or does not point to valid json secrets
     */
    private function readSecrets(string $secretsLocation): array
    {
        if (!$this->isValidSecretsFile($secretsLocation)) {
            throw new InvalidArgumentException(sprintf(
                'encrypted secrets location %s must point to an existing, readable file',
                $secretsLocation
            ));
        }

        $rawSecrets = file_get_contents($secretsLocation);
        $secrets = json_decode($rawSecrets, true);

        if (false === $secrets) {
            throw new InvalidArgumentException(sprintf(
                'encrypted_secrets.secrets_file location %s must contain valid json secrets',
                $secretsLocation
            ));
        }

        return $secrets;
    }

    private function setSecrets(array $secrets): void
    {
        $this->encryptedSecrets = $secrets;
    }

    private function writeEncrypted(): void
    {
        $this->writeFile($this->encryptedLocation, json_encode($this->getEncryptedSecrets(), self::JSON_ENCODE_OPTIONS));
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

    /**
     * writes $keyPair to the configured key file locations, generates new keys if no $keyPair is provided
     */
    private function writeKeyPair(string $keyPair = null): void
    {
        if (null === $keyPair) {
            $keyPair = sodium_crypto_box_keypair();
        }

        $this->writeFile($this->privateKeyLocation, sodium_crypto_box_secretkey($keyPair));
        $this->writeFile($this->publicKeyLocation, sodium_crypto_box_publickey($keyPair));
    }
}
