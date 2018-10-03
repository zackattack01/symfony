<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\DependencyInjection;

use Symfony\Component\DependencyInjection\Exception\RuntimeException;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;

class SecretVarProcessor implements EnvVarProcessorInterface
{
    const CIPHERTEXT_KEY = 'ciphertext';

    const IV_KEY = 'iv';

    const ENCRYPTION_METHOD = 'aes-256-cbc';

    private $masterKeyLocation;

    private $encryptedSecrets = [];

    private $configuration = [];

    /**
     * {@inheritdoc}
     */
    public static function getProvidedTypes()
    {
        return array(
            'secret' => 'string'
        );
    }

    /**
     * @param string $masterKeyLocation
     * @param string $secretsLocation
     */
    public function configureEncryptedSecrets(string $masterKeyLocation, string $secretsLocation)
    {
        $this->setMasterKeyFileLocation($masterKeyLocation);
        $this->configuration['master_key_file'] = $masterKeyLocation;
        $this->setEncryptedSecretsFromLocation($secretsLocation);
        $this->configuration['secrets_file'] = $secretsLocation;
    }

    /**
     * {@inheritdoc}
     */
    public function getEnv($prefix, $name, \Closure $getEnv)
    {
        if ('secret' === $prefix) {
            if (!empty($this->getConfiguration())) {
                if (isset($this->encryptedSecrets[$name])) {
                    return $this->decryptSecretValue($this->encryptedSecrets[$name]);
                } else {
                    throw new RuntimeException(sprintf(
                        "Missing secret variable %s in encrypted secrets",
                        $name
                    ));
                }
            } else {
                throw new RuntimeException(sprintf(
                    '"%s" must be configured through configureEncryptedSecrets before use',
                    get_class($this)
                ));
            }
        }

        throw new RuntimeException(sprintf('Unsupported env var prefix "%s".', $prefix));
    }

    public function getConfiguration()
    {
        return $this->configuration;
    }

    /**
     * @return array
     */
    public function getEncryptedSecrets()
    {
        return $this->encryptedSecrets;
    }

    /**
     * @param string $keyFileLocation
     * @return SecretVarProcessor
     *
     * @throws InvalidArgumentException When master key file is not valid
     */
    private function setMasterKeyFileLocation(string $keyFileLocation)
    {
        $this->readValidatedFileContent($keyFileLocation);

        $this->masterKeyLocation = $keyFileLocation;
        return $this;
    }

    /**
     * @param string $encryptedSecretsLocation
     * @return SecretVarProcessor
     *
     * @throws InvalidArgumentException When secrets file does not exist or contain valid json secrets
     */
    private function setEncryptedSecretsFromLocation(string $encryptedSecretsLocation)
    {
        $secretsContent = $this->readValidatedFileContent($encryptedSecretsLocation);
        $secrets = json_decode($secretsContent, true);
        if (false === $secrets) {
            throw new InvalidArgumentException(sprintf('%s should contain a valid JSON array. Check your JSON syntax.', $encryptedSecretsLocation));
        }
        $this->validateEncryptedSecrets($secrets);
        $this->encryptedSecrets = $secrets;

        return $this;
    }

    private function validateEncryptedSecrets(array $secrets)
    {
        if (is_array($secrets)) {
            foreach ($secrets as $key => $encryptedValues) {
                if (!isset($encryptedValues[self::CIPHERTEXT_KEY]) || !is_string($encryptedValues[self::CIPHERTEXT_KEY])) {
                    throw new InvalidArgumentException(sprintf('The encrypted secrets entry for %s should contain a string "ciphertext" entry.', $key));
                }

                if (!isset($encryptedValues[self::IV_KEY]) || !is_string($encryptedValues[self::IV_KEY])) {
                    throw new InvalidArgumentException(sprintf('The encrypted secrets entry for %s should contain a string "iv" entry.', $key));
                }

                //verify that the provided key works for all values being set
                $this->decryptSecretValue($encryptedValues);
            }
        } else {
            throw new InvalidArgumentException('Encrypted secrets should decode to a valid JSON array. Check your JSON syntax.');
        }
    }

    private function readValidatedFileContent(string $filePath)
    {
        if (!stream_is_local($filePath)) {
            throw new InvalidArgumentException(sprintf('The file at "%s" is not a local file .', $filePath));
        }

        if (!file_exists($filePath)) {
            throw new InvalidArgumentException(sprintf('The file at "%s" does not exist.', $filePath));
        }

        $content = trim(file_get_contents($filePath));
        if ("" === $content) {
            throw new InvalidArgumentException(sprintf('The file at "%s" is empty', $filePath));
        }

        return $content;
    }

    private function getMasterKey()
    {
        return trim(file_get_contents($this->masterKeyLocation));
    }

    public function decryptSecretValue(array $secretsEntry)
    {
        $secretValue = $secretsEntry[self::CIPHERTEXT_KEY];
        $iv = $secretsEntry[self::IV_KEY];

        $plaintextSecret = openssl_decrypt($secretValue, self::ENCRYPTION_METHOD, $this->getMasterKey(), $options = null, $iv);
        if (false === $plaintextSecret) {
            throw new RuntimeException(sprintf(
                'Unable to decrypt secret value %s. Verify the password provided.',
                $secretValue
            ));
        }

        return $plaintextSecret;
    }

    public function generateEncryptedEntry(string $secretValue, string $iv)
    {
        $entry = [];
        $entry[self::CIPHERTEXT_KEY] = $this->encryptSecretValue($secretValue, $iv);
        $entry[self::IV_KEY] = $iv;
        return $entry;
    }

    private function encryptSecretValue(string $secretValue, string $iv)
    {
        return openssl_encrypt($secretValue, SecretVarProcessor::ENCRYPTION_METHOD, $this->getMasterKey(), $options = null, $iv);
    }
}
