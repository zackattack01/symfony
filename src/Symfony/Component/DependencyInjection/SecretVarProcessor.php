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

class SecretVarProcessor implements EnvVarProcessorInterface
{
    const CIPHERTEXT_KEY = "ciphertext";

    const IV_KEY = "iv";

    const ENCRYPTION_METHOD = "aes-256-cbc";

    private $masterKeyFileLocation;

    private $encryptedSecrets;

    public function __construct(array $encryptedSecrets, $masterKeyFileLocation)
    {
        $this->masterKeyFileLocation = $masterKeyFileLocation;
        $this->encryptedSecrets = $encryptedSecrets;
    }

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
     * {@inheritdoc}
     */
    public function getEnv($prefix, $name, \Closure $getEnv)
    {
        if ('secret' === $prefix) {
            $masterKey = $this->readMasterkey($this->masterKeyFileLocation);

            $secret = $this->encryptedSecrets[$name]['ciphertext'];
            $iv = $this->encryptedSecrets[$name]['iv'];
            return $this->decryptSecretValue($secret, $masterKey, $iv);
        }

        throw new RuntimeException(sprintf('Unsupported env var prefix "%s".', $prefix));
    }

    private function readMasterKey(string $fileLocation)
    {
        if (file_exists($fileLocation)) {
            return trim(file_get_contents($fileLocation));
        } else {
            throw new RuntimeException(sprintf('No master key file found at "%s".', $fileLocation));
        }
    }

    protected function decryptSecretValue(string $secretValue, string $masterKey, string $iv)
    {
        return openssl_decrypt($secretValue, self::ENCRYPTION_METHOD, $masterKey, $options = null, $iv);
    }
}
