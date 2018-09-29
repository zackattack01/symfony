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

use Symfony\Bundle\FrameworkBundle\Secrets\SecretsHandlerTrait;

class SecretVarProcessor implements EnvVarProcessorInterface
{
    use SecretsHandlerTrait;

    const SUPPORTS_ENCRYPTED_SECRETS = 'encrypted_secrets.enabled';
    const SECRETS_FILE_PARAMETER = 'encrypted_secrets.secrets_file';
    const MASTER_KEY_PARAMETER = 'encrypted_secrets.master_key_file';
    
    private $container;

    private $encryptedFileLocation;

    private $masterKeyFileLocation;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        if ($this->container->hasParameter(self::SECRETS_FILE_PARAMETER)) {
            $this->encryptedFileLocation = $this->container->getParameter(self::SECRETS_FILE_PARAMETER);
        }

        if ($this->container->hasParameter(self::MASTER_KEY_PARAMETER)) {
            $this->masterKeyFileLocation = $this->container->getParameter(self::MASTER_KEY_PARAMETER);
        }
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
            if (is_null($this->masterKeyFileLocation)) {
                throw new RuntimeException(sprintf('"%s" value must be set in framework.yaml to use the secret: ENV prefix', self::MASTER_KEY_PARAMETER));
            }

            if (is_null($this->encryptedFileLocation)) {
                throw new RuntimeException(sprintf('"%s" value must be set in framework.yaml to use the secret: ENV prefix', self::SECRETS_FILE_PARAMETER));
            }

            $masterKey = $this->readMasterkey($this->masterKeyFileLocation);
            $encryptedSecret = $this->fetchSingleSecret($this->encryptedFileLocation, $name);
            $secret = $encryptedSecret["ciphertext"];
            $iv = $encryptedSecret["iv"];
            return $this->decryptSecretValue($secret, $masterKey, $iv);
            
        }

        throw new RuntimeException(sprintf('Unsupported env var prefix "%s".', $prefix));
    }


}
