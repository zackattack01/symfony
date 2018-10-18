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
use Symfony\Component\DependencyInjection\Secrets\JweHandler;

final class SecretVarProcessor implements EnvVarProcessorInterface
{
    private $secretsHandler;

    public function __construct(JweHandler $secretsHandler = null)
    {
        $this->secretsHandler = $secretsHandler;
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
            if ($this->isSecretsLookupEnabled()) {
                return $this->secretsHandler->decrypt($name);
            } else {
                // if encrypted_secrets config is not enabled for the current environment, drop the secret prefix
                // and defer processing. this is done to allow users to opt into encrypted_secrets per
                // environment without needing to override each config parameter with the secret prefix.
                return $getEnv($name);
            }
        }

        throw new RuntimeException(sprintf('Unsupported env var prefix "%s".', $prefix));
    }

    public function isSecretsLookupEnabled()
    {
        return isset($this->secretsHandler);
    }
}
