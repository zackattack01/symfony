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

    public function __construct(JweHandler $secretsHandler)
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
            return $this->secretsHandler->decrypt($name);
        }

        throw new RuntimeException(sprintf('Unsupported env var prefix "%s".', $prefix));
    }
}
