<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets\Exception;

/**
 * Thrown when a required secrets config file does not contain valid JSON.
 */
final class InvalidSecretsFormatException extends \RuntimeException
{
    public function __construct(string $secretsPath, int $code = 0, \Exception $previous = null)
    {
        parent::__construct(
            sprintf('%s does not contain valid json for secrets. Verify the format, password, and initialization vector being used.', $secretsPath),
            $code,
            $previous
        );
    }
}
