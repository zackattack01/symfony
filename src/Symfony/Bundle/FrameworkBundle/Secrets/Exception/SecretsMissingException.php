<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets\Exception;

/**
 * Thrown when a required secrets config file is missing.
 */
final class SecretsMissingException extends \RuntimeException
{
    public function __construct(string $secretsPath, int $code = 0, \Exception $previous = null)
    {
        parent::__construct(sprintf('Unable to find %s. Verify the file is present before generating secrets.', $secretsPath), $code, $previous);
    }
}
