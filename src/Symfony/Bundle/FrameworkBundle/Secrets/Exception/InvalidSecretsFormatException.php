<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets\Exception;

/**
 * Thrown when a required secrets config file does not contain valid JSON.
 */
final class InvalidSecretsFormatException extends \RuntimeException
{
    public function __construct(string $msg, int $code = 0, \Exception $previous = null)
    {
        parent::__construct($msg, $code, $previous);
    }
}
