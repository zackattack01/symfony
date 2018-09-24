<?php

namespace Symfony\Bundle\FrameworkBundle\Secrets\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Secrets\SecretsWriter;
use Symfony\Bundle\FrameworkBundle\Secrets\BaseSecretsHandler;
use Symfony\Component\HttpKernel\KernelInterface;

class SecretsWriterTest extends TestCase
{
    const MASTER_KEY = "hunter2";
    const IV = "123456789abcdefg";
    const USERNAME_KEY = "username";
    const USERNAME_VALUE = "username_value";
    const PASSWORD_KEY = "password";
    const PASSWORD_VALUE = "password_value";

    private $secretsWriter;

    protected function setUp()
    {
        $kernel = $this->getMockBuilder(KernelInterface::class)->getMock();
        $this->secretsWriter = new SecretsWriter("", "test");  
    }

    public function testGenerateEncryptedSecrets()
    {
        
    }

    public function generateExpectedSecret($plaintext, $iv)
    {
        return openssl_encrypt(
            $plaintext,
            BaseSecretsHandler::ENCRYPTION_METHOD,
            self::MASTER_KEY,
            $options = null,
            $iv
        );
    }
}
