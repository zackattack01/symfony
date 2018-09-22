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
        $this->secretsWriter = new SecretsWriter($kernel);  
    }

    public function testTransformSecretsBasicKeyValuePair()
    {
        $plaintextSecretPair = [self::USERNAME_KEY => self::USERNAME_VALUE, self::PASSWORD_KEY => self::PASSWORD_VALUE];
        $encryptedValues = $this->secretsWriter->transformSecrets(self::MASTER_KEY, self::IV, $plaintextSecretPair, SecretsWriter::ENCRYPTION_CONFIG['action']);
        $this->assertEquals($this->generateExpectedSecret(self::USERNAME_VALUE), $encryptedValues[self::USERNAME_KEY]);
        $this->assertEquals($this->generateExpectedSecret(self::PASSWORD_VALUE), $encryptedValues[self::PASSWORD_KEY]);

        $decryptedValues = $this->secretsWriter->transformSecrets(self::MASTER_KEY, self::IV, $encryptedValues, SecretsWriter::DECRYPTION_CONFIG['action']);
        $this->assertEquals($plaintextSecretPair, $decryptedValues);
    }

    public function testTransformSecretsNestedKeyValuePair()
    {
        $plaintextNestedSecrets = ['account_credentials' => ['admin' => [self::USERNAME_KEY => self::USERNAME_VALUE, self::PASSWORD_KEY => self::PASSWORD_VALUE]]];
        $encryptedValues = $this->secretsWriter->transformSecrets(self::MASTER_KEY, self::IV, $plaintextNestedSecrets, SecretsWriter::ENCRYPTION_CONFIG['action']);
        $this->assertEquals($this->generateExpectedSecret(self::USERNAME_VALUE), $encryptedValues['account_credentials']['admin'][self::USERNAME_KEY]);
        $this->assertEquals($this->generateExpectedSecret(self::PASSWORD_VALUE), $encryptedValues['account_credentials']['admin'][self::PASSWORD_KEY]);

        $decryptedValues = $this->secretsWriter->transformSecrets(self::MASTER_KEY, self::IV, $encryptedValues, SecretsWriter::DECRYPTION_CONFIG['action']);
        $this->assertEquals($plaintextNestedSecrets, $decryptedValues);
    }

    public function testTransformSecretsNestedKeyWithArrayValues()
    {
        $extraKeyValue = "arraySupportTesterKey";
        $numericValue = 3;
        $plaintextArraySecrets = ['account_credentials' => ['admin_keys' => [self::PASSWORD_VALUE, $extraKeyValue, $numericValue]]];
        $encryptedValues = $this->secretsWriter->transformSecrets(self::MASTER_KEY, self::IV, $plaintextArraySecrets, SecretsWriter::ENCRYPTION_CONFIG['action']);
        $this->assertEquals($this->generateExpectedSecret(self::PASSWORD_VALUE), $encryptedValues['account_credentials']['admin_keys'][0]);
        $this->assertEquals($this->generateExpectedSecret($extraKeyValue), $encryptedValues['account_credentials']['admin_keys'][1]);
        $this->assertEquals($this->generateExpectedSecret($numericValue), $encryptedValues['account_credentials']['admin_keys'][2]);

        $decryptedValues = $this->secretsWriter->transformSecrets(self::MASTER_KEY, self::IV, $encryptedValues, SecretsWriter::DECRYPTION_CONFIG['action']);
        $this->assertEquals($plaintextArraySecrets, $decryptedValues);
    }

    public function testWriteSecrets()
    {
        //TODO after refactoring to use File class
    }

    public function generateExpectedSecret($plaintext)
    {
        return openssl_encrypt(
            $plaintext,
            BaseSecretsHandler::ENCRYPTION_METHOD,
            self::MASTER_KEY,
            $options = null,
            self::IV
        );
    }
}
