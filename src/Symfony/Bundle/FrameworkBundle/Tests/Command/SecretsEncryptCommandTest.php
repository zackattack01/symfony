<?php

namespace Symfony\Bundle\FrameworkBundle\Tests\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Bundle\FrameworkBundle\Command\SecretsEncryptCommand;
use Symfony\Bundle\FrameworkBundle\Secrets\SecretsWriter;

class SecretsEncryptCommandTest extends TestCase
{
    const EXPECTED_MASTER_KEY = 'm@st3rP@zw0rd';
    const EXPECTED_IV = 'ahdTXAM/vxvmksd6';

    public function testAcceptsMasterKeyAndIV()
    {
        $secretsWriter = $this->generateMockSecretsWriter();
        $secretsWriter
            ->expects($this->once())
            ->method('writeSecrets')
            ->with(self::EXPECTED_MASTER_KEY, self::EXPECTED_IV, SecretsWriter::ENCRYPTION_CONFIG);
        $tester = $this->createCommandTester($secretsWriter);

        $responseCode = $tester->execute(['master-key' => self::EXPECTED_MASTER_KEY, 'iv' => self::EXPECTED_IV]);
        $this->assertEquals(0, $responseCode, 'Returns 0 after successful encryption');
    }

    public function testAcceptsMasterKeyAndGeneratesIV()
    {
        $secretsWriter = $this->generateMockSecretsWriter();
        $secretsWriter
            ->expects($this->once())
            ->method('writeSecrets')
            ->with(self::EXPECTED_MASTER_KEY, $this->matchesRegularExpression('/.{16}/'), SecretsWriter::ENCRYPTION_CONFIG);
        $tester = $this->createCommandTester($secretsWriter);

        $responseCode = $tester->execute(['master-key' => self::EXPECTED_MASTER_KEY, '--generate-iv' => true]);
        $this->assertEquals(0, $responseCode, 'Returns 0 after successful encryption.');
        //user should be shown the generated IV
        $this->assertRegExp('/Generated IV: .{16}/', $tester->getDisplay());
    }

    public function testRequiresMasterKeyAndIVorGenerateIVArg()
    {
        $secretsWriter = $this->generateMockSecretsWriter();
        $secretsWriter
            ->expects($this->never())
            ->method('writeSecrets');
        $tester = $this->createCommandTester($secretsWriter);

        $this->expectException('Symfony\Component\Console\Exception\RuntimeException', 'Raises a RuntimeException if user does not supply or request an IV.');
        $responseCode = $tester->execute(['master-key' => self::EXPECTED_MASTER_KEY]);
    }

    public function testAlwaysRequiresMasterKey()
    {
        $secretsWriter = $this->generateMockSecretsWriter();
        $secretsWriter
            ->expects($this->never())
            ->method('writeSecrets');
        $tester = $this->createCommandTester($secretsWriter);

        $this->expectException('Symfony\Component\Console\Exception\RuntimeException', 'Raises a RuntimeException if user does not supply a master-key.');
        $responseCode = $tester->execute(['iv' => self::EXPECTED_IV]);
    }

    /**
     * @return CommandTester
     */
    private function createCommandTester($secretsWriter)
    {
        $application = new Application($this->generateMockKernel());
        $application->add(new SecretsEncryptCommand($secretsWriter));

        return new CommandTester($application->find('secrets:encrypt'));
    }

    private function generateMockKernel()
    {
        $container = $this->getMockBuilder('Symfony\Component\DependencyInjection\ContainerInterface')->getMock();
        $container
            ->expects($this->atLeastOnce())
            ->method('has')
            ->will($this->returnCallback(function ($id) {
                if ('console.command_loader' === $id) {
                    return false;
                }

                return true;
            }))
        ;

        $kernel = $this->getMockBuilder(KernelInterface::class)->getMock();
        $kernel
            ->expects($this->any())
            ->method('getContainer')
            ->willReturn($container)
        ;
        $kernel
            ->expects($this->once())
            ->method('getBundles')
            ->willReturn(array())
        ;

        return $kernel;
    }

    private function generateMockSecretsWriter()
    {
        return $this->getMockBuilder(SecretsWriter::class)
                            ->setConstructorArgs([
                                $this->getMockBuilder(KernelInterface::class)->getMock()
                            ])
                            ->getMock();
    }
}
