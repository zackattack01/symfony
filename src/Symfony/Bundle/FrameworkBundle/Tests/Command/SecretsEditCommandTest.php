<?php

namespace Symfony\Bundle\FrameworkBundle\Tests\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Bundle\FrameworkBundle\Command\SecretsEditCommand;
use Symfony\Bundle\FrameworkBundle\Secrets\SecretsWriter;

class SecretsEditCommandTest extends TestCase
{
    const EXPECTED_MASTER_KEY = 'm@st3rP@zw0rd';

    public function testAcceptsMasterKeyAndIV()
    {
        $secretsWriter = $this->generateMockSecretsWriter();
        $secretsWriter
            ->expects($this->once())
            ->method('writeEncryptedSecrets')
            ->with(self::EXPECTED_MASTER_KEY);
        $tester = $this->createCommandTester($secretsWriter);

        $responseCode = $tester->execute(['master-key' => self::EXPECTED_MASTER_KEY]);
        $this->assertEquals(0, $responseCode, 'Returns 0 after successful encryption');
    }

    public function testRequiresMasterKeyIfNoFileProvided()
    {
        $secretsWriter = $this->generateMockSecretsWriter();
        $secretsWriter
            ->expects($this->never())
            ->method('writeEncryptedSecrets');
        $tester = $this->createCommandTester($secretsWriter);

        $this->expectException('Symfony\Component\Console\Exception\RuntimeException', 'Raises a RuntimeException if user does not supply a master-key.');
        $responseCode = $tester->execute([]);
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
                            ->setConstructorArgs(["", "test"])
                            ->getMock();
    }
}
