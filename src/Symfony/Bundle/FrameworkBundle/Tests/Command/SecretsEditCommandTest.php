<?php

namespace Symfony\Bundle\FrameworkBundle\Tests\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Command\SecretsEditCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\SecretVarProcessor;
use Symfony\Component\HttpKernel\KernelInterface;

class SecretsEditCommandTest extends TestCase
{

    /**
     * @return CommandTester
     */
    private function createCommandTester($secretsHandler)
    {
        $application = new Application($this->generateMockKernel());
        $application->add(new SecretsEditCommand($secretsHandler));

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

    private function generateMockSecretsHandler()
    {
        return $this->getMockBuilder(SecretVarProcessor::class)
                            ->getMock();
    }
}
