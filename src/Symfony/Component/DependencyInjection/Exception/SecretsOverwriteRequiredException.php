<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\DependencyInjection\Exception;


final class SecretsOverwriteRequiredException extends \InvalidArgumentException implements ExceptionInterface
{
    private $existingFileLocations;

    public function __construct(string $message, array $existingFileLocations)
    {
        $this->existingFileLocations = $existingFileLocations;
        parent::__construct($message);
    }

    public function getExistingFileLocations()
    {
        return $this->existingFileLocations;
    }
}
