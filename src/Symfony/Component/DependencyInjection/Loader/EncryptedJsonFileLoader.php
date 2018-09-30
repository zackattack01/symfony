<?php


namespace Symfony\Component\DependencyInjection\Loader;

use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\SecretVarProcessor;

class EncryptedJsonFileLoader extends FileLoader
{

    public function load($resource, $type = null)
    {
        $path = $this->locator->locate($resource);
        $content = $this->loadFile($path);
        $this->container->fileExists($path);

        return $content;
    }

    /**
     * {@inheritdoc}
     */
    public function supports($resource, $type = null)
    {
        if (!is_string($resource)) {
            return false;
        }

        $pathInfo = pathinfo($resource);
        $outerType = $type ?? $pathInfo['extension'];
        if ("json" !== $outerType) {
            return false;
        }

        $innerType = pathinfo($pathInfo['filename'], PATHINFO_EXTENSION);

        return "enc" === $innerType;
    }

    protected function loadFile($file)
    {
        if (!stream_is_local($file)) {
            throw new InvalidArgumentException(sprintf('This is not a local file "%s".', $file));
        }

        if (!file_exists($file)) {
            throw new InvalidArgumentException(sprintf('The file "%s" does not exist.', $file));
        }

        $content = json_decode(file_get_contents($file), true);
        if (is_null($content)) {
            throw new InvalidArgumentException(sprintf('The file "%s" does not contain valid JSON.', $file));
        }

        return $this->validate($content, $file);
    }

    /**
     * Validates a JSON file containing encrypted secrets.
     *
     * @param mixed  $content
     * @param string $file
     *
     * @return array
     *
     * @throws InvalidArgumentException When secrets file is not valid
     */
    protected function validate($content, $file)
    {
        if (is_array($content)) {
            foreach ($content as $key => $encryptedValues) {
                if (!isset($encryptedValues[SecretVarProcessor::CIPHERTEXT_KEY]) || !is_string($encryptedValues[SecretVarProcessor::CIPHERTEXT_KEY])) {
                    throw new InvalidArgumentException(sprintf('The encrypted key entry %s in %s should contain a string "ciphertext" entry.', $key, $file));
                }
                if (!isset($encryptedValues[SecretVarProcessor::IV_KEY]) || !is_string($encryptedValues[SecretVarProcessor::IV_KEY])) {
                    throw new InvalidArgumentException(sprintf('The encrypted key entry %s in %s should contain a string "iv" entry.', $key, $file));
                }
            }
        } else {
            throw new InvalidArgumentException(sprintf('%s should contain a valid JSON array. Check your JSON syntax.', $file));
        }

        return $content;
    }
}