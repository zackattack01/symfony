<?php

namespace Symfony\Bundle\FrameworkBundle\Command;

use Symfony\Component\DependencyInjection\SecretVarProcessor;
use Symfony\Component\Filesystem\Filesystem;

class SecretsCommandHelper
{
    private $filesystem;
    private $secretVarProcessor;

    public function __construct(SecretVarProcessor $secretVarProcessor, Filesystem $filesystem = null)
    {
        $this->secretVarProcessor = $secretVarProcessor;
        $this->filesystem = $filesystem ?: new Filesystem();
    }

    public function writeEncryptedSecretsToTempFile(string $plaintextTempLocation)
    {
        $plaintextSecrets = json_decode(file_get_contents($plaintextTempLocation), true);
        $encryptedSecrets = [];
        foreach ($plaintextSecrets as $secretName => $secretValue) {
            $iv = $this->generateIv();
            $encryptedSecrets[$secretName] = $this->secretVarProcessor->generateEncryptedEntry($secretValue, $iv);
        }

        $formattedSecrets = json_encode($encryptedSecrets, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
        file_put_contents($this->secretVarProcessor->getConfiguration()['secrets_file'], $formattedSecrets) > 0;
        unlink($plaintextTempLocation);
    }

//    public function writeSingleSecret(string $secretName, string $secretValue, string $masterKey, string $encryptedSecretsLocation)
//    {
//        $encryptedSecrets = $this->readEncryptedSecrets($encryptedSecretsLocation, $allowEmptySecrets = true);
//        $this->addSingleSecret($secretName, $secretValue, $masterKey, $encryptedSecrets);
//        $formattedSecrets = json_encode($encryptedSecrets, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
//        return file_put_contents($this->encryptedSecretsLocation, $formattedSecrets) > 0;
//    }


    public function writePlaintextSecretsToTempFile()
    {
        $encryptedSecrets = $this->secretVarProcessor->getEncryptedSecrets();
        $plaintextSecrets = [];
        foreach ($encryptedSecrets as $secretName => $secretsEntry) {
            $plaintextSecrets[$secretName] = $this->secretVarProcessor->decryptSecretValue($secretsEntry);
        }
        $tempContent = json_encode($plaintextSecrets, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
        return $this->writeContentToTempFile($tempContent);
    }

    private function generateIv()
    {
        return base64_encode(random_bytes(12));
    }

    public function writeContentToTempFile($content)
    {
        $tempName = tempnam(sys_get_temp_dir(), "");
        $handle = fopen($tempName, "w");
        fwrite($handle, $content);
        fclose($handle);
        return $tempName;
    }
}
