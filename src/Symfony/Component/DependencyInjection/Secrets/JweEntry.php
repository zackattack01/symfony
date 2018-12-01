<?php

namespace Symfony\Component\DependencyInjection\Secrets;

use Symfony\Component\DependencyInjection\Exception\RuntimeException;

final class JweEntry
{
    private $header;
    private $encryptedKey;
    private $iv;
    private $cipherText;
    private $authTag;

    public static function decrypt(string $compactedEntry, string &$keyPair)
    {
        $entry = new self();
        $entry->hydrate($compactedEntry);
        $plaintext = $entry->decryptedSecret($keyPair);
        sodium_memzero($keyPair);

        return $plaintext;
    }

    public static function encrypt(string $secret, string $pubKey)
    {
        $entry = new self();
        $entry->setEncryptedValues($secret, $pubKey);

        return $entry->compact();
    }

    private function __contruct() {}

    private function base64url_encode($data)
    {
        return urlencode(base64_encode($data));
    }

    private function base64url_decode($data)
    {
        return base64_decode(urldecode($data));
    }

    // see the JWE compact serialization format for details https://tools.ietf.org/html/rfc7516#section-7.1
    private function compact()
    {
        $valuesForCompaction = array(
            $this->base64url_encode($this->header),
            sodium_bin2base64($this->encryptedKey, SODIUM_BASE64_VARIANT_URLSAFE),
            sodium_bin2base64($this->iv, SODIUM_BASE64_VARIANT_URLSAFE),
            sodium_bin2base64($this->cipherText, SODIUM_BASE64_VARIANT_URLSAFE),
            $this->base64url_encode($this->authTag),
        );

        return implode('.', $valuesForCompaction);
    }

    private function decryptedSecret(string &$keyPair)
    {
        $plaintextCek = sodium_crypto_box_seal_open(
            $this->encryptedKey,
            $keyPair
        );

        $decrypted = sodium_crypto_aead_aes256gcm_decrypt(
            $this->cipherText,
            $this->authTag,
            $this->iv,
            $plaintextCek
        );
        if (false === $decrypted) {
            throw new RuntimeException('Unable to decrypt secrets. Verify the configured key pair');
        }

        return $decrypted;
    }

    private function generateHeader()
    {
        //TODO: remove header logic if full JWE implementation is not required
        return '{"alg":"curve25519xsalsa20poly1305","enc":"A256GCM"}';
    }

    private function hydrate(string $compactedEntry)
    {
        list($header, $encryptedKey, $iv, $cipherText, $authTag) = explode('.', $compactedEntry);
        $this->header = $this->base64url_decode($header);
        $this->encryptedKey = sodium_base642bin($encryptedKey, SODIUM_BASE64_VARIANT_URLSAFE);
        $this->iv = sodium_base642bin($iv, SODIUM_BASE64_VARIANT_URLSAFE);
        $this->cipherText = sodium_base642bin($cipherText, SODIUM_BASE64_VARIANT_URLSAFE);
        $this->authTag = $this->base64url_decode($authTag);
    }

    private function setEncryptedValues(string $secret, string $pubKey)
    {
        $this->header = $this->generateHeader();
        $rawCek = sodium_crypto_aead_aes256gcm_keygen();
        $encryptedCek = sodium_crypto_box_seal(
            $rawCek,
            $pubKey
        );

        $this->encryptedKey = $encryptedCek;
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $this->iv = $nonce;
        $additionalData = $this->generateHeader();
        $ciphertext = sodium_crypto_aead_aes256gcm_encrypt(
            $secret,
            $additionalData,
            $nonce,
            $rawCek
        );

        $this->authTag = $additionalData;
        $this->cipherText = $ciphertext;
    }
}
