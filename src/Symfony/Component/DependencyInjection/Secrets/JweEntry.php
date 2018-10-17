<?php

namespace Symfony\Component\DependencyInjection\Secrets;


use Symfony\Component\DependencyInjection\Exception\RuntimeException;

final class JweEntry
{
    //TODO do we need to store header and auth tag separately?
    private $header;
    private $encryptedKey;
    private $iv;
    private $cipherText;
    private $authTag;

    public static function decrypt(string $compactedEntry, string $keyPair)
    {
        $entry = new JweEntry();
        $entry->hydrate($compactedEntry);
        return $entry->decryptedSecret($keyPair);
    }

    public static function encrypt(string $secret, string $pubKey)
    {
        $entry = new JweEntry();
        $entry->setEncryptedValues($secret, $pubKey);
        return $entry->compact();
    }

    // see the JWE compact serialization format for details https://tools.ietf.org/html/rfc7516#section-7.1
    private function compact()
    {
        $valuesForCompaction = array(
            $this->base64url_encode($this->header),
            sodium_bin2base64($this->encryptedKey, SODIUM_BASE64_VARIANT_URLSAFE),
            sodium_bin2base64($this->iv, SODIUM_BASE64_VARIANT_URLSAFE),
            sodium_bin2base64($this->cipherText, SODIUM_BASE64_VARIANT_URLSAFE),
            $this->base64url_encode($this->authTag)
        );

        return implode(".", $valuesForCompaction);
    }

    private function decryptedSecret(string $keyPair)
    {
        $plaintextCek = sodium_crypto_box_seal_open(
            $this->encryptedKey,
            $keyPair
        );

        if (sodium_crypto_aead_aes256gcm_is_available()) {
            $decrypted = sodium_crypto_aead_aes256gcm_decrypt(
                $this->cipherText,
                $this->authTag,
                $this->iv,
                $plaintextCek
            );
            if ($decrypted === false) {
                throw new RuntimeException(sprintf(
                    "Unable to decrypt secrets. Verify the configured key pair"
                ));
            }
        } else {
            //TODO add alt decryption method
            $decrypted = "";
        }

        return $decrypted;
    }

    private function hydrate(string $compactedEntry)
    {
        //TODO add validations
        list($header, $encryptedKey, $iv, $cipherText, $authTag) = explode(".", $compactedEntry);
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
        if (sodium_crypto_aead_aes256gcm_is_available()) {
            $ciphertext = sodium_crypto_aead_aes256gcm_encrypt(
                $secret,
                $additionalData,
                $nonce,
                $rawCek
            );
        } else {
            $ciphertext = "";
            //TODO: add alternative encryption method
        }

        //TODO: figure out if this conversion is needed
        //mb_convert_encoding($additionalData, "ASCII");
        $this->authTag = $additionalData;
        $this->cipherText = $ciphertext;
    }

    private function base64url_encode($data)
    {
        return urlencode(base64_encode($data));
    }

    private function base64url_decode($data)
    {
        return base64_decode(urldecode($data));
    }

    private function generateHeader()
    {
        //TODO: can you force utf8 in string declaration in php?
        //TODO: figure out correct name for alg
        return '{"alg":"curve25519xsalsa20poly1305","enc":"A256GCM"}';
    }
}