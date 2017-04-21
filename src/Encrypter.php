<?php
/**
 *
 * author : edwin
 * createTime : 2017/4/17  下午2:48
 * version  : 1.0.0
 * 
 */
class  Encrypter
{
    //加密算法
    public $cipher;

    //密钥
    public $key;



    /**
     * create a new instance
     * Encrypter constructor.
     * @param $key
     * @param string $cipher
     */
    public function __construct($key, $cipher='AES-128-CBC')
    {
        $key = (string) $key;
        if (static::supported($cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        }else{
            throw new RuntimeException('支持的加密算法包括AES-128-CBC and AES-256-CBC');
        }
    }

    /**
     * encrypt data
     * @param $data
     * @return string
     */
    public function encrypt($data)
    {
        $iv = openssl_random_pseudo_bytes($this->getIvSize());

        $value = openssl_encrypt(serialize($data),$this->cipher,$this->key,0,$iv);


        $mac = $this->hash($iv = base64_encode($iv), $value);


        $json = json_encode(compact('iv', 'value', 'mac'));
        if (! is_string($json)) {
            throw new RuntimeException('Could not encrypt the data.');
        }
        return base64_encode($json);

    }

    /**
     * decryp data
     * @param $data
     * @return mixed
     */
    public function decrypt($data)
    {
        $payload = $this->getJsonPayload($data);
        $iv = base64_decode($payload['iv']);
        $decrypted = \openssl_decrypt($payload['value'], $this->cipher, $this->key, 0, $iv);
        if ($decrypted === false) {
            throw new RuntimeException('Could not decrypt the data.');
        }
        return unserialize($decrypted);
    }

    /**check algorim
     * @param $cipher
     * @return bool
     */
    protected function  supported($cipher)
    {
        return ($cipher === 'AES-128-CBC') || ($cipher === 'AES-256-CBC');
    }


    /**
     * Get the IV size for the cipher.
     *
     * @return int
     */
    protected function getIvSize()
    {
        return 16;
    }


    /**
     * Create a MAC for the given value.
     *
     * @param  string  $iv
     * @param  string  $value
     * @return string
     */
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv.$value, $this->key);
    }
    /**
     * Get the JSON array from the given payload.
     *
     * @param  string  $payload
     * @return array
     *
     *
     */
    protected function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);
        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (! $payload || $this->invalidPayload($payload)) {
            throw new RuntimeException('The payload is invalid.');
        }
        if (! $this->validMac($payload)) {
            throw new RuntimeException('The MAC is invalid.');
        }
        return $payload;
    }
    /**
     * Verify that the encryption payload is valid.
     *
     * @param  array|mixed  $data
     * @return bool
     */
    protected function invalidPayload($data)
    {
        return ! is_array($data) || ! isset($data['iv']) || ! isset($data['value']) || ! isset($data['mac']);
    }
    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param  array  $payload
     * @return bool
     *
     * @throws \RuntimeException
     */
    protected function validMac(array $payload)
    {
        $bytes = openssl_random_pseudo_bytes($this->getIvSize());
        $calcMac = hash_hmac('sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true);
        return hash_equals(hash_hmac('sha256', $payload['mac'], $bytes, true), $calcMac);
    }

}
