<?php

namespace Psecio\SessionEncrypt;

class Handler
{
    /**
     * Path to save the sessions to
     * @var string
     */
    private static $savePathRoot = '/tmp';

    /**
     * Save path of the saved path
     * @var string
     */
    private static $savePath = '';

    /**
     * Salt for hashing the session data
     * @var string
     */
    private static $saltHash = null;

    /**
     * Current IV key
     * @var string
     */
    private static $key = null;

    /**
     * Initialize the session handler and set salt hash
     * 
     * @param string $saltHash Salt hash to init with
     */
    public static function init($saltHash = null)
    {
        if ($saltHash !== null) {
            self::$saltHash = $saltHash;
        }
        if (self::$saltHash === null) {
            error_log('SESSION HANDLER: You must set a salt hash for the encryption!');
        }

    	session_set_save_handler(
            array("\\Psecio\\SessionEncrypt\\Handler", "open"),
            array("\\Psecio\\SessionEncrypt\\Handler", "close"),
            array("\\Psecio\\SessionEncrypt\\Handler", "read"),
            array("\\Psecio\\SessionEncrypt\\Handler", "write"),
            array("\\Psecio\\SessionEncrypt\\Handler", "destroy"),
            array("\\Psecio\\SessionEncrypt\\Handler", "gc")
        );

		$savePath = ini_get('session.save_path');
		if (!empty($savePath)) {
			self::$savePathRoot = $savePath;
		}
    }

    /**
     * Encrypt the given data
     *
     * @param mixed $data Session data to encrypt
     * @return mixed $data Encrypted data
     */
    private static function encrypt($data)
    {
        $ivSize  = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
        $iv      = mcrypt_create_iv($ivSize, MCRYPT_RAND);
        $keySize = mcrypt_get_key_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
        $key     = substr(sha1(self::$key), 0, $keySize);

        // add in our IV and base64 encode the data
        $data    = base64_encode(
            $iv.mcrypt_encrypt(
                MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_CBC, $iv
            )
        );
        return $data;
    }

    /**
     * Decrypt the given session data
     *
     * @param mixed $data Data to decrypt
     * @return $data Decrypted data
     */
    private static function decrypt($data)
    {
        $data    = base64_decode($data, true);

        $ivSize  = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
        $keySize = mcrypt_get_key_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
        $key     = substr(sha1(self::$key), 0, $keySize);

        $iv   = substr($data, 0, $ivSize);
        $data = substr($data, $ivSize);

        $data = mcrypt_decrypt(
            MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_CBC, $iv
        );

        return $data;
    }

    /**
     * Set the key for the session encryption to use (default is set)
     *
     * @param string $key Key string
     * @return null
     */
    public static function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * Write to the session
     *
     * @param integer $id   Session ID
     * @param mixed   $data Data to write to the log
     * @return null
     */
    public static function write($id, $data)
    {
        $path = self::$savePathRoot.'/'.$id;
        $data = self::encrypt($data);

        file_put_contents($path, $data);
    }

    /**
     * Read in the session
     *
     * @param string $id Session ID
     * @return null
     */
    public static function read($id)
    {
        $path = self::$savePathRoot.'/'.$id;
        $data = null;

        if (is_file($path)) {
            // get the data and extract the IV
            $data = file_get_contents($path);
            $data = self::decrypt($data);
        }
        return $data;
    }

    /**
     * Open the session
     *
     * @param string $savePath  Path to save the session file locally
     * @param string $sessionId Session ID
     * @return null
     */
    public static function open($savePath, $sessionId)
    {
        // open session, do nothing by default
    }

    /**
     * Close the session
     *
     * @return boolean Default return (true)
     */
    public static function close()
    {
        return true;
    }

    /**
     * Perform garbage collection on the session
     *
     * @param int $maxlifetime Lifetime in seconds
     * @return null
     */
    public static function gc($maxlifetime)
    {
        $path = self::$savePathRoot.'/*';

        foreach (glob($path) as $file) {
            if (filemtime($file) + $maxlifetime < time() && file_exists($file)) {
                unlink($file);
            }
        }

        return true;
    }

    /**
     * Destroy the session
     *
     * @param string $id Session ID
     * @return null
     */
    public static function destroy($id)
    {
        $path = $this->savePathRoot.'/'.$id;
        if (is_file($path)) {
            unlink($path);
        }
        return true;
    }
}