SessionEncrypt
=====================

This is a custom encrypted session handler for PHP (using `session_set_save_handler`). It is
compatible with just about any version of PHP out there and doesn't use the newer `SessionHandler`
interface.

### Example Usage

```php
<?php

require_once 'vendor/autoload.php';

$salt = 'b6a8904db8ef59b3a4c6841e6eddf048a9194208';
Psecio\SessionEncrypt\Handler::init($salt);
session_start();

?>
```

The value for `$salt` should be as randomized as possible as it's used to encrypt the data with `mcrypt_decrypt`.
The handler uses `MCRYPT_RIJNDAEL_256` and `MCRYPT_MODE_CBC` to encrypt the data.
It will store the session files in the path defined by the `session.save_path` or, if it's not set, will default to `/tmp`.
