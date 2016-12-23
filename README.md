# smartcrypt

Simple encryption library for encrypting and decrypting arrays.

This was created for passing sensitive data to a URL via the query string.

It currently only supports the `aes-256-gcm` algorithm.

## Installation

```
npm install smartcrypt
```

## Examples

***NEVER expose your encryption keys to the public.***

Each key is expected to be 32 bytes. You will receive an error if the key not the correct length.

You can use [random.org](https://www.random.org/bytes/) to generate your keys.

### Using a single key for all variables

```
var SmartCrypt = require('smartcrypt');

var keys = [
  '42901afcce3af267df40f9da54b2f3816ff4b2e9a148fdd207e8246454fb46c5'
];

var crypt = new SmartCrypt(keys);

var encrypted = crypt.encrypt(['foo@bar.com', 'foobar123']).toString('base64');
console.log('encrypted:', encrypted);

var decrypted = this.crypt.decrypt(encrypted);
console.log('username:', decrypted[0]);
console.log('password:', decrypted[1]);
```

### Using a unique key for each variable

```
var SmartCrypt = require('smartcrypt');

var keys = [
  'f015411c712a818b37d42bba37bf1984d5b26bf39c12395d5c9d83543a672a3b', // key for "username"
  '1a3034a435cc0ed70da1f7ad36e8889e5016f6ef7cf1bde5328891947dd1b326'  // Key for "password"
];

var crypt = new SmartCrypt(keys);

var encrypted = crypt.encrypt(['foo@bar.com', 'foobar123']).toString('base64');
console.log('encrypted:', encrypted);

var decrypted = this.crypt.decrypt(encrypted);
console.log('username:', decrypted[0]);
console.log('password:', decrypted[1]);
```
