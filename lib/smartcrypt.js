'use strict';

var crypto = require('crypto');
var extend = require('util')._extend;

var dataStore = [];

function SmartCrypt(options) {
  this.iv = null;
  this.keys = [];
  this.keyCounter = 0;

  if (Array.isArray(options)) {
    options = {keys: options};
  }

  options = extend({}, options);

  if (!options.algorithm || !SmartCrypt.algorithms[options.algorithm]) {
    options.algorithm = Object.keys(SmartCrypt.algorithms)[0];
  }

  this.algorithm = extend(extend({}, SmartCrypt.algorithms[options.algorithm]), {name: options.algorithm});

  if (options.delimiter) {
    this.setDelimiter(options.delimiter);
  }

  if (!options.keys && options.password) {
    options.keys = options.password;
    delete options.password;
  } else if (!options.keys && options.key) {
    options.keys = options.key;
    delete options.key;
  }

  if (!options.keys || !options.keys.length) {
    throw new TypeError('Parameter \'keys\' must not be empty');
  } else if (options.keys instanceof Buffer) {
    options.keys = [options.keys];
  } else if (!Array.isArray(options.keys)) {
    throw new TypeError('Parameter \'keys\' must be an array, not ' + typeof options.keys);
  }

  for (var i = 0; i < options.keys.length; i++) {
    var key = options.keys[i];
    var regexHex = new RegExp('^[0-9a-f]{' + (this.algorithm.keyLength * 2) + '}$');

    if (key instanceof Buffer) {
      this.keys.push(key);
    } else if ('string' === typeof key && regexHex.test(key)) {
      this.keys.push(new Buffer(key, 'hex'));
    } else {
      this.keys.push(new Buffer(key));
    }
  }
}

SmartCrypt.algorithms = {
  'aes-256-gcm': {
    keyLength: 32,
    ivLength: 12
  },
};

SmartCrypt.prototype.join = function(buffers) {
  var joining = [];

  for (var i = 0; i < buffers.length; i++) {
    joining.push(buffers[i], this.getDelimiter());
  }

  joining.pop();

  return Buffer.concat(joining);
};

SmartCrypt.prototype.split = function(buffer) {
  var buffers = [];
  var offset  = -1;

  while (-1 !== (offset = buffer.indexOf(this.getDelimiter()))) {
    buffers.push(buffer.slice(0, offset));
    buffer = buffer.slice(offset + this.getDelimiter().length);
  }

  if (buffer.length) {
    buffers.push(buffer);
  }

  return buffers;
};

SmartCrypt.prototype.getKey = function(decrypting) {
  if (decrypting) {
    if (this.keyCounter > 0) {
      this.keyCounter = 0;
    }

    return this.keys[(this.keys.length - 1) + (this.keyCounter-- % this.keys.length)];
  }

  if (this.keyCounter < 0) {
    this.keyCounter = 0;
  }

  return this.keys[this.keyCounter++ % this.keys.length];
};

SmartCrypt.prototype.getDelimiter = function() {
  if (this.delimiter) {
    return this.delimiter;
  }

  return this.setDelimiter();
};

SmartCrypt.prototype.setDelimiter = function(delimiter) {
  var delimLength = this.algorithm.ivLength;

  this.delimiter = delimiter || crypto.randomBytes(delimLength);

  if (!(this.delimiter instanceof Buffer)) {
    this.delimiter = new Buffer(this.delimiter);
  }

  if (this.delimiter.length != delimLength) {
    throw new TypeError('Parameter \'delimiter\' must be ' + delimLength + ' bytes');
  }

  return this.delimiter;
};

SmartCrypt.prototype.encrypt = function(decrypted, finalPass) {
  if ('undefined' === typeof finalPass) {
    finalPass = true;
  }

  if (!Array.isArray(decrypted)) {
    decrypted = [decrypted];
  }

  for (var i = 0; i < decrypted.length; i++) {
    if (!(decrypted[i] instanceof Buffer)) {
      decrypted[i] = new Buffer(decrypted[i]);
    }
  }

  if (decrypted.length > 1) {
    // Take the last element off and encrypt it
    var popped = this.encrypt(decrypted.pop(), false);

    // Append joined hashes to popped element
    decrypted.push(this.join([decrypted.pop()].concat(popped)));

    // Return encryption of the new array
    return this.encrypt(decrypted);
  }

  decrypted = decrypted.pop();

  var cipher = crypto.createCipheriv(this.algorithm.name, this.getKey(), this.getDelimiter());
  var encrypted = Buffer.concat([cipher.update(decrypted), cipher.final()]);
  var tag = cipher.getAuthTag();

  var results = [encrypted, tag];

  if (finalPass) {
    results.unshift(new Buffer([this.getDelimiter().length + 96]));
    results = this.join(results);
  }

  return results;
};

SmartCrypt.prototype.decrypt = function(encrypted) {
  if (!Array.isArray(encrypted)) {
    if ('string' === typeof encrypted) {
      var checkBase64 = new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$');

      if (checkBase64.test(encrypted)) {
        encrypted = new Buffer(encrypted, 'base64');
      }
    }

    if (!(encrypted instanceof Buffer)) {
      throw new TypeError('Parameter \'encrypted\' must be a buffer, not ' + typeof encrypted);
    }

    this.setDelimiter(encrypted.slice(1, (parseInt(encrypted[0]) - 96) + 1));

    encrypted = this.split(encrypted);
    encrypted.shift();

    return this.decrypt(encrypted);
  }

  var tag = encrypted.pop();
  var data = encrypted.pop();

  var decipher, decrypted;

  for (var i = 0; i < this.keys.length; i++) {
    try {
      decipher = crypto.createDecipheriv(this.algorithm.name, this.getKey(true), this.getDelimiter());
      decipher.setAuthTag(tag);

      decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    } catch (ex) {
      if ('Unsupported state or unable to authenticate data' !== ex.message) {
        throw ex;
      }
    }
  }

  if (!decrypted) {
    throw new Error('Unable to decrypt data');
    return;
  }

  decrypted = this.split(decrypted);
  dataStore.push(decrypted.shift());

  if (!decrypted.length) {
    decrypted = dataStore;
    dataStore = [];

    return decrypted;
  }

  return this.decrypt(decrypted);
};

module.exports = SmartCrypt;
