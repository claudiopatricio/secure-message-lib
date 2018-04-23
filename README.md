# Security class to encrypt and decrypt secure messages

Simple library to encrypt and decrypt or messages, useful for any project that requires to send encrypted messages in a network.

```
sec = MessageEncrypter()
encrypted = sec.encrypt("Hello World")
decrypted = sec.decrypt(encrypted)
```

It uses a passphrase and multiple deviations with a random salt message for the key creation to guarantee security. With random salt in key creation, encrypted message will never be same and can only be decrypted knowing the passphrase, also the block size, key size and salt size will increase security against a brute force attack.

After the key generation, the message will be encrypted using AES256 algorithm and then a hex or base64 hash will be created to be able to save it in a database or send it as text.

For a communication protocol using this library, i would recommend to create the passphrase using a secure key exchange method like Diffie-Hellman.

## Required libraries

* [Pycrypto](https://pypi.org/project/pycrypto/)

# Donate

If you like my work and want to contribute by donating money, check my [Donation page](http://anjo2.com/donate/)

# License
Copyright (c) 2018 Cláudio Patrício

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.