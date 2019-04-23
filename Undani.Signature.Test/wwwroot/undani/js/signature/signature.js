CryptoJS.enc.u8array = {
    /**
     * Converts a word array to a Uint8Array.
     *
     * @param {WordArray} wordArray The word array.
     *
     * @return {Uint8Array} The Uint8Array.
     *
     * @static
     *
     * @example
     *
     *     var u8arr = CryptoJS.enc.u8array.stringify(wordArray);
     */
    stringify: function (wordArray) {
        // Shortcuts
        var words = wordArray.words;
        var sigBytes = wordArray.sigBytes;

        // Convert
        var u8 = new Uint8Array(sigBytes);
        for (var i = 0; i < sigBytes; i++) {
            var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            u8[i] = byte;
        }

        return u8;
    },

    /**
     * Converts a Uint8Array to a word array.
     *
     * @param {string} u8Str The Uint8Array.
     *
     * @return {WordArray} The word array.
     *
     * @static
     *
     * @example
     *
     *     var wordArray = CryptoJS.enc.u8array.parse(u8arr);
     */
    parse: function (u8arr) {
        // Shortcut
        var len = u8arr.length;

        // Convert
        var words = [];
        for (var i = 0; i < len; i++) {
            words[i >>> 2] |= (u8arr[i] & 0xff) << (24 - (i % 4) * 8);
        }

        return CryptoJS.lib.WordArray.create(words, len);
    }
};

var Signature = Signature || {};
Signature.Crypto = Signature.Crypto || (function () {
    var lib = this;

    lib._OIDpkcs5PBES2 =
    [
        6,
        9,
        42,
        134,
        72,
        134,
        247,
        13,
        1,
        5,
        13
    ];
    lib._OIDpkcs5PBKDF2 =
    [
        6,
        9,
        42,
        134,
        72,
        134,
        247,
        13,
        1,
        5,
        12
    ];
    lib._OIDdesEDE3CBC =
    [
        6,
        8,
        42,
        134,
        72,
        134,
        247,
        13,
        3,
        7
    ];

    lib.BufferReader = function (arrayBuffer) {
        var self = this;
        self.arrayBuffer = new Uint8Array(arrayBuffer);
        self.CurrentPosition = 0;

        self.ReadUInt16 = function () {
            var array = new Uint8Array(self.ReadBytes(2)).buffer;
            var value = new Uint16Array(array);
            return value[0];
        };
        self.ReadInt16 = function () {
            var array = new Uint8Array(self.ReadBytes(2)).buffer;
            var value = new Int16Array(array);
            return value[0];
        };
        self.ReadByte = function () {
            return self.arrayBuffer[self.CurrentPosition++];
        };
        self.ReadBytes = function (length) {
            var array = new Array(length);
            for (var i = 0; i < length; i++) {
                array[i] = self.ReadByte();
            }
            return array;
        };
    };

    lib._CompareByteArrays = function (a, b) {
        var result;
        if (a.length != b.length) {
            result = false;
        }
        else {
            var i = 0;
            for (var j = 0; j < a.length; j++) {
                var c = a[j];
                if (c != b[i]) {
                    return false;
                }
                i++;
            }
            result = true;
        }
        return result;
    };
    lib._ToInt32 = function (a) {
        var byteArray = new Int8Array(a);
        return new Int16Array(byteArray.buffer)[0];
    };
    lib._StringToByteArray = function (text) {
        var array = [text.length];
        for (var i = 0; i < text.length; i++) {
            array[i] = text.charCodeAt(i);
        }
        return array;
    };

    lib._ByteArrayToString = function (array) {
        var text = '';
        for (var i = 0; i < array.length; i++) {
            text += String.fromCharCode(array[i]);
        }
        return text;
    };

    lib._DecryptPBDK2 = function (edata, salt, IV, secpswd, iterations) {
        var parsedSalt = CryptoJS.enc.u8array.parse(salt);
        var parsedKey = CryptoJS.PBKDF2(secpswd, parsedSalt, { keySize: 6, iterations: iterations });

        var key = CryptoJS.enc.u8array.stringify(parsedKey);

        var parsedMessage = CryptoJS.enc.u8array.parse(edata);
        var parsedIv = CryptoJS.enc.u8array.parse(IV);
        var decrypt =
            CryptoJS.TripleDES.decrypt(
                { ciphertext: parsedMessage },
                parsedKey,
                { iv: parsedIv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        return CryptoJS.enc.u8array.stringify(decrypt);
    };

    lib._byteArrayToLong = function (/*byte[]*/byteArray) {
        var value = 0;
        for (var i = byteArray.length - 1; i >= 0; i--) {
            value = (value * 256) + byteArray[i];
        }

        return value;
    };

    lib._GetIntegerSize = function (binr) {
        var bt = binr.ReadByte();
        var result;
        if (bt != 2) {
            result = 0;
        }
        else {
            bt = binr.ReadByte();
            var count;
            if (bt == 129) {
                count = binr.ReadByte();
            }
            else {
                if (bt == 130) {
                    var highbyte = binr.ReadByte();
                    var lowbyte = binr.ReadByte();
                    //var array = new byte[4];
                    var array = new Uint8Array(4);
                    array[0] = lowbyte;
                    array[1] = highbyte;
                    var modint = array;
                    count = lib._byteArrayToLong(modint);
                }
                else {
                    count = bt;
                }
            }
            while (binr.ReadByte() == 0) {
                count--;
            }
            binr.CurrentPosition--;
            result = count;
        }
        return result;
    };

    lib._DecodeRSAPrivateKey = function (privkey) {
        var binr = new lib.BufferReader(privkey);
        var twobytes = binr.ReadUInt16();
        if (twobytes == 33072) {
            binr.ReadByte();
        }
        else {
            if (twobytes != 33328) {
                result = null;
                return result;
            }
            binr.ReadInt16();
        }
        twobytes = binr.ReadUInt16();
        if (twobytes != 258) {
            result = null;
        }
        else {
            var bt = binr.ReadByte();
            if (bt != 0) {
                result = null;
            }
            else {
                var elems = lib._GetIntegerSize(binr);
                var MODULUS = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var E = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var D = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var P = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var Q = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var DP = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var DQ = binr.ReadBytes(elems);
                elems = lib._GetIntegerSize(binr);
                var IQ = binr.ReadBytes(elems);

                //    System.Security.Cryptography.RSACryptoServiceProvider RSA = new System.Security.Cryptography.RSACryptoServiceProvider();

                var RSA = {
                    Modulus: MODULUS,
                    Exponent: E,
                    D: D,
                    P: P,
                    Q: Q,
                    DP: DP,
                    DQ: DQ,
                    InverseQ: IQ
                };
                result = RSA;
            }
        }
        return result;
    };

    lib._DecodePrivateKeyInfo = function (pkcs8) {
        var SeqOID = [
            48,
            13,
            6,
            9,
            42,
            134,
            72,
            134,
            247,
            13,
            1,
            1,
            1,
            5,
            0
        ];
        var seq = [];
        var mem = pkcs8;
        var lenstream = pkcs8.length;
        var binr = new lib.BufferReader(pkcs8);
        var result;

        var twobytes = binr.ReadUInt16();
        if (twobytes == 33072) {
            binr.ReadByte();
        }
        else {
            if (twobytes != 33328) {
                return null;
            }
            binr.ReadInt16();
        }
        var bt = binr.ReadByte();
        if (bt != 2) {
            result = null;
        }
        else {
            twobytes = binr.ReadUInt16();
            if (twobytes != 1) {
                result = null;
            }
            else {
                seq = binr.ReadBytes(15);
                if (!lib._CompareByteArrays(seq, SeqOID)) {
                    result = null;
                }
                else {
                    bt = binr.ReadByte();
                    if (bt != 4) {
                        result = null;
                    }
                    else {
                        bt = binr.ReadByte();
                        if (bt == 129) {
                            binr.ReadByte();
                        }
                        else {
                            if (bt == 130) {
                                binr.ReadUInt16();
                            }
                        }
                        var rsaprivkey = binr.ReadBytes(lenstream - binr.CurrentPosition);
                        var rsacsp = lib._DecodeRSAPrivateKey(rsaprivkey);
                        result = rsacsp;
                    }
                }
            }
        }

        return result;
    };

    lib._DecodeEncryptedPrivateKeyInfo = function (encpkcs8, secpswd) {
        var seqdes = new Array(10);
        var seq = new Array(11);
        var lenstream = encpkcs8.byteLength;
        var binr = new lib.BufferReader(encpkcs8);
        var result;

        var twobytes = binr.ReadUInt16();
        if (twobytes == 33072) {
            binr.ReadByte();
        }
        else {
            if (twobytes != 33328) {
                return null;
            }
            binr.ReadInt16();
        }
        twobytes = binr.ReadUInt16();
        if (twobytes == 33072) {
            binr.ReadByte();
        }
        else {
            if (twobytes == 33328) {
                binr.ReadInt16();
            }
        }
        seq = binr.ReadBytes(11);
        if (!lib._CompareByteArrays(seq, lib._OIDpkcs5PBES2)) {
            result = null;
        }
        else {
            twobytes = binr.ReadUInt16();
            if (twobytes == 33072) {
                binr.ReadByte();
            }
            else {
                if (twobytes == 33328) {
                    binr.ReadInt16();
                }
            }
            twobytes = binr.ReadUInt16();
            if (twobytes == 33072) {
                binr.ReadByte();
            }
            else {
                if (twobytes == 33328) {
                    binr.ReadInt16();
                }
            }
            seq = binr.ReadBytes(11);
            if (!lib._CompareByteArrays(seq, lib._OIDpkcs5PBKDF2)) {
                result = null;
            }
            else {
                twobytes = binr.ReadUInt16();
                if (twobytes == 33072) {
                    binr.ReadByte();
                }
                else {
                    if (twobytes == 33328) {
                        binr.ReadInt16();
                    }
                }
                var bt = binr.ReadByte();
                if (bt != 4) {
                    result = null;
                }
                else {
                    var saltsize = binr.ReadByte();
                    var salt = binr.ReadBytes(saltsize);
                    bt = binr.ReadByte();
                    if (bt != 2) {
                        result = null;
                    }
                    else {
                        var itbytes = binr.ReadByte();
                        var iterations;
                        if (itbytes == 1) {
                            iterations = binr.ReadByte();
                        }
                        else {
                            if (itbytes != 2) {
                                return null;
                            }
                            iterations = 256 * binr.ReadByte() + binr.ReadByte();
                        }
                        twobytes = binr.ReadUInt16();
                        if (twobytes == 33072) {
                            binr.ReadByte();
                        }
                        else {
                            if (twobytes == 33328) {
                                binr.ReadInt16();
                            }
                        }
                        seqdes = binr.ReadBytes(10);
                        if (!lib._CompareByteArrays(seqdes, lib._OIDdesEDE3CBC)) {
                            result = null;
                        }
                        else {
                            bt = binr.ReadByte();
                            if (bt != 4) {
                                result = null;
                            }
                            else {
                                var ivsize = binr.ReadByte();
                                var IV = binr.ReadBytes(ivsize);
                                bt = binr.ReadByte();
                                if (bt != 4) {
                                    result = null;
                                }
                                else {
                                    bt = binr.ReadByte();
                                    var encblobsize;
                                    if (bt == 129) {
                                        encblobsize = binr.ReadByte();
                                    }
                                    else {
                                        if (bt == 130) {
                                            encblobsize = 256 * binr.ReadByte() + binr.ReadByte();
                                        }
                                        else {
                                            encblobsize = bt;
                                        }
                                    }
                                    var encryptedpkcs8 = binr.ReadBytes(encblobsize);
                                    var pkcs8 = lib._DecryptPBDK2(encryptedpkcs8, salt, IV, secpswd, iterations);
                                    if (pkcs8 == null) {
                                        result = null;
                                    }
                                    else {
                                        var rsa = lib._DecodePrivateKeyInfo(pkcs8);
                                        result = rsa;
                                    }
                                    return result;
                                }
                            }
                        }
                    }
                }
            }
        }

        return result;
    };

    lib.PublicAndPrivateKeyMatch = function (publicKey, privateKey) {
        var match =
            lib._CompareByteArrays(publicKey.Modulus, privateKey.Modulus)
            && lib._CompareByteArrays(publicKey.Exponent, privateKey.Exponent);
    };

    lib.DecodeX509PublicKey = function (x509key) {
        var SeqOID =
        [
                    48,
                    13,
                    6,
                    9,
                    42,
                    134,
                    72,
                    134,
                    247,
                    13,
                    1,
                    1,
                    1,
                    5,
                    0
        ];
        var seq = [15];
        var binr = new lib.BufferReader(x509key);
        var result;
        var twobytes = binr.ReadUInt16();
        if (twobytes == 33072) {
            binr.ReadByte();
        }
        else {
            if (twobytes != 33328) {
                result = null;
                return result;
            }
            binr.ReadInt16();
        }
        seq = binr.ReadBytes(15);
        if (!lib._CompareByteArrays(seq, SeqOID)) {
            result = null;
        }
        else {
            twobytes = binr.ReadUInt16();
            if (twobytes == 33027) {
                binr.ReadByte();
            }
            else {
                if (twobytes != 33283) {
                    result = null;
                    return result;
                }
                binr.ReadInt16();
            }
            var bt = binr.ReadByte();
            if (bt != 0) {
                result = null;
            }
            else {
                twobytes = binr.ReadUInt16();
                if (twobytes == 33072) {
                    binr.ReadByte();
                }
                else {
                    if (twobytes != 33328) {
                        result = null;
                        return result;
                    }
                    binr.ReadInt16();
                }
                twobytes = binr.ReadUInt16();
                var highbyte = 0;
                var lowbyte;
                if (twobytes == 33026) {
                    lowbyte = binr.ReadByte();
                }
                else {
                    if (twobytes != 33282) {
                        result = null;
                        return result;
                    }
                    highbyte = binr.ReadByte();
                    lowbyte = binr.ReadByte();
                }
                array = new byte[4];
                array[0] = lowbyte;
                array[1] = highbyte;
                modint = array;
                var modsize = lib._byteArrayToLong(modint, 0);
                var firstbyte = binr.ReadByte();
                binr.CurrentPosition--;
                if (firstbyte == 0) {
                    binr.ReadByte();
                    modsize--;
                }
                modulus = binr.ReadBytes(modsize);
                if (binr.ReadByte() != 2) {
                    result = null;
                }
                else {
                    var expbytes = binr.ReadByte();
                    exponent = binr.ReadBytes(expbytes);
                    RSA = {
                        Modulus: modulus,
                        Exponent: exponent
                    };
                    result = RSA;
                }
            }
        }
        return result;
    };

    lib.TextToBase64 = function (text) {
        var contentAsBase64 = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Latin1.parse(text));
        return contentAsBase64;
    };

    lib.ArrayToBase64 = function (array) {
        var contentAsBase64 = CryptoJS.enc.Base64.stringify(CryptoJS.enc.u8array.parse(array));
        return contentAsBase64;
    };

    lib.GetDateFromJsonDate = function (jsonDate) {
        return new Date(parseInt(jsonDate.replace("/Date(", "").replace(")/", ""), 10));
    };

    lib.SignAsync = function (keyAsFile, password, contentAsBase64, hashAlgName) {
        var result = $.Deferred()

        var keyReader = new FileReader();
        keyReader.onload = function (event) {
            var buffer = event.target.result;
            setTimeout(function () {
                var rsaPrivateKey = lib._DecodeEncryptedPrivateKeyInfo(buffer, password);
                if (!rsaPrivateKey || !rsaPrivateKey.Modulus) {
                    result.reject({ error: 'Verifique la contraseña o clave privada.' });
                    return;
                }

                var rsaKey = new RSAKey();
                rsaKey.setPrivateEx2(
                    rsaPrivateKey.Modulus,
                    rsaPrivateKey.Exponent,
                    rsaPrivateKey.D,
                    rsaPrivateKey.P,
                    rsaPrivateKey.Q,
                    rsaPrivateKey.DP,
                    rsaPrivateKey.DQ,
                    rsaPrivateKey.InverseQ);

                var contentAsHex = b64tohex(contentAsBase64);
                var hSig = rsaKey.signWithMessageHash(contentAsHex, hashAlgName);
                var signatureAsArray =
                    CryptoJS.enc.u8array.stringify(CryptoJS.enc.Hex.parse(hSig));

                result.resolve({
                    signatureAsArray: signatureAsArray
                });
            });
        };
        keyReader.readAsArrayBuffer(keyAsFile);

        return result;
    };

    return lib;
})();