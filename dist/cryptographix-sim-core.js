  import { Container, autoinject as inject } from 'aurelia-dependency-injection';
  import { EventAggregator } from 'aurelia-event-aggregator';

export class HexCodec {
    static decode(a) {
        if (HexCodec.hexDecodeMap == undefined) {
            var hex = "0123456789ABCDEF";
            var allow = " \f\n\r\t\u00A0\u2028\u2029";
            var dec = [];
            for (var i = 0; i < 16; ++i)
                dec[hex.charAt(i)] = i;
            hex = hex.toLowerCase();
            for (var i = 10; i < 16; ++i)
                dec[hex.charAt(i)] = i;
            for (var i = 0; i < allow.length; ++i)
                dec[allow.charAt(i)] = -1;
            HexCodec.hexDecodeMap = dec;
        }
        var out = [];
        var bits = 0, char_count = 0;
        for (var i = 0; i < a.length; ++i) {
            var c = a.charAt(i);
            if (c == '=')
                break;
            var b = HexCodec.hexDecodeMap[c];
            if (b == -1)
                continue;
            if (b == undefined)
                throw 'Illegal character at offset ' + i;
            bits |= b;
            if (++char_count >= 2) {
                out.push(bits);
                bits = 0;
                char_count = 0;
            }
            else {
                bits <<= 4;
            }
        }
        if (char_count)
            throw "Hex encoding incomplete: 4 bits missing";
        return Uint8Array.from(out);
    }
}

var BASE64SPECIALS;
(function (BASE64SPECIALS) {
    BASE64SPECIALS[BASE64SPECIALS["PLUS"] = '+'.charCodeAt(0)] = "PLUS";
    BASE64SPECIALS[BASE64SPECIALS["SLASH"] = '/'.charCodeAt(0)] = "SLASH";
    BASE64SPECIALS[BASE64SPECIALS["NUMBER"] = '0'.charCodeAt(0)] = "NUMBER";
    BASE64SPECIALS[BASE64SPECIALS["LOWER"] = 'a'.charCodeAt(0)] = "LOWER";
    BASE64SPECIALS[BASE64SPECIALS["UPPER"] = 'A'.charCodeAt(0)] = "UPPER";
    BASE64SPECIALS[BASE64SPECIALS["PLUS_URL_SAFE"] = '-'.charCodeAt(0)] = "PLUS_URL_SAFE";
    BASE64SPECIALS[BASE64SPECIALS["SLASH_URL_SAFE"] = '_'.charCodeAt(0)] = "SLASH_URL_SAFE";
})(BASE64SPECIALS || (BASE64SPECIALS = {}));
export class Base64Codec {
    static decode(b64) {
        if (b64.length % 4 > 0) {
            throw new Error('Invalid base64 string. Length must be a multiple of 4');
        }
        function decode(elt) {
            var code = elt.charCodeAt(0);
            if (code === BASE64SPECIALS.PLUS || code === BASE64SPECIALS.PLUS_URL_SAFE)
                return 62;
            if (code === BASE64SPECIALS.SLASH || code === BASE64SPECIALS.SLASH_URL_SAFE)
                return 63;
            if (code >= BASE64SPECIALS.NUMBER) {
                if (code < BASE64SPECIALS.NUMBER + 10)
                    return code - BASE64SPECIALS.NUMBER + 26 + 26;
                if (code < BASE64SPECIALS.UPPER + 26)
                    return code - BASE64SPECIALS.UPPER;
                if (code < BASE64SPECIALS.LOWER + 26)
                    return code - BASE64SPECIALS.LOWER + 26;
            }
            throw new Error('Invalid base64 string. Character not valid');
        }
        let len = b64.length;
        let placeHolders = b64.charAt(len - 2) === '=' ? 2 : b64.charAt(len - 1) === '=' ? 1 : 0;
        let arr = new Uint8Array(b64.length * 3 / 4 - placeHolders);
        let l = placeHolders > 0 ? b64.length - 4 : b64.length;
        var L = 0;
        function push(v) {
            arr[L++] = v;
        }
        let i = 0, j = 0;
        for (; i < l; i += 4, j += 3) {
            let tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3));
            push((tmp & 0xFF0000) >> 16);
            push((tmp & 0xFF00) >> 8);
            push(tmp & 0xFF);
        }
        if (placeHolders === 2) {
            let tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4);
            push(tmp & 0xFF);
        }
        else if (placeHolders === 1) {
            let tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2);
            push((tmp >> 8) & 0xFF);
            push(tmp & 0xFF);
        }
        return arr;
    }
    static encode(uint8) {
        var i;
        var extraBytes = uint8.length % 3;
        var output = '';
        const lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        function encode(num) {
            return lookup.charAt(num);
        }
        function tripletToBase64(num) {
            return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F);
        }
        let length = uint8.length - extraBytes;
        for (i = 0; i < length; i += 3) {
            let temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
            output += tripletToBase64(temp);
        }
        switch (extraBytes) {
            case 1:
                let temp = uint8[uint8.length - 1];
                output += encode(temp >> 2);
                output += encode((temp << 4) & 0x3F);
                output += '==';
                break;
            case 2:
                temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1]);
                output += encode(temp >> 10);
                output += encode((temp >> 4) & 0x3F);
                output += encode((temp << 2) & 0x3F);
                output += '=';
                break;
            default:
                break;
        }
        return output;
    }
}



export var ByteEncoding;
(function (ByteEncoding) {
    ByteEncoding[ByteEncoding["RAW"] = 0] = "RAW";
    ByteEncoding[ByteEncoding["HEX"] = 1] = "HEX";
    ByteEncoding[ByteEncoding["BASE64"] = 2] = "BASE64";
    ByteEncoding[ByteEncoding["UTF8"] = 3] = "UTF8";
})(ByteEncoding || (ByteEncoding = {}));
export class ByteArray {
    constructor(bytes, encoding, opt) {
        if (!bytes) {
            this.byteArray = new Uint8Array(0);
        }
        else if (!encoding || encoding == ByteEncoding.RAW) {
            if (bytes instanceof ArrayBuffer)
                this.byteArray = new Uint8Array(bytes);
            else if (bytes instanceof Uint8Array)
                this.byteArray = bytes;
            else if (bytes instanceof ByteArray)
                this.byteArray = bytes.byteArray;
            else if (bytes instanceof Array)
                this.byteArray = new Uint8Array(bytes);
        }
        else if (typeof bytes == "string") {
            if (encoding == ByteEncoding.BASE64) {
                this.byteArray = Base64Codec.decode(bytes);
            }
            else if (encoding == ByteEncoding.HEX) {
                this.byteArray = HexCodec.decode(bytes);
            }
            else if (encoding == ByteEncoding.UTF8) {
                let l = bytes.length;
                let ba = new Uint8Array(l);
                for (let i = 0; i < l; ++i)
                    ba[i] = bytes.charCodeAt(i);
                this.byteArray = ba;
            }
        }
        if (!this.byteArray) {
            throw new Error("Invalid Params for ByteArray()");
        }
    }
    static encodingToString(encoding) {
        switch (encoding) {
            case ByteEncoding.BASE64:
                return 'BASE64';
            case ByteEncoding.UTF8:
                return 'UTF8';
            case ByteEncoding.HEX:
                return 'HEX';
            default:
                return 'RAW';
        }
    }
    static stringToEncoding(encoding) {
        if (encoding.toUpperCase() == 'BASE64')
            return ByteEncoding.BASE64;
        else if (encoding.toUpperCase() == 'UTF8')
            return ByteEncoding.UTF8;
        else if (encoding.toUpperCase() == 'HEX')
            return ByteEncoding.HEX;
        else
            return ByteEncoding.RAW;
    }
    get length() {
        return this.byteArray.length;
    }
    set length(len) {
        if (this.byteArray.length >= len) {
            this.byteArray = this.byteArray.slice(0, len);
        }
        else {
            let old = this.byteArray;
            this.byteArray = new Uint8Array(len);
            this.byteArray.set(old, 0);
        }
    }
    get backingArray() {
        return this.byteArray;
    }
    equals(value) {
        let ba = this.byteArray;
        let vba = value.byteArray;
        var ok = (ba.length == vba.length);
        if (ok) {
            for (let i = 0; i < ba.length; ++i)
                ok = ok && (ba[i] == vba[i]);
        }
        return ok;
    }
    byteAt(offset) {
        return this.byteArray[offset];
    }
    wordAt(offset) {
        return (this.byteArray[offset] << 8)
            + (this.byteArray[offset + 1]);
    }
    littleEndianWordAt(offset) {
        return (this.byteArray[offset])
            + (this.byteArray[offset + 1] << 8);
    }
    dwordAt(offset) {
        return (this.byteArray[offset] << 24)
            + (this.byteArray[offset + 1] << 16)
            + (this.byteArray[offset + 2] << 8)
            + (this.byteArray[offset + 3]);
    }
    setByteAt(offset, value) {
        this.byteArray[offset] = value;
        return this;
    }
    setBytesAt(offset, value) {
        this.byteArray.set(value.byteArray, offset);
        return this;
    }
    clone() {
        return new ByteArray(this.byteArray.slice());
    }
    bytesAt(offset, count) {
        if (!Number.isInteger(count))
            count = (this.length - offset);
        return new ByteArray(this.byteArray.slice(offset, offset + count));
    }
    viewAt(offset, count) {
        if (!Number.isInteger(count))
            count = (this.length - offset);
        return new ByteArray(this.byteArray.subarray(offset, offset + count));
    }
    addByte(value) {
        this.byteArray[this.byteArray.length] = value;
        return this;
    }
    setLength(len) {
        this.length = len;
        return this;
    }
    concat(bytes) {
        let ba = this.byteArray;
        this.byteArray = new Uint8Array(ba.length + bytes.length);
        this.byteArray.set(ba);
        this.byteArray.set(bytes.byteArray, ba.length);
        return this;
    }
    not() {
        let ba = this.byteArray;
        for (let i = 0; i < ba.length; ++i)
            ba[i] = ba[i] ^ 0xFF;
        return this;
    }
    and(value) {
        let ba = this.byteArray;
        let vba = value.byteArray;
        for (let i = 0; i < ba.length; ++i)
            ba[i] = ba[i] & vba[i];
        return this;
    }
    or(value) {
        let ba = this.byteArray;
        let vba = value.byteArray;
        for (let i = 0; i < ba.length; ++i)
            ba[i] = ba[i] | vba[i];
        return this;
    }
    xor(value) {
        let ba = this.byteArray;
        let vba = value.byteArray;
        for (let i = 0; i < ba.length; ++i)
            ba[i] = ba[i] ^ vba[i];
        return this;
    }
    toString(encoding, opt) {
        let s = "";
        let i = 0;
        switch (encoding || ByteEncoding.HEX) {
            case ByteEncoding.HEX:
                for (i = 0; i < this.length; ++i)
                    s += ("0" + this.byteArray[i].toString(16)).slice(-2);
                break;
            case ByteEncoding.BASE64:
                return Base64Codec.encode(this.byteArray);
            case ByteEncoding.UTF8:
                for (i = 0; i < this.length; ++i)
                    s += String.fromCharCode(this.byteArray[i]);
                break;
            default:
                for (i = 0; i < this.length; ++i)
                    s += String.fromCharCode(this.byteArray[i]);
                break;
        }
        return s;
    }
}
ByteArray.RAW = ByteEncoding.RAW;
ByteArray.HEX = ByteEncoding.HEX;
ByteArray.BASE64 = ByteEncoding.BASE64;
ByteArray.UTF8 = ByteEncoding.UTF8;

export var CryptographicOperation;
(function (CryptographicOperation) {
    CryptographicOperation[CryptographicOperation["ENCRYPT"] = 0] = "ENCRYPT";
    CryptographicOperation[CryptographicOperation["DECRYPT"] = 1] = "DECRYPT";
    CryptographicOperation[CryptographicOperation["DIGEST"] = 2] = "DIGEST";
    CryptographicOperation[CryptographicOperation["SIGN"] = 3] = "SIGN";
    CryptographicOperation[CryptographicOperation["VERIFY"] = 4] = "VERIFY";
    CryptographicOperation[CryptographicOperation["DERIVE_BITS"] = 5] = "DERIVE_BITS";
    CryptographicOperation[CryptographicOperation["DERIVE_KEY"] = 6] = "DERIVE_KEY";
    CryptographicOperation[CryptographicOperation["IMPORT_KEY"] = 7] = "IMPORT_KEY";
    CryptographicOperation[CryptographicOperation["EXPORT_KEY"] = 8] = "EXPORT_KEY";
    CryptographicOperation[CryptographicOperation["GENERATE_KEY"] = 9] = "GENERATE_KEY";
    CryptographicOperation[CryptographicOperation["WRAP_KEY"] = 10] = "WRAP_KEY";
    CryptographicOperation[CryptographicOperation["UNWRAP_KEY"] = 11] = "UNWRAP_KEY";
})(CryptographicOperation || (CryptographicOperation = {}));
export class CryptographicServiceRegistry {
    constructor() {
        this._serviceMap = new Map();
        this._keyServiceMap = new Map();
    }
    getService(algorithm) {
        let algo = (algorithm instanceof Object) ? algorithm.name : algorithm;
        let service = this._serviceMap.get(algo);
        return { name: algo, instance: service ? new service() : null };
    }
    getKeyService(algorithm) {
        let algo = (algorithm instanceof Object) ? algorithm.name : algorithm;
        let service = this._keyServiceMap.get(algo);
        return { name: algo, instance: service ? new service() : null };
    }
    setService(algorithm, ctor, opers) {
        ctor.supportedOperations = opers;
        this._serviceMap.set(algorithm, ctor);
    }
    setKeyService(algorithm, ctor, opers) {
        ctor.supportedOperations = opers;
        this._keyServiceMap.set(algorithm, ctor);
    }
}
export class CryptographicServiceProvider {
    static registerService(name, ctor, opers) {
        CryptographicServiceProvider._registry.setService(name, ctor, opers);
    }
    static registerKeyService(name, ctor, opers) {
        CryptographicServiceProvider._registry.setKeyService(name, ctor, opers);
    }
    get registry() {
        return CryptographicServiceProvider._registry;
    }
    encrypt(algorithm, key, data) {
        let { name, instance } = this.registry.getService(algorithm);
        return (instance && instance.encrypt)
            ? instance.encrypt(name, key, data)
            : Promise.reject("");
    }
    decrypt(algorithm, key, data) {
        let { name, instance } = this.registry.getService(algorithm);
        return (instance && instance.decrypt)
            ? instance.decrypt(name, key, data)
            : Promise.reject("");
    }
    digest(algorithm, data) {
        let { name, instance } = this.registry.getService(algorithm);
        return (instance && instance.digest)
            ? instance.digest(name, data)
            : Promise.reject("");
    }
    sign(algorithm, key, data) {
        let { name, instance } = this.registry.getService(algorithm);
        return (instance && instance.sign)
            ? instance.sign(name, key, data)
            : Promise.reject("");
    }
    verify(algorithm, key, signature, data) {
        let { name, instance } = this.registry.getService(algorithm);
        return (instance && instance.verify)
            ? instance.verify(name, key, signature, data)
            : Promise.reject("");
    }
    exportKey(format, key) {
        let { name, instance } = this.registry.getKeyService(key.algorithm);
        return (instance && instance.exportKey)
            ? instance.exportKey(format, key)
            : Promise.reject("");
    }
    generateKey(algorithm, extractable, keyUsages) {
        let { name, instance } = this.registry.getKeyService(algorithm);
        return (instance && instance.generateKey)
            ? instance.generateKey(name, extractable, keyUsages)
            : Promise.reject("");
    }
    importKey(format, keyData, algorithm, extractable, keyUsages) {
        let { name, instance } = this.registry.getKeyService(algorithm);
        return (instance && instance.importKey)
            ? instance.importKey(format, keyData, name, extractable, keyUsages)
            : Promise.reject("");
    }
    deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        let { name, instance } = this.registry.getKeyService(algorithm);
        return (instance && instance.deriveKey)
            ? instance.deriveKey(name, baseKey, derivedKeyType, extractable, keyUsages)
            : Promise.reject("");
    }
    deriveBits(algorithm, baseKey, length) {
        let { name, instance } = this.registry.getService(algorithm);
        return (instance && instance.deriveBits)
            ? instance.deriveBits(name, baseKey, length)
            : Promise.reject("");
    }
    wrapKey(format, key, wrappingKey, wrapAlgorithm) {
        let { name, instance } = this.registry.getKeyService(key.algorithm);
        return (instance && instance.wrapKey)
            ? instance.wrapKey(format, key, wrappingKey, wrapAlgorithm)
            : Promise.reject("");
    }
    unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        let { name, instance } = this.registry.getKeyService(unwrapAlgorithm);
        return (instance && instance.unwrapKey)
            ? instance.unwrapKey(format, wrappedKey, unwrappingKey, name, unwrappedKeyAlgorithm, extractable, keyUsages)
            : Promise.reject("");
    }
}
CryptographicServiceProvider._registry = new CryptographicServiceRegistry();



export class WebCryptoService {
    constructor() {
    }
    static get subtle() {
        let subtle = WebCryptoService._subtle
            || (crypto && crypto.subtle)
            || (window && window.crypto && window.crypto.subtle)
            || msrcrypto;
        if (!WebCryptoService._subtle)
            WebCryptoService._subtle = subtle;
        return subtle;
    }
    encrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.encrypt(algorithm, key, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    decrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.decrypt(algorithm, key, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    digest(algorithm, data) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.digest(algorithm, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    exportKey(format, key) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.exportKey(format, key)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    generateKey(algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
        });
    }
    importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.importKey(format, keyData.backingArray, algorithm, extractable, keyUsages)
                .then((res) => { resolve(res); })
                .catch((err) => { reject(err); });
        });
    }
    sign(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.sign(algorithm, key, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    verify(algorithm, key, signature, data) {
        return new Promise((resolve, reject) => {
            WebCryptoService.subtle.verify(algorithm, key, signature.backingArray, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
}
if (WebCryptoService.subtle) {
    CryptographicServiceProvider.registerService('AES-CBC', WebCryptoService, [CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT]);
    CryptographicServiceProvider.registerService('AES-GCM', WebCryptoService, [CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT]);
}



class DESSecretKey {
    constructor(keyMaterial, algorithm, extractable, usages) {
        this._keyMaterial = keyMaterial;
        this._algorithm = algorithm;
        this._extractable = extractable;
        this._type = 'secret';
        this._usages = usages;
        Object.freeze(this._usages);
    }
    get algorithm() { return this._algorithm; }
    get extractable() { return this._extractable; }
    get type() { return this._type; }
    get usages() { return Array.from(this._usages); }
    get keyMaterial() { return this._keyMaterial; }
    ;
}
export class DESCryptographicService {
    constructor() {
    }
    encrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            let desKey = key;
            resolve(new ByteArray(this.des(desKey.keyMaterial.backingArray, data.backingArray, 1, 0)));
        });
    }
    decrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            let desKey = key;
            resolve(new ByteArray(this.des(desKey.keyMaterial.backingArray, data.backingArray, 0, 0)));
        });
    }
    importKey(format, keyData, algorithm, extractable, keyUsages) {
        return new Promise((resolve, reject) => {
            let desKey = new DESSecretKey(keyData, algorithm, extractable, keyUsages);
            resolve(desKey);
        });
    }
    sign(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            let desKey = key;
            resolve(new ByteArray(this.des(desKey.keyMaterial.backingArray, data.backingArray, 0, 0)));
        });
    }
    des(key, message, encrypt, mode, iv, padding) {
        function des_createKeys(key) {
            let desPC = DESCryptographicService.desPC;
            if (!desPC) {
                desPC = DESCryptographicService.desPC = {
                    pc2bytes0: new Uint32Array([0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204]),
                    pc2bytes1: new Uint32Array([0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101]),
                    pc2bytes2: new Uint32Array([0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808]),
                    pc2bytes3: new Uint32Array([0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000]),
                    pc2bytes4: new Uint32Array([0, 0x40000, 0x10, 0x40010, 0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010]),
                    pc2bytes5: new Uint32Array([0, 0x400, 0x20, 0x420, 0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420]),
                    pc2bytes6: new Uint32Array([0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002]),
                    pc2bytes7: new Uint32Array([0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800]),
                    pc2bytes8: new Uint32Array([0, 0x40000, 0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002]),
                    pc2bytes9: new Uint32Array([0, 0x10000000, 0x8, 0x10000008, 0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408]),
                    pc2bytes10: new Uint32Array([0, 0x20, 0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020]),
                    pc2bytes11: new Uint32Array([0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200]),
                    pc2bytes12: new Uint32Array([0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010]),
                    pc2bytes13: new Uint32Array([0, 0x4, 0x100, 0x104, 0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105])
                };
            }
            var iterations = key.length > 8 ? 3 : 1;
            var keys = new Uint32Array(32 * iterations);
            var shifts = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];
            var lefttemp, righttemp, m = 0, n = 0, temp;
            for (var j = 0; j < iterations; j++) {
                left = (key[m++] << 24) | (key[m++] << 16) | (key[m++] << 8) | key[m++];
                right = (key[m++] << 24) | (key[m++] << 16) | (key[m++] << 8) | key[m++];
                temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
                right ^= temp;
                left ^= (temp << 4);
                temp = ((right >>> -16) ^ left) & 0x0000ffff;
                left ^= temp;
                right ^= (temp << -16);
                temp = ((left >>> 2) ^ right) & 0x33333333;
                right ^= temp;
                left ^= (temp << 2);
                temp = ((right >>> -16) ^ left) & 0x0000ffff;
                left ^= temp;
                right ^= (temp << -16);
                temp = ((left >>> 1) ^ right) & 0x55555555;
                right ^= temp;
                left ^= (temp << 1);
                temp = ((right >>> 8) ^ left) & 0x00ff00ff;
                left ^= temp;
                right ^= (temp << 8);
                temp = ((left >>> 1) ^ right) & 0x55555555;
                right ^= temp;
                left ^= (temp << 1);
                temp = (left << 8) | ((right >>> 20) & 0x000000f0);
                left = (right << 24) | ((right << 8) & 0xff0000) | ((right >>> 8) & 0xff00) | ((right >>> 24) & 0xf0);
                right = temp;
                for (var i = 0; i < shifts.length; i++) {
                    if (shifts[i]) {
                        left = (left << 2) | (left >>> 26);
                        right = (right << 2) | (right >>> 26);
                    }
                    else {
                        left = (left << 1) | (left >>> 27);
                        right = (right << 1) | (right >>> 27);
                    }
                    left &= -0xf;
                    right &= -0xf;
                    lefttemp = desPC.pc2bytes0[left >>> 28] | desPC.pc2bytes1[(left >>> 24) & 0xf]
                        | desPC.pc2bytes2[(left >>> 20) & 0xf] | desPC.pc2bytes3[(left >>> 16) & 0xf]
                        | desPC.pc2bytes4[(left >>> 12) & 0xf] | desPC.pc2bytes5[(left >>> 8) & 0xf]
                        | desPC.pc2bytes6[(left >>> 4) & 0xf];
                    righttemp = desPC.pc2bytes7[right >>> 28] | desPC.pc2bytes8[(right >>> 24) & 0xf]
                        | desPC.pc2bytes9[(right >>> 20) & 0xf] | desPC.pc2bytes10[(right >>> 16) & 0xf]
                        | desPC.pc2bytes11[(right >>> 12) & 0xf] | desPC.pc2bytes12[(right >>> 8) & 0xf]
                        | desPC.pc2bytes13[(right >>> 4) & 0xf];
                    temp = ((righttemp >>> 16) ^ lefttemp) & 0x0000ffff;
                    keys[n++] = lefttemp ^ temp;
                    keys[n++] = righttemp ^ (temp << 16);
                }
            }
            return keys;
        }
        let desSP = DESCryptographicService.desSP;
        if (desSP == undefined) {
            desSP = DESCryptographicService.desSP = {
                spfunction1: new Uint32Array([0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0, 0x10004, 0x10400, 0, 0x1010004]),
                spfunction2: new Uint32Array([-0x7fef7fe0, -0x7fff8000, 0x8000, 0x108020, 0x100000, 0x20, -0x7fefffe0, -0x7fff7fe0, -0x7fffffe0, -0x7fef7fe0, -0x7fef8000, -0x80000000, -0x7fff8000, 0x100000, 0x20, -0x7fefffe0, 0x108000, 0x100020, -0x7fff7fe0, 0, -0x80000000, 0x8000, 0x108020, -0x7ff00000, 0x100020, -0x7fffffe0, 0, 0x108000, 0x8020, -0x7fef8000, -0x7ff00000, 0x8020, 0, 0x108020, -0x7fefffe0, 0x100000, -0x7fff7fe0, -0x7ff00000, -0x7fef8000, 0x8000, -0x7ff00000, -0x7fff8000, 0x20, -0x7fef7fe0, 0x108020, 0x20, 0x8000, -0x80000000, 0x8020, -0x7fef8000, 0x100000, -0x7fffffe0, 0x100020, -0x7fff7fe0, -0x7fffffe0, 0x100020, 0x108000, 0, -0x7fff8000, 0x8020, -0x80000000, -0x7fefffe0, -0x7fef7fe0, 0x108000]),
                spfunction3: new Uint32Array([0x208, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200]),
                spfunction4: new Uint32Array([0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0, 0x802000, 0x802000, 0x802081, 0x81, 0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0, 0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080]),
                spfunction5: new Uint32Array([0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0, 0x40080000, 0x2080100, 0x40000100]),
                spfunction6: new Uint32Array([0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0, 0x20404000, 0x20000000, 0x400010, 0x20004010]),
                spfunction7: new Uint32Array([0x200000, 0x4200002, 0x4000802, 0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0, 0x2, 0x4200802, 0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002]),
                spfunction8: new Uint32Array([0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0, 0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000]),
            };
        }
        var keys = des_createKeys(key);
        var m = 0, i, j, temp, left, right, looping;
        var cbcleft, cbcleft2, cbcright, cbcright2;
        var len = message.length;
        var iterations = keys.length == 32 ? 3 : 9;
        if (iterations == 3) {
            looping = encrypt ? [0, 32, 2] : [30, -2, -2];
        }
        else {
            looping = encrypt ? [0, 32, 2, 62, 30, -2, 64, 96, 2] : [94, 62, -2, 32, 64, 2, 30, -2, -2];
        }
        if ((padding != undefined) && (padding != 4)) {
            var unpaddedMessage = message;
            var pad = 8 - (len % 8);
            message = new Uint8Array(len + 8);
            message.set(unpaddedMessage, 0);
            switch (padding) {
                case 0:
                    message.set(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), len);
                    break;
                case 1:
                    {
                        message.set(new Uint8Array([pad, pad, pad, pad, pad, pad, pad, pad]), 8);
                        if (pad == 8)
                            len += 8;
                        break;
                    }
                case 2:
                    message.set(new Uint8Array([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20]), 8);
                    break;
            }
            len += 8 - (len % 8);
        }
        var result = new Uint8Array(len);
        if (mode == 1) {
            var m = 0;
            cbcleft = (iv[m++] << 24) | (iv[m++] << 16) | (iv[m++] << 8) | iv[m++];
            cbcright = (iv[m++] << 24) | (iv[m++] << 16) | (iv[m++] << 8) | iv[m++];
        }
        var rm = 0;
        while (m < len) {
            left = (message[m++] << 24) | (message[m++] << 16) | (message[m++] << 8) | message[m++];
            right = (message[m++] << 24) | (message[m++] << 16) | (message[m++] << 8) | message[m++];
            if (mode == 1) {
                if (encrypt) {
                    left ^= cbcleft;
                    right ^= cbcright;
                }
                else {
                    cbcleft2 = cbcleft;
                    cbcright2 = cbcright;
                    cbcleft = left;
                    cbcright = right;
                }
            }
            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
            right ^= temp;
            left ^= (temp << 4);
            temp = ((left >>> 16) ^ right) & 0x0000ffff;
            right ^= temp;
            left ^= (temp << 16);
            temp = ((right >>> 2) ^ left) & 0x33333333;
            left ^= temp;
            right ^= (temp << 2);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff;
            left ^= temp;
            right ^= (temp << 8);
            temp = ((left >>> 1) ^ right) & 0x55555555;
            right ^= temp;
            left ^= (temp << 1);
            left = ((left << 1) | (left >>> 31));
            right = ((right << 1) | (right >>> 31));
            for (j = 0; j < iterations; j += 3) {
                var endloop = looping[j + 1];
                var loopinc = looping[j + 2];
                for (i = looping[j]; i != endloop; i += loopinc) {
                    var right1 = right ^ keys[i];
                    var right2 = ((right >>> 4) | (right << 28)) ^ keys[i + 1];
                    temp = left;
                    left = right;
                    right = temp ^ (desSP.spfunction2[(right1 >>> 24) & 0x3f] | desSP.spfunction4[(right1 >>> 16) & 0x3f]
                        | desSP.spfunction6[(right1 >>> 8) & 0x3f] | desSP.spfunction8[right1 & 0x3f]
                        | desSP.spfunction1[(right2 >>> 24) & 0x3f] | desSP.spfunction3[(right2 >>> 16) & 0x3f]
                        | desSP.spfunction5[(right2 >>> 8) & 0x3f] | desSP.spfunction7[right2 & 0x3f]);
                }
                temp = left;
                left = right;
                right = temp;
            }
            left = ((left >>> 1) | (left << 31));
            right = ((right >>> 1) | (right << 31));
            temp = ((left >>> 1) ^ right) & 0x55555555;
            right ^= temp;
            left ^= (temp << 1);
            temp = ((right >>> 8) ^ left) & 0x00ff00ff;
            left ^= temp;
            right ^= (temp << 8);
            temp = ((right >>> 2) ^ left) & 0x33333333;
            left ^= temp;
            right ^= (temp << 2);
            temp = ((left >>> 16) ^ right) & 0x0000ffff;
            right ^= temp;
            left ^= (temp << 16);
            temp = ((left >>> 4) ^ right) & 0x0f0f0f0f;
            right ^= temp;
            left ^= (temp << 4);
            if (mode == 1) {
                if (encrypt) {
                    cbcleft = left;
                    cbcright = right;
                }
                else {
                    left ^= cbcleft2;
                    right ^= cbcright2;
                }
            }
            result.set(new Uint8Array([(left >>> 24) & 0xff, (left >>> 16) & 0xff, (left >>> 8) & 0xff, (left) & 0xff, (right >>> 24) & 0xff, (right >>> 16) & 0xff, (right >>> 8) & 0xff, (right) & 0xff]), rm);
            rm += 8;
        }
        return result;
    }
}
CryptographicServiceProvider.registerService('DES-ECB', DESCryptographicService, [CryptographicOperation.ENCRYPT, CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT, CryptographicOperation.IMPORT_KEY,]);



export { Container, inject };


export class Enum {
}
export class Integer extends Number {
}
export class FieldArray {
}
export var FieldTypes = {
    Boolean: Boolean,
    Number: Number,
    Integer: Integer,
    ByteArray: ByteArray,
    Enum: Enum,
    Array: FieldArray,
    String: String,
    Kind: Kind
};
export class KindInfo {
    constructor() {
        this.fields = {};
    }
}
export class KindBuilder {
    constructor(ctor, description) {
        this.ctor = ctor;
        ctor.kindInfo = {
            name: ctor.name,
            description: description,
            fields: {}
        };
    }
    static init(ctor, description) {
        let builder = new KindBuilder(ctor, description);
        return builder;
    }
    field(name, description, fieldType, opts = {}) {
        let field = opts;
        field.description = description;
        field.fieldType = fieldType;
        this.ctor.kindInfo.fields[name] = field;
        return this;
    }
    boolField(name, description, opts = {}) {
        return this.field(name, description, Boolean, opts);
    }
    numberField(name, description, opts = {}) {
        return this.field(name, description, Number, opts);
    }
    integerField(name, description, opts = {}) {
        return this.field(name, description, Integer, opts);
    }
    uint32Field(name, description, opts = {}) {
        opts.minimum = opts.minimum || 0;
        opts.maximum = opts.maximum || 0xFFFFFFFF;
        return this.field(name, description, Integer, opts);
    }
    byteField(name, description, opts = {}) {
        opts.minimum = opts.minimum || 0;
        opts.maximum = opts.maximum || 255;
        return this.field(name, description, Integer, opts);
    }
    stringField(name, description, opts = {}) {
        return this.field(name, description, String, opts);
    }
    kindField(name, description, kind, opts = {}) {
        opts.kind = kind;
        return this.field(name, description, Kind, opts);
    }
    enumField(name, description, enumm, opts = {}) {
        opts.enumMap = new Map();
        for (let idx in enumm) {
            if (1 * idx == idx)
                opts.enumMap.set(idx, enumm[idx]);
        }
        return this.field(name, description, Enum, opts);
    }
}
export class Kind {
    static getKindInfo(kind) {
        return (kind.constructor).kindInfo;
    }
    static initFields(kind, attributes = {}) {
        let kindInfo = Kind.getKindInfo(kind);
        for (let id in kindInfo.fields) {
            let field = kindInfo.fields[id];
            let fieldType = field.fieldType;
            let val;
            if (!field.calculated) {
                if (attributes[id])
                    val = attributes[id];
                else if (field.default != undefined)
                    val = field.default;
                else if (fieldType == String)
                    val = '';
                else if (fieldType == Number)
                    val = 0;
                else if (fieldType == Integer)
                    val = field.minimum || 0;
                else if (fieldType == Boolean)
                    val = false;
                else if (fieldType == ByteArray)
                    val = new ByteArray();
                else if (fieldType == Enum)
                    val = field.enumMap.keys[0];
                else if (fieldType == Kind) {
                    let xx = fieldType.constructor;
                    val = Object.create(xx);
                }
                kind[id] = val;
            }
        }
    }
}

export class Message {
    constructor(header, payload) {
        this._header = header || {};
        this._payload = payload;
    }
    get header() {
        return this._header;
    }
    get payload() {
        return this._payload;
    }
}
export class KindMessage extends Message {
}

var window = window || {};
export class TaskScheduler {
    constructor() {
        this.taskQueue = [];
        var self = this;
        if (typeof TaskScheduler.BrowserMutationObserver === 'function') {
            this.requestFlushTaskQueue = TaskScheduler.makeRequestFlushFromMutationObserver(function () {
                return self.flushTaskQueue();
            });
        }
        else {
            this.requestFlushTaskQueue = TaskScheduler.makeRequestFlushFromTimer(function () {
                return self.flushTaskQueue();
            });
        }
    }
    static makeRequestFlushFromMutationObserver(flush) {
        var toggle = 1;
        var observer = new TaskScheduler.BrowserMutationObserver(flush);
        var node = document.createTextNode('');
        observer.observe(node, { characterData: true });
        return function requestFlush() {
            toggle = -toggle;
            node["data"] = toggle;
        };
    }
    static makeRequestFlushFromTimer(flush) {
        return function requestFlush() {
            var timeoutHandle = setTimeout(handleFlushTimer, 0);
            var intervalHandle = setInterval(handleFlushTimer, 50);
            function handleFlushTimer() {
                clearTimeout(timeoutHandle);
                clearInterval(intervalHandle);
                flush();
            }
        };
    }
    shutdown() {
    }
    queueTask(task) {
        if (this.taskQueue.length < 1) {
            this.requestFlushTaskQueue();
        }
        this.taskQueue.push(task);
    }
    flushTaskQueue() {
        var queue = this.taskQueue, capacity = TaskScheduler.taskQueueCapacity, index = 0, task;
        while (index < queue.length) {
            task = queue[index];
            try {
                task.call();
            }
            catch (error) {
                this.onError(error, task);
            }
            index++;
            if (index > capacity) {
                for (var scan = 0; scan < index; scan++) {
                    queue[scan] = queue[scan + index];
                }
                queue.length -= index;
                index = 0;
            }
        }
        queue.length = 0;
    }
    onError(error, task) {
        if ('onError' in task) {
            task.onError(error);
        }
        else if (TaskScheduler.hasSetImmediate) {
            setImmediate(function () {
                throw error;
            });
        }
        else {
            setTimeout(function () {
                throw error;
            }, 0);
        }
    }
}
TaskScheduler.BrowserMutationObserver = window["MutationObserver"] || window["WebKitMutationObserver"];
TaskScheduler.hasSetImmediate = typeof setImmediate === 'function';
TaskScheduler.taskQueueCapacity = 1024;



export class Channel {
    constructor() {
        this._active = false;
        this._endPoints = [];
    }
    shutdown() {
        this._active = false;
        this._endPoints = [];
        if (this._taskScheduler) {
            this._taskScheduler.shutdown();
            this._taskScheduler = undefined;
        }
    }
    get active() {
        return this._active;
    }
    activate() {
        this._taskScheduler = new TaskScheduler();
        this._active = true;
    }
    deactivate() {
        this._taskScheduler = undefined;
        this._active = false;
    }
    addEndPoint(endPoint) {
        this._endPoints.push(endPoint);
    }
    removeEndPoint(endPoint) {
        let idx = this._endPoints.indexOf(endPoint);
        if (idx >= 0) {
            this._endPoints.splice(idx, 1);
        }
    }
    get endPoints() {
        return this._endPoints;
    }
    sendMessage(origin, message) {
        let isResponse = (message.header && message.header.isResponse);
        if (!this._active)
            return;
        if (origin.direction == Direction.IN && !isResponse)
            throw new Error('Unable to send on IN port');
        this._endPoints.forEach(endPoint => {
            if (origin != endPoint) {
                if (endPoint.direction != Direction.OUT || isResponse) {
                    this._taskScheduler.queueTask(() => {
                        endPoint.handleMessage(message, origin, this);
                    });
                }
            }
        });
    }
}

export var Direction;
(function (Direction) {
    Direction[Direction["IN"] = 1] = "IN";
    Direction[Direction["OUT"] = 2] = "OUT";
    Direction[Direction["INOUT"] = 3] = "INOUT";
})(Direction || (Direction = {}));
;
export class EndPoint {
    constructor(id, direction = Direction.INOUT) {
        this._id = id;
        this._direction = direction;
        this._channels = [];
        this._messageListeners = [];
    }
    shutdown() {
        this.detachAll();
        this._messageListeners = [];
    }
    get id() {
        return this._id;
    }
    attach(channel) {
        this._channels.push(channel);
        channel.addEndPoint(this);
    }
    detach(channelToDetach) {
        let idx = this._channels.indexOf(channelToDetach);
        if (idx >= 0) {
            channelToDetach.removeEndPoint(this);
            this._channels.splice(idx, 1);
        }
    }
    detachAll() {
        this._channels.forEach(channel => {
            channel.removeEndPoint(this);
        });
        this._channels = [];
    }
    get attached() {
        return (this._channels.length > 0);
    }
    get direction() {
        return this._direction;
    }
    handleMessage(message, fromEndPoint, fromChannel) {
        this._messageListeners.forEach(messageListener => {
            messageListener(message, this, fromChannel);
        });
    }
    sendMessage(message) {
        this._channels.forEach(channel => {
            channel.sendMessage(this, message);
        });
    }
    onMessage(messageListener) {
        this._messageListeners.push(messageListener);
    }
}


export var ProtocolTypeBits;
(function (ProtocolTypeBits) {
    ProtocolTypeBits[ProtocolTypeBits["PACKET"] = 0] = "PACKET";
    ProtocolTypeBits[ProtocolTypeBits["STREAM"] = 1] = "STREAM";
    ProtocolTypeBits[ProtocolTypeBits["ONEWAY"] = 0] = "ONEWAY";
    ProtocolTypeBits[ProtocolTypeBits["CLIENTSERVER"] = 4] = "CLIENTSERVER";
    ProtocolTypeBits[ProtocolTypeBits["PEER2PEER"] = 6] = "PEER2PEER";
    ProtocolTypeBits[ProtocolTypeBits["UNTYPED"] = 0] = "UNTYPED";
    ProtocolTypeBits[ProtocolTypeBits["TYPED"] = 8] = "TYPED";
})(ProtocolTypeBits || (ProtocolTypeBits = {}));
export class Protocol {
}
Protocol.protocolType = 0;
class ClientServerProtocol extends Protocol {
}
ClientServerProtocol.protocolType = ProtocolTypeBits.CLIENTSERVER | ProtocolTypeBits.TYPED;
class APDU {
}
class APDUMessage extends Message {
}
class APDUProtocol extends ClientServerProtocol {
}

export class PortInfo {
    constructor() {
        this.count = 0;
        this.required = false;
    }
}

export class ComponentInfo {
    constructor() {
        this.detailLink = '';
        this.category = '';
        this.author = '';
        this.ports = {};
        this.stores = {};
    }
}

export class StoreInfo {
}


export class ComponentBuilder {
    constructor(ctor, name, description, category) {
        this.ctor = ctor;
        ctor.componentInfo = {
            name: name || ctor.name,
            description: description,
            detailLink: '',
            category: category,
            author: '',
            ports: {},
            stores: {},
            configKind: Kind,
            defaultConfig: {}
        };
    }
    static init(ctor, name, description, category) {
        let builder = new ComponentBuilder(ctor, name, description, category);
        return builder;
    }
    config(configKind, defaultConfig) {
        this.ctor.componentInfo.configKind = configKind;
        this.ctor.componentInfo.defaultConfig = defaultConfig;
        return this;
    }
    port(id, description, direction, opts) {
        opts = opts || {};
        this.ctor.componentInfo.ports[id] = {
            direction: direction,
            description: description,
            protocol: opts.protocol,
            count: opts.count,
            required: opts.required
        };
        return this;
    }
}

export class EventHub {
    constructor() {
        this._eventAggregator = new EventAggregator();
    }
    publish(event, data) {
        this._eventAggregator.publish(event, data);
    }
    subscribe(event, handler) {
        return this._eventAggregator.subscribe(event, handler);
    }
    subscribeOnce(event, handler) {
        return this._eventAggregator.subscribeOnce(event, handler);
    }
}


export class Port {
    constructor(owner, endPoint, attributes = {}) {
        if (!endPoint) {
            let direction = attributes.direction || Direction.INOUT;
            if (typeof attributes.direction == "string")
                direction = Direction[direction.toUpperCase()];
            endPoint = new EndPoint(attributes.id, direction);
        }
        this._owner = owner;
        this._endPoint = endPoint;
        this._protocolID = attributes['protocol'] || 'any';
        this.metadata = attributes.metadata || { x: 100, y: 100 };
    }
    get endPoint() {
        return this._endPoint;
    }
    set endPoint(endPoint) {
        this._endPoint = endPoint;
    }
    toObject(opts) {
        var port = {
            id: this._endPoint.id,
            direction: this._endPoint.direction,
            protocol: (this._protocolID != 'any') ? this._protocolID : undefined,
            metadata: this.metadata,
        };
        return port;
    }
    get owner() {
        return this._owner;
    }
    get protocolID() {
        return this._protocolID;
    }
    get id() {
        return this._endPoint.id;
    }
    get direction() {
        return this._endPoint.direction;
    }
}
export class PublicPort extends Port {
    constructor(owner, endPoint, attributes) {
        super(owner, endPoint, attributes);
        let proxyDirection = (this._endPoint.direction == Direction.IN)
            ? Direction.OUT
            : (this._endPoint.direction == Direction.OUT)
                ? Direction.IN
                : Direction.INOUT;
        this.proxyEndPoint = new EndPoint(this._endPoint.id, proxyDirection);
        this.proxyEndPoint.onMessage((message) => {
            this._endPoint.handleMessage(message, this.proxyEndPoint, this.proxyChannel);
        });
        this._endPoint.onMessage((message) => {
            this.proxyEndPoint.sendMessage(message);
        });
        this.proxyChannel = null;
    }
    connectPrivate(channel) {
        this.proxyChannel = channel;
        this.proxyEndPoint.attach(channel);
    }
    disconnectPrivate() {
        this.proxyEndPoint.detach(this.proxyChannel);
    }
    toObject(opts) {
        var port = super.toObject(opts);
        return port;
    }
}



export class Node extends EventHub {
    constructor(owner, attributes = {}) {
        super();
        this._owner = owner;
        this._id = attributes.id || '';
        this._component = attributes.component;
        this._initialData = attributes.initialData || {};
        this._ports = new Map();
        this.metadata = attributes.metadata || {};
        Object.keys(attributes.ports || {}).forEach((id) => {
            this.addPlaceholderPort(id, attributes.ports[id]);
        });
    }
    toObject(opts) {
        var node = {
            id: this.id,
            component: this._component,
            initialData: this._initialData,
            ports: {},
            metadata: this.metadata
        };
        this._ports.forEach((port, id) => {
            node.ports[id] = port.toObject();
        });
        return node;
    }
    get owner() {
        return this._owner;
    }
    get id() {
        return this._id;
    }
    set id(id) {
        this._id = id;
    }
    updatePorts(endPoints) {
        let currentPorts = this._ports;
        let newPorts = new Map();
        endPoints.forEach((ep) => {
            let id = ep.id;
            if (currentPorts.has(id)) {
                let port = currentPorts.get(id);
                port.endPoint = ep;
                newPorts.set(id, port);
                currentPorts.delete(id);
            }
            else {
                let port = new Port(this, ep, { id: id, direction: ep.direction });
                newPorts.set(id, port);
            }
        });
        this._ports = newPorts;
    }
    addPlaceholderPort(id, attributes) {
        attributes["id"] = id;
        let port = new Port(this, null, attributes);
        this._ports.set(id, port);
        return port;
    }
    get ports() {
        return this._ports;
    }
    getPortArray() {
        let xports = [];
        this._ports.forEach((port, id) => {
            xports.push(port);
        });
        return xports;
    }
    getPortByID(id) {
        return this._ports.get(id);
    }
    identifyPort(id, protocolID) {
        var port;
        if (id)
            port = this._ports.get(id);
        else if (protocolID) {
            this._ports.forEach((p, id) => {
                if (p.protocolID == protocolID)
                    port = p;
            }, this);
        }
        return port;
    }
    removePort(id) {
        return this._ports.delete(id);
    }
    loadComponent(factory) {
        this.unloadComponent();
        let ctx = this._context = factory.createContext(this._component, this._initialData);
        ctx.node = this;
        return ctx.load();
    }
    get context() {
        return this._context;
    }
    unloadComponent() {
        if (this._context) {
            this._context.release();
            this._context = null;
        }
    }
}


export var RunState;
(function (RunState) {
    RunState[RunState["NEWBORN"] = 0] = "NEWBORN";
    RunState[RunState["LOADING"] = 1] = "LOADING";
    RunState[RunState["LOADED"] = 2] = "LOADED";
    RunState[RunState["READY"] = 3] = "READY";
    RunState[RunState["RUNNING"] = 4] = "RUNNING";
    RunState[RunState["PAUSED"] = 5] = "PAUSED";
})(RunState || (RunState = {}));
export class RuntimeContext {
    constructor(factory, container, id, config, deps = []) {
        this._runState = RunState.NEWBORN;
        this._factory = factory;
        this._id = id;
        this._config = config;
        this._container = container;
        for (let i in deps) {
            if (!this._container.hasResolver(deps[i]))
                this._container.registerSingleton(deps[i], deps[i]);
        }
    }
    get node() {
        return this._node;
    }
    set node(node) {
        this._node = node;
        this._container.registerInstance(Node, this);
    }
    get instance() {
        return this._instance;
    }
    get container() {
        return this._container;
    }
    load() {
        let me = this;
        this._instance = null;
        return new Promise((resolve, reject) => {
            me._runState = RunState.LOADING;
            this._factory.loadComponent(this, this._id)
                .then((instance) => {
                me._instance = instance;
                me.setRunState(RunState.LOADED);
                resolve();
            })
                .catch((err) => {
                me._runState = RunState.NEWBORN;
                reject(err);
            });
        });
    }
    get runState() {
        return this._runState;
    }
    inState(states) {
        return new Set(states).has(this._runState);
    }
    setRunState(runState) {
        let inst = this.instance;
        switch (runState) {
            case RunState.LOADED:
                if (this.inState([RunState.READY, RunState.RUNNING, RunState.PAUSED])) {
                    if (inst.teardown) {
                        inst.teardown();
                        this._instance = null;
                    }
                }
                break;
            case RunState.READY:
                if (this.inState([RunState.LOADED])) {
                    let endPoints = [];
                    if (inst.initialize)
                        endPoints = this.instance.initialize(this._config);
                    if (this._node)
                        this._node.updatePorts(endPoints);
                }
                else if (this.inState([RunState.RUNNING, RunState.PAUSED])) {
                    if (inst.stop)
                        this.instance.stop();
                }
                else
                    throw new Error('Component cannot be initialized, not loaded');
                break;
            case RunState.RUNNING:
                if (this.inState([RunState.READY, RunState.RUNNING])) {
                    if (inst.start)
                        this.instance.start();
                }
                else if (this.inState([RunState.PAUSED])) {
                    if (inst.resume)
                        this.instance.resume();
                }
                else
                    throw new Error('Component cannot be started, not ready');
                break;
            case RunState.PAUSED:
                if (this.inState([RunState.RUNNING])) {
                    if (inst.pause)
                        this.instance.pause();
                }
                else if (this.inState([RunState.PAUSED])) {
                }
                else
                    throw new Error('Component cannot be paused');
                break;
        }
        this._runState = runState;
    }
    release() {
        this._instance = null;
        this._factory = null;
    }
}

;
class ModuleRegistryEntry {
    constructor(address) {
    }
}
export class SystemModuleLoader {
    constructor() {
        this.moduleRegistry = new Map();
    }
    getOrCreateModuleRegistryEntry(address) {
        return this.moduleRegistry[address] || (this.moduleRegistry[address] = new ModuleRegistryEntry(address));
    }
    loadModule(id) {
        let newId = System.normalizeSync(id);
        let existing = this.moduleRegistry[newId];
        if (existing) {
            return Promise.resolve(existing);
        }
        return System.import(newId).then(m => {
            this.moduleRegistry[newId] = m;
            return m;
        });
    }
}



export class ComponentFactory {
    constructor(container, loader) {
        this._loader = loader;
        this._container = container || new Container();
        this._components = new Map();
        this._components.set(undefined, Object);
        this._components.set("", Object);
    }
    createContext(id, config, deps = []) {
        let childContainer = this._container.createChild();
        return new RuntimeContext(this, childContainer, id, config, deps);
    }
    getChildContainer() {
        return;
    }
    loadComponent(ctx, id) {
        let createComponent = function (ctor) {
            let newInstance = ctx.container.invoke(ctor);
            return newInstance;
        };
        let me = this;
        return new Promise((resolve, reject) => {
            let ctor = this.get(id);
            if (ctor) {
                resolve(createComponent(ctor));
            }
            else if (this._loader) {
                this._loader.loadModule(id)
                    .then((ctor) => {
                    me._components.set(id, ctor);
                    resolve(createComponent(ctor));
                })
                    .catch((e) => {
                    reject('ComponentFactory: Unable to load component "' + id + '" - ' + e);
                });
            }
            else {
                reject('ComponentFactory: Component "' + id + '" not registered, and Loader not available');
            }
        });
    }
    get(id) {
        return this._components.get(id);
    }
    register(id, ctor) {
        this._components.set(id, ctor);
    }
}

export class Link {
    constructor(owner, attributes = {}) {
        this._owner = owner;
        this._id = attributes.id || "";
        this._from = attributes['from'];
        this._to = attributes['to'];
        this._protocolID = attributes['protocol'] || 'any';
        this.metadata = attributes.metadata || { x: 100, y: 100 };
    }
    toObject(opts) {
        let link = {
            id: this._id,
            protocol: (this._protocolID != 'any') ? this._protocolID : undefined,
            metadata: this.metadata,
            from: this._from,
            to: this._to
        };
        return link;
    }
    set id(id) {
        this._id = id;
    }
    connect(channel) {
        let fromPort = this.fromNode.identifyPort(this._from.portID, this._protocolID);
        let toPort = this.toNode.identifyPort(this._to.portID, this._protocolID);
        this._channel = channel;
        fromPort.endPoint.attach(channel);
        toPort.endPoint.attach(channel);
    }
    disconnect() {
        let chan = this._channel;
        if (chan) {
            this._channel.endPoints.forEach((endPoint) => {
                endPoint.detach(this._channel);
            });
            this._channel = undefined;
        }
        return chan;
    }
    get fromNode() {
        return this._owner.getNodeByID(this._from.nodeID);
    }
    get fromPort() {
        let node = this.fromNode;
        return (node) ? node.identifyPort(this._from.portID, this._protocolID) : undefined;
    }
    set fromPort(port) {
        this._from = {
            nodeID: port.owner.id,
            portID: port.id
        };
        this._protocolID = port.protocolID;
    }
    get toNode() {
        return this._owner.getNodeByID(this._to.nodeID);
    }
    get toPort() {
        let node = this.toNode;
        return (node) ? node.identifyPort(this._to.portID, this._protocolID) : undefined;
    }
    set toPort(port) {
        this._to = {
            nodeID: port.owner.id,
            portID: port.id
        };
        this._protocolID = port.protocolID;
    }
    get protocolID() {
        return this._protocolID;
    }
}





export class Network extends EventHub {
    constructor(factory, graph) {
        super();
        this._factory = factory;
        this._graph = graph || new Graph(null, {});
        let me = this;
        this._graph.subscribe(Graph.EVENT_ADD_NODE, (data) => {
            let runState = me._graph.context.runState;
            if (runState != RunState.NEWBORN) {
                let { node } = data;
                node.loadComponent(me._factory)
                    .then(() => {
                    if (Network.inState([RunState.RUNNING, RunState.PAUSED, RunState.READY], runState))
                        Network.setRunState(node, RunState.READY);
                    if (Network.inState([RunState.RUNNING, RunState.PAUSED], runState))
                        Network.setRunState(node, runState);
                    this.publish(Network.EVENT_GRAPH_CHANGE, { node: node });
                });
            }
        });
    }
    get graph() {
        return this._graph;
    }
    loadComponents() {
        let me = this;
        this.publish(Network.EVENT_STATE_CHANGE, { state: RunState.LOADING });
        return this._graph.loadComponent(this._factory).then(() => {
            this.publish(Network.EVENT_STATE_CHANGE, { state: RunState.LOADED });
        });
    }
    initialize() {
        this.setRunState(RunState.READY);
    }
    teardown() {
        this.setRunState(RunState.LOADED);
    }
    static inState(states, runState) {
        return new Set(states).has(runState);
    }
    static setRunState(node, runState) {
        let ctx = node.context;
        let currentState = ctx.runState;
        if (node instanceof Graph) {
            let nodes = node.nodes;
            if ((runState == RunState.LOADED) && (currentState >= RunState.READY)) {
                let links = node.links;
                links.forEach((link) => {
                    Network.unwireLink(link);
                });
            }
            nodes.forEach(function (subNode) {
                Network.setRunState(subNode, runState);
            });
            ctx.setRunState(runState);
            if ((runState == RunState.READY) && (currentState >= RunState.LOADED)) {
                let links = node.links;
                links.forEach((link) => {
                    Network.wireLink(link);
                });
            }
        }
        else {
            ctx.setRunState(runState);
        }
    }
    static unwireLink(link) {
        let fromNode = link.fromNode;
        let toNode = link.toNode;
        let chan = link.disconnect();
        if (chan)
            chan.deactivate();
    }
    static wireLink(link) {
        let fromNode = link.fromNode;
        let toNode = link.toNode;
        let channel = new Channel();
        link.connect(channel);
        channel.activate();
    }
    setRunState(runState) {
        Network.setRunState(this._graph, runState);
        this.publish(Network.EVENT_STATE_CHANGE, { state: runState });
    }
    start(initiallyPaused = false) {
        this.setRunState(initiallyPaused ? RunState.PAUSED : RunState.RUNNING);
    }
    step() {
    }
    stop() {
        this.setRunState(RunState.READY);
    }
    pause() {
        this.setRunState(RunState.PAUSED);
    }
    resume() {
        this.setRunState(RunState.RUNNING);
    }
}
Network.EVENT_STATE_CHANGE = 'network:state-change';
Network.EVENT_GRAPH_CHANGE = 'network:graph-change';




export class Graph extends Node {
    constructor(owner, attributes = {}) {
        super(owner, attributes);
        this.initFromObject(attributes);
    }
    initFromString(jsonString) {
        this.initFromObject(JSON.parse(jsonString));
    }
    initFromObject(attributes) {
        this.id = attributes.id || "$graph";
        this._nodes = new Map();
        this._links = new Map();
        Object.keys(attributes.nodes || {}).forEach((id) => {
            this.addNode(id, attributes.nodes[id]);
        });
        Object.keys(attributes.links || {}).forEach((id) => {
            this.addLink(id, attributes.links[id]);
        });
    }
    toObject(opts) {
        var graph = super.toObject();
        let nodes = graph["nodes"] = {};
        this._nodes.forEach((node, id) => {
            nodes[id] = node.toObject();
        });
        let links = graph["links"] = {};
        this._links.forEach((link, id) => {
            links[id] = link.toObject();
        });
        return graph;
    }
    loadComponent(factory) {
        return new Promise((resolve, reject) => {
            let pendingCount = 0;
            let nodes = new Map(this._nodes);
            nodes.set('$graph', this);
            nodes.forEach((node, id) => {
                let done;
                pendingCount++;
                if (node == this) {
                    done = super.loadComponent(factory);
                }
                else {
                    done = node.loadComponent(factory);
                }
                done.then(() => {
                    --pendingCount;
                    if (pendingCount == 0)
                        resolve();
                })
                    .catch((reason) => {
                    reject(reason);
                });
            });
        });
    }
    get nodes() {
        return this._nodes;
    }
    get links() {
        return this._links;
    }
    getNodeByID(id) {
        if (id == '$graph')
            return this;
        return this._nodes.get(id);
    }
    addNode(id, attributes) {
        let node = new Node(this, attributes);
        node.id = id;
        this._nodes.set(id, node);
        this.publish(Graph.EVENT_ADD_NODE, { node: node });
        return node;
    }
    renameNode(id, newID) {
        let node = this._nodes.get(id);
        if (id != newID) {
            let eventData = { node: node, attrs: { id: node.id } };
            this._nodes.delete(id);
            node.id = newID;
            this._nodes.set(newID, node);
            this.publish(Graph.EVENT_UPD_NODE, eventData);
        }
    }
    removeNode(id) {
        let node = this._nodes.get(id);
        if (node)
            this.publish(Graph.EVENT_DEL_NODE, { node: node });
        return this._nodes.delete(id);
    }
    getLinkByID(id) {
        return this._links[id];
    }
    addLink(id, attributes) {
        let link = new Link(this, attributes);
        link.id = id;
        this._links.set(id, link);
        this.publish(Graph.EVENT_ADD_LINK, { link: link });
        return link;
    }
    renameLink(id, newID) {
        let link = this._links.get(id);
        this._links.delete(id);
        let eventData = { link: link, attrs: { id: link.id } };
        link.id = newID;
        this.publish(Graph.EVENT_UPD_NODE, eventData);
        this._links.set(newID, link);
    }
    removeLink(id) {
        let link = this._links.get(id);
        if (link)
            this.publish(Graph.EVENT_DEL_LINK, { link: link });
        return this._links.delete(id);
    }
    addPublicPort(id, attributes) {
        attributes["id"] = id;
        let port = new PublicPort(this, null, attributes);
        this._ports.set(id, port);
        return port;
    }
}
Graph.EVENT_ADD_NODE = 'graph:add-node';
Graph.EVENT_UPD_NODE = 'graph:upd-node';
Graph.EVENT_DEL_NODE = 'graph:del-node';
Graph.EVENT_ADD_LINK = 'graph:add-link';
Graph.EVENT_UPD_LINK = 'graph:upd-link';
Graph.EVENT_DEL_LINK = 'graph:del-link';


export class SimulationEngine {
    constructor(loader, container) {
        this.loader = loader;
        this.container = container;
    }
    getComponentFactory() {
        return new ComponentFactory(this.container, this.loader);
    }
}

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeS50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvd2ViY3J5cHRvLnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9kZXMudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS5qcyIsImRlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lci50cyIsImtpbmQva2luZC50cyIsIm1lc3NhZ2luZy9tZXNzYWdlLnRzIiwicnVudGltZS90YXNrLXNjaGVkdWxlci50cyIsIm1lc3NhZ2luZy9jaGFubmVsLnRzIiwibWVzc2FnaW5nL2VuZC1wb2ludC50cyIsIm1lc3NhZ2luZy9wcm90b2NvbC50cyIsImNvbXBvbmVudC9wb3J0LWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LWluZm8udHMiLCJjb21wb25lbnQvc3RvcmUtaW5mby50cyIsImNvbXBvbmVudC9jb21wb25lbnQudHMiLCJldmVudC1odWIvZXZlbnQtaHViLnRzIiwiZ3JhcGgvcG9ydC50cyIsImdyYXBoL25vZGUudHMiLCJydW50aW1lL3J1bnRpbWUtY29udGV4dC50cyIsInJ1bnRpbWUvbW9kdWxlLWxvYWRlci50cyIsInJ1bnRpbWUvY29tcG9uZW50LWZhY3RvcnkudHMiLCJncmFwaC9saW5rLnRzIiwiZ3JhcGgvbmV0d29yay50cyIsImdyYXBoL2dyYXBoLnRzIiwicnVudGltZS9zaW11bGF0aW9uLWVuZ2luZS50cyJdLCJuYW1lcyI6WyJIZXhDb2RlYyIsIkhleENvZGVjLmRlY29kZSIsIkJBU0U2NFNQRUNJQUxTIiwiQmFzZTY0Q29kZWMiLCJCYXNlNjRDb2RlYy5kZWNvZGUiLCJCYXNlNjRDb2RlYy5kZWNvZGUuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLnB1c2giLCJCYXNlNjRDb2RlYy5lbmNvZGUiLCJCYXNlNjRDb2RlYy5lbmNvZGUuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLnRyaXBsZXRUb0Jhc2U2NCIsIkJ5dGVFbmNvZGluZyIsIkJ5dGVBcnJheSIsIkJ5dGVBcnJheS5jb25zdHJ1Y3RvciIsIkJ5dGVBcnJheS5lbmNvZGluZ1RvU3RyaW5nIiwiQnl0ZUFycmF5LnN0cmluZ1RvRW5jb2RpbmciLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJDcnlwdG9ncmFwaGljT3BlcmF0aW9uIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkuY29uc3RydWN0b3IiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0cnkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmVuY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRpZ2VzdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuc2lnbiIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudmVyaWZ5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5leHBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmdlbmVyYXRlS2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5pbXBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlcml2ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuZGVyaXZlQml0cyIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIud3JhcEtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudW53cmFwS2V5IiwiV2ViQ3J5cHRvU2VydmljZSIsIldlYkNyeXB0b1NlcnZpY2UuY29uc3RydWN0b3IiLCJXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSIsIldlYkNyeXB0b1NlcnZpY2UuZW5jcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGVjcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGlnZXN0IiwiV2ViQ3J5cHRvU2VydmljZS5leHBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLmdlbmVyYXRlS2V5IiwiV2ViQ3J5cHRvU2VydmljZS5pbXBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLnNpZ24iLCJXZWJDcnlwdG9TZXJ2aWNlLnZlcmlmeSIsIkRFU1NlY3JldEtleSIsIkRFU1NlY3JldEtleS5jb25zdHJ1Y3RvciIsIkRFU1NlY3JldEtleS5hbGdvcml0aG0iLCJERVNTZWNyZXRLZXkuZXh0cmFjdGFibGUiLCJERVNTZWNyZXRLZXkudHlwZSIsIkRFU1NlY3JldEtleS51c2FnZXMiLCJERVNTZWNyZXRLZXkua2V5TWF0ZXJpYWwiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZSIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmNvbnN0cnVjdG9yIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZW5jcnlwdCIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlY3J5cHQiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5pbXBvcnRLZXkiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5zaWduIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzLmRlc19jcmVhdGVLZXlzIiwiRW51bSIsIkludGVnZXIiLCJGaWVsZEFycmF5IiwiS2luZEluZm8iLCJLaW5kSW5mby5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyIiwiS2luZEJ1aWxkZXIuY29uc3RydWN0b3IiLCJLaW5kQnVpbGRlci5pbml0IiwiS2luZEJ1aWxkZXIuZmllbGQiLCJLaW5kQnVpbGRlci5ib29sRmllbGQiLCJLaW5kQnVpbGRlci5udW1iZXJGaWVsZCIsIktpbmRCdWlsZGVyLmludGVnZXJGaWVsZCIsIktpbmRCdWlsZGVyLnVpbnQzMkZpZWxkIiwiS2luZEJ1aWxkZXIuYnl0ZUZpZWxkIiwiS2luZEJ1aWxkZXIuc3RyaW5nRmllbGQiLCJLaW5kQnVpbGRlci5raW5kRmllbGQiLCJLaW5kQnVpbGRlci5lbnVtRmllbGQiLCJLaW5kIiwiS2luZC5nZXRLaW5kSW5mbyIsIktpbmQuaW5pdEZpZWxkcyIsIk1lc3NhZ2UiLCJNZXNzYWdlLmNvbnN0cnVjdG9yIiwiTWVzc2FnZS5oZWFkZXIiLCJNZXNzYWdlLnBheWxvYWQiLCJLaW5kTWVzc2FnZSIsIlRhc2tTY2hlZHVsZXIiLCJUYXNrU2NoZWR1bGVyLmNvbnN0cnVjdG9yIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyLnJlcXVlc3RGbHVzaC5oYW5kbGVGbHVzaFRpbWVyIiwiVGFza1NjaGVkdWxlci5zaHV0ZG93biIsIlRhc2tTY2hlZHVsZXIucXVldWVUYXNrIiwiVGFza1NjaGVkdWxlci5mbHVzaFRhc2tRdWV1ZSIsIlRhc2tTY2hlZHVsZXIub25FcnJvciIsIkNoYW5uZWwiLCJDaGFubmVsLmNvbnN0cnVjdG9yIiwiQ2hhbm5lbC5zaHV0ZG93biIsIkNoYW5uZWwuYWN0aXZlIiwiQ2hhbm5lbC5hY3RpdmF0ZSIsIkNoYW5uZWwuZGVhY3RpdmF0ZSIsIkNoYW5uZWwuYWRkRW5kUG9pbnQiLCJDaGFubmVsLnJlbW92ZUVuZFBvaW50IiwiQ2hhbm5lbC5lbmRQb2ludHMiLCJDaGFubmVsLnNlbmRNZXNzYWdlIiwiRGlyZWN0aW9uIiwiRW5kUG9pbnQiLCJFbmRQb2ludC5jb25zdHJ1Y3RvciIsIkVuZFBvaW50LnNodXRkb3duIiwiRW5kUG9pbnQuaWQiLCJFbmRQb2ludC5hdHRhY2giLCJFbmRQb2ludC5kZXRhY2giLCJFbmRQb2ludC5kZXRhY2hBbGwiLCJFbmRQb2ludC5hdHRhY2hlZCIsIkVuZFBvaW50LmRpcmVjdGlvbiIsIkVuZFBvaW50LmhhbmRsZU1lc3NhZ2UiLCJFbmRQb2ludC5zZW5kTWVzc2FnZSIsIkVuZFBvaW50Lm9uTWVzc2FnZSIsIlByb3RvY29sVHlwZUJpdHMiLCJQcm90b2NvbCIsIkNsaWVudFNlcnZlclByb3RvY29sIiwiQVBEVSIsIkFQRFVNZXNzYWdlIiwiQVBEVVByb3RvY29sIiwiUG9ydEluZm8iLCJQb3J0SW5mby5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEluZm8iLCJDb21wb25lbnRJbmZvLmNvbnN0cnVjdG9yIiwiU3RvcmVJbmZvIiwiQ29tcG9uZW50QnVpbGRlciIsIkNvbXBvbmVudEJ1aWxkZXIuY29uc3RydWN0b3IiLCJDb21wb25lbnRCdWlsZGVyLmluaXQiLCJDb21wb25lbnRCdWlsZGVyLmNvbmZpZyIsIkNvbXBvbmVudEJ1aWxkZXIucG9ydCIsIkV2ZW50SHViIiwiRXZlbnRIdWIuY29uc3RydWN0b3IiLCJFdmVudEh1Yi5wdWJsaXNoIiwiRXZlbnRIdWIuc3Vic2NyaWJlIiwiRXZlbnRIdWIuc3Vic2NyaWJlT25jZSIsIlBvcnQiLCJQb3J0LmNvbnN0cnVjdG9yIiwiUG9ydC5lbmRQb2ludCIsIlBvcnQudG9PYmplY3QiLCJQb3J0Lm93bmVyIiwiUG9ydC5wcm90b2NvbElEIiwiUG9ydC5pZCIsIlBvcnQuZGlyZWN0aW9uIiwiUHVibGljUG9ydCIsIlB1YmxpY1BvcnQuY29uc3RydWN0b3IiLCJQdWJsaWNQb3J0LmNvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC5kaXNjb25uZWN0UHJpdmF0ZSIsIlB1YmxpY1BvcnQudG9PYmplY3QiLCJOb2RlIiwiTm9kZS5jb25zdHJ1Y3RvciIsIk5vZGUudG9PYmplY3QiLCJOb2RlLm93bmVyIiwiTm9kZS5pZCIsIk5vZGUudXBkYXRlUG9ydHMiLCJOb2RlLmFkZFBsYWNlaG9sZGVyUG9ydCIsIk5vZGUucG9ydHMiLCJOb2RlLmdldFBvcnRBcnJheSIsIk5vZGUuZ2V0UG9ydEJ5SUQiLCJOb2RlLmlkZW50aWZ5UG9ydCIsIk5vZGUucmVtb3ZlUG9ydCIsIk5vZGUubG9hZENvbXBvbmVudCIsIk5vZGUuY29udGV4dCIsIk5vZGUudW5sb2FkQ29tcG9uZW50IiwiUnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dCIsIlJ1bnRpbWVDb250ZXh0LmNvbnN0cnVjdG9yIiwiUnVudGltZUNvbnRleHQubm9kZSIsIlJ1bnRpbWVDb250ZXh0Lmluc3RhbmNlIiwiUnVudGltZUNvbnRleHQuY29udGFpbmVyIiwiUnVudGltZUNvbnRleHQubG9hZCIsIlJ1bnRpbWVDb250ZXh0LnJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQuaW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnNldFJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQucmVsZWFzZSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkiLCJNb2R1bGVSZWdpc3RyeUVudHJ5LmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeSIsIlN5c3RlbU1vZHVsZUxvYWRlci5sb2FkTW9kdWxlIiwiQ29tcG9uZW50RmFjdG9yeSIsIkNvbXBvbmVudEZhY3RvcnkuY29uc3RydWN0b3IiLCJDb21wb25lbnRGYWN0b3J5LmNyZWF0ZUNvbnRleHQiLCJDb21wb25lbnRGYWN0b3J5LmdldENoaWxkQ29udGFpbmVyIiwiQ29tcG9uZW50RmFjdG9yeS5sb2FkQ29tcG9uZW50IiwiQ29tcG9uZW50RmFjdG9yeS5nZXQiLCJDb21wb25lbnRGYWN0b3J5LnJlZ2lzdGVyIiwiTGluayIsIkxpbmsuY29uc3RydWN0b3IiLCJMaW5rLnRvT2JqZWN0IiwiTGluay5pZCIsIkxpbmsuY29ubmVjdCIsIkxpbmsuZGlzY29ubmVjdCIsIkxpbmsuZnJvbU5vZGUiLCJMaW5rLmZyb21Qb3J0IiwiTGluay50b05vZGUiLCJMaW5rLnRvUG9ydCIsIkxpbmsucHJvdG9jb2xJRCIsIk5ldHdvcmsiLCJOZXR3b3JrLmNvbnN0cnVjdG9yIiwiTmV0d29yay5ncmFwaCIsIk5ldHdvcmsubG9hZENvbXBvbmVudHMiLCJOZXR3b3JrLmluaXRpYWxpemUiLCJOZXR3b3JrLnRlYXJkb3duIiwiTmV0d29yay5pblN0YXRlIiwiTmV0d29yay5zZXRSdW5TdGF0ZSIsIk5ldHdvcmsudW53aXJlTGluayIsIk5ldHdvcmsud2lyZUxpbmsiLCJOZXR3b3JrLnN0YXJ0IiwiTmV0d29yay5zdGVwIiwiTmV0d29yay5zdG9wIiwiTmV0d29yay5wYXVzZSIsIk5ldHdvcmsucmVzdW1lIiwiR3JhcGgiLCJHcmFwaC5jb25zdHJ1Y3RvciIsIkdyYXBoLmluaXRGcm9tU3RyaW5nIiwiR3JhcGguaW5pdEZyb21PYmplY3QiLCJHcmFwaC50b09iamVjdCIsIkdyYXBoLmxvYWRDb21wb25lbnQiLCJHcmFwaC5ub2RlcyIsIkdyYXBoLmxpbmtzIiwiR3JhcGguZ2V0Tm9kZUJ5SUQiLCJHcmFwaC5hZGROb2RlIiwiR3JhcGgucmVuYW1lTm9kZSIsIkdyYXBoLnJlbW92ZU5vZGUiLCJHcmFwaC5nZXRMaW5rQnlJRCIsIkdyYXBoLmFkZExpbmsiLCJHcmFwaC5yZW5hbWVMaW5rIiwiR3JhcGgucmVtb3ZlTGluayIsIkdyYXBoLmFkZFB1YmxpY1BvcnQiLCJTaW11bGF0aW9uRW5naW5lIiwiU2ltdWxhdGlvbkVuZ2luZS5jb25zdHJ1Y3RvciIsIlNpbXVsYXRpb25FbmdpbmUuZ2V0Q29tcG9uZW50RmFjdG9yeSJdLCJtYXBwaW5ncyI6IkFBQUE7SUFJRUEsT0FBT0EsTUFBTUEsQ0FBRUEsQ0FBU0E7UUFFdEJDLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pDQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFHQSxHQUFHQSxrQkFBa0JBLENBQUNBO1lBQzdCQSxJQUFJQSxLQUFLQSxHQUFHQSw2QkFBNkJBLENBQUNBO1lBQzFDQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtZQUN2QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3ZCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsR0FBR0EsR0FBR0EsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7WUFDeEJBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO2dCQUN4QkEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDM0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO2dCQUNqQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLFFBQVFBLENBQUNBLFlBQVlBLEdBQUdBLEdBQUdBLENBQUNBO1FBQzlCQSxDQUFDQTtRQUVEQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtRQUN2QkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDN0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBLEVBQ2pDQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNwQkEsRUFBRUEsQ0FBQ0EsQ0FB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LENBQUNBLEdBQUdBLFlBQVlBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZEQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVWQSxjQUFlQSxDQUFPQTtZQUNwQkUsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDZkEsQ0FBQ0E7UUFFREYsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFakJBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQzdCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMzSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDN0JBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFFQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzlHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUN4QkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRURELE9BQU9BLE1BQU1BLENBQUVBLEtBQWlCQTtRQUU5QkksSUFBSUEsQ0FBU0EsQ0FBQ0E7UUFDZEEsSUFBSUEsVUFBVUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDbENBLElBQUlBLE1BQU1BLEdBQUdBLEVBQUVBLENBQUNBO1FBRWhCQSxNQUFNQSxNQUFNQSxHQUFHQSxrRUFBa0VBLENBQUNBO1FBQ2xGQSxnQkFBaUJBLEdBQVNBO1lBQ3hCQyxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM1QkEsQ0FBQ0E7UUFFREQseUJBQTBCQSxHQUFXQTtZQUNuQ0UsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDNUdBLENBQUNBO1FBR0RGLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLFVBQVVBLENBQUNBO1FBQ3ZDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQTtZQUMvQkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbkVBLE1BQU1BLElBQUlBLGVBQWVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBO1FBQ2xDQSxDQUFDQTtRQUdEQSxNQUFNQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuQkEsS0FBS0EsQ0FBQ0E7Z0JBQ0pBLElBQUlBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO2dCQUNuQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzVCQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDckNBLE1BQU1BLElBQUlBLElBQUlBLENBQUNBO2dCQUNmQSxLQUFLQSxDQUFBQTtZQUNQQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2xFQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDN0JBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQTtnQkFDZEEsS0FBS0EsQ0FBQUE7WUFDUEE7Z0JBQ0VBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO0lBQ2hCQSxDQUFDQTtBQUNISixDQUFDQTtBQUFBO09DaklNLEVBQUUsUUFBUSxFQUFFLE1BQU0sYUFBYTtPQUMvQixFQUFFLFdBQVcsRUFBRSxNQUFNLGdCQUFnQjtBQUU1QyxXQUFZLFlBS1g7QUFMRCxXQUFZLFlBQVk7SUFDdEJPLDZDQUFHQSxDQUFBQTtJQUNIQSw2Q0FBR0EsQ0FBQUE7SUFDSEEsbURBQU1BLENBQUFBO0lBQ05BLCtDQUFJQSxDQUFBQTtBQUNOQSxDQUFDQSxFQUxXLFlBQVksS0FBWixZQUFZLFFBS3ZCO0FBRUQ7SUEyQ0VDLFlBQWFBLEtBQXFFQSxFQUFFQSxRQUFpQkEsRUFBRUEsR0FBU0E7UUFFOUdDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO1lBRUNBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3ZDQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxRQUFRQSxJQUFJQSxRQUFRQSxJQUFJQSxZQUFZQSxDQUFDQSxHQUFJQSxDQUFDQSxDQUNyREEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsV0FBWUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFlQSxLQUFLQSxDQUFFQSxDQUFDQTtZQUN4REEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsVUFBV0EsQ0FBQ0E7Z0JBQ3JDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUN6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsU0FBVUEsQ0FBQ0E7Z0JBQ3BDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUNuQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsS0FBTUEsQ0FBQ0E7Z0JBQ2hDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtRQUs3Q0EsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsS0FBS0EsSUFBSUEsUUFBU0EsQ0FBQ0EsQ0FDcENBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLE1BQU9BLENBQUNBLENBQ3RDQSxDQUFDQTtnQkFDR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDekRBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQ3hDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLElBQUtBLENBQUNBLENBQ3pDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtnQkFDN0JBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBO29CQUN4QkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBRTVDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxFQUFFQSxDQUFDQTtZQUN0QkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBVUEsQ0FBQ0EsQ0FDdEJBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGdDQUFnQ0EsQ0FBQ0EsQ0FBQUE7UUFDcERBLENBQUNBO0lBQ0hBLENBQUNBO0lBcEZERCxPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQXNCQTtRQUM3Q0UsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLE1BQU1BO2dCQUN0QkEsTUFBTUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLElBQUlBO2dCQUNwQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7WUFDaEJBLEtBQUtBLFlBQVlBLENBQUNBLEdBQUdBO2dCQUNuQkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFDZkE7Z0JBQ0VBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBO1FBQ2pCQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVERixPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQWdCQTtRQUN2Q0csRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsV0FBV0EsRUFBRUEsSUFBSUEsUUFBU0EsQ0FBQ0E7WUFDdkNBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLE1BQU1BLENBQUNBO1FBQzdCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxRQUFRQSxDQUFDQSxXQUFXQSxFQUFFQSxJQUFJQSxNQUFPQSxDQUFDQTtZQUMxQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFDM0JBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFdBQVdBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBO1lBQ3pDQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQSxHQUFHQSxDQUFDQTtRQUMxQkEsSUFBSUE7WUFDRkEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBZ0VESCxJQUFJQSxNQUFNQTtRQUVSSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUMvQkEsQ0FBQ0E7SUFFREosSUFBSUEsTUFBTUEsQ0FBRUEsR0FBV0E7UUFFckJJLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLElBQUlBLEdBQUlBLENBQUNBLENBQ25DQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUNsREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDekJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQ3ZDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFREosSUFBSUEsWUFBWUE7UUFFZEssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURMLE1BQU1BLENBQUVBLEtBQWdCQTtRQUV0Qk0sSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFDeEJBLElBQUlBLEdBQUdBLEdBQUdB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QUFDQSxHQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUN0Q0EsS0FBS0EsWUFBWUEsQ0FBQ0EsR0FBR0E7Z0JBRW5CQSxHQUFHQSxDQUFBQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtvQkFDOUJBLENBQUNBLElBQUlBLENBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLENBQUVBLENBQUNBLFFBQVFBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO2dCQUMvREEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsWUFBWUEsQ0FBQ0EsTUFBTUE7Z0JBQ3RCQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUU5Q0EsS0FBS0EsWUFBWUEsQ0FBQ0EsSUFBSUE7Z0JBQ3BCQSxHQUFHQSxDQUFBQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtvQkFDOUJBLENBQUNBLElBQUlBLE1BQU1BLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dCQUNsREEsS0FBS0EsQ0FBQ0E7WUFFUkE7Z0JBQ0VBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xEQSxLQUFLQSxDQUFDQTtRQUNWQSxDQUFD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Q0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFbkdBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBS09MLEdBQUdBLENBQUVBLEdBQWVBLEVBQUVBLE9BQW1CQSxFQUFFQSxPQUFlQSxFQUFFQSxJQUFZQSxFQUFFQSxFQUFlQSxFQUFFQSxPQUFnQkE7UUFLakhNLHdCQUF5QkEsR0FBR0E7WUFFMUJDLElBQUlBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFFMUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO2dCQUVDQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLEdBQUdBO29CQUN0Q0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBRUEsQ0FBRUE7b0JBQzVLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNySkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzlLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxDQUFDQSxDQUFFQTtvQkFDM0lBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQ3JLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDakxBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUM3SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtvQkFDbkpBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNuTEEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3RLQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxDQUFDQSxDQUFFQTtpQkFDOUdBLENBQUNBO1lBQ0pBLENBQUNBO1lBR0RBLElBQUlBLFVBQVVBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRXhDQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxXQUFXQSxDQUFDQSxFQUFFQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtZQUU1Q0EsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFaEVBLElBQUlBLFFBQVFBLEVBQUVBLFNBQVNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBO1lBRXhDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUMvQkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLEdBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUN6RUEsS0FBS0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBRXpFQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDbkZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUcvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0EsQ0FBQ0E7Z0JBRW5EQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDdEdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBO2dCQUdiQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUNwQ0EsQ0FBQ0E7b0JBRUNBLEVBQUVBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO3dCQUNDQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTt3QkFBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7b0JBQzVFQSxDQUFDQTtvQkFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBTTVCQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDbkVBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUMzRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzFFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtvQkFDL0NBLFNBQVNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNyRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzlFQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDOUVBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUNsREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsU0FBU0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7b0JBQ3BEQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsU0FBU0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3BFQSxDQUFDQTtZQUNIQSxDQUFDQTtZQUVEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtRQUNkQSxDQUFDQTtRQUdERCxJQUFJQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLENBQUNBO1FBRTFDQSxFQUFFQSxDQUFDQSxDQUFFQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUN6QkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsdUJBQXVCQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDdENBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNyb0JBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNqZkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JtQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3pqQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7YUFDdGxCQSxDQUFDQTtRQUNKQSxDQUFDQTtRQUdEQSxJQUFJQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVqQ0EsSUFBSUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsRUFBRUEsT0FBT0EsQ0FBQ0E7UUFDMUNBLElBQUlBLE9BQU9BLEVBQUVBLFFBQVFBLEVBQUVBLFFBQVFBLEVBQUVBLFNBQVNBLENBQUFBO1FBQzFDQSxJQUFJQSxHQUFHQSxHQUFHQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUd6QkEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFM0NBLEVBQUVBLENBQUNBLENBQUNBLFVBQVVBLElBQUlBLENBQUNBLENBQUNBLENBQ3BCQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsT0FBT0EsR0FBR0EsT0FBT0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEdBLENBQUNBO1FBR0RBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLE9BQU9BLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUVBLE9BQU9BLElBQUlBLENBQUNBLENBQUdBLENBQUNBLENBQ25EQSxDQUFDQTtZQUNDQSxJQUFJQSxlQUFlQSxHQUFHQSxPQUFPQSxDQUFDQTtZQUM5QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFFcEJBLE9BQU9BLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO1lBQ3BDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxlQUFlQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVsQ0EsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO2dCQUNDQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7b0JBQ3pGQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsQ0FBQ0E7b0JBQ05BLENBQUNBO3dCQUNDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTt3QkFFOUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUVBLENBQUVBLENBQUNBOzRCQUNYQSxHQUFHQSxJQUFFQSxDQUFDQSxDQUFDQTt3QkFFVEEsS0FBS0EsQ0FBQ0E7b0JBQ1JBLENBQUNBO2dCQUVEQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3ZGQSxLQUFLQSxDQUFDQTtZQUVWQSxDQUFDQTtZQUVEQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFBQTtRQUNsQkEsQ0FBQ0E7UUFHREEsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFbkNBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRVZBLE9BQU9BLEdBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBQ3hFQSxRQUFRQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtRQUMxRUEsQ0FBQ0E7UUFFREEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFHWEEsT0FBT0EsQ0FBQ0EsR0FBR0EsR0FBR0EsRUFDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDekZBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBR3pGQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtnQkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FDWkEsQ0FBQ0E7b0JBQ0NBLElBQUlBLElBQUlBLE9BQU9BLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxRQUFRQSxDQUFDQTtnQkFDckNBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtvQkFDQ0EsUUFBUUEsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQ25CQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtvQkFDckJBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBO29CQUNmQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDbkJBLENBQUNBO1lBQ0hBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUUvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxJQUFFQSxDQUFDQSxFQUM1QkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUMzQkEsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRzNCQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUN6Q0EsQ0FBQ0E7b0JBQ0NBLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUM3QkEsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBR3pEQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDWkEsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0E7b0JBQ2JBLEtBQUtBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNyRkEsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQzVFQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDckZBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQU1BLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUNoR0EsQ0FBQ0E7Z0JBRURBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFBQ0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7WUFDMUNBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBQ3JDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUd4Q0EsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDakZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRy9FQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtnQkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FDWkEsQ0FBQ0E7b0JBQ0NBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBO29CQUNmQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDbkJBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsUUFBUUEsQ0FBQ0E7b0JBQ2pCQSxLQUFLQSxJQUFJQSxTQUFTQSxDQUFDQTtnQkFDckJBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUdBLENBQUVBLENBQUNBLElBQUlBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLElBQUlBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLElBQUlBLEtBQUdBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLEtBQUtBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLEtBQUtBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLEtBQUtB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Q0EsTUFBTUEsR0FBR0EsS0FBS0EsQ0FBQ0E7UUFDcEJBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLFVBQVVBLENBQUNBLEVBQUVBLElBQUlBLEVBQUVBLENBQUNBO1FBQy9CQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxVQUFVQSxDQUFDQSxTQUFTQSxDQUFDQTtRQUN2Q0EsSUFBSUEsQ0FBQ0EsWUFBWUEsR0FBR0EsVUFBVUEsQ0FBQ0EsV0FBV0EsSUFBSUEsRUFBRUEsQ0FBQ0E7UUFFakRBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLElBQUlBLEdBQUdBLEVBQWdCQSxDQUFDQTtRQUV0Q0EsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsVUFBVUEsQ0FBQ0EsUUFBUUEsSUFBSUEsRUFBR0EsQ0FBQ0E7UUFLM0NBLE1BQU1BLENBQUNBLElBQUlBLENBQUVBLFVBQVVBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBLEVBQUVBO1lBQ2hEQSxJQUFJQSxDQUFDQSxrQkFBa0JBLENBQUVBLEVBQUVBLEVBQUVBLFVBQVVBLENBQUNBLEtBQUtBLENBQUVBLEVBQUVBLENBQUVBLENBQUVBLENBQUNBO1FBQ3hEQSxDQUFDQSxDQUFFQSxDQUFDQTtJQUNOQSxDQUFDQTtJQUtERCxRQUFRQSxDQUFFQSxJQUFVQTtRQUVsQkUsSUFBSUEsSUFBSUEsR0FBR0E7WUFDVEEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUE7WUFDWEEsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsVUFBVUE7WUFDMUJBLFdBQVdBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBO1lBQzlCQSxLQUFLQSxFQUFFQSxFQUFFQTtZQUNUQSxRQUFRQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQTtTQUN4QkEsQ0FBQ0E7UUFFRkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUE7WUFDN0JBLElBQUlBLENBQUNBLEtBQUtBLENBQUVBLEVBQUVB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Q0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRTVFQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFTQSxDQUFDQSxDQUNwQkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO3dCQUdoQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ3hCQSxDQUFDQTtnQkFDSEEsQ0FBQ0E7Z0JBQ0RBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLFFBQVFBLENBQUNBLEtBQUtBO2dCQUNqQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRzFDQSxJQUFJQSxTQUFTQSxHQUFlQSxFQUFFQSxDQUFDQTtvQkFFL0JBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFVBQVdBLENBQUNBO3dCQUNwQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBUUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0E7b0JBRTdEQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFNQSxDQUFDQTt3QkFDZkEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7Z0JBQ3hDQSxDQUFDQTtnQkFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRWpFQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxJQUFLQSxDQUFDQTt3QkFDZEEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0E7Z0JBQ3pCQSxDQUFDQTtnQkFDREEsSUFBSUE7b0JBQ0ZBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLDZDQUE2Q0EsQ0FBRUEsQ0FBQ0E7Z0JBQ25FQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxRQUFRQSxDQUFDQSxPQUFPQTtnQkFDbkJBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUUzREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBTUEsQ0FBQ0E7d0JBQ2ZBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLENBQUNBO2dCQUMxQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUUvQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0E7d0JBQ2hCQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQTtnQkFDM0JBLENBQUNBO2dCQUNEQSxJQUFJQTtvQkFDRkEsTUFBTUEsSUFBSUEsS0FBS0EsQ0FBRUEsd0NBQXdDQSxDQUFFQSxDQUFDQTtnQkFDOURBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLFFBQVFBLENBQUNBLE1BQU1BO2dCQUNsQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzFDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFNQSxDQUFDQTt3QkFDZkEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0Es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LEdBQUdBLFVBQVVBLENBQUVBLFVBQVVBLENBQUVBLElBQUlBLEtBQUtBLENBQUNBO1FBRXJEQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxVQUFVQSxDQUFDQSxRQUFRQSxJQUFJQSxFQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtJQUM1REEsQ0FBQ0E7SUFFREQsUUFBUUEsQ0FBRUEsSUFBVUE7UUFFbEJFLElBQUlBLElBQUlBLEdBQUdBO1lBQ1RBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ1pBLFFBQVFBLEVBQUVBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLElBQUlBLEtBQUtBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFNBQVNBO1lBQ3RFQSxRQUFRQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQTtZQUN2QkEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsS0FBS0E7WUFDaEJBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1NBQ2JBLENBQUNBO1FBRUZBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRURGLElBQUlBLEVBQUVBLENBQUVBLEVBQVVBO1FBRWhCRyxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUFFQSxDQUFDQTtJQUNoQkEsQ0FBQ0E7SUFFREgsT0FBT0EsQ0FBRUEsT0FBZ0JBO1FBR3ZCSSxJQUFJQSxRQUFRQSxHQUFTQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxDQUFDQTtRQUd2RkEsSUFBSUEsTUFBTUEsR0FBU0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0E7UUFFakZBLElBQUlB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QVVBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBO1FBRXRCQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUVwREEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0FBQ0hoQixDQUFDQTtBQTdQUSxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBQ2xDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUVsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBQ2xDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0F1UHpDOztPQzFRTSxFQUFFLGdCQUFnQixFQUFFLE1BQU0scUJBQXFCO0FBS3REO0lBVUVpQixZQUFhQSxNQUFvQkEsRUFBRUEsU0FBb0JBO1FBQ3JEQyxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxNQUFNQSxDQUFDQTtRQUNyQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsU0FBU0EsQ0FBQ0E7SUFDN0JBLENBQUNBO0lBTURELG1CQUFtQkE7UUFDakJFLE1BQU1BLENBQUNBLElBQUlBLGdCQUFnQkEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDN0RBLENBQUNBO0FBRUhGLENBQUNBO0FBQUEiLCJmaWxlIjoiY3J5cHRvZ3JhcGhpeC1zaW0tY29yZS5qcyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBjbGFzcyBIZXhDb2RlY1xue1xuICBwcml2YXRlIHN0YXRpYyBoZXhEZWNvZGVNYXA6IG51bWJlcltdO1xuXG4gIHN0YXRpYyBkZWNvZGUoIGE6IHN0cmluZyApOiBVaW50OEFycmF5XG4gIHtcbiAgICBpZiAoIEhleENvZGVjLmhleERlY29kZU1hcCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIHZhciBoZXggPSBcIjAxMjM0NTY3ODlBQkNERUZcIjtcbiAgICAgIHZhciBhbGxvdyA9IFwiIFxcZlxcblxcclxcdFxcdTAwQTBcXHUyMDI4XFx1MjAyOVwiO1xuICAgICAgdmFyIGRlYzogbnVtYmVyW10gPSBbXTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMTY7ICsraSlcbiAgICAgICAgICBkZWNbaGV4LmNoYXJBdChpKV0gPSBpO1xuICAgICAgaGV4ID0gaGV4LnRvTG93ZXJDYXNlKCk7XG4gICAgICBmb3IgKHZhciBpID0gMTA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFsbG93Lmxlbmd0aDsgKytpKVxuICAgICAgICAgIGRlY1thbGxvdy5jaGFyQXQoaSldID0gLTE7XG4gICAgICBIZXhDb2RlYy5oZXhEZWNvZGVNYXAgPSBkZWM7XG4gICAgfVxuXG4gICAgdmFyIG91dDogbnVtYmVyW10gPSBbXTtcbiAgICB2YXIgYml0cyA9IDAsIGNoYXJfY291bnQgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYS5sZW5ndGg7ICsraSlcbiAgICB7XG4gICAgICB2YXIgYyA9IGEuY2hhckF0KGkpO1xuICAgICAgaWYgKGMgPT0gJz0nKVxuICAgICAgICAgIGJyZWFrO1xuICAgICAgdmFyIGIgPSBIZXhDb2RlYy5oZXhEZWNvZGVNYXBbY107XG4gICAgICBpZiAoYiA9PSAtMSlcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgIGlmIChiID09IHVuZGVmaW5lZClcbiAgICAgICAgICB0aHJvdyAnSWxsZWdhbCBjaGFyYWN0ZXIgYXQgb2Zmc2V0ICcgKyBpO1xuICAgICAgYml0cyB8PSBiO1xuICAgICAgaWYgKCsrY2hhcl9jb3VudCA+PSAyKSB7XG4gICAgICAgICAgb3V0LnB1c2goIGJpdHMgKTtcbiAgICAgICAgICBiaXRzID0gMDtcbiAgICAgICAgICBjaGFyX2NvdW50ID0gMDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYml0cyA8PD0gNDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoY2hhcl9jb3VudClcbiAgICAgIHRocm93IFwiSGV4IGVuY29kaW5nIGluY29tcGxldGU6IDQgYml0cyBtaXNzaW5nXCI7XG5cbiAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKCBvdXQgKTtcbiAgfVxufVxuIiwidHlwZSBieXRlID0gbnVtYmVyO1xuXG5lbnVtIEJBU0U2NFNQRUNJQUxTIHtcbiAgUExVUyA9ICcrJy5jaGFyQ29kZUF0KDApLFxuICBTTEFTSCA9ICcvJy5jaGFyQ29kZUF0KDApLFxuICBOVU1CRVIgPSAnMCcuY2hhckNvZGVBdCgwKSxcbiAgTE9XRVIgPSAnYScuY2hhckNvZGVBdCgwKSxcbiAgVVBQRVIgPSAnQScuY2hhckNvZGVBdCgwKSxcbiAgUExVU19VUkxfU0FGRSA9ICctJy5jaGFyQ29kZUF0KDApLFxuICBTTEFTSF9VUkxfU0FGRSA9ICdfJy5jaGFyQ29kZUF0KDApXG59XG5cbmV4cG9ydCBjbGFzcyBCYXNlNjRDb2RlY1xue1xuICBzdGF0aWMgZGVjb2RlKCBiNjQ6IHN0cmluZyApOiBVaW50OEFycmF5XG4gIHtcbiAgICBpZiAoYjY0Lmxlbmd0aCAlIDQgPiAwKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gTGVuZ3RoIG11c3QgYmUgYSBtdWx0aXBsZSBvZiA0Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZGVjb2RlKCBlbHQ6IFN0cmluZyApOiBudW1iZXJcbiAgICB7XG4gICAgICB2YXIgY29kZSA9IGVsdC5jaGFyQ29kZUF0KDApO1xuXG4gICAgICBpZiAoY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuUExVUyB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTX1VSTF9TQUZFKVxuICAgICAgICByZXR1cm4gNjI7IC8vICcrJ1xuXG4gICAgICBpZiAoY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuU0xBU0ggfHwgY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuU0xBU0hfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MzsgLy8gJy8nXG5cbiAgICAgIGlmIChjb2RlID49IEJBU0U2NFNQRUNJQUxTLk5VTUJFUilcbiAgICAgIHtcbiAgICAgICAgaWYgKGNvZGUgPCBCQVNFNjRTUEVDSUFMUy5OVU1CRVIgKyAxMClcbiAgICAgICAgICByZXR1cm4gY29kZSAtIEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDI2ICsgMjY7XG5cbiAgICAgICAgaWYgKGNvZGUgPCBCQVNFNjRTUEVDSUFMUy5VUFBFUiArIDI2KVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuVVBQRVI7XG5cbiAgICAgICAgaWYgKGNvZGUgPCBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2KVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTE9XRVIgKyAyNjtcbiAgICAgIH1cblxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGJhc2U2NCBzdHJpbmcuIENoYXJhY3RlciBub3QgdmFsaWQnKTtcbiAgICB9XG5cbiAgICAvLyB0aGUgbnVtYmVyIG9mIGVxdWFsIHNpZ25zIChwbGFjZSBob2xkZXJzKVxuICAgIC8vIGlmIHRoZXJlIGFyZSB0d28gcGxhY2Vob2xkZXJzLCB0aGFuIHRoZSB0d28gY2hhcmFjdGVycyBiZWZvcmUgaXRcbiAgICAvLyByZXByZXNlbnQgb25lIGJ5dGVcbiAgICAvLyBpZiB0aGVyZSBpcyBvbmx5IG9uZSwgdGhlbiB0aGUgdGhyZWUgY2hhcmFjdGVycyBiZWZvcmUgaXQgcmVwcmVzZW50IDIgYnl0ZXNcbiAgICAvLyB0aGlzIGlzIGp1c3QgYSBjaGVhcCBoYWNrIHRvIG5vdCBkbyBpbmRleE9mIHR3aWNlXG4gICAgbGV0IGxlbiA9IGI2NC5sZW5ndGg7XG4gICAgbGV0IHBsYWNlSG9sZGVycyA9IGI2NC5jaGFyQXQobGVuIC0gMikgPT09ICc9JyA/IDIgOiBiNjQuY2hhckF0KGxlbiAtIDEpID09PSAnPScgPyAxIDogMDtcblxuICAgIC8vIGJhc2U2NCBpcyA0LzMgKyB1cCB0byB0d28gY2hhcmFjdGVycyBvZiB0aGUgb3JpZ2luYWwgZGF0YVxuICAgIGxldCBhcnIgPSBuZXcgVWludDhBcnJheSggYjY0Lmxlbmd0aCAqIDMgLyA0IC0gcGxhY2VIb2xkZXJzICk7XG5cbiAgICAvLyBpZiB0aGVyZSBhcmUgcGxhY2Vob2xkZXJzLCBvbmx5IGdldCB1cCB0byB0aGUgbGFzdCBjb21wbGV0ZSA0IGNoYXJzXG4gICAgbGV0IGwgPSBwbGFjZUhvbGRlcnMgPiAwID8gYjY0Lmxlbmd0aCAtIDQgOiBiNjQubGVuZ3RoO1xuXG4gICAgdmFyIEwgPSAwO1xuXG4gICAgZnVuY3Rpb24gcHVzaCAodjogYnl0ZSkge1xuICAgICAgYXJyW0wrK10gPSB2O1xuICAgIH1cblxuICAgIGxldCBpID0gMCwgaiA9IDA7XG5cbiAgICBmb3IgKDsgaSA8IGw7IGkgKz0gNCwgaiArPSAzKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAxOCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDEpKSA8PCAxMikgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA8PCA2KSB8IGRlY29kZShiNjQuY2hhckF0KGkgKyAzKSk7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDAwMCkgPj4gMTYpO1xuICAgICAgcHVzaCgodG1wICYgMHhGRjAwKSA+PiA4KTtcbiAgICAgIHB1c2godG1wICYgMHhGRik7XG4gICAgfVxuXG4gICAgaWYgKHBsYWNlSG9sZGVycyA9PT0gMikge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMikgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDEpKSA+PiA0KTtcbiAgICAgIHB1c2godG1wICYgMHhGRik7XG4gICAgfSBlbHNlIGlmIChwbGFjZUhvbGRlcnMgPT09IDEpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDEwKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDQpIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAyKSkgPj4gMik7XG4gICAgICBwdXNoKCh0bXAgPj4gOCkgJiAweEZGKTtcbiAgICAgIHB1c2godG1wICYgMHhGRik7XG4gICAgfVxuXG4gICAgcmV0dXJuIGFycjtcbiAgfVxuXG4gIHN0YXRpYyBlbmNvZGUoIHVpbnQ4OiBVaW50OEFycmF5ICk6IHN0cmluZ1xuICB7XG4gICAgdmFyIGk6IG51bWJlcjtcbiAgICB2YXIgZXh0cmFCeXRlcyA9IHVpbnQ4Lmxlbmd0aCAlIDM7IC8vIGlmIHdlIGhhdmUgMSBieXRlIGxlZnQsIHBhZCAyIGJ5dGVzXG4gICAgdmFyIG91dHB1dCA9ICcnO1xuXG4gICAgY29uc3QgbG9va3VwID0gJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nO1xuICAgIGZ1bmN0aW9uIGVuY29kZSggbnVtOiBieXRlICkge1xuICAgICAgcmV0dXJuIGxvb2t1cC5jaGFyQXQobnVtKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB0cmlwbGV0VG9CYXNlNjQoIG51bTogbnVtYmVyICkge1xuICAgICAgcmV0dXJuIGVuY29kZShudW0gPj4gMTggJiAweDNGKSArIGVuY29kZShudW0gPj4gMTIgJiAweDNGKSArIGVuY29kZShudW0gPj4gNiAmIDB4M0YpICsgZW5jb2RlKG51bSAmIDB4M0YpO1xuICAgIH1cblxuICAgIC8vIGdvIHRocm91Z2ggdGhlIGFycmF5IGV2ZXJ5IHRocmVlIGJ5dGVzLCB3ZSdsbCBkZWFsIHdpdGggdHJhaWxpbmcgc3R1ZmYgbGF0ZXJcbiAgICBsZXQgbGVuZ3RoID0gdWludDgubGVuZ3RoIC0gZXh0cmFCeXRlcztcbiAgICBmb3IgKGkgPSAwOyBpIDwgbGVuZ3RoOyBpICs9IDMpIHtcbiAgICAgIGxldCB0ZW1wID0gKHVpbnQ4W2ldIDw8IDE2KSArICh1aW50OFtpICsgMV0gPDwgOCkgKyAodWludDhbaSArIDJdKTtcbiAgICAgIG91dHB1dCArPSB0cmlwbGV0VG9CYXNlNjQodGVtcCk7XG4gICAgfVxuXG4gICAgLy8gcGFkIHRoZSBlbmQgd2l0aCB6ZXJvcywgYnV0IG1ha2Ugc3VyZSB0byBub3QgZm9yZ2V0IHRoZSBleHRyYSBieXRlc1xuICAgIHN3aXRjaCAoZXh0cmFCeXRlcykge1xuICAgICAgY2FzZSAxOlxuICAgICAgICBsZXQgdGVtcCA9IHVpbnQ4W3VpbnQ4Lmxlbmd0aCAtIDFdO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKHRlbXAgPj4gMik7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPDwgNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9ICc9PSc7XG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlIDI6XG4gICAgICAgIHRlbXAgPSAodWludDhbdWludDgubGVuZ3RoIC0gMl0gPDwgOCkgKyAodWludDhbdWludDgubGVuZ3RoIC0gMV0pO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKHRlbXAgPj4gMTApO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKCh0ZW1wID4+IDQpICYgMHgzRik7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPDwgMikgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9ICc9JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHJldHVybiBvdXRwdXQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IEhleENvZGVjIH0gZnJvbSAnLi9oZXgtY29kZWMnO1xuaW1wb3J0IHsgQmFzZTY0Q29kZWMgfSBmcm9tICcuL2Jhc2U2NC1jb2RlYyc7XG5cbmV4cG9ydCBlbnVtIEJ5dGVFbmNvZGluZyB7XG4gIFJBVyxcbiAgSEVYLFxuICBCQVNFNjQsXG4gIFVURjhcbn1cblxuZXhwb3J0IGNsYXNzIEJ5dGVBcnJheSAvL2V4dGVuZHMgVWludDhBcnJheVxue1xuICBwdWJsaWMgc3RhdGljIFJBVyA9IEJ5dGVFbmNvZGluZy5SQVc7XG4gIHB1YmxpYyBzdGF0aWMgSEVYID0gQnl0ZUVuY29kaW5nLkhFWDtcbiAgcHVibGljIHN0YXRpYyBCQVNFNjQgPSBCeXRlRW5jb2RpbmcuQkFTRTY0O1xuICBwdWJsaWMgc3RhdGljIFVURjggPSBCeXRlRW5jb2RpbmcuVVRGODtcblxuICBzdGF0aWMgZW5jb2RpbmdUb1N0cmluZyggZW5jb2Rpbmc6IEJ5dGVFbmNvZGluZyApOiBzdHJpbmcge1xuICAgIHN3aXRjaCggZW5jb2RpbmcgKSB7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5CQVNFNjQ6XG4gICAgICAgIHJldHVybiAnQkFTRTY0JztcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLlVURjg6XG4gICAgICAgIHJldHVybiAnVVRGOCc7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5IRVg6XG4gICAgICAgIHJldHVybiAnSEVYJztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiAnUkFXJztcbiAgICB9XG4gIH1cblxuICBzdGF0aWMgc3RyaW5nVG9FbmNvZGluZyggZW5jb2Rpbmc6IHN0cmluZyApOiBCeXRlRW5jb2Rpbmcge1xuICAgIGlmICggZW5jb2RpbmcudG9VcHBlckNhc2UoKSA9PSAnQkFTRTY0JyApXG4gICAgICByZXR1cm4gQnl0ZUVuY29kaW5nLkJBU0U2NDtcbiAgICBlbHNlIGlmICggZW5jb2RpbmcudG9VcHBlckNhc2UoKSA9PSAnVVRGOCcgKVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5VVEY4O1xuICAgIGVsc2UgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdIRVgnIClcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuSEVYO1xuICAgIGVsc2VcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuUkFXO1xuICB9XG5cblxuICBwcml2YXRlIGJ5dGVBcnJheTogVWludDhBcnJheTtcbiAgLyoqXG4gICAqIENyZWF0ZSBhIEJ5dGVBcnJheVxuICAgKiBAcGFyYW0gYnl0ZXMgLSBpbml0aWFsIGNvbnRlbnRzLCBvcHRpb25hbFxuICAgKiAgIG1heSBiZTpcbiAgICogICAgIGFuIGV4aXN0aW5nIEJ5dGVBcnJheVxuICAgKiAgICAgYW4gQXJyYXkgb2YgbnVtYmVycyAoMC4uMjU1KVxuICAgKiAgICAgYSBzdHJpbmcsIHRvIGJlIGNvbnZlcnRlZFxuICAgKiAgICAgYW4gQXJyYXlCdWZmZXJcbiAgICogICAgIGEgVWludDhBcnJheVxuICAgKi9cbiAgY29uc3RydWN0b3IoIGJ5dGVzPzogQnl0ZUFycmF5IHwgQXJyYXk8bnVtYmVyPiB8IFN0cmluZyB8IEFycmF5QnVmZmVyIHwgVWludDhBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIsIG9wdD86IGFueSApXG4gIHtcbiAgICBpZiAoICFieXRlcyApXG4gICAge1xuICAgICAgLy8gemVyby1sZW5ndGggYXJyYXlcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDAgKTtcbiAgICB9XG4gICAgZWxzZSBpZiAoICFlbmNvZGluZyB8fCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuUkFXIClcbiAgICB7XG4gICAgICBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCA8QXJyYXlCdWZmZXI+Ynl0ZXMgKTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBieXRlcy5ieXRlQXJyYXk7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJ5dGVzICk7XG4gICAgICAvL2Vsc2UgaWYgKCB0eXBlb2YgYnl0ZXMgPT0gXCJzdHJpbmdcIiApXG4gICAgICAvL3tcbi8vICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICAvL31cbiAgICB9XG4gICAgZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICB7XG4gICAgICBpZiAoIGVuY29kaW5nID09IEJ5dGVFbmNvZGluZy5CQVNFNjQgKVxuICAgICAge1xuICAgICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gQmFzZTY0Q29kZWMuZGVjb2RlKCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLkhFWCApXG4gICAgICB7XG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gSGV4Q29kZWMuZGVjb2RlKCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLlVURjggKVxuICAgICAge1xuICAgICAgICBsZXQgbCA9ICggPHN0cmluZz5ieXRlcyApLmxlbmd0aDtcbiAgICAgICAgbGV0IGJhID0gbmV3IFVpbnQ4QXJyYXkoIGwgKTtcbiAgICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBsOyArK2kgKVxuICAgICAgICAgIGJhW2ldID0gKCA8c3RyaW5nPmJ5dGVzICkuY2hhckNvZGVBdCggaSApO1xuXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYmE7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gTXVzdCBoYXZlIGV4ZWMgb25lIG9mIGFib3ZlIGFsbG9jYXRvcnNcbiAgICBpZiAoICF0aGlzLmJ5dGVBcnJheSApXG4gICAge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIkludmFsaWQgUGFyYW1zIGZvciBCeXRlQXJyYXkoKVwiKVxuICAgIH1cbiAgfVxuXG4gIGdldCBsZW5ndGgoKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xuICB9XG5cbiAgc2V0IGxlbmd0aCggbGVuOiBudW1iZXIgKVxuICB7XG4gICAgaWYgKCB0aGlzLmJ5dGVBcnJheS5sZW5ndGggPj0gbGVuIClcbiAgICB7XG4gICAgICB0aGlzLmJ5dGVBcnJheSA9IHRoaXMuYnl0ZUFycmF5LnNsaWNlKCAwLCBsZW4gKTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxldCBvbGQgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiApO1xuICAgICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBvbGQsIDAgKTtcbiAgICB9XG4gIH1cblxuICBnZXQgYmFja2luZ0FycmF5KCk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheTtcbiAgfVxuXG4gIGVxdWFscyggdmFsdWU6IEJ5dGVBcnJheSApOiBib29sZWFuXG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuICAgIHZhciBvayA9ICggYmEubGVuZ3RoID09IHZiYS5sZW5ndGggKTtcblxuICAgIGlmICggb2sgKVxuICAgIHtcbiAgICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgICBvayA9IG9rICYmICggYmFbaV0gPT0gdmJhW2ldICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG9rO1xuICB9XG5cbiAgLyoqXG4gICAgKiBnZXQgYnl0ZSBhdCBvZmZzZXRcbiAgICAqL1xuICBieXRlQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgXTtcbiAgfVxuXG4gIHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdICAgICAgICk7XG4gIH1cblxuICBsaXR0bGVFbmRpYW5Xb3JkQXQoIG9mZnNldCApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gPDwgIDggKTtcbiAgfVxuXG4gIGR3b3JkQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSA8PCAyNCApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAxNiApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDIgXSA8PCAgOCApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDMgXSAgICAgICApO1xuICB9XG5cbiAgLyoqXG4gICAgKiBzZXQgYnl0ZSBhdCBvZmZzZXRcbiAgICAqIEBmbHVlbnRcbiAgICAqL1xuICBzZXRCeXRlQXQoIG9mZnNldDogbnVtYmVyLCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldEJ5dGVzQXQoIG9mZnNldDogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCB2YWx1ZS5ieXRlQXJyYXksIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjbG9uZSgpOiBCeXRlQXJyYXlcbiAge1xuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSgpICk7XG4gIH1cblxuICAvKipcbiAgKiBFeHRyYWN0IGEgc2VjdGlvbiAob2Zmc2V0LCBjb3VudCkgZnJvbSB0aGUgQnl0ZUFycmF5XG4gICogQGZsdWVudFxuICAqIEByZXR1cm5zIGEgbmV3IEJ5dGVBcnJheSBjb250YWluaW5nIGEgc2VjdGlvbi5cbiAgKi9cbiAgYnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIGNvdW50PzogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgaWYgKCAhTnVtYmVyLmlzSW50ZWdlciggY291bnQgKSApXG4gICAgICBjb3VudCA9ICggdGhpcy5sZW5ndGggLSBvZmZzZXQgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSggb2Zmc2V0LCBvZmZzZXQgKyBjb3VudCApICk7XG4gIH1cblxuICAvKipcbiAgKiBDcmVhdGUgYSB2aWV3IGludG8gdGhlIEJ5dGVBcnJheVxuICAqXG4gICogQHJldHVybnMgYSBCeXRlQXJyYXkgcmVmZXJlbmNpbmcgYSBzZWN0aW9uIG9mIG9yaWdpbmFsIEJ5dGVBcnJheS5cbiAgKi9cbiAgdmlld0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnN1YmFycmF5KCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFwcGVuZCBieXRlXG4gICogQGZsdWVudFxuICAqL1xuICBhZGRCeXRlKCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXlbIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldExlbmd0aCggbGVuOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmxlbmd0aCA9IGxlbjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgY29uY2F0KCBieXRlczogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG5cbiAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCBiYS5sZW5ndGggKyBieXRlcy5sZW5ndGggKTtcblxuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYmEgKTtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIGJ5dGVzLmJ5dGVBcnJheSwgYmEubGVuZ3RoICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG5vdCggKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeMHhGRjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgYW5kKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSAmIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBvciggdmFsdWU6IEJ5dGVBcnJheSApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG5cbiAgICBmb3IoIGxldCBpID0gMDsgaSA8IGJhLmxlbmd0aDsgKytpIClcbiAgICAgIGJhW2ldID0gYmFbaV0gfCB2YmFbIGkgXTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgeG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB0b1N0cmluZyggZW5jb2Rpbmc/OiBudW1iZXIsIG9wdD86IGFueSApXG4gIHtcbiAgICBsZXQgcyA9IFwiXCI7XG4gICAgbGV0IGkgPSAwO1xuXG4gICAgc3dpdGNoKCBlbmNvZGluZyB8fCBCeXRlRW5jb2RpbmcuSEVYICkge1xuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuSEVYOlxuICAgICAgICAvL3JldHVybiBIZXhDb2RlYy5lbmNvZGUoIHRoaXMuYnl0ZUFycmF5ICk7XG4gICAgICAgIGZvciggaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgKytpIClcbiAgICAgICAgICBzICs9ICggXCIwXCIgKyB0aGlzLmJ5dGVBcnJheVsgaSBdLnRvU3RyaW5nKCAxNiApKS5zbGljZSggLTIgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkJBU0U2NDpcbiAgICAgICAgcmV0dXJuIEJhc2U2NENvZGVjLmVuY29kZSggdGhpcy5ieXRlQXJyYXkgKTtcblxuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuVVRGODpcbiAgICAgICAgZm9yKCBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyArK2kgKVxuICAgICAgICAgIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSggdGhpcy5ieXRlQXJyYXlbIGkgXSApO1xuICAgICAgICBicmVhaztcblxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgZm9yKCBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyArK2kgKVxuICAgICAgICAgIHMgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSggdGhpcy5ieXRlQXJyYXlbIGkgXSApO1xuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICByZXR1cm4gcztcbiAgfVxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi4va2luZC9ieXRlLWFycmF5JztcblxuZXhwb3J0IGVudW0gQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiB7XG4gIEVOQ1JZUFQsXG4gIERFQ1JZUFQsXG4gIERJR0VTVCxcbiAgU0lHTixcbiAgVkVSSUZZLFxuICBERVJJVkVfQklUUyxcblxuICBERVJJVkVfS0VZLFxuICBJTVBPUlRfS0VZLFxuICBFWFBPUlRfS0VZLFxuICBHRU5FUkFURV9LRVksXG4gIFdSQVBfS0VZLFxuICBVTldSQVBfS0VZLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyeXB0b2dyYXBoaWNTZXJ2aWNlIHtcbiAgZW5jcnlwdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcbiAgZGVjcnlwdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcblxuICBkaWdlc3Q/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcblxuICBzaWduPyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuICB2ZXJpZnk/KCBhbGdvcml0aG06IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIGRlcml2ZUJpdHM/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBsZW5ndGg6IG51bWJlciApOiBQcm9taXNlPEJ5dGVBcnJheT47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3RvciB7XG4gIG5ldygpOiBDcnlwdG9ncmFwaGljU2VydmljZTtcblxuICBzdXBwb3J0ZWRPcGVyYXRpb25zPzogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgZGVyaXZlS2V5PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgZGVyaXZlZEtleVR5cGU6IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuXG4gIHdyYXBLZXk/KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IEFsZ29yaXRobSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG4gIHVud3JhcEtleT8oIGZvcm1hdDogc3RyaW5nLCB3cmFwcGVkS2V5OiBCeXRlQXJyYXksIHVud3JhcHBpbmdLZXk6IENyeXB0b0tleSwgdW53cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0sIHVud3JhcHBlZEtleUFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PjtcblxuICBpbXBvcnRLZXk/KCBmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5LCBhbGdvcml0aG06IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuICBnZW5lcmF0ZUtleT8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+O1xuICBleHBvcnRLZXk/KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3Ige1xuICBuZXcoKTogQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2U7XG5cbiAgc3VwcG9ydGVkT3BlcmF0aW9ucz86IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXTtcbn1cblxuZXhwb3J0IGNsYXNzIENyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkge1xuICBwcml2YXRlIF9zZXJ2aWNlTWFwOiBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPjtcbiAgcHJpdmF0ZSBfa2V5U2VydmljZU1hcDogTWFwPHN0cmluZywgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3Rvcj47XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5fc2VydmljZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yPigpO1xuICAgIHRoaXMuX2tleVNlcnZpY2VNYXAgPSBuZXcgTWFwPHN0cmluZywgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3Rvcj4oKTtcbiAgfVxuXG4gIGdldFNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtICk6IHsgbmFtZTogc3RyaW5nLCBpbnN0YW5jZTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2UgfSB7XG4gICAgbGV0IGFsZ28gPSAoIGFsZ29yaXRobSBpbnN0YW5jZW9mIE9iamVjdCApID8gKDxBbGdvcml0aG0+YWxnb3JpdGhtKS5uYW1lIDogPHN0cmluZz5hbGdvcml0aG07XG4gICAgbGV0IHNlcnZpY2UgPSB0aGlzLl9zZXJ2aWNlTWFwLmdldCggYWxnbyApO1xuXG4gICAgcmV0dXJuIHsgbmFtZTogYWxnbywgaW5zdGFuY2U6IHNlcnZpY2UgPyBuZXcgc2VydmljZSgpIDogbnVsbCB9O1xuICB9XG5cbiAgZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0gKTogeyBuYW1lOiBzdHJpbmcsIGluc3RhbmNlOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB9IHtcbiAgICBsZXQgYWxnbyA9ICggYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0ICkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICBsZXQgc2VydmljZSA9IHRoaXMuX2tleVNlcnZpY2VNYXAuZ2V0KCBhbGdvICk7XG5cbiAgICByZXR1cm4geyBuYW1lOiBhbGdvLCBpbnN0YW5jZTogc2VydmljZSA/IG5ldyBzZXJ2aWNlKCkgOiBudWxsIH07XG4gIH1cblxuICBzZXRTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBjdG9yLnN1cHBvcnRlZE9wZXJhdGlvbnMgPSBvcGVycztcblxuICAgIHRoaXMuX3NlcnZpY2VNYXAuc2V0KCBhbGdvcml0aG0sIGN0b3IgKTtcbiAgfVxuICBzZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBjdG9yLnN1cHBvcnRlZE9wZXJhdGlvbnMgPSBvcGVycztcblxuICAgIHRoaXMuX2tleVNlcnZpY2VNYXAuc2V0KCBhbGdvcml0aG0sIGN0b3IgKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciBpbXBsZW1lbnRzIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB7XG4gIC8vIHNpbmdsZXRvbiByZWdpc3RyeVxuICBwcml2YXRlIHN0YXRpYyBfcmVnaXN0cnk6IENyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkgPSBuZXcgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSgpO1xuXG4gIHB1YmxpYyBzdGF0aWMgcmVnaXN0ZXJTZXJ2aWNlKCBuYW1lOiBzdHJpbmcsIGN0b3I6IENyeXB0b2dyYXBoaWNTZXJ2aWNlQ29uc3RydWN0b3IsIG9wZXJzOiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW10gKSB7XG4gICAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnkuc2V0U2VydmljZSggbmFtZSwgY3Rvciwgb3BlcnMgKTtcbiAgfVxuICBwdWJsaWMgc3RhdGljIHJlZ2lzdGVyS2V5U2VydmljZSggbmFtZTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuX3JlZ2lzdHJ5LnNldEtleVNlcnZpY2UoIG5hbWUsIGN0b3IsIG9wZXJzICk7XG4gIH1cblxuICBnZXQgcmVnaXN0cnkoKTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSB7XG4gICAgcmV0dXJuIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuX3JlZ2lzdHJ5O1xuICB9XG5cbiAgZW5jcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5lbmNyeXB0IClcbiAgICAgID8gaW5zdGFuY2UuZW5jcnlwdCggbmFtZSwga2V5LCBkYXRhIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgZGVjcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZWNyeXB0IClcbiAgICAgID8gaW5zdGFuY2UuZGVjcnlwdCggbmFtZSwga2V5LCBkYXRhIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgZGlnZXN0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZGlnZXN0IClcbiAgICAgID8gaW5zdGFuY2UuZGlnZXN0KCBuYW1lLCBkYXRhIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgc2lnbiggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLnNpZ24gKVxuICAgICAgPyBpbnN0YW5jZS5zaWduKCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB2ZXJpZnkoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBzaWduYXR1cmU6IEJ5dGVBcnJheSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLnZlcmlmeSApXG4gICAgICA/IGluc3RhbmNlLnZlcmlmeSggbmFtZSwga2V5LCBzaWduYXR1cmUsIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBleHBvcnRLZXkoIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGtleS5hbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmV4cG9ydEtleSApXG4gICAgICA/IGluc3RhbmNlLmV4cG9ydEtleSggZm9ybWF0LCBrZXkgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBnZW5lcmF0ZUtleSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZ2VuZXJhdGVLZXkgKVxuICAgICAgPyBpbnN0YW5jZS5nZW5lcmF0ZUtleSggbmFtZSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApXG4gICAgICA6IFByb21pc2UucmVqZWN0PENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+KCBcIlwiICk7XG4gIH1cblxuICBpbXBvcnRLZXkoIGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXkgLCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmltcG9ydEtleSApXG4gICAgICA/IGluc3RhbmNlLmltcG9ydEtleSggZm9ybWF0LCBrZXlEYXRhLCBuYW1lLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG5cbiAgZGVyaXZlS2V5KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZGVyaXZlS2V5IClcbiAgICAgID8gaW5zdGFuY2UuZGVyaXZlS2V5KCBuYW1lLCBiYXNlS2V5LCBkZXJpdmVkS2V5VHlwZSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApXG4gICAgICA6IFByb21pc2UucmVqZWN0PENyeXB0b0tleT4oIFwiXCIgKTtcbiAgfVxuXG4gIGRlcml2ZUJpdHMoIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGxlbmd0aDogbnVtYmVyICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZXJpdmVCaXRzIClcbiAgICAgID8gaW5zdGFuY2UuZGVyaXZlQml0cyggbmFtZSwgYmFzZUtleSwgbGVuZ3RoIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgd3JhcEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5LCB3cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB3cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0gKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRLZXlTZXJ2aWNlKCBrZXkuYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS53cmFwS2V5IClcbiAgICAgID8gaW5zdGFuY2Uud3JhcEtleSggZm9ybWF0LCBrZXksIHdyYXBwaW5nS2V5LCB3cmFwQWxnb3JpdGhtIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgdW53cmFwS2V5KCBmb3JtYXQ6IHN0cmluZywgd3JhcHBlZEtleTogQnl0ZUFycmF5LCB1bndyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHVud3JhcEFsZ29yaXRobTogQWxnb3JpdGhtLCB1bndyYXBwZWRLZXlBbGdvcml0aG06IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIHVud3JhcEFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UudW53cmFwS2V5IClcbiAgICAgID8gaW5zdGFuY2UudW53cmFwS2V5KCBmb3JtYXQsIHdyYXBwZWRLZXksIHVud3JhcHBpbmdLZXksIG5hbWUsIHVud3JhcHBlZEtleUFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApXG4gICAgICA6IFByb21pc2UucmVqZWN0PENyeXB0b0tleT4oIFwiXCIgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi4va2luZC9ieXRlLWFycmF5JztcbmltcG9ydCB7IENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24sIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB9IGZyb20gJy4vY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlLXJlZ2lzdHJ5JztcblxuZGVjbGFyZSB2YXIgbXNyY3J5cHRvO1xuXG5leHBvcnQgY2xhc3MgV2ViQ3J5cHRvU2VydmljZSBpbXBsZW1lbnRzIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB7XG4gIHByb3RlY3RlZCBjcnlwdG86IFN1YnRsZUNyeXB0bztcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgfVxuXG4gIHN0YXRpYyBfc3VidGxlOiBTdWJ0bGVDcnlwdG87XG4gIHN0YXRpYyBnZXQgc3VidGxlKCk6IFN1YnRsZUNyeXB0byB7XG4gICAgbGV0IHN1YnRsZSA9IFdlYkNyeXB0b1NlcnZpY2UuX3N1YnRsZVxuICAgICAgfHwgKCBjcnlwdG8gJiYgY3J5cHRvLnN1YnRsZSApXG4gICAgICB8fCAoIHdpbmRvdyAmJiB3aW5kb3cuY3J5cHRvICYmIHdpbmRvdy5jcnlwdG8uc3VidGxlIClcbiAgICAgIHx8IG1zcmNyeXB0bztcblxuICAgIGlmICggIVdlYkNyeXB0b1NlcnZpY2UuX3N1YnRsZSApXG4gICAgICAgV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlID0gc3VidGxlO1xuXG4gICAgcmV0dXJuIHN1YnRsZTtcbiAgfVxuXG4gIGVuY3J5cHQoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZW5jcnlwdChhbGdvcml0aG0sIGtleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5kZWNyeXB0KGFsZ29yaXRobSwga2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGRpZ2VzdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZGF0YTogQnl0ZUFycmF5KTogYW55IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBleHBvcnRLZXkoIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmV4cG9ydEtleShmb3JtYXQsIGtleSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGdlbmVyYXRlS2V5KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+KChyZXNvbHZlLCByZWplY3QpID0+IHtcblxuICAgfSk7XG4gIH1cblxuICBpbXBvcnRLZXkoZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSwgYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q3J5cHRvS2V5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5pbXBvcnRLZXkoZm9ybWF0LCBrZXlEYXRhLmJhY2tpbmdBcnJheSwgYWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzKVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUocmVzKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgfSk7XG4gIH1cblxuICBzaWduKGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5zaWduKGFsZ29yaXRobSwga2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHZlcmlmeShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLnZlcmlmeShhbGdvcml0aG0sIGtleSwgc2lnbmF0dXJlLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cbn1cblxuLypjbGFzcyBTSEExQ3J5cHRvU2VydmljZSBpbXBsZW1lbnRzIENyeXB0b2dyYXBoaWNTZXJ2aWNlIHtcbiAgZGlnZXN0KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gVE9ETzogSW1wbGVtZW50IFNIQS0xXG4gICAgICBtc3JjcnlwdG8uZGlnZXN0KGFsZ29yaXRobSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG59XG5cbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnU0hBLTEnLCBTSEExQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRJR0VTVCBdICk7XG5cbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnU0hBLTI1NicsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ESUdFU1QgXSApO1xuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtNTEyJywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRJR0VTVCBdICk7XG4qL1xuXG5pZiAoIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlICkge1xuICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ0FFUy1DQkMnLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ERUNSWVBUIF0gKTtcbiAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdBRVMtR0NNJywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkVOQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uREVDUllQVCBdICk7XG4gIC8vQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdSU0FTU0EtWFlaJywgV2ViQ3J5cHRvU2VydmljZSApO1xuXG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiwgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0gZnJvbSAnLi9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnknO1xuXG5jbGFzcyBERVNTZWNyZXRLZXkgaW1wbGVtZW50cyBDcnlwdG9LZXkge1xuICBwcml2YXRlIF9rZXlNYXRlcmlhbDogQnl0ZUFycmF5O1xuICBwcml2YXRlIF9leHRyYWN0YWJsZTogYm9vbGVhbjtcbiAgcHJpdmF0ZSBfYWxnb3JpdGhtOiBLZXlBbGdvcml0aG07XG4gIHByaXZhdGUgX3R5cGU6IHN0cmluZztcbiAgcHJpdmF0ZSBfdXNhZ2VzOiBzdHJpbmdbXTtcblxuICBjb25zdHJ1Y3Rvcigga2V5TWF0ZXJpYWw6IEJ5dGVBcnJheSwgYWxnb3JpdGhtOiBLZXlBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCB1c2FnZXM6IHN0cmluZ1tdICkge1xuXG4gICAgdGhpcy5fa2V5TWF0ZXJpYWwgPSBrZXlNYXRlcmlhbDtcblxuICAgIHRoaXMuX2FsZ29yaXRobSA9IGFsZ29yaXRobTtcblxuICAgIHRoaXMuX2V4dHJhY3RhYmxlID0gZXh0cmFjdGFibGU7XG5cbiAgICB0aGlzLl90eXBlID0gJ3NlY3JldCc7XG5cbiAgICB0aGlzLl91c2FnZXMgPSB1c2FnZXM7XG4gICAgT2JqZWN0LmZyZWV6ZSggdGhpcy5fdXNhZ2VzICk7XG4gIH1cblxuICBnZXQgYWxnb3JpdGhtKCkgeyByZXR1cm4gdGhpcy5fYWxnb3JpdGhtOyB9XG4gIGdldCBleHRyYWN0YWJsZSgpOiBib29sZWFuIHsgcmV0dXJuIHRoaXMuX2V4dHJhY3RhYmxlOyB9XG4gIGdldCB0eXBlKCkgeyByZXR1cm4gdGhpcy5fdHlwZTsgfVxuICBnZXQgdXNhZ2VzKCk6IHN0cmluZ1tdIHsgcmV0dXJuIEFycmF5LmZyb20oIHRoaXMuX3VzYWdlcyApOyB9XG5cbiAgZ2V0IGtleU1hdGVyaWFsKCkgeyByZXR1cm4gdGhpcy5fa2V5TWF0ZXJpYWwgfTtcbn1cblxuZXhwb3J0IGNsYXNzIERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgY29uc3RydWN0b3IoKSB7XG4gIH1cblxuICBlbmNyeXB0KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuXG4gICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDEsIDAgKSApICk7XG4gICAgfSk7XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuXG4gICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDAsIDAgKSApICk7XG4gICAgICAvL2NhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgaW1wb3J0S2V5KGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENyeXB0b0tleT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGRlc0tleSA9IG5ldyBERVNTZWNyZXRLZXkoIGtleURhdGEsIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApO1xuXG4gICAgICByZXNvbHZlKCBkZXNLZXkgKTtcbiAgIH0pO1xuICB9XG5cbiAgc2lnbiggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuXG4gICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDAsIDAgKSApICk7XG4gICAgICAvL2NhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgc3RhdGljIGRlc1BDO1xuICBzdGF0aWMgZGVzU1A7XG5cbiAgcHJpdmF0ZSBkZXMoIGtleTogVWludDhBcnJheSwgbWVzc2FnZTogVWludDhBcnJheSwgZW5jcnlwdDogbnVtYmVyLCBtb2RlOiBudW1iZXIsIGl2PzogVWludDhBcnJheSwgcGFkZGluZz86IG51bWJlciApOiBVaW50OEFycmF5XG4gIHtcbiAgICAvL2Rlc19jcmVhdGVLZXlzXG4gICAgLy90aGlzIHRha2VzIGFzIGlucHV0IGEgNjQgYml0IGtleSAoZXZlbiB0aG91Z2ggb25seSA1NiBiaXRzIGFyZSB1c2VkKVxuICAgIC8vYXMgYW4gYXJyYXkgb2YgMiBpbnRlZ2VycywgYW5kIHJldHVybnMgMTYgNDggYml0IGtleXNcbiAgICBmdW5jdGlvbiBkZXNfY3JlYXRlS2V5cyAoa2V5KVxuICAgIHtcbiAgICAgIGxldCBkZXNQQyA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1BDO1xuXG4gICAgICBpZiAoICFkZXNQQyApXG4gICAgICB7XG4gICAgICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgICAgIGRlc1BDID0gREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzUEMgPSB7XG4gICAgICAgICAgcGMyYnl0ZXMwIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MjAwMDAwMDAsMHgyMDAwMDAwNCwweDEwMDAwLDB4MTAwMDQsMHgyMDAxMDAwMCwweDIwMDEwMDA0LDB4MjAwLDB4MjA0LDB4MjAwMDAyMDAsMHgyMDAwMDIwNCwweDEwMjAwLDB4MTAyMDQsMHgyMDAxMDIwMCwweDIwMDEwMjA0IF0gKSxcbiAgICAgICAgICBwYzJieXRlczEgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEsMHgxMDAwMDAsMHgxMDAwMDEsMHg0MDAwMDAwLDB4NDAwMDAwMSwweDQxMDAwMDAsMHg0MTAwMDAxLDB4MTAwLDB4MTAxLDB4MTAwMTAwLDB4MTAwMTAxLDB4NDAwMDEwMCwweDQwMDAxMDEsMHg0MTAwMTAwLDB4NDEwMDEwMV0gKSxcbiAgICAgICAgICBwYzJieXRlczIgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4LDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOF0gKSxcbiAgICAgICAgICBwYzJieXRlczMgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDIwMDAwMCwweDgwMDAwMDAsMHg4MjAwMDAwLDB4MjAwMCwweDIwMjAwMCwweDgwMDIwMDAsMHg4MjAyMDAwLDB4MjAwMDAsMHgyMjAwMDAsMHg4MDIwMDAwLDB4ODIyMDAwMCwweDIyMDAwLDB4MjIyMDAwLDB4ODAyMjAwMCwweDgyMjIwMDBdICksXG4gICAgICAgICAgcGMyYnl0ZXM0IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMF0gKSxcbiAgICAgICAgICBwYzJieXRlczUgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMCwweDIwLDB4NDIwLDAsMHg0MDAsMHgyMCwweDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4MDAwMCwweDEwMDgwMDAwLDB4MiwweDEwMDAwMDAyLDB4ODAwMDIsMHgxMDA4MDAwMiwwLDB4MTAwMDAwMDAsMHg4MDAwMCwweDEwMDgwMDAwLDB4MiwweDEwMDAwMDAyLDB4ODAwMDIsMHgxMDA4MDAwMl0gKSxcbiAgICAgICAgICBwYzJieXRlczcgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwLDB4ODAwLDB4MTA4MDAsMHgyMDAwMDAwMCwweDIwMDEwMDAwLDB4MjAwMDA4MDAsMHgyMDAxMDgwMCwweDIwMDAwLDB4MzAwMDAsMHgyMDgwMCwweDMwODAwLDB4MjAwMjAwMDAsMHgyMDAzMDAwMCwweDIwMDIwODAwLDB4MjAwMzA4MDBdICksXG4gICAgICAgICAgcGMyYnl0ZXM4IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAwMCwwLDB4NDAwMDAsMHgyLDB4NDAwMDIsMHgyLDB4NDAwMDIsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMiwweDIwNDAwMDIsMHgyMDAwMDAyLDB4MjA0MDAwMl0gKSxcbiAgICAgICAgICBwYzJieXRlczkgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAsMCwweDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MjAwMCwweDIwMjAsMHgyMDAwLDB4MjAyMCwweDEwMjAwMCwweDEwMjAyMCwweDEwMjAwMCwweDEwMjAyMF0gKSxcbiAgICAgICAgICBwYzJieXRlczExOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAsMHgyMDAsMHgxMDAwMjAwLDB4MjAwMDAwLDB4MTIwMDAwMCwweDIwMDIwMCwweDEyMDAyMDAsMHg0MDAwMDAwLDB4NTAwMDAwMCwweDQwMDAyMDAsMHg1MDAwMjAwLDB4NDIwMDAwMCwweDUyMDAwMDAsMHg0MjAwMjAwLDB4NTIwMDIwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczEyOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAsMHg4MDAwMDAwLDB4ODAwMTAwMCwweDgwMDAwLDB4ODEwMDAsMHg4MDgwMDAwLDB4ODA4MTAwMCwweDEwLDB4MTAxMCwweDgwMDAwMTAsMHg4MDAxMDEwLDB4ODAwMTAsMHg4MTAxMCwweDgwODAwMTAsMHg4MDgxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTM6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NCwweDEwMCwweDEwNCwwLDB4NCwweDEwMCwweDEwNCwweDEsMHg1LDB4MTAxLDB4MTA1LDB4MSwweDUsMHgxMDEsMHgxMDVdIClcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy9ob3cgbWFueSBpdGVyYXRpb25zICgxIGZvciBkZXMsIDMgZm9yIHRyaXBsZSBkZXMpXG4gICAgICB2YXIgaXRlcmF0aW9ucyA9IGtleS5sZW5ndGggPiA4ID8gMyA6IDE7IC8vY2hhbmdlZCBieSBQYXVsIDE2LzYvMjAwNyB0byB1c2UgVHJpcGxlIERFUyBmb3IgOSsgYnl0ZSBrZXlzXG4gICAgICAvL3N0b3JlcyB0aGUgcmV0dXJuIGtleXNcbiAgICAgIHZhciBrZXlzID0gbmV3IFVpbnQzMkFycmF5KDMyICogaXRlcmF0aW9ucyk7XG4gICAgICAvL25vdyBkZWZpbmUgdGhlIGxlZnQgc2hpZnRzIHdoaWNoIG5lZWQgdG8gYmUgZG9uZVxuICAgICAgdmFyIHNoaWZ0cyA9IFsgMCwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCBdO1xuICAgICAgLy9vdGhlciB2YXJpYWJsZXNcbiAgICAgIHZhciBsZWZ0dGVtcCwgcmlnaHR0ZW1wLCBtPTAsIG49MCwgdGVtcDtcblxuICAgICAgZm9yICh2YXIgaj0wOyBqPGl0ZXJhdGlvbnM7IGorKylcbiAgICAgIHsgLy9laXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcbiAgICAgICAgbGVmdCA9ICAoa2V5W20rK10gPDwgMjQpIHwgKGtleVttKytdIDw8IDE2KSB8IChrZXlbbSsrXSA8PCA4KSB8IGtleVttKytdO1xuICAgICAgICByaWdodCA9IChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG5cbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAyKSBeIHJpZ2h0KSAmIDB4MzMzMzMzMzM7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMik7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAgICAgLy90aGUgcmlnaHQgc2lkZSBuZWVkcyB0byBiZSBzaGlmdGVkIGFuZCB0byBnZXQgdGhlIGxhc3QgZm91ciBiaXRzIG9mIHRoZSBsZWZ0IHNpZGVcbiAgICAgICAgdGVtcCA9IChsZWZ0IDw8IDgpIHwgKChyaWdodCA+Pj4gMjApICYgMHgwMDAwMDBmMCk7XG4gICAgICAgIC8vbGVmdCBuZWVkcyB0byBiZSBwdXQgdXBzaWRlIGRvd25cbiAgICAgICAgbGVmdCA9IChyaWdodCA8PCAyNCkgfCAoKHJpZ2h0IDw8IDgpICYgMHhmZjAwMDApIHwgKChyaWdodCA+Pj4gOCkgJiAweGZmMDApIHwgKChyaWdodCA+Pj4gMjQpICYgMHhmMCk7XG4gICAgICAgIHJpZ2h0ID0gdGVtcDtcblxuICAgICAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZXNlIHNoaWZ0cyBvbiB0aGUgbGVmdCBhbmQgcmlnaHQga2V5c1xuICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCBzaGlmdHMubGVuZ3RoOyBpKyspXG4gICAgICAgIHtcbiAgICAgICAgICAvL3NoaWZ0IHRoZSBrZXlzIGVpdGhlciBvbmUgb3IgdHdvIGJpdHMgdG8gdGhlIGxlZnRcbiAgICAgICAgICBpZiAoc2hpZnRzW2ldKVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAyKSB8IChsZWZ0ID4+PiAyNik7IHJpZ2h0ID0gKHJpZ2h0IDw8IDIpIHwgKHJpZ2h0ID4+PiAyNik7XG4gICAgICAgICAgfVxuICAgICAgICAgIGVsc2VcbiAgICAgICAgICB7XG4gICAgICAgICAgICBsZWZ0ID0gKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMjcpOyByaWdodCA9IChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMjcpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBsZWZ0ICY9IC0weGY7IHJpZ2h0ICY9IC0weGY7XG5cbiAgICAgICAgICAvL25vdyBhcHBseSBQQy0yLCBpbiBzdWNoIGEgd2F5IHRoYXQgRSBpcyBlYXNpZXIgd2hlbiBlbmNyeXB0aW5nIG9yIGRlY3J5cHRpbmdcbiAgICAgICAgICAvL3RoaXMgY29udmVyc2lvbiB3aWxsIGxvb2sgbGlrZSBQQy0yIGV4Y2VwdCBvbmx5IHRoZSBsYXN0IDYgYml0cyBvZiBlYWNoIGJ5dGUgYXJlIHVzZWRcbiAgICAgICAgICAvL3JhdGhlciB0aGFuIDQ4IGNvbnNlY3V0aXZlIGJpdHMgYW5kIHRoZSBvcmRlciBvZiBsaW5lcyB3aWxsIGJlIGFjY29yZGluZyB0b1xuICAgICAgICAgIC8vaG93IHRoZSBTIHNlbGVjdGlvbiBmdW5jdGlvbnMgd2lsbCBiZSBhcHBsaWVkOiBTMiwgUzQsIFM2LCBTOCwgUzEsIFMzLCBTNSwgUzdcbiAgICAgICAgICBsZWZ0dGVtcCA9IGRlc1BDLnBjMmJ5dGVzMFtsZWZ0ID4+PiAyOF0gfCBkZXNQQy5wYzJieXRlczFbKGxlZnQgPj4+IDI0KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzMlsobGVmdCA+Pj4gMjApICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzM1sobGVmdCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXM0WyhsZWZ0ID4+PiAxMikgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXM1WyhsZWZ0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzNlsobGVmdCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHJpZ2h0dGVtcCA9IGRlc1BDLnBjMmJ5dGVzN1tyaWdodCA+Pj4gMjhdIHwgZGVzUEMucGMyYnl0ZXM4WyhyaWdodCA+Pj4gMjQpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzOVsocmlnaHQgPj4+IDIwKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczEwWyhyaWdodCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzMTFbKHJpZ2h0ID4+PiAxMikgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXMxMlsocmlnaHQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzMTNbKHJpZ2h0ID4+PiA0KSAmIDB4Zl07XG4gICAgICAgICAgdGVtcCA9ICgocmlnaHR0ZW1wID4+PiAxNikgXiBsZWZ0dGVtcCkgJiAweDAwMDBmZmZmO1xuICAgICAgICAgIGtleXNbbisrXSA9IGxlZnR0ZW1wIF4gdGVtcDsga2V5c1tuKytdID0gcmlnaHR0ZW1wIF4gKHRlbXAgPDwgMTYpO1xuICAgICAgICB9XG4gICAgICB9IC8vZm9yIGVhY2ggaXRlcmF0aW9uc1xuXG4gICAgICByZXR1cm4ga2V5cztcbiAgICB9IC8vZW5kIG9mIGRlc19jcmVhdGVLZXlzXG5cbiAgICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICAgIGxldCBkZXNTUCA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1NQO1xuXG4gICAgaWYgKCBkZXNTUCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIGRlc1NQID0gREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzU1AgPSB7XG4gICAgICAgIHNwZnVuY3Rpb24xOiBuZXcgVWludDMyQXJyYXkoIFsweDEwMTA0MDAsMCwweDEwMDAwLDB4MTAxMDQwNCwweDEwMTAwMDQsMHgxMDQwNCwweDQsMHgxMDAwMCwweDQwMCwweDEwMTA0MDAsMHgxMDEwNDA0LDB4NDAwLDB4MTAwMDQwNCwweDEwMTAwMDQsMHgxMDAwMDAwLDB4NCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDB4MTA0MDAsMHgxMDQwMCwweDEwMTAwMDAsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDA0LDB4MTAwMDAwNCwweDEwMDAwMDQsMHgxMDAwNCwwLDB4NDA0LDB4MTA0MDQsMHgxMDAwMDAwLDB4MTAwMDAsMHgxMDEwNDA0LDB4NCwweDEwMTAwMDAsMHgxMDEwNDAwLDB4MTAwMDAwMCwweDEwMDAwMDAsMHg0MDAsMHgxMDEwMDA0LDB4MTAwMDAsMHgxMDQwMCwweDEwMDAwMDQsMHg0MDAsMHg0LDB4MTAwMDQwNCwweDEwNDA0LDB4MTAxMDQwNCwweDEwMDA0LDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwMDA0LDB4NDA0LDB4MTA0MDQsMHgxMDEwNDAwLDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMCwweDEwMDA0LDB4MTA0MDAsMCwweDEwMTAwMDRdICksXG4gICAgICAgIHNwZnVuY3Rpb24yOiBuZXcgVWludDMyQXJyYXkoIFstMHg3ZmVmN2ZlMCwtMHg3ZmZmODAwMCwweDgwMDAsMHgxMDgwMjAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwtMHg3ZmZmN2ZlMCwtMHg3ZmZmZmZlMCwtMHg3ZmVmN2ZlMCwtMHg3ZmVmODAwMCwtMHg4MDAwMDAwMCwtMHg3ZmZmODAwMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLDB4MTA4MDAwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLDAsLTB4ODAwMDAwMDAsMHg4MDAwLDB4MTA4MDIwLC0weDdmZjAwMDAwLDB4MTAwMDIwLC0weDdmZmZmZmUwLDAsMHgxMDgwMDAsMHg4MDIwLC0weDdmZWY4MDAwLC0weDdmZjAwMDAwLDB4ODAyMCwwLDB4MTA4MDIwLC0weDdmZWZmZmUwLDB4MTAwMDAwLC0weDdmZmY3ZmUwLC0weDdmZjAwMDAwLC0weDdmZWY4MDAwLDB4ODAwMCwtMHg3ZmYwMDAwMCwtMHg3ZmZmODAwMCwweDIwLC0weDdmZWY3ZmUwLDB4MTA4MDIwLDB4MjAsMHg4MDAwLC0weDgwMDAwMDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwweDEwMDAwMCwtMHg3ZmZmZmZlMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwtMHg3ZmZmZmZlMCwweDEwMDAyMCwweDEwODAwMCwwLC0weDdmZmY4MDAwLDB4ODAyMCwtMHg4MDAwMDAwMCwtMHg3ZmVmZmZlMCwtMHg3ZmVmN2ZlMCwweDEwODAwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjM6IG5ldyBVaW50MzJBcnJheSggWzB4MjA4LDB4ODAyMDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDAsMCwweDIwMjA4LDB4ODAwMDIwMCwweDIwMDA4LDB4ODAwMDAwOCwweDgwMDAwMDgsMHgyMDAwMCwweDgwMjAyMDgsMHgyMDAwOCwweDgwMjAwMDAsMHgyMDgsMHg4MDAwMDAwLDB4OCwweDgwMjAyMDAsMHgyMDAsMHgyMDIwMCwweDgwMjAwMDAsMHg4MDIwMDA4LDB4MjAyMDgsMHg4MDAwMjA4LDB4MjAyMDAsMHgyMDAwMCwweDgwMDAyMDgsMHg4LDB4ODAyMDIwOCwweDIwMCwweDgwMDAwMDAsMHg4MDIwMjAwLDB4ODAwMDAwMCwweDIwMDA4LDB4MjA4LDB4MjAwMDAsMHg4MDIwMjAwLDB4ODAwMDIwMCwwLDB4MjAwLDB4MjAwMDgsMHg4MDIwMjA4LDB4ODAwMDIwMCwweDgwMDAwMDgsMHgyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjA4LDB4MjAwMDAsMHg4MDAwMDAwLDB4ODAyMDIwOCwweDgsMHgyMDIwOCwweDIwMjAwLDB4ODAwMDAwOCwweDgwMjAwMDAsMHg4MDAwMjA4LDB4MjA4LDB4ODAyMDAwMCwweDIwMjA4LDB4OCwweDgwMjAwMDgsMHgyMDIwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjQ6IG5ldyBVaW50MzJBcnJheSggWzB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MCwweDgwMDA4MSwweDgwMDAwMSwweDIwMDEsMCwweDgwMjAwMCwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMHg4MDAwODAsMHg4MDAwMDEsMHgxLDB4MjAwMCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMSwweDIwODAsMHg4MDAwODEsMHgxLDB4MjA4MCwweDgwMDA4MCwweDIwMDAsMHg4MDIwODAsMHg4MDIwODEsMHg4MSwweDgwMDA4MCwweDgwMDAwMSwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMCwweDgwMjAwMCwweDIwODAsMHg4MDAwODAsMHg4MDAwODEsMHgxLDB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MSwweDgxLDB4MSwweDIwMDAsMHg4MDAwMDEsMHgyMDAxLDB4ODAyMDgwLDB4ODAwMDgxLDB4MjAwMSwweDIwODAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDAsMHg4MDIwODBdICksXG4gICAgICAgIHNwZnVuY3Rpb241OiBuZXcgVWludDMyQXJyYXkoIFsweDEwMCwweDIwODAxMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg4MDAwMCwweDEwMCwweDQwMDAwMDAwLDB4MjA4MDAwMCwweDQwMDgwMTAwLDB4ODAwMDAsMHgyMDAwMTAwLDB4NDAwODAxMDAsMHg0MjAwMDEwMCwweDQyMDgwMDAwLDB4ODAxMDAsMHg0MDAwMDAwMCwweDIwMDAwMDAsMHg0MDA4MDAwMCwweDQwMDgwMDAwLDAsMHg0MDAwMDEwMCwweDQyMDgwMTAwLDB4NDIwODAxMDAsMHgyMDAwMTAwLDB4NDIwODAwMDAsMHg0MDAwMDEwMCwwLDB4NDIwMDAwMDAsMHgyMDgwMTAwLDB4MjAwMDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHg4MDAwMCwweDQyMDAwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQwMDAwMDAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4NDAwODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAwMDAsMHg0MjA4MDAwMCwweDIwODAxMDAsMHg0MDA4MDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MjA4MDAwMCwweDQyMDgwMTAwLDB4ODAxMDAsMHg0MjAwMDAwMCwweDQyMDgwMTAwLDB4MjA4MDAwMCwwLDB4NDAwODAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMTAwLDB4ODAwMDAsMCwweDQwMDgwMDAwLDB4MjA4MDEwMCwweDQwMDAwMTAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNjogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDAwMDAxMCwweDIwNDAwMDAwLDB4NDAwMCwweDIwNDA0MDEwLDB4MjA0MDAwMDAsMHgxMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHg0MDQwMTAsMHg0MDAwMDAsMHgyMDAwMDAxMCwweDQwMDAxMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwweDQwMDAsMHg0MDQwMDAsMHgyMDAwNDAxMCwweDEwLDB4MjA0MDAwMTAsMHgyMDQwMDAxMCwwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMHg0MDEwLDB4NDA0MDAwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDIwMDA0MDAwLDB4MTAsMHgyMDQwMDAxMCwweDQwNDAwMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDIwNDA0MDEwLDB4NDA0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwwLDB4MjA0MDAwMTAsMHgxMCwweDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDQwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDQwMDAxMCwweDIwMDA0MDEwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDAwMDAsMHg0MjAwMDAyLDB4NDAwMDgwMiwwLDB4ODAwLDB4NDAwMDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg0MjAwODAyLDB4MjAwMDAwLDAsMHg0MDAwMDAyLDB4MiwweDQwMDAwMDAsMHg0MjAwMDAyLDB4ODAyLDB4NDAwMDgwMCwweDIwMDgwMiwweDIwMDAwMiwweDQwMDA4MDAsMHg0MDAwMDAyLDB4NDIwMDAwMCwweDQyMDA4MDAsMHgyMDAwMDIsMHg0MjAwMDAwLDB4ODAwLDB4ODAyLDB4NDIwMDgwMiwweDIwMDgwMCwweDIsMHg0MDAwMDAwLDB4MjAwODAwLDB4NDAwMDAwMCwweDIwMDgwMCwweDIwMDAwMCwweDQwMDA4MDIsMHg0MDAwODAyLDB4NDIwMDAwMiwweDQyMDAwMDIsMHgyLDB4MjAwMDAyLDB4NDAwMDAwMCwweDQwMDA4MDAsMHgyMDAwMDAsMHg0MjAwODAwLDB4ODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDgwMiwweDQwMDAwMDIsMHg0MjAwODAyLDB4NDIwMDAwMCwweDIwMDgwMCwwLDB4MiwweDQyMDA4MDIsMCwweDIwMDgwMiwweDQyMDAwMDAsMHg4MDAsMHg0MDAwMDAyLDB4NDAwMDgwMCwweDgwMCwweDIwMDAwMl0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjg6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwMDEwNDAsMHgxMDAwLDB4NDAwMDAsMHgxMDA0MTA0MCwweDEwMDAwMDAwLDB4MTAwMDEwNDAsMHg0MCwweDEwMDAwMDAwLDB4NDAwNDAsMHgxMDA0MDAwMCwweDEwMDQxMDQwLDB4NDEwMDAsMHgxMDA0MTAwMCwweDQxMDQwLDB4MTAwMCwweDQwLDB4MTAwNDAwMDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4MTA0MCwweDQxMDAwLDB4NDAwNDAsMHgxMDA0MDA0MCwweDEwMDQxMDAwLDB4MTA0MCwwLDAsMHgxMDA0MDA0MCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHg0MTA0MCwweDQwMDAwLDB4NDEwNDAsMHg0MDAwMCwweDEwMDQxMDAwLDB4MTAwMCwweDQwLDB4MTAwNDAwNDAsMHgxMDAwLDB4NDEwNDAsMHgxMDAwMTAwMCwweDQwLDB4MTAwMDAwNDAsMHgxMDA0MDAwMCwweDEwMDQwMDQwLDB4MTAwMDAwMDAsMHg0MDAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQwMDQwLDB4MTAwMDAwNDAsMHgxMDA0MDAwMCwweDEwMDAxMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDEwMDAsMHg0MTAwMCwweDEwNDAsMHgxMDQwLDB4NDAwNDAsMHgxMDAwMDAwMCwweDEwMDQxMDAwXSApLFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvL2NyZWF0ZSB0aGUgMTYgb3IgNDggc3Via2V5cyB3ZSB3aWxsIG5lZWRcbiAgICB2YXIga2V5cyA9IGRlc19jcmVhdGVLZXlzKCBrZXkgKTtcblxuICAgIHZhciBtPTAsIGksIGosIHRlbXAsIGxlZnQsIHJpZ2h0LCBsb29waW5nO1xuICAgIHZhciBjYmNsZWZ0LCBjYmNsZWZ0MiwgY2JjcmlnaHQsIGNiY3JpZ2h0MlxuICAgIHZhciBsZW4gPSBtZXNzYWdlLmxlbmd0aDtcblxuICAgIC8vc2V0IHVwIHRoZSBsb29wcyBmb3Igc2luZ2xlIGFuZCB0cmlwbGUgZGVzXG4gICAgdmFyIGl0ZXJhdGlvbnMgPSBrZXlzLmxlbmd0aCA9PSAzMiA/IDMgOiA5OyAvL3NpbmdsZSBvciB0cmlwbGUgZGVzXG5cbiAgICBpZiAoaXRlcmF0aW9ucyA9PSAzKVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiBdIDogWyAzMCwgLTIsIC0yIF07XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICBsb29waW5nID0gZW5jcnlwdCA/IFsgMCwgMzIsIDIsIDYyLCAzMCwgLTIsIDY0LCA5NiwgMiBdIDogWyA5NCwgNjIsIC0yLCAzMiwgNjQsIDIsIDMwLCAtMiwgLTIgXTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIG1lc3NhZ2UgZGVwZW5kaW5nIG9uIHRoZSBwYWRkaW5nIHBhcmFtZXRlclxuICAgIGlmICggKCBwYWRkaW5nICE9IHVuZGVmaW5lZCApICYmICggcGFkZGluZyAhPSA0ICkgKVxuICAgIHtcbiAgICAgIHZhciB1bnBhZGRlZE1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgdmFyIHBhZCA9IDgtKGxlbiU4KTtcblxuICAgICAgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KCBsZW4gKyA4ICk7XG4gICAgICBtZXNzYWdlLnNldCggdW5wYWRkZWRNZXNzYWdlLCAwICk7XG5cbiAgICAgIHN3aXRjaCggcGFkZGluZyApXG4gICAgICB7XG4gICAgICAgIGNhc2UgMDogLy8gemVyby1wYWRcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdICksIGxlbiApO1xuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgIGNhc2UgMTogLy8gUEtDUzcgcGFkZGluZ1xuICAgICAgICB7XG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkXSApLCA4ICk7XG5cbiAgICAgICAgICBpZiAoIHBhZD09OCApXG4gICAgICAgICAgICBsZW4rPTg7XG5cbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuXG4gICAgICAgIGNhc2UgMjogIC8vIHBhZCB0aGUgbWVzc2FnZSB3aXRoIHNwYWNlc1xuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwIF0gKSwgOCApO1xuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICB9XG5cbiAgICAgIGxlbiArPSA4LShsZW4lOClcbiAgICB9XG5cbiAgICAvLyBzdG9yZSB0aGUgcmVzdWx0IGhlcmVcbiAgICB2YXIgcmVzdWx0ID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiApO1xuXG4gICAgaWYgKG1vZGUgPT0gMSlcbiAgICB7IC8vQ0JDIG1vZGVcbiAgICAgIHZhciBtID0gMDtcblxuICAgICAgY2JjbGVmdCA9ICAoaXZbbSsrXSA8PCAyNCkgfCAoaXZbbSsrXSA8PCAxNikgfCAoaXZbbSsrXSA8PCA4KSB8IGl2W20rK107XG4gICAgICBjYmNyaWdodCA9IChpdlttKytdIDw8IDI0KSB8IChpdlttKytdIDw8IDE2KSB8IChpdlttKytdIDw8IDgpIHwgaXZbbSsrXTtcbiAgICB9XG5cbiAgICB2YXIgcm0gPSAwO1xuXG4gICAgLy9sb29wIHRocm91Z2ggZWFjaCA2NCBiaXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICB3aGlsZSAobSA8IGxlbilcbiAgICB7XG4gICAgICBsZWZ0ID0gIChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuICAgICAgcmlnaHQgPSAobWVzc2FnZVttKytdIDw8IDI0KSB8IChtZXNzYWdlW20rK10gPDwgMTYpIHwgKG1lc3NhZ2VbbSsrXSA8PCA4KSB8IG1lc3NhZ2VbbSsrXTtcblxuICAgICAgLy9mb3IgQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUsIHhvciB0aGUgbWVzc2FnZSB3aXRoIHRoZSBwcmV2aW91cyByZXN1bHRcbiAgICAgIGlmIChtb2RlID09IDEpXG4gICAgICB7XG4gICAgICAgIGlmIChlbmNyeXB0KVxuICAgICAgICB7XG4gICAgICAgICAgbGVmdCBePSBjYmNsZWZ0OyByaWdodCBePSBjYmNyaWdodDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0MiA9IGNiY2xlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQyID0gY2JjcmlnaHQ7XG4gICAgICAgICAgY2JjbGVmdCA9IGxlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQgPSByaWdodDtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvL2ZpcnN0IGVhY2ggNjQgYnV0IGNodW5rIG9mIHRoZSBtZXNzYWdlIG11c3QgYmUgcGVybXV0ZWQgYWNjb3JkaW5nIHRvIElQXG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxNikgXiByaWdodCkgJiAweDAwMDBmZmZmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDE2KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgbGVmdCA9ICgobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAzMSkpO1xuXG4gICAgICAvL2RvIHRoaXMgZWl0aGVyIDEgb3IgMyB0aW1lcyBmb3IgZWFjaCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgICAgZm9yIChqPTA7IGo8aXRlcmF0aW9uczsgais9MylcbiAgICAgIHtcbiAgICAgICAgdmFyIGVuZGxvb3AgPSBsb29waW5nW2orMV07XG4gICAgICAgIHZhciBsb29waW5jID0gbG9vcGluZ1tqKzJdO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlIGVuY3J5cHRpb24gb3IgZGVjcnlwdGlvblxuICAgICAgICBmb3IgKGk9bG9vcGluZ1tqXTsgaSE9ZW5kbG9vcDsgaSs9bG9vcGluYylcbiAgICAgICAgeyAvL2ZvciBlZmZpY2llbmN5XG4gICAgICAgICAgdmFyIHJpZ2h0MSA9IHJpZ2h0IF4ga2V5c1tpXTtcbiAgICAgICAgICB2YXIgcmlnaHQyID0gKChyaWdodCA+Pj4gNCkgfCAocmlnaHQgPDwgMjgpKSBeIGtleXNbaSsxXTtcblxuICAgICAgICAgIC8vdGhlIHJlc3VsdCBpcyBhdHRhaW5lZCBieSBwYXNzaW5nIHRoZXNlIGJ5dGVzIHRocm91Z2ggdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9uc1xuICAgICAgICAgIHRlbXAgPSBsZWZ0O1xuICAgICAgICAgIGxlZnQgPSByaWdodDtcbiAgICAgICAgICByaWdodCA9IHRlbXAgXiAoZGVzU1Auc3BmdW5jdGlvbjJbKHJpZ2h0MSA+Pj4gMjQpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uNFsocmlnaHQxID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBkZXNTUC5zcGZ1bmN0aW9uNlsocmlnaHQxID4+PiAgOCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb244W3JpZ2h0MSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IGRlc1NQLnNwZnVuY3Rpb24xWyhyaWdodDIgPj4+IDI0KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjNbKHJpZ2h0MiA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgZGVzU1Auc3BmdW5jdGlvbjVbKHJpZ2h0MiA+Pj4gIDgpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uN1tyaWdodDIgJiAweDNmXSk7XG4gICAgICAgIH1cblxuICAgICAgICB0ZW1wID0gbGVmdDsgbGVmdCA9IHJpZ2h0OyByaWdodCA9IHRlbXA7IC8vdW5yZXZlcnNlIGxlZnQgYW5kIHJpZ2h0XG4gICAgICB9IC8vZm9yIGVpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuXG4gICAgICAvL21vdmUgdGhlbiBlYWNoIG9uZSBiaXQgdG8gdGhlIHJpZ2h0XG4gICAgICBsZWZ0ID0gKChsZWZ0ID4+PiAxKSB8IChsZWZ0IDw8IDMxKSk7XG4gICAgICByaWdodCA9ICgocmlnaHQgPj4+IDEpIHwgKHJpZ2h0IDw8IDMxKSk7XG5cbiAgICAgIC8vbm93IHBlcmZvcm0gSVAtMSwgd2hpY2ggaXMgSVAgaW4gdGhlIG9wcG9zaXRlIGRpcmVjdGlvblxuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMTYpIF4gcmlnaHQpICYgMHgwMDAwZmZmZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxNik7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG5cbiAgICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgICBpZiAobW9kZSA9PSAxKVxuICAgICAge1xuICAgICAgICBpZiAoZW5jcnlwdClcbiAgICAgICAge1xuICAgICAgICAgIGNiY2xlZnQgPSBsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0ID0gcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICB7XG4gICAgICAgICAgbGVmdCBePSBjYmNsZWZ0MjtcbiAgICAgICAgICByaWdodCBePSBjYmNyaWdodDI7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmVzdWx0LnNldCggbmV3IFVpbnQ4QXJyYXkgKCBbIChsZWZ0Pj4+MjQpICYgMHhmZiwgKGxlZnQ+Pj4xNikgJiAweGZmLCAobGVmdD4+PjgpICYgMHhmZiwgKGxlZnQpICYgMHhmZiwgKHJpZ2h0Pj4+MjQpICYgMHhmZiwgKHJpZ2h0Pj4+MTYpICYgMHhmZiwgKHJpZ2h0Pj4+OCkgJiAweGZmLCAocmlnaHQpICYgMHhmZiBdICksIHJtICk7XG5cbiAgICAgIHJtICs9IDg7XG4gICAgfSAvL2ZvciBldmVyeSA4IGNoYXJhY3RlcnMsIG9yIDY0IGJpdHMgaW4gdGhlIG1lc3NhZ2VcblxuICAgIHJldHVybiByZXN1bHQ7XG4gIH0gLy9lbmQgb2YgZGVzXG5cbn1cblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdERVMtRUNCJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkVOQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uREVDUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5JTVBPUlRfS0VZLCBdICk7XG4iLG51bGwsImltcG9ydCB7IENvbnRhaW5lciwgYXV0b2luamVjdCBhcyBpbmplY3QgfSBmcm9tICdhdXJlbGlhLWRlcGVuZGVuY3ktaW5qZWN0aW9uJztcbmltcG9ydCB7IG1ldGFkYXRhIH0gZnJvbSAnYXVyZWxpYS1tZXRhZGF0YSc7XG5cbmV4cG9ydCB7IENvbnRhaW5lciwgaW5qZWN0IH07XG5leHBvcnQgaW50ZXJmYWNlIEluamVjdGFibGUge1xuICBuZXcoIC4uLmFyZ3MgKTogT2JqZWN0O1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi9ieXRlLWFycmF5JztcblxuZXhwb3J0IGNsYXNzIEVudW0ge1xufVxuXG5leHBvcnQgY2xhc3MgSW50ZWdlciBleHRlbmRzIE51bWJlciB7XG59XG5cbi8qKlxuICogU2V0IG9mIGRhdGEgdHlwZXMgdGhhdCBhcmUgdmFsaWQgYXMgS2luZCBmaWVsZHNcbiAqIGluY2x1ZGVzIEZpZWxkVHlwZUFycmF5IGtsdWRnZSByZXF1aXJlZCBmb3IgVFMgdG8gcGFyc2UgcmVjdXJzaXZlXG4gKiB0eXBlIGRlZmluaXRpb25zXG4gKi9cblxuZXhwb3J0IGludGVyZmFjZSBGaWVsZEFycmF5IGV4dGVuZHMgQXJyYXk8RmllbGRUeXBlPiB7fVxuZXhwb3J0IHR5cGUgRmllbGRUeXBlID0gU3RyaW5nIHwgTnVtYmVyIHwgSW50ZWdlciB8IEVudW0gfCBCeXRlQXJyYXkgfCBLaW5kIHwgRmllbGRBcnJheTtcblxuZXhwb3J0IGNsYXNzIEZpZWxkQXJyYXkgaW1wbGVtZW50cyBGaWVsZEFycmF5IHt9XG5cbmV4cG9ydCB2YXIgRmllbGRUeXBlcyA9IHtcbiAgQm9vbGVhbjogQm9vbGVhbixcblxuICBOdW1iZXI6IE51bWJlcixcblxuICBJbnRlZ2VyOiBJbnRlZ2VyLFxuXG4gIEJ5dGVBcnJheTogQnl0ZUFycmF5LFxuXG4gIEVudW06IEVudW0sXG5cbiAgQXJyYXk6IEZpZWxkQXJyYXksXG5cbiAgU3RyaW5nOiBTdHJpbmcsXG5cbiAgS2luZDogS2luZFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkT3B0aW9ucyB7XG4gIC8qKlxuICAqIG1pbmltdW0gbGVuZ3RoIGZvciBTdHJpbmcsIG1pbmltdW0gdmFsdWUgZm9yIE51bWJlci9JbnRlZ2VyXG4gICovXG4gIG1pbmltdW0/OiBudW1iZXI7XG5cbiAgLyoqXG4gICogbWF4aW11bSBsZW5ndGggZm9yIFN0cmluZywgbWF4aW11bSB2YWx1ZSBmb3IgTnVtYmVyL0ludGVnZXJcbiAgKi9cbiAgbWF4aW11bT86IG51bWJlcjtcblxuICAvKipcbiAgKiBkZWZhdWx0IHZhbHVlIGR1cmluZyBpbml0aWFsaXphdGlvblxuICAqL1xuICBcImRlZmF1bHRcIj86IGFueTtcblxuICAvKipcbiAgKiBkb2VzIG5vdCBleGlzdCBhcyBhbiBvd25Qcm9wZXJ0eVxuICAqL1xuICBjYWxjdWxhdGVkPzogYm9vbGVhbjtcblxuICAvKipcbiAgKiBzdWIta2luZCwgd2hlbiBmaWVsZCBpcyB0eXBlIEtpbmRcbiAgKi9cbiAga2luZD86IEtpbmQ7XG5cbiAgLyoqXG4gICogc3ViLWZpZWxkIGluZm8sIHdoZW4gZmllbGQgaXMgdHlwZSBGaWVsZEFycmF5XG4gICovXG4gIGFycmF5SW5mbz86IEZpZWxkSW5mbztcblxuICAvKipcbiAgKiBpbmRleC92YWx1ZSBtYXAsIHdoZW4gZmllbGQgaWYgdHlwZSBFbnVtXG4gICovXG4gIGVudW1NYXA/OiBNYXA8bnVtYmVyLCBzdHJpbmc+O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkSW5mbyBleHRlbmRzIEZpZWxkT3B0aW9ucyB7XG4gIC8qKlxuICAqIERlc2NyaXB0aW9uIGZvciBmaWVsZFxuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIFR5cGUgb2YgZmllbGQsIG9uZSBvZiBGaWVsZFR5cGVzXG4gICovXG4gIGZpZWxkVHlwZTogRmllbGRUeXBlO1xufVxuXG5cbi8qKlxuKiBNZXRhZGF0YSBhYm91dCBhIEtpbmQuIENvbnRhaW5zIG5hbWUsIGRlc2NyaXB0aW9uIGFuZCBhIG1hcCBvZlxuKiBwcm9wZXJ0eS1kZXNjcmlwdG9ycyB0aGF0IGRlc2NyaWJlIHRoZSBzZXJpYWxpemFibGUgZmllbGRzIG9mXG4qIGFuIG9iamVjdCBvZiB0aGF0IEtpbmQuXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRJbmZvXG57XG4gIG5hbWU6IHN0cmluZztcblxuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIGZpZWxkczogeyBbaWQ6IHN0cmluZ106IEZpZWxkSW5mbyB9ID0ge307XG59XG5cbi8qKlxuKiBCdWlsZGVyIGZvciAnS2luZCcgbWV0YWRhdGFcbiovXG5leHBvcnQgY2xhc3MgS2luZEJ1aWxkZXJcbntcbiAgcHJpdmF0ZSBjdG9yOiBLaW5kQ29uc3RydWN0b3I7XG5cbiAgY29uc3RydWN0b3IoIGN0b3I6IEtpbmRDb25zdHJ1Y3RvciwgZGVzY3JpcHRpb246IHN0cmluZyApIHtcbiAgICB0aGlzLmN0b3IgPSBjdG9yO1xuXG4gICAgY3Rvci5raW5kSW5mbyA9IHtcbiAgICAgIG5hbWU6IGN0b3IubmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIGZpZWxkczoge31cbiAgICB9XG4gIH1cblxuXG4gIHByaXZhdGUga2luZEluZm86IEtpbmRJbmZvO1xuXG4gIHB1YmxpYyBzdGF0aWMgaW5pdCggY3RvcjogS2luZENvbnN0cnVjdG9yLCBkZXNjcmlwdGlvbjogc3RyaW5nICk6IEtpbmRCdWlsZGVyXG4gIHtcbiAgICBsZXQgYnVpbGRlciA9IG5ldyBLaW5kQnVpbGRlciggY3RvciwgZGVzY3JpcHRpb24gKTtcblxuICAgIHJldHVybiBidWlsZGVyO1xuICB9XG5cbiAgcHVibGljIGZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGZpZWxkVHlwZTogRmllbGRUeXBlLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlclxuICB7XG4gICAgbGV0IGZpZWxkOiBGaWVsZEluZm8gPSA8RmllbGRJbmZvPm9wdHM7XG5cbiAgICBmaWVsZC5kZXNjcmlwdGlvbiA9IGRlc2NyaXB0aW9uO1xuICAgIGZpZWxkLmZpZWxkVHlwZSA9IGZpZWxkVHlwZTtcblxuICAgIHRoaXMuY3Rvci5raW5kSW5mby5maWVsZHNbIG5hbWUgXSA9IGZpZWxkO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgYm9vbEZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEJvb2xlYW4sIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBudW1iZXJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBOdW1iZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBpbnRlZ2VyRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgSW50ZWdlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIHVpbnQzMkZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLm1pbmltdW0gPSBvcHRzLm1pbmltdW0gfHwgMDtcbiAgICBvcHRzLm1heGltdW0gPSBvcHRzLm1heGltdW0gfHwgMHhGRkZGRkZGRjtcblxuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgSW50ZWdlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGJ5dGVGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgb3B0cy5taW5pbXVtID0gb3B0cy5taW5pbXVtIHx8IDA7XG4gICAgb3B0cy5tYXhpbXVtID0gb3B0cy5tYXhpbXVtIHx8IDI1NTtcblxuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgSW50ZWdlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIHN0cmluZ0ZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIFN0cmluZywgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGtpbmRGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBraW5kOiBLaW5kLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgb3B0cy5raW5kID0ga2luZDtcblxuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgS2luZCwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGVudW1GaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBlbnVtbTogeyBbIGlkeDogbnVtYmVyIF06IHN0cmluZyB9LCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG5cbiAgICBvcHRzLmVudW1NYXAgPSBuZXcgTWFwPG51bWJlcixzdHJpbmc+KCApO1xuXG4gICAgZm9yKCBsZXQgaWR4IGluIGVudW1tICkge1xuICAgICAgaWYgKCAxICogaWR4ID09IGlkeCApXG4gICAgICAgIG9wdHMuZW51bU1hcC5zZXQoIGlkeCwgZW51bW1bIGlkeCBdICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBFbnVtLCBvcHRzICk7XG4gIH1cbn1cblxuLyogIG1ha2VLaW5kKCBraW5kQ29uc3RydWN0b3IsIGtpbmRPcHRpb25zIClcbiAge1xuICAgIHZhciAka2luZEluZm8gPSBraW5kT3B0aW9ucy5raW5kSW5mbztcblxuICAgIGtpbmRDb25zdHJ1Y3Rvci4ka2luZE5hbWUgPSAka2luZEluZm8udGl0bGU7XG5cbiAgICB2YXIga2V5cyA9IE9iamVjdC5rZXlzKCBraW5kT3B0aW9ucy5raW5kTWV0aG9kcyApO1xuXG4gICAgZm9yICggdmFyIGogPSAwLCBqaiA9IGtleXMubGVuZ3RoOyBqIDwgamo7IGorKyApIHtcbiAgICAgIHZhciBrZXkgPSBrZXlzW2pdO1xuICAgICAga2luZENvbnN0cnVjdG9yW2tleV0gPSBraW5kT3B0aW9ucy5raW5kTWV0aG9kc1trZXldO1xuICAgIH1cblxuICAgIGtpbmRDb25zdHJ1Y3Rvci5nZXRLaW5kSW5mbyA9IGtpbmRDb25zdHJ1Y3Rvci5wcm90b3R5cGUuZ2V0S2luZEluZm8gPSBmdW5jdGlvbiBnZXRLaW5kSW5mbygpIHtcbiAgICAgIHJldHVybiAka2luZEluZm87XG4gICAgfVxuXG4gICAgcmV0dXJuIGtpbmRDb25zdHJ1Y3RvcjtcbiAgfVxuKi9cblxuLyoqXG4qIFJlcHJlc2VudHMgYSBzZXJpYWxpemFibGUgYW5kIGluc3BlY3RhYmxlIGRhdGEtdHlwZVxuKiBpbXBsZW1lbnRlZCBhcyBhIGhhc2gtbWFwIGNvbnRhaW5pbmcga2V5LXZhbHVlIHBhaXJzLFxuKiBhbG9uZyB3aXRoIG1ldGFkYXRhIHRoYXQgZGVzY3JpYmVzIGVhY2ggZmllbGQgdXNpbmcgYSBqc29uLXNjaGVtZSBsaWtlXG4qL1xuZXhwb3J0IGludGVyZmFjZSBLaW5kXG57XG59XG5cbmV4cG9ydCBjbGFzcyBLaW5kIGltcGxlbWVudHMgS2luZCB7XG4gIHN0YXRpYyBnZXRLaW5kSW5mbygga2luZDogS2luZCApOiBLaW5kSW5mbyB7XG4gICAgcmV0dXJuICg8S2luZENvbnN0cnVjdG9yPihraW5kLmNvbnN0cnVjdG9yKSkua2luZEluZm87XG4gIH1cblxuICBzdGF0aWMgaW5pdEZpZWxkcygga2luZDogS2luZCwgYXR0cmlidXRlczoge30gPSB7fSAgKSB7XG4gICAgbGV0IGtpbmRJbmZvID0gS2luZC5nZXRLaW5kSW5mbygga2luZCApO1xuXG4gICAgZm9yKCBsZXQgaWQgaW4ga2luZEluZm8uZmllbGRzICkge1xuICAgICAgbGV0IGZpZWxkID0ga2luZEluZm8uZmllbGRzWyBpZCBdO1xuICAgICAgbGV0IGZpZWxkVHlwZSA9IGZpZWxkLmZpZWxkVHlwZTtcblxuLy8gICAgICBjb25zb2xlLmxvZyggaWQgKyAnOicgKyBmaWVsZFR5cGUgKTtcbi8vICAgICAgY29uc29sZS5sb2coIGtpbmQuaGFzT3duUHJvcGVydHkoaWQpICApO1xuXG4gICAgICBsZXQgdmFsOiBhbnk7XG5cbiAgICAgIGlmICggIWZpZWxkLmNhbGN1bGF0ZWQgKSB7XG4gICAgICAgIC8vIHdlIG9ubHkgc2V0ICdub24nLWNhbGN1bGF0ZWQgZmllbGQsIHNpbmNlIGNhbGN1bGF0ZWQgZmllbGQgaGF2ZVxuICAgICAgICAvLyBubyBzZXR0ZXJcblxuICAgICAgICAvLyBnb3QgYSB2YWx1ZSBmb3IgdGhpcyBmaWVsZCA/XG4gICAgICAgIGlmICggYXR0cmlidXRlc1sgaWQgXSApXG4gICAgICAgICAgdmFsID0gYXR0cmlidXRlc1sgaWQgXTtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkLmRlZmF1bHQgIT0gdW5kZWZpbmVkIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5kZWZhdWx0O1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IFN0cmluZyApXG4gICAgICAgICAgdmFsID0gJyc7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gTnVtYmVyIClcbiAgICAgICAgICB2YWwgPSAwO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEludGVnZXIgKVxuICAgICAgICAgIHZhbCA9IGZpZWxkLm1pbmltdW0gfHwgMDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBCb29sZWFuIClcbiAgICAgICAgICB2YWwgPSBmYWxzZTtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBCeXRlQXJyYXkgKVxuICAgICAgICAgIHZhbCA9IG5ldyBCeXRlQXJyYXkoKTtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBFbnVtIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5lbnVtTWFwLmtleXNbMF07XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gS2luZCApIHtcbiAgICAgICAgICBsZXQgeHggPSAoPEtpbmQ+ZmllbGRUeXBlKS5jb25zdHJ1Y3RvcjtcbiAgICAgICAgICB2YWwgPSBPYmplY3QuY3JlYXRlKCB4eCApO1xuICAgICAgICB9XG5cbiAgICAgICAga2luZFsgaWQgXSA9IHZhbDtcblxuLy8gICAgICAgIGNvbnNvbGUubG9nKCBraW5kW2lkXSApO1xuICAgICAgfVxuICAgIH1cbiAgfVxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEtpbmRDb25zdHJ1Y3Rvclxue1xuICBuZXcgKCAuLi5hcmdzICk6IEtpbmQ7XG5cbiAga2luZEluZm8/OiBLaW5kSW5mbztcbn1cbiIsImltcG9ydCB7IEtpbmQgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuL2VuZC1wb2ludCc7XG5cbi8qXG4qIE1lc3NhZ2UgSGVhZGVyXG4qL1xuZXhwb3J0IGludGVyZmFjZSBNZXNzYWdlSGVhZGVyXG57XG4gIC8qXG4gICogTWVzc2FnZSBOYW1lLCBpbmRpY2F0ZXMgYSBjb21tYW5kIC8gbWV0aG9kIC8gcmVzcG9uc2UgdG8gZXhlY3V0ZVxuICAqL1xuICBtZXRob2Q/OiBzdHJpbmc7XG5cbiAgLypcbiAgKiBNZXNzYWdlIElkZW50aWZpZXIgKHVuaXF1ZSkgZm9yIGVhY2ggc2VudCBtZXNzYWdlIChvciBDTUQtUkVTUCBwYWlyKVxuICAqL1xuICBpZD86IG51bWJlcjtcblxuXG4gIC8qXG4gICogRGVzY3JpcHRpb24sIHVzZWZ1bCBmb3IgdHJhY2luZyBhbmQgbG9nZ2luZ1xuICAqL1xuICBkZXNjcmlwdGlvbj86IHN0cmluZztcblxuICAvKlxuICAqIEZvciBDTUQvUkVTUCBzdHlsZSBwcm90b2NvbHMsIGluZGljYXRlcyB0aGF0IG1lc3NhZ2UgZGlzcGF0Y2hlZFxuICAqIGluIHJlc3BvbnNlIHRvIGEgcHJldmlvdXMgY29tbWFuZFxuICAqL1xuICBpc1Jlc3BvbnNlPzogYm9vbGVhbjtcblxuICAvKlxuICAqIEVuZFBvaW50IHRoYXQgb3JpZ2luYXRlZCB0aGUgbWVzc2FnZVxuICAqL1xuICBvcmlnaW4/OiBFbmRQb2ludDtcblxuXG4gIC8qXG4gICogSW5kaWNhdGVzIHRoZSBLaW5kIG9mIGRhdGEgKHdoZW4gc2VyaWFsaXplZClcbiAgKi9cbiAga2luZE5hbWU/OiBzdHJpbmc7XG59XG5cbi8qXG4qIEEgVHlwZWQgTWVzc2FnZSwgd2l0aCBoZWFkZXIgYW5kIHBheWxvYWRcbiovXG5leHBvcnQgY2xhc3MgTWVzc2FnZTxUPlxue1xuICBwcml2YXRlIF9oZWFkZXI6IE1lc3NhZ2VIZWFkZXI7XG4gIHByaXZhdGUgX3BheWxvYWQ6IFQ7XG5cbiAgY29uc3RydWN0b3IoIGhlYWRlcjogTWVzc2FnZUhlYWRlciwgcGF5bG9hZDogVCApXG4gIHtcbiAgICB0aGlzLl9oZWFkZXIgPSBoZWFkZXIgfHwge307XG4gICAgdGhpcy5fcGF5bG9hZCA9IHBheWxvYWQ7XG4gIH1cblxuICBnZXQgaGVhZGVyKCk6IE1lc3NhZ2VIZWFkZXJcbiAge1xuICAgIHJldHVybiB0aGlzLl9oZWFkZXI7XG4gIH1cblxuICBnZXQgcGF5bG9hZCgpOiBUXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcGF5bG9hZDtcbiAgfVxufVxuXG4vKlxuKiBBIHR5cGVkIE1lc3NhZ2Ugd2hvc2UgcGF5bG9hZCBpcyBhIEtpbmRcbiovXG5leHBvcnQgY2xhc3MgS2luZE1lc3NhZ2U8SyBleHRlbmRzIEtpbmQ+IGV4dGVuZHMgTWVzc2FnZTxLPlxue1xufVxuIiwiZXhwb3J0IHR5cGUgVGFzayA9ICgpID0+IHZvaWQ7XG5leHBvcnQgdHlwZSBGbHVzaEZ1bmMgPSAoKSA9PiB2b2lkO1xudmFyIHdpbmRvdyA9IHdpbmRvdyB8fCB7fTtcblxuZXhwb3J0IGNsYXNzIFRhc2tTY2hlZHVsZXJcbntcbiAgc3RhdGljIG1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlcihmbHVzaCk6IEZsdXNoRnVuY1xuICB7XG4gICAgdmFyIHRvZ2dsZSA9IDE7XG5cbiAgICB2YXIgb2JzZXJ2ZXIgPSBuZXcgVGFza1NjaGVkdWxlci5Ccm93c2VyTXV0YXRpb25PYnNlcnZlcihmbHVzaCk7XG5cbiAgICB2YXIgbm9kZTogT2JqZWN0ID0gZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUoJycpO1xuXG4gICAgb2JzZXJ2ZXIub2JzZXJ2ZShub2RlLCB7IGNoYXJhY3RlckRhdGE6IHRydWUgfSk7XG5cbiAgICByZXR1cm4gZnVuY3Rpb24gcmVxdWVzdEZsdXNoKClcbiAgICB7XG4gICAgICB0b2dnbGUgPSAtdG9nZ2xlO1xuICAgICAgbm9kZVtcImRhdGFcIl0gPSB0b2dnbGU7XG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBtYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyKGZsdXNoKTogRmx1c2hGdW5jXG4gIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gcmVxdWVzdEZsdXNoKCkge1xuICAgICAgdmFyIHRpbWVvdXRIYW5kbGUgPSBzZXRUaW1lb3V0KGhhbmRsZUZsdXNoVGltZXIsIDApO1xuXG4gICAgICB2YXIgaW50ZXJ2YWxIYW5kbGUgPSBzZXRJbnRlcnZhbChoYW5kbGVGbHVzaFRpbWVyLCA1MCk7XG4gICAgICBmdW5jdGlvbiBoYW5kbGVGbHVzaFRpbWVyKClcbiAgICAgIHtcbiAgICAgICAgY2xlYXJUaW1lb3V0KHRpbWVvdXRIYW5kbGUpO1xuICAgICAgICBjbGVhckludGVydmFsKGludGVydmFsSGFuZGxlKTtcbiAgICAgICAgZmx1c2goKTtcbiAgICAgIH1cbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIEJyb3dzZXJNdXRhdGlvbk9ic2VydmVyID0gd2luZG93WyBcIk11dGF0aW9uT2JzZXJ2ZXJcIiBdIHx8IHdpbmRvd1sgXCJXZWJLaXRNdXRhdGlvbk9ic2VydmVyXCJdO1xuICBzdGF0aWMgaGFzU2V0SW1tZWRpYXRlID0gdHlwZW9mIHNldEltbWVkaWF0ZSA9PT0gJ2Z1bmN0aW9uJztcblxuICBzdGF0aWMgdGFza1F1ZXVlQ2FwYWNpdHkgPSAxMDI0O1xuICB0YXNrUXVldWU6IFRhc2tbXTtcblxuICByZXF1ZXN0Rmx1c2hUYXNrUXVldWU6IEZsdXNoRnVuYztcblxuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgICB0aGlzLnRhc2tRdWV1ZSA9IFtdO1xuXG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgaWYgKHR5cGVvZiBUYXNrU2NoZWR1bGVyLkJyb3dzZXJNdXRhdGlvbk9ic2VydmVyID09PSAnZnVuY3Rpb24nKVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlID0gVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIoZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gc2VsZi5mbHVzaFRhc2tRdWV1ZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSA9IFRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lcihmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBzZWxmLmZsdXNoVGFza1F1ZXVlKCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBUYXNrU2NoZWR1bGVyLCBjYW5jZWxsaW5nIGFueSBwZW5kaW5nIGNvbW11bmljYXRpb25zLlxuICAqL1xuICBzaHV0ZG93bigpXG4gIHtcbiAgfVxuXG4gIHF1ZXVlVGFzayggdGFzaylcbiAge1xuICAgIGlmICggdGhpcy50YXNrUXVldWUubGVuZ3RoIDwgMSApXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUoKTtcbiAgICB9XG5cbiAgICB0aGlzLnRhc2tRdWV1ZS5wdXNoKHRhc2spO1xuICB9XG5cbiAgZmx1c2hUYXNrUXVldWUoKVxuICB7XG4gICAgdmFyIHF1ZXVlID0gdGhpcy50YXNrUXVldWUsXG4gICAgICAgIGNhcGFjaXR5ID0gVGFza1NjaGVkdWxlci50YXNrUXVldWVDYXBhY2l0eSxcbiAgICAgICAgaW5kZXggPSAwLFxuICAgICAgICB0YXNrO1xuXG4gICAgd2hpbGUgKGluZGV4IDwgcXVldWUubGVuZ3RoKVxuICAgIHtcbiAgICAgIHRhc2sgPSBxdWV1ZVtpbmRleF07XG5cbiAgICAgIHRyeVxuICAgICAge1xuICAgICAgICB0YXNrLmNhbGwoKTtcbiAgICAgIH1cbiAgICAgIGNhdGNoIChlcnJvcilcbiAgICAgIHtcbiAgICAgICAgdGhpcy5vbkVycm9yKGVycm9yLCB0YXNrKTtcbiAgICAgIH1cblxuICAgICAgaW5kZXgrKztcblxuICAgICAgaWYgKGluZGV4ID4gY2FwYWNpdHkpXG4gICAgICB7XG4gICAgICAgIGZvciAodmFyIHNjYW4gPSAwOyBzY2FuIDwgaW5kZXg7IHNjYW4rKylcbiAgICAgICAge1xuICAgICAgICAgIHF1ZXVlW3NjYW5dID0gcXVldWVbc2NhbiArIGluZGV4XTtcbiAgICAgICAgfVxuXG4gICAgICAgIHF1ZXVlLmxlbmd0aCAtPSBpbmRleDtcbiAgICAgICAgaW5kZXggPSAwO1xuICAgICAgfVxuICAgIH1cblxuICAgIHF1ZXVlLmxlbmd0aCA9IDA7XG4gIH1cblxuICBvbkVycm9yKGVycm9yLCB0YXNrKVxuICB7XG4gICAgaWYgKCdvbkVycm9yJyBpbiB0YXNrKSB7XG4gICAgICB0YXNrLm9uRXJyb3IoZXJyb3IpO1xuICAgIH1cbiAgICBlbHNlIGlmICggVGFza1NjaGVkdWxlci5oYXNTZXRJbW1lZGlhdGUgKVxuICAgIHtcbiAgICAgIHNldEltbWVkaWF0ZShmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9LCAwKTtcbiAgICB9XG4gIH1cbn1cbiIsImltcG9ydCB7IFRhc2tTY2hlZHVsZXIgfSBmcm9tICcuLi9ydW50aW1lL3Rhc2stc2NoZWR1bGVyJztcbmltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcblxuLyoqXG4qIEEgbWVzc2FnZS1wYXNzaW5nIGNoYW5uZWwgYmV0d2VlbiBtdWx0aXBsZSBFbmRQb2ludHNcbipcbiogRW5kUG9pbnRzIG11c3QgZmlyc3QgcmVnaXN0ZXIgd2l0aCB0aGUgQ2hhbm5lbC4gV2hlbmV2ZXIgdGhlIENoYW5uZWwgaXMgaW5cbiogYW4gYWN0aXZlIHN0YXRlLCBjYWxscyB0byBzZW5kTWVzc2FnZSB3aWxsIGZvcndhcmQgdGhlIG1lc3NhZ2UgdG8gYWxsXG4qIHJlZ2lzdGVyZWQgRW5kUG9pbnRzIChleGNlcHQgdGhlIG9yaWdpbmF0b3IgRW5kUG9pbnQpLlxuKi9cbmV4cG9ydCBjbGFzcyBDaGFubmVsXG57XG4gIC8qKlxuICAqIFRydWUgaWYgQ2hhbm5lbCBpcyBhY3RpdmVcbiAgKi9cbiAgcHJpdmF0ZSBfYWN0aXZlOiBib29sZWFuO1xuXG4gIC8qKlxuICAqIEFycmF5IG9mIEVuZFBvaW50cyBhdHRhY2hlZCB0byB0aGlzIENoYW5uZWxcbiAgKi9cbiAgcHJpdmF0ZSBfZW5kUG9pbnRzOiBFbmRQb2ludFtdO1xuXG4gIC8qKlxuICAqIFByaXZhdGUgVGFza1NjaGVkdWxlciB1c2VkIHRvIG1ha2UgbWVzc2FnZS1zZW5kcyBhc3luY2hyb25vdXMuXG4gICovXG4gIHByaXZhdGUgX3Rhc2tTY2hlZHVsZXI6IFRhc2tTY2hlZHVsZXI7XG5cbiAgLyoqXG4gICogQ3JlYXRlIGEgbmV3IENoYW5uZWwsIGluaXRpYWxseSBpbmFjdGl2ZVxuICAqL1xuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcbiAgICB0aGlzLl9lbmRQb2ludHMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIENsZWFudXAgdGhlIENoYW5uZWwsIGRlYWN0aXZhdGUsIHJlbW92ZSBhbGwgRW5kUG9pbnRzIGFuZFxuICAqIGFib3J0IGFueSBwZW5kaW5nIGNvbW11bmljYXRpb25zLlxuICAqL1xuICBwdWJsaWMgc2h1dGRvd24oKVxuICB7XG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG5cbiAgICB0aGlzLl9lbmRQb2ludHMgPSBbXTtcblxuICAgIGlmICggdGhpcy5fdGFza1NjaGVkdWxlciApXG4gICAge1xuICAgICAgdGhpcy5fdGFza1NjaGVkdWxlci5zaHV0ZG93bigpO1xuXG4gICAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gdW5kZWZpbmVkO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIElzIENoYW5uZWwgYWN0aXZlP1xuICAqXG4gICogQHJldHVybnMgdHJ1ZSBpZiBjaGFubmVsIGlzIGFjdGl2ZSwgZmFsc2Ugb3RoZXJ3aXNlXG4gICovXG4gIHB1YmxpYyBnZXQgYWN0aXZlKCk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9hY3RpdmU7XG4gIH1cblxuICAvKipcbiAgKiBBY3RpdmF0ZSB0aGUgQ2hhbm5lbCwgZW5hYmxpbmcgY29tbXVuaWNhdGlvblxuICAqL1xuICBwdWJsaWMgYWN0aXZhdGUoKVxuICB7XG4gICAgdGhpcy5fdGFza1NjaGVkdWxlciA9IG5ldyBUYXNrU2NoZWR1bGVyKCk7XG5cbiAgICB0aGlzLl9hY3RpdmUgPSB0cnVlO1xuICB9XG5cbiAgLyoqXG4gICogRGVhY3RpdmF0ZSB0aGUgQ2hhbm5lbCwgZGlzYWJsaW5nIGFueSBmdXJ0aGVyIGNvbW11bmljYXRpb25cbiAgKi9cbiAgcHVibGljIGRlYWN0aXZhdGUoKVxuICB7XG4gICAgdGhpcy5fdGFza1NjaGVkdWxlciA9IHVuZGVmaW5lZDtcblxuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuICB9XG5cbiAgLyoqXG4gICogUmVnaXN0ZXIgYW4gRW5kUG9pbnQgdG8gc2VuZCBhbmQgcmVjZWl2ZSBtZXNzYWdlcyB2aWEgdGhpcyBDaGFubmVsLlxuICAqXG4gICogQHBhcmFtIGVuZFBvaW50IC0gdGhlIEVuZFBvaW50IHRvIHJlZ2lzdGVyXG4gICovXG4gIHB1YmxpYyBhZGRFbmRQb2ludCggZW5kUG9pbnQ6IEVuZFBvaW50IClcbiAge1xuICAgIHRoaXMuX2VuZFBvaW50cy5wdXNoKCBlbmRQb2ludCApO1xuICB9XG5cbiAgLyoqXG4gICogVW5yZWdpc3RlciBhbiBFbmRQb2ludC5cbiAgKlxuICAqIEBwYXJhbSBlbmRQb2ludCAtIHRoZSBFbmRQb2ludCB0byB1bnJlZ2lzdGVyXG4gICovXG4gIHB1YmxpYyByZW1vdmVFbmRQb2ludCggZW5kUG9pbnQ6IEVuZFBvaW50IClcbiAge1xuICAgIGxldCBpZHggPSB0aGlzLl9lbmRQb2ludHMuaW5kZXhPZiggZW5kUG9pbnQgKTtcblxuICAgIGlmICggaWR4ID49IDAgKVxuICAgIHtcbiAgICAgIHRoaXMuX2VuZFBvaW50cy5zcGxpY2UoIGlkeCwgMSApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIEdldCBFbmRQb2ludHMgcmVnaXN0ZXJlZCB3aXRoIHRoaXMgQ2hhbm5lbFxuICAqXG4gICogQHJldHVybiBBcnJheSBvZiBFbmRQb2ludHNcbiAgKi9cbiAgcHVibGljIGdldCBlbmRQb2ludHMoKTogRW5kUG9pbnRbXVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50cztcbiAgfVxuXG4gIC8qKlxuICAqIFNlbmQgYSBtZXNzYWdlIHRvIGFsbCBsaXN0ZW5lcnMgKGV4Y2VwdCBvcmlnaW4pXG4gICpcbiAgKiBAcGFyYW0gb3JpZ2luIC0gRW5kUG9pbnQgdGhhdCBpcyBzZW5kaW5nIHRoZSBtZXNzYWdlXG4gICogQHBhcmFtIG1lc3NhZ2UgLSBNZXNzYWdlIHRvIGJlIHNlbnRcbiAgKi9cbiAgcHVibGljIHNlbmRNZXNzYWdlKCBvcmlnaW46IEVuZFBvaW50LCBtZXNzYWdlOiBNZXNzYWdlPGFueT4gKVxuICB7XG4gICAgbGV0IGlzUmVzcG9uc2UgPSAoIG1lc3NhZ2UuaGVhZGVyICYmIG1lc3NhZ2UuaGVhZGVyLmlzUmVzcG9uc2UgKTtcblxuICAgIGlmICggIXRoaXMuX2FjdGl2ZSApXG4gICAgICByZXR1cm47XG5cbiAgICBpZiAoIG9yaWdpbi5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLklOICYmICFpc1Jlc3BvbnNlIClcbiAgICAgIHRocm93IG5ldyBFcnJvciggJ1VuYWJsZSB0byBzZW5kIG9uIElOIHBvcnQnKTtcblxuICAgIHRoaXMuX2VuZFBvaW50cy5mb3JFYWNoKCBlbmRQb2ludCA9PiB7XG4gICAgICAvLyBTZW5kIHRvIGFsbCBsaXN0ZW5lcnMsIGV4Y2VwdCBmb3Igb3JpZ2luYXRvciAuLi5cbiAgICAgIGlmICggb3JpZ2luICE9IGVuZFBvaW50IClcbiAgICAgIHtcbiAgICAgICAgLy8gT25seSBzZW5kIHRvIElOIG9yIElOT1VUIGxpc3RlbmVycywgVU5MRVNTIG1lc3NhZ2UgaXMgYVxuICAgICAgICAvLyByZXBseSAoaW4gYSBjbGllbnQtc2VydmVyKSBjb25maWd1cmF0aW9uXG4gICAgICAgIGlmICggZW5kUG9pbnQuZGlyZWN0aW9uICE9IERpcmVjdGlvbi5PVVQgfHwgaXNSZXNwb25zZSApXG4gICAgICAgIHtcbiAgICAgICAgICB0aGlzLl90YXNrU2NoZWR1bGVyLnF1ZXVlVGFzayggKCkgPT4ge1xuICAgICAgICAgICAgZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgb3JpZ2luLCB0aGlzICk7XG4gICAgICAgICAgfSApO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn1cbiIsImltcG9ydCB7IE1lc3NhZ2UgfSBmcm9tICcuL21lc3NhZ2UnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4vY2hhbm5lbCc7XG5cbmV4cG9ydCBlbnVtIERpcmVjdGlvbiB7XG4gIElOID0gMSxcbiAgT1VUID0gMixcbiAgSU5PVVQgPSAzXG59O1xuXG5leHBvcnQgdHlwZSBIYW5kbGVNZXNzYWdlRGVsZWdhdGUgPSAoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiwgcmVjZWl2aW5nRW5kUG9pbnQ/OiBFbmRQb2ludCwgcmVjZWl2aW5nQ2hhbm5lbD86IENoYW5uZWwgKSA9PiB2b2lkO1xuXG4vKipcbiogQW4gRW5kUG9pbnQgaXMgYSBzZW5kZXIvcmVjZWl2ZXIgZm9yIG1lc3NhZ2UtcGFzc2luZy4gSXQgaGFzIGFuIGlkZW50aWZpZXJcbiogYW5kIGFuIG9wdGlvbmFsIGRpcmVjdGlvbiwgd2hpY2ggbWF5IGJlIElOLCBPVVQgb3IgSU4vT1VUIChkZWZhdWx0KS5cbipcbiogRW5kUG9pbnRzIG1heSBoYXZlIG11bHRpcGxlIGNoYW5uZWxzIGF0dGFjaGVkLCBhbmQgd2lsbCBmb3J3YXJkIG1lc3NhZ2VzXG4qIHRvIGFsbCBvZiB0aGVtLlxuKi9cbmV4cG9ydCBjbGFzcyBFbmRQb2ludFxue1xuICBwcm90ZWN0ZWQgX2lkOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogQSBsaXN0IG9mIGF0dGFjaGVkIENoYW5uZWxzXG4gICovXG4gIHByb3RlY3RlZCBfY2hhbm5lbHM6IENoYW5uZWxbXTtcblxuICAvKipcbiAgKiBBIGxpc3Qgb2YgYXR0YWNoZWQgQ2hhbm5lbHNcbiAgKi9cbiAgcHJvdGVjdGVkIF9tZXNzYWdlTGlzdGVuZXJzOiBIYW5kbGVNZXNzYWdlRGVsZWdhdGVbXTtcblxuICBwcml2YXRlIF9kaXJlY3Rpb246IERpcmVjdGlvbjtcblxuICBjb25zdHJ1Y3RvciggaWQ6IHN0cmluZywgZGlyZWN0aW9uOiBEaXJlY3Rpb24gPSBEaXJlY3Rpb24uSU5PVVQgKVxuICB7XG4gICAgdGhpcy5faWQgPSBpZDtcblxuICAgIHRoaXMuX2RpcmVjdGlvbiA9IGRpcmVjdGlvbjtcblxuICAgIHRoaXMuX2NoYW5uZWxzID0gW107XG5cbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzID0gW107XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBFbmRQb2ludCwgZGV0YWNoaW5nIGFueSBhdHRhY2hlZCBDaGFubmVscyBhbmQgcmVtb3ZpbmcgYW55XG4gICogbWVzc2FnZS1saXN0ZW5lcnMuIENhbGxpbmcgc2h1dGRvd24oKSBpcyBtYW5kYXRvcnkgdG8gYXZvaWQgbWVtb3J5LWxlYWtzXG4gICogZHVlIHRvIHRoZSBjaXJjdWxhciByZWZlcmVuY2VzIHRoYXQgZXhpc3QgYmV0d2VlbiBDaGFubmVscyBhbmQgRW5kUG9pbnRzXG4gICovXG4gIHB1YmxpYyBzaHV0ZG93bigpXG4gIHtcbiAgICB0aGlzLmRldGFjaEFsbCgpO1xuXG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgRW5kUG9pbnQncyBpZFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2lkO1xuICB9XG5cbiAgLyoqXG4gICogQXR0YWNoIGEgQ2hhbm5lbCB0byB0aGlzIEVuZFBvaW50LiBPbmNlIGF0dGFjaGVkLCB0aGUgQ2hhbm5lbCB3aWxsIGZvcndhcmRcbiAgKiBtZXNzYWdlcyB0byB0aGlzIEVuZFBvaW50LCBhbmQgd2lsbCBhY2NlcHQgbWVzc2FnZXMgb3JpZ2luYXRlZCBoZXJlLlxuICAqIEFuIEVuZFBvaW50IGNhbiBoYXZlIG11bHRpcGxlIENoYW5uZWxzIGF0dGFjaGVkLCBpbiB3aGljaCBjYXNlIGl0IHdpbGxcbiAgKiBicm9hZGNhc3QgdG8gdGhlbSBhbGwgd2hlbiBzZW5kaW5nLCBhbmQgd2lsbCByZWNlaXZlIG1lc3NhZ2VzIGluXG4gICogYXJyaXZhbC1vcmRlci5cbiAgKi9cbiAgcHVibGljIGF0dGFjaCggY2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5wdXNoKCBjaGFubmVsICk7XG5cbiAgICBjaGFubmVsLmFkZEVuZFBvaW50KCB0aGlzICk7XG4gIH1cblxuICAvKipcbiAgKiBEZXRhY2ggYSBzcGVjaWZpYyBDaGFubmVsIGZyb20gdGhpcyBFbmRQb2ludC5cbiAgKi9cbiAgcHVibGljIGRldGFjaCggY2hhbm5lbFRvRGV0YWNoOiBDaGFubmVsIClcbiAge1xuICAgIGxldCBpZHggPSB0aGlzLl9jaGFubmVscy5pbmRleE9mKCBjaGFubmVsVG9EZXRhY2ggKTtcblxuICAgIGlmICggaWR4ID49IDAgKVxuICAgIHtcbiAgICAgIGNoYW5uZWxUb0RldGFjaC5yZW1vdmVFbmRQb2ludCggdGhpcyApO1xuXG4gICAgICB0aGlzLl9jaGFubmVscy5zcGxpY2UoIGlkeCwgMSApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIERldGFjaCBhbGwgQ2hhbm5lbHMgZnJvbSB0aGlzIEVuZFBvaW50LlxuICAqL1xuICBwdWJsaWMgZGV0YWNoQWxsKClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLmZvckVhY2goIGNoYW5uZWwgPT4ge1xuICAgICAgY2hhbm5lbC5yZW1vdmVFbmRQb2ludCggdGhpcyApO1xuICAgIH0gKTtcblxuICAgIHRoaXMuX2NoYW5uZWxzID0gW107XG4gIH1cblxuICAvKipcbiAgKiBBcmUgYW55IGNoYW5uZWxzIGF0dGFjaGVkIHRvIHRoaXMgRW5kUG9pbnQ/XG4gICpcbiAgKiBAcmV0dXJucyB0cnVlIGlmIEVuZHBvaW50IGlzIGF0dGFjaGVkIHRvIGF0LWxlYXN0LW9uZSBDaGFubmVsXG4gICovXG4gIGdldCBhdHRhY2hlZCgpXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLl9jaGFubmVscy5sZW5ndGggPiAwICk7XG4gIH1cblxuICBnZXQgZGlyZWN0aW9uKCk6IERpcmVjdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2RpcmVjdGlvbjtcbiAgfVxuXG4gIC8qKlxuICAqIEhhbmRsZSBhbiBpbmNvbWluZyBNZXNzYWdlLCBtZXRob2QgY2FsbGVkIGJ5IENoYW5uZWwuXG4gICovXG4gIHB1YmxpYyBoYW5kbGVNZXNzYWdlKCBtZXNzYWdlOiBNZXNzYWdlPGFueT4sIGZyb21FbmRQb2ludDogRW5kUG9pbnQsIGZyb21DaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMuZm9yRWFjaCggbWVzc2FnZUxpc3RlbmVyID0+IHtcbiAgICAgIG1lc3NhZ2VMaXN0ZW5lciggbWVzc2FnZSwgdGhpcywgZnJvbUNoYW5uZWwgKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgKiBTZW5kIGEgTWVzc2FnZS5cbiAgKi9cbiAgcHVibGljIHNlbmRNZXNzYWdlKCBtZXNzYWdlOiBNZXNzYWdlPGFueT4gKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMuZm9yRWFjaCggY2hhbm5lbCA9PiB7XG4gICAgICBjaGFubmVsLnNlbmRNZXNzYWdlKCB0aGlzLCBtZXNzYWdlICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICogUmVnaXN0ZXIgYSBkZWxlZ2F0ZSB0byByZWNlaXZlIGluY29taW5nIE1lc3NhZ2VzXG4gICpcbiAgKiBAcGFyYW0gbWVzc2FnZUxpc3RlbmVyIC0gZGVsZWdhdGUgdG8gYmUgY2FsbGVkIHdpdGggcmVjZWl2ZWQgTWVzc2FnZVxuICAqL1xuICBwdWJsaWMgb25NZXNzYWdlKCBtZXNzYWdlTGlzdGVuZXI6IEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZSApXG4gIHtcbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzLnB1c2goIG1lc3NhZ2VMaXN0ZW5lciApO1xuICB9XG59XG5cbi8qKlxuKiBBbiBpbmRleGVkIGNvbGxlY3Rpb24gb2YgRW5kUG9pbnQgb2JqZWN0cywgbm9ybWFsbHkgaW5kZXhlZCB2aWEgRW5kUG9pbnQnc1xuKiB1bmlxdWUgaWRlbnRpZmllclxuKi9cbmV4cG9ydCB0eXBlIEVuZFBvaW50Q29sbGVjdGlvbiA9IHsgW2lkOiBzdHJpbmddOiBFbmRQb2ludDsgfTtcbiIsImltcG9ydCB7IE1lc3NhZ2UgfSBmcm9tICcuL21lc3NhZ2UnO1xuaW1wb3J0IHsgS2luZCwgS2luZEluZm8gfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuXG5leHBvcnQgZW51bSBQcm90b2NvbFR5cGVCaXRzXG57XG4gIFBBQ0tFVCA9IDAsICAgICAgICAgLyoqIERhdGFncmFtLW9yaWVudGVkIChhbHdheXMgY29ubmVjdGVkLi4uKSAqL1xuICBTVFJFQU0gPSAxLCAgICAgICAgIC8qKiBDb25uZWN0aW9uLW9yaWVudGVkICovXG5cbiAgT05FV0FZID0gMCwgICAgICAgICAvKiogVW5pZGlyZWN0aW9uYWwgT1VUIChzb3VyY2UpIC0+IElOIChzaW5rKSAqL1xuICBDTElFTlRTRVJWRVIgPSA0LCAgIC8qKiBDb21tYW5kIE9VVC0+SU4sIFJlc3BvbnNlIElOLT5PVVQgKi9cbiAgUEVFUjJQRUVSID0gNiwgICAgICAvKiogQmlkaXJlY3Rpb25hbDogSU5PVVQgPC0+IElOT1VUICovXG5cbiAgVU5UWVBFRCA9IDAsICAgICAgICAvKiogVW50eXBlZCBkYXRhICovXG4gIFRZUEVEID0gOCwgICAgICAgICAgLyoqIFR5cGVkIGRhdGEgKiovXG59XG5cbmV4cG9ydCB0eXBlIFByb3RvY29sVHlwZSA9IG51bWJlcjtcblxuZXhwb3J0IGNsYXNzIFByb3RvY29sPFQ+XG57XG4gIHN0YXRpYyBwcm90b2NvbFR5cGU6IFByb3RvY29sVHlwZSA9IDA7XG59XG5cbi8qKlxuKiBBIENsaWVudC1TZXJ2ZXIgUHJvdG9jb2wsIHRvIGJlIHVzZWQgYmV0d2VlblxuKi9cbmNsYXNzIENsaWVudFNlcnZlclByb3RvY29sPFQ+IGV4dGVuZHMgUHJvdG9jb2w8VD5cbntcbiAgc3RhdGljIHByb3RvY29sVHlwZTogUHJvdG9jb2xUeXBlID0gUHJvdG9jb2xUeXBlQml0cy5DTElFTlRTRVJWRVIgfCBQcm90b2NvbFR5cGVCaXRzLlRZUEVEO1xufVxuXG5jbGFzcyBBUERVIGltcGxlbWVudHMgS2luZCB7XG4gIGtpbmRJbmZvOiBLaW5kSW5mbztcbiAgcHJvcGVydGllcztcbn1cblxuY2xhc3MgQVBEVU1lc3NhZ2UgZXh0ZW5kcyBNZXNzYWdlPEFQRFU+XG57XG59XG5cbmNsYXNzIEFQRFVQcm90b2NvbCBleHRlbmRzIENsaWVudFNlcnZlclByb3RvY29sPEFQRFVNZXNzYWdlPlxue1xuXG59XG4iLCJpbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24sIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuXG4vKipcbiogQGNsYXNzIFBvcnRJbmZvXG4qXG4qIE1ldGFkYXRhIGFib3V0IGEgY29tcG9uZW50J3MgUG9ydFxuKi9cbmV4cG9ydCBjbGFzcyBQb3J0SW5mb1xue1xuICAvKipcbiAgKiBCcmllZiBkZXNjcmlwdGlvbiBmb3IgdGhlIHBvcnQsIHRvIGFwcGVhciBpbiAnaGludCdcbiAgKi9cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICAvKipcbiAgKiBEaXJlY3Rpb246IElOLCBPVVQsIG9yIElOT1VUXG4gICogICBmb3IgY2xpZW50LXNlcnZlciwgT1VUPUNsaWVudCwgSU49U2VydmVyXG4gICovXG4gIGRpcmVjdGlvbjogRGlyZWN0aW9uO1xuXG4gIC8qKlxuICAqIFByb3RvY29sIGltcGxlbWVudGVkIGJ5IHRoZSBwb3J0XG4gICovXG4gIHByb3RvY29sOiBQcm90b2NvbDxhbnk+O1xuXG4gIC8qKlxuICAqIFJGVSAtIGluZGV4YWJsZSBwb3J0c1xuICAqL1xuICBjb3VudDogbnVtYmVyID0gMDtcblxuICAvKipcbiAgKiB0cnVlIGlzIHBvcnQgbXVzdCBiZSBjb25uZWN0ZWQgZm9yIGNvbXBvbmVudCB0byBleGVjdXRlXG4gICovXG4gIHJlcXVpcmVkOiBib29sZWFuID0gZmFsc2U7XG59XG4iLCJpbXBvcnQgeyBLaW5kLCBLaW5kQ29uc3RydWN0b3IgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5cbi8qKlxuKiBAY2xhc3MgQ29tcG9uZW50SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIENvbXBvbmVudFxuKi9cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRJbmZvXG57XG4gIC8qKlxuICAqIENvbXBvbmVudCBOYW1lXG4gICovXG4gIG5hbWU6IHN0cmluZztcblxuICAvKipcbiAgKiBCcmllZiBkZXNjcmlwdGlvbiBmb3IgdGhlIGNvbXBvbmVudCwgdG8gYXBwZWFyIGluICdoaW50J1xuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIExpbmsgdG8gZGV0YWlsZWQgaW5mb3JtYXRpb24gZm9yIHRoZSBjb21wb25lbnRcbiAgKi9cbiAgZGV0YWlsTGluazogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQ2F0ZWdvcnkgbmFtZSBmb3IgdGhlIGNvbXBvbmVudCwgZ3JvdXBzIHNhbWUgY2F0ZWdvcmllcyB0b2dldGhlclxuICAqL1xuICBjYXRlZ29yeTogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQXV0aG9yJ3MgbmFtZVxuICAqL1xuICBhdXRob3I6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIEFycmF5IG9mIFBvcnQgZGVzY3JpcHRvcnMuIFdoZW4gYWN0aXZlLCB0aGUgY29tcG9uZW50IHdpbGwgY29tbXVuaWNhdGVcbiAgKiB0aHJvdWdoIGNvcnJlc3BvbmRpbmcgRW5kUG9pbnRzXG4gICovXG4gIHBvcnRzOiB7IFtpZDogc3RyaW5nXTogUG9ydEluZm8gfSA9IHt9O1xuICBzdG9yZXM6IHsgW2lkOiBzdHJpbmddOiBQb3J0SW5mbyB9ID0ge307XG5cbiAgLyoqXG4gICpcbiAgKi9cbiAgY29uZmlnS2luZDogS2luZENvbnN0cnVjdG9yO1xuICBkZWZhdWx0Q29uZmlnOiBLaW5kO1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICB9XG59XG4iLCJcbi8qKlxuKiBNZXRhZGF0YSBhYm91dCBhIGNvbXBvbmVudCdzIFN0b3JlXG4qIFRPRE86IFxuKi9cbmV4cG9ydCBjbGFzcyBTdG9yZUluZm9cbntcbn1cbiIsImltcG9ydCB7IFBvcnRJbmZvIH0gZnJvbSAnLi9wb3J0LWluZm8nO1xuaW1wb3J0IHsgU3RvcmVJbmZvIH0gZnJvbSAnLi9zdG9yZS1pbmZvJztcbmltcG9ydCB7IENvbXBvbmVudEluZm8gfSBmcm9tICcuL2NvbXBvbmVudC1pbmZvJztcbmltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcbmltcG9ydCB7IEtpbmQsIEtpbmRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5cbi8qKlxuKiBCdWlsZGVyIGZvciAnQ29tcG9uZW50JyBtZXRhZGF0YSAoc3RhdGljIGNvbXBvbmVudEluZm8pXG4qL1xuZXhwb3J0IGNsYXNzIENvbXBvbmVudEJ1aWxkZXJcbntcbiAgcHJpdmF0ZSBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvcjtcblxuICBjb25zdHJ1Y3RvciggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IsIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgY2F0ZWdvcnk/OiBzdHJpbmcgKSB7XG5cbiAgICB0aGlzLmN0b3IgPSBjdG9yO1xuXG4gICAgY3Rvci5jb21wb25lbnRJbmZvID0ge1xuICAgICAgbmFtZTogbmFtZSB8fCBjdG9yLm5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24sXG4gICAgICBkZXRhaWxMaW5rOiAnJyxcbiAgICAgIGNhdGVnb3J5OiBjYXRlZ29yeSxcbiAgICAgIGF1dGhvcjogJycsXG4gICAgICBwb3J0czoge30sXG4gICAgICBzdG9yZXM6IHt9LFxuICAgICAgY29uZmlnS2luZDogS2luZCxcbiAgICAgIGRlZmF1bHRDb25maWc6IHt9XG4gICAgfTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgaW5pdCggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IsIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgY2F0ZWdvcnk/OiBzdHJpbmcgKTogQ29tcG9uZW50QnVpbGRlclxuICB7XG4gICAgbGV0IGJ1aWxkZXIgPSBuZXcgQ29tcG9uZW50QnVpbGRlciggY3RvciwgbmFtZSwgZGVzY3JpcHRpb24sIGNhdGVnb3J5ICk7XG5cbiAgICByZXR1cm4gYnVpbGRlcjtcbiAgfVxuXG4gIHB1YmxpYyBjb25maWcoIGNvbmZpZ0tpbmQ6IEtpbmRDb25zdHJ1Y3RvciwgZGVmYXVsdENvbmZpZz86IEtpbmQgKTogdGhpcyB7XG5cbiAgICB0aGlzLmN0b3IuY29tcG9uZW50SW5mby5jb25maWdLaW5kID0gY29uZmlnS2luZDtcbiAgICB0aGlzLmN0b3IuY29tcG9uZW50SW5mby5kZWZhdWx0Q29uZmlnID0gZGVmYXVsdENvbmZpZztcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgcHVibGljIHBvcnQoIGlkOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGRpcmVjdGlvbjogRGlyZWN0aW9uLCBvcHRzPzogeyBwcm90b2NvbD86IFByb3RvY29sPGFueT47IGNvdW50PzogbnVtYmVyOyByZXF1aXJlZD86IGJvb2xlYW4gfSApOiB0aGlzXG4gIHtcbiAgICBvcHRzID0gb3B0cyB8fCB7fTtcblxuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLnBvcnRzWyBpZCBdID0ge1xuICAgICAgZGlyZWN0aW9uOiBkaXJlY3Rpb24sXG4gICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24sXG4gICAgICBwcm90b2NvbDogb3B0cy5wcm90b2NvbCxcbiAgICAgIGNvdW50OiBvcHRzLmNvdW50LFxuICAgICAgcmVxdWlyZWQ6IG9wdHMucmVxdWlyZWRcbiAgICB9O1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbn1cblxuLyoqXG4qIENvbXBvbmVudHMgYXJlIHJ1bnRpbWUgb2JqZWN0cyB0aGF0IGV4ZWN1dGUgd2l0aGluIGEgR3JhcGguXG4qXG4qIEEgZ3JhcGggTm9kZSBpcyBhIHBsYWNlaG9sZGVyIGZvciB0aGUgYWN0dWFsIENvbXBvbmVudCB0aGF0XG4qIHdpbGwgZXhlY3V0ZS5cbipcbiogVGhpcyBpbnRlcmZhY2UgZGVmaW5lcyB0aGUgc3RhbmRhcmQgbWV0aG9kcyBhbmQgcHJvcGVydGllcyB0aGF0IGEgQ29tcG9uZW50XG4qIGNhbiBvcHRpb25hbGx5IGltcGxlbWVudC5cbiovXG5leHBvcnQgaW50ZXJmYWNlIENvbXBvbmVudFxue1xuICAvLyBJbml0aWFsaXphdGlvbiBhbmQgc2h1dGRvd25cbiAgaW5pdGlhbGl6ZT8oIGNvbmZpZz86IEtpbmQgKTogRW5kUG9pbnRbXTtcbiAgdGVhcmRvd24/KCk7XG5cbiAgLy8gUnVubmluZ1xuICBzdGFydD8oKTtcbiAgc3RvcD8oKTtcblxuICAvLyBQYXVzaW5nIGFuZCBjb250aW51aW5nIGV4ZWN1dGlvbiAod2l0aG91dCByZXNldHRpbmcgLi4pXG4gIHBhdXNlPygpO1xuICByZXN1bWU/KCk7XG5cbiAgYmluZFZpZXc/KCB2aWV3OiBhbnkgKTtcbiAgdW5iaW5kVmlldz8oKTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDb21wb25lbnRDb25zdHJ1Y3Rvclxue1xuICBuZXcgKCAuLi5hcmdzICk6IENvbXBvbmVudDtcblxuICBjb21wb25lbnRJbmZvPzogQ29tcG9uZW50SW5mbztcbn1cbiIsImltcG9ydCB7IEV2ZW50QWdncmVnYXRvciwgU3Vic2NyaXB0aW9uLCBIYW5kbGVyIGFzIEV2ZW50SGFuZGxlciB9IGZyb20gJ2F1cmVsaWEtZXZlbnQtYWdncmVnYXRvcic7XG5cbi8vZXhwb3J0IHsgRXZlbnRIYW5kbGVyIH07XG5cbmV4cG9ydCBjbGFzcyBFdmVudEh1Ylxue1xuICBfZXZlbnRBZ2dyZWdhdG9yOiBFdmVudEFnZ3JlZ2F0b3I7XG5cbiAgY29uc3RydWN0b3IoIClcbiAge1xuICAgIHRoaXMuX2V2ZW50QWdncmVnYXRvciA9IG5ldyBFdmVudEFnZ3JlZ2F0b3IoKTtcbiAgfVxuXG4gIHB1YmxpYyBwdWJsaXNoKCBldmVudDogc3RyaW5nLCBkYXRhPzogYW55IClcbiAge1xuICAgIHRoaXMuX2V2ZW50QWdncmVnYXRvci5wdWJsaXNoKCBldmVudCwgZGF0YSApO1xuICB9XG5cbiAgcHVibGljIHN1YnNjcmliZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZSggZXZlbnQsIGhhbmRsZXIgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmVPbmNlKCBldmVudDogc3RyaW5nLCBoYW5kbGVyOiBGdW5jdGlvbiApOiBTdWJzY3JpcHRpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9ldmVudEFnZ3JlZ2F0b3Iuc3Vic2NyaWJlT25jZSggZXZlbnQsIGhhbmRsZXIgKTtcbiAgfVxufVxuXG4vKmZ1bmN0aW9uIGV2ZW50SHViKCk6IGFueSB7XG4gIHJldHVybiBmdW5jdGlvbiBldmVudEh1YjxURnVuY3Rpb24gZXh0ZW5kcyBGdW5jdGlvbiwgRXZlbnRIdWI+KHRhcmdldDogVEZ1bmN0aW9uKTogVEZ1bmN0aW9uIHtcblxuICAgIHRhcmdldC5wcm90b3R5cGUuc3Vic2NyaWJlID0gbmV3Q29uc3RydWN0b3IucHJvdG90eXBlID0gT2JqZWN0LmNyZWF0ZSh0YXJnZXQucHJvdG90eXBlKTtcbiAgICBuZXdDb25zdHJ1Y3Rvci5wcm90b3R5cGUuY29uc3RydWN0b3IgPSB0YXJnZXQ7XG5cbiAgICByZXR1cm4gPGFueT4gbmV3Q29uc3RydWN0b3I7XG4gIH1cbn1cblxuQGV2ZW50SHViKClcbmNsYXNzIE15Q2xhc3Mge307XG4qL1xuIiwiaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuXG4vKipcbiogQSBQb3J0IGlzIGEgcGxhY2Vob2xkZXIgZm9yIGFuIEVuZFBvaW50IHB1Ymxpc2hlZCBieSB0aGUgdW5kZXJseWluZ1xuKiBjb21wb25lbnQgb2YgYSBOb2RlLlxuKi9cbmV4cG9ydCBjbGFzcyBQb3J0XG57XG4gIHByb3RlY3RlZCBfb3duZXI6IE5vZGU7XG4gIHByb3RlY3RlZCBfcHJvdG9jb2xJRDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfZW5kUG9pbnQ6IEVuZFBvaW50O1xuXG4gIHB1YmxpYyBtZXRhZGF0YTogYW55O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogTm9kZSwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICAvLyBXYXMgYW4gRW5kUG9pbnQgc3VwcGxpZWQ/XG4gICAgaWYgKCAhZW5kUG9pbnQgKVxuICAgIHtcbiAgICAgIGxldCBkaXJlY3Rpb24gPSBhdHRyaWJ1dGVzLmRpcmVjdGlvbiB8fCBEaXJlY3Rpb24uSU5PVVQ7XG5cbiAgICAgIGlmICggdHlwZW9mIGF0dHJpYnV0ZXMuZGlyZWN0aW9uID09IFwic3RyaW5nXCIgKVxuICAgICAgICBkaXJlY3Rpb24gPSBEaXJlY3Rpb25bIGRpcmVjdGlvbi50b1VwcGVyQ2FzZSgpIF07XG5cbiAgICAgIC8vIENyZWF0ZSBhIFwiZHVtbXlcIiBlbmRQb2ludCB3aXRoIGNvcnJlY3QgaWQgKyBkaXJlY3Rpb25cbiAgICAgIGVuZFBvaW50ID0gbmV3IEVuZFBvaW50KCBhdHRyaWJ1dGVzLmlkLCBkaXJlY3Rpb24gKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2VuZFBvaW50ID0gZW5kUG9pbnQ7XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gYXR0cmlidXRlc1sgJ3Byb3RvY29sJyBdIHx8ICdhbnknO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB4OiAxMDAsIHk6IDEwMCB9O1xuICB9XG5cbiAgcHVibGljIGdldCBlbmRQb2ludCgpIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQ7XG4gIH1cbiAgcHVibGljIHNldCBlbmRQb2ludCggZW5kUG9pbnQ6IEVuZFBvaW50ICkge1xuICAgIHRoaXMuX2VuZFBvaW50ID0gZW5kUG9pbnQ7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIFBPSk8gZm9yIHNlcmlhbGl6YXRpb25cbiAgICovXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIHBvcnQgPSB7XG4gICAgICBpZDogdGhpcy5fZW5kUG9pbnQuaWQsXG4gICAgICBkaXJlY3Rpb246IHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbixcbiAgICAgIHByb3RvY29sOiAoIHRoaXMuX3Byb3RvY29sSUQgIT0gJ2FueScgKSA/IHRoaXMuX3Byb3RvY29sSUQgOiB1bmRlZmluZWQsXG4gICAgICBtZXRhZGF0YTogdGhpcy5tZXRhZGF0YSxcbiAgICB9O1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3Mgb3duZXJcbiAgICovXG4gIGdldCBvd25lcigpOiBOb2RlIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXJcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBwcm90b2NvbCBJRFxuICAgKi9cbiAgZ2V0IHByb3RvY29sSUQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcHJvdG9jb2xJRDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBJRFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50LmlkO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIEVuZFBvaW50IERpcmVjdGlvblxuICAgKi9cbiAgZ2V0IGRpcmVjdGlvbigpOiBEaXJlY3Rpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb247XG4gIH1cblxufVxuXG5leHBvcnQgY2xhc3MgUHVibGljUG9ydCBleHRlbmRzIFBvcnRcbntcbiAgcHJveHlFbmRQb2ludDogRW5kUG9pbnQ7XG4gIHByb3h5Q2hhbm5lbDogQ2hhbm5lbDtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBlbmRQb2ludDogRW5kUG9pbnQsIGF0dHJpYnV0ZXM6IHt9IClcbiAge1xuICAgIHN1cGVyKCBvd25lciwgZW5kUG9pbnQsIGF0dHJpYnV0ZXMgKTtcblxuICAgIGxldCBwcm94eURpcmVjdGlvbiA9XG4gICAgICAoIHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uSU4gKVxuICAgICAgICA/IERpcmVjdGlvbi5PVVRcbiAgICAgICAgOiAoIHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uT1VUIClcbiAgICAgICAgICA/IERpcmVjdGlvbi5JTlxuICAgICAgICAgIDogRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgLy8gQ3JlYXRlIGFuIEVuZFBvaW50IHRvIHByb3h5IGJldHdlZW4gdGhlIFB1YmxpYyBhbmQgUHJpdmF0ZSAoaW50ZXJuYWwpXG4gICAgLy8gc2lkZXMgb2YgdGhlIFBvcnQuXG4gICAgdGhpcy5wcm94eUVuZFBvaW50ID0gbmV3IEVuZFBvaW50KCB0aGlzLl9lbmRQb2ludC5pZCwgcHJveHlEaXJlY3Rpb24gKTtcblxuICAgIC8vIFdpcmUtdXAgcHJveHkgLVxuXG4gICAgLy8gRm9yd2FyZCBpbmNvbWluZyBwYWNrZXRzIChmcm9tIHB1YmxpYyBpbnRlcmZhY2UpIHRvIHByaXZhdGVcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQub25NZXNzYWdlKCAoIG1lc3NhZ2UgKSA9PiB7XG4gICAgICB0aGlzLl9lbmRQb2ludC5oYW5kbGVNZXNzYWdlKCBtZXNzYWdlLCB0aGlzLnByb3h5RW5kUG9pbnQsIHRoaXMucHJveHlDaGFubmVsICk7XG4gICAgfSk7XG5cbiAgICAvLyBGb3J3YXJkIG91dGdvaW5nIHBhY2tldHMgKGZyb20gcHJpdmF0ZSBpbnRlcmZhY2UpIHRvIHB1YmxpY1xuICAgIHRoaXMuX2VuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5wcm94eUVuZFBvaW50LnNlbmRNZXNzYWdlKCBtZXNzYWdlICk7XG4gICAgfSk7XG5cbiAgICAvLyBub3QgeWV0IGNvbm5lY3RlZFxuICAgIHRoaXMucHJveHlDaGFubmVsID0gbnVsbDtcbiAgfVxuXG4gIC8vIENvbm5lY3QgdG8gUHJpdmF0ZSAoaW50ZXJuYWwpIEVuZFBvaW50LiBUbyBiZSBjYWxsZWQgZHVyaW5nIGdyYXBoXG4gIC8vIHdpcmVVcCBwaGFzZVxuICBwdWJsaWMgY29ubmVjdFByaXZhdGUoIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5wcm94eUNoYW5uZWwgPSBjaGFubmVsO1xuXG4gICAgdGhpcy5wcm94eUVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICB9XG5cbiAgcHVibGljIGRpc2Nvbm5lY3RQcml2YXRlKClcbiAge1xuICAgIHRoaXMucHJveHlFbmRQb2ludC5kZXRhY2goIHRoaXMucHJveHlDaGFubmVsICk7XG4gIH1cblxuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0gc3VwZXIudG9PYmplY3QoIG9wdHMgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG59XG4iLCJpbXBvcnQgeyBSdW50aW1lQ29udGV4dCB9IGZyb20gJy4uL3J1bnRpbWUvcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IFBvcnQgfSBmcm9tICcuL3BvcnQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcblxuZXhwb3J0IGNsYXNzIE5vZGUgZXh0ZW5kcyBFdmVudEh1Ylxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBHcmFwaDtcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfY29tcG9uZW50OiBzdHJpbmc7XG4gIHByb3RlY3RlZCBfaW5pdGlhbERhdGE6IE9iamVjdDtcblxuICBwcm90ZWN0ZWQgX3BvcnRzOiBNYXA8c3RyaW5nLCBQb3J0PjtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICAvKipcbiAgICogUnVudGltZSBhbmQgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgICovXG4gIHByb3RlY3RlZCBfY29udGV4dDogUnVudGltZUNvbnRleHQ7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5faWQgPSBhdHRyaWJ1dGVzLmlkIHx8ICcnO1xuICAgIHRoaXMuX2NvbXBvbmVudCA9IGF0dHJpYnV0ZXMuY29tcG9uZW50O1xuICAgIHRoaXMuX2luaXRpYWxEYXRhID0gYXR0cmlidXRlcy5pbml0aWFsRGF0YSB8fCB7fTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IH07XG5cbiAgICAvLyBJbml0aWFsbHkgY3JlYXRlICdwbGFjZWhvbGRlcicgcG9ydHMuIE9uY2UgY29tcG9uZW50IGhhcyBiZWVuXG4gICAgLy8gbG9hZGVkIGFuZCBpbnN0YW50aWF0ZWQsIHRoZXkgd2lsbCBiZSBjb25uZWN0ZWQgY29ubmVjdGVkIHRvXG4gICAgLy8gdGhlIGNvbXBvbmVudCdzIGNvbW11bmljYXRpb24gZW5kLXBvaW50c1xuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLnBvcnRzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZFBsYWNlaG9sZGVyUG9ydCggaWQsIGF0dHJpYnV0ZXMucG9ydHNbIGlkIF0gKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIFBPSk8gZm9yIHNlcmlhbGl6YXRpb25cbiAgICovXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIG5vZGUgPSB7XG4gICAgICBpZDogdGhpcy5pZCxcbiAgICAgIGNvbXBvbmVudDogdGhpcy5fY29tcG9uZW50LFxuICAgICAgaW5pdGlhbERhdGE6IHRoaXMuX2luaXRpYWxEYXRhLFxuICAgICAgcG9ydHM6IHt9LFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGFcbiAgICB9O1xuXG4gICAgdGhpcy5fcG9ydHMuZm9yRWFjaCggKCBwb3J0LCBpZCApID0+IHtcbiAgICAgIG5vZGUucG9ydHNbIGlkIF0gPSBwb3J0LnRvT2JqZWN0KCk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBOb2RlJ3Mgb3duZXJcbiAgICovXG4gIHB1YmxpYyBnZXQgb3duZXIoKTogR3JhcGgge1xuICAgIHJldHVybiB0aGlzLl9vd25lclxuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIGlkXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cbiAgLyoqXG4gICAqIFNldCB0aGUgTm9kZSdzIGlkXG4gICAqIEBwYXJhbSBpZCAtIG5ldyBpZGVudGlmaWVyXG4gICAqL1xuICBzZXQgaWQoIGlkOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIHB1YmxpYyB1cGRhdGVQb3J0cyggZW5kUG9pbnRzOiBFbmRQb2ludFtdICkge1xuICAgIGxldCBjdXJyZW50UG9ydHMgPSB0aGlzLl9wb3J0cztcbiAgICBsZXQgbmV3UG9ydHM6IE1hcDxzdHJpbmcsUG9ydD4gPSBuZXcgTWFwPHN0cmluZywgUG9ydD4oKTtcblxuICAgIC8vIFBhcmFtIGVuZFBvaW50cyBpcyBhbiBhcnJheSBvZiBFbmRQb2ludHMgZXhwb3J0ZWQgYnkgYSBjb21wb25lbnRcbiAgICAvLyB1cGRhdGUgb3VyIG1hcCBvZiBQb3J0cyB0byByZWZsZWN0IHRoaXMgYXJyYXlcbiAgICAvLyBUaGlzIG1heSBtZWFuIGluY2x1ZGluZyBhIG5ldyBQb3J0LCB1cGRhdGluZyBhbiBleGlzdGluZyBQb3J0IHRvXG4gICAgLy8gdXNlIHRoaXMgc3VwcGxpZWQgRW5kUG9pbnQsIG9yIGV2ZW4gZGVsZXRpbmcgYSAnbm8tbG9uZ2VyJyB2YWxpZCBQb3J0XG4gICAgZW5kUG9pbnRzLmZvckVhY2goIChlcDogRW5kUG9pbnQgKSA9PiB7XG4gICAgICBsZXQgaWQgPSBlcC5pZDtcblxuICAgICAgaWYgKCBjdXJyZW50UG9ydHMuaGFzKCBpZCApICkge1xuICAgICAgICBsZXQgcG9ydCA9IGN1cnJlbnRQb3J0cy5nZXQoIGlkICk7XG5cbiAgICAgICAgcG9ydC5lbmRQb2ludCA9IGVwO1xuXG4gICAgICAgIG5ld1BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgICAgICBjdXJyZW50UG9ydHMuZGVsZXRlKCBpZCApO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIC8vIGVuZFBvaW50IG5vdCBmb3VuZCwgY3JlYXRlIGEgcG9ydCBmb3IgaXRcbiAgICAgICAgbGV0IHBvcnQgPSBuZXcgUG9ydCggdGhpcywgZXAsIHsgaWQ6IGlkLCBkaXJlY3Rpb246IGVwLmRpcmVjdGlvbiB9ICk7XG5cbiAgICAgICAgbmV3UG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgdGhpcy5fcG9ydHMgPSBuZXdQb3J0cztcbiAgfVxuXG5cbiAgLyoqXG4gICAqIEFkZCBhIHBsYWNlaG9sZGVyIFBvcnRcbiAgICovXG4gIHByb3RlY3RlZCBhZGRQbGFjZWhvbGRlclBvcnQoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IHt9ICk6IFBvcnRcbiAge1xuICAgIGF0dHJpYnV0ZXNbXCJpZFwiXSA9IGlkO1xuXG4gICAgbGV0IHBvcnQgPSBuZXcgUG9ydCggdGhpcywgbnVsbCwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5fcG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIHBvcnRzIGFzIGFuIGFycmF5IG9mIFBvcnRzXG4gICAqXG4gICAqIEByZXR1cm4gUG9ydFtdXG4gICAqL1xuICBnZXQgcG9ydHMoKTogTWFwPHN0cmluZywgUG9ydD5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cztcbiAgfVxuXG4gIGdldFBvcnRBcnJheSgpOiBQb3J0W10ge1xuICAgIGxldCB4cG9ydHM6IFBvcnRbXSA9IFtdO1xuXG4gICAgdGhpcy5fcG9ydHMuZm9yRWFjaCggKCBwb3J0LCBpZCApID0+IHtcbiAgICAgIHhwb3J0cy5wdXNoKCBwb3J0ICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIHhwb3J0cztcbiAgfVxuXG4gIC8qKlxuICAgKiBMb29rdXAgYSBQb3J0IGJ5IGl0J3MgSURcbiAgICogQHBhcmFtIGlkIC0gcG9ydCBpZGVudGlmaWVyXG4gICAqXG4gICAqIEByZXR1cm4gUG9ydCBvciB1bmRlZmluZWRcbiAgICovXG4gIGdldFBvcnRCeUlEKCBpZDogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5nZXQoIGlkICk7XG4gIH1cblxuICBpZGVudGlmeVBvcnQoIGlkOiBzdHJpbmcsIHByb3RvY29sSUQ/OiBzdHJpbmcgKTogUG9ydFxuICB7XG4gICAgdmFyIHBvcnQ6IFBvcnQ7XG5cbiAgICBpZiAoIGlkIClcbiAgICAgIHBvcnQgPSB0aGlzLl9wb3J0cy5nZXQoIGlkICk7XG4gICAgZWxzZSBpZiAoIHByb3RvY29sSUQgKVxuICAgIHtcbiAgICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcCwgaWQgKSA9PiB7XG4gICAgICAgIGlmICggcC5wcm90b2NvbElEID09IHByb3RvY29sSUQgKVxuICAgICAgICAgIHBvcnQgPSBwO1xuICAgICAgfSwgdGhpcyApO1xuICAgIH1cblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZSBhIFBvcnQgZnJvbSB0aGlzIE5vZGVcbiAgICogQHBhcmFtIGlkIC0gaWRlbnRpZmllciBvZiBQb3J0IHRvIGJlIHJlbW92ZWRcbiAgICogQHJldHVybiB0cnVlIC0gcG9ydCByZW1vdmVkXG4gICAqICAgICAgICAgZmFsc2UgLSBwb3J0IGluZXhpc3RlbnRcbiAgICovXG4gIHJlbW92ZVBvcnQoIGlkOiBzdHJpbmcgKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BvcnRzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnkgKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy51bmxvYWRDb21wb25lbnQoKTtcblxuICAgIC8vIEdldCBhIENvbXBvbmVudENvbnRleHQgcmVzcG9uc2FibGUgZm9yIENvbXBvbmVudCdzIGxpZmUtY3ljbGUgY29udHJvbFxuICAgIGxldCBjdHggPSB0aGlzLl9jb250ZXh0ID0gZmFjdG9yeS5jcmVhdGVDb250ZXh0KCB0aGlzLl9jb21wb25lbnQsIHRoaXMuX2luaXRpYWxEYXRhICk7XG5cbiAgICAvLyBNYWtlIG91cnNlbHZlcyB2aXNpYmxlIHRvIGNvbnRleHQgKGFuZCBpbnN0YW5jZSlcbiAgICBjdHgubm9kZSA9IHRoaXM7XG5cbiAgICAvL2xldCBtZSA9IHRoaXM7XG5cbiAgICAvLyBMb2FkIGNvbXBvbmVudFxuICAgIHJldHVybiBjdHgubG9hZCgpO1xuICB9XG5cbiAgcHVibGljIGdldCBjb250ZXh0KCk6IFJ1bnRpbWVDb250ZXh0IHtcbiAgICByZXR1cm4gdGhpcy5fY29udGV4dDtcbiAgfVxuXG4gIHVubG9hZENvbXBvbmVudCgpXG4gIHtcbiAgICBpZiAoIHRoaXMuX2NvbnRleHQgKVxuICAgIHtcbiAgICAgIHRoaXMuX2NvbnRleHQucmVsZWFzZSgpO1xuXG4gICAgICB0aGlzLl9jb250ZXh0ID0gbnVsbDtcbiAgICB9XG4gIH1cblxufVxuIiwiaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludCwgRW5kUG9pbnRDb2xsZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi4vZ3JhcGgvbm9kZSc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi4vZ3JhcGgvcG9ydCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IENvbXBvbmVudCB9IGZyb20gJy4uL2NvbXBvbmVudC9jb21wb25lbnQnO1xuXG5pbXBvcnQgeyBDb250YWluZXIsIEluamVjdGFibGUgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuXG5leHBvcnQgZW51bSBSdW5TdGF0ZSB7XG4gIE5FV0JPUk4sICAgICAgLy8gTm90IHlldCBsb2FkZWRcbiAgTE9BRElORywgICAgICAvLyBXYWl0aW5nIGZvciBhc3luYyBsb2FkIHRvIGNvbXBsZXRlXG4gIExPQURFRCwgICAgICAgLy8gQ29tcG9uZW50IGxvYWRlZCwgbm90IHlldCBleGVjdXRhYmxlXG4gIFJFQURZLCAgICAgICAgLy8gUmVhZHkgZm9yIEV4ZWN1dGlvblxuICBSVU5OSU5HLCAgICAgIC8vIE5ldHdvcmsgYWN0aXZlLCBhbmQgcnVubmluZ1xuICBQQVVTRUQgICAgICAgIC8vIE5ldHdvcmsgdGVtcG9yYXJpbHkgcGF1c2VkXG59XG5cbi8qKlxuKiBUaGUgcnVudGltZSBjb250ZXh0IGluZm9ybWF0aW9uIGZvciBhIENvbXBvbmVudCBpbnN0YW5jZVxuKi9cbmV4cG9ydCBjbGFzcyBSdW50aW1lQ29udGV4dFxue1xuICAvKipcbiAgKiBUaGUgY29tcG9uZW50IGlkIC8gYWRkcmVzc1xuICAqL1xuICBwcml2YXRlIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIFRoZSBydW50aW1lIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICovXG4gIHByaXZhdGUgX2luc3RhbmNlOiBDb21wb25lbnQ7XG5cbiAgLyoqXG4gICogSW5pdGlhbCBEYXRhIGZvciB0aGUgY29tcG9uZW50IGluc3RhbmNlXG4gICovXG4gIHByaXZhdGUgX2NvbmZpZzoge307XG5cbiAgLyoqXG4gICogVGhlIHJ1bnRpbWUgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgKi9cbiAgcHJpdmF0ZSBfY29udGFpbmVyOiBDb250YWluZXI7XG5cbiAgLyoqXG4gICogVGhlIGNvbXBvbmVudCBmYWN0b3J5IHRoYXQgY3JlYXRlZCB1c1xuICAqL1xuICBwcml2YXRlIF9mYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5O1xuXG4gIC8qKlxuICAqIFRoZSBub2RlXG4gICovXG4gIHByaXZhdGUgX25vZGU6IE5vZGU7XG5cbiAgLyoqXG4gICpcbiAgKlxuICAqL1xuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgY29udGFpbmVyOiBDb250YWluZXIsIGlkOiBzdHJpbmcsIGNvbmZpZzoge30sIGRlcHM6IEluamVjdGFibGVbXSA9IFtdICkge1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG5cbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fY29uZmlnID0gY29uZmlnO1xuXG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyO1xuXG4gICAgLy8gUmVnaXN0ZXIgYW55IGNvbnRleHQgZGVwZW5kZW5jaWVzXG4gICAgZm9yKCBsZXQgaSBpbiBkZXBzIClcbiAgICB7XG4gICAgICBpZiAoICF0aGlzLl9jb250YWluZXIuaGFzUmVzb2x2ZXIoIGRlcHNbaV0gKSApXG4gICAgICAgIHRoaXMuX2NvbnRhaW5lci5yZWdpc3RlclNpbmdsZXRvbiggZGVwc1tpXSwgZGVwc1tpXSApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBub2RlKCk6IE5vZGUge1xuICAgIHJldHVybiB0aGlzLl9ub2RlO1xuICB9XG4gIHNldCBub2RlKCBub2RlOiBOb2RlICkge1xuICAgIHRoaXMuX25vZGUgPSBub2RlO1xuXG4gICAgLy8gbWFrZSBub2RlICdpbmplY3RhYmxlJyBpbiBjb250YWluZXJcbiAgICB0aGlzLl9jb250YWluZXIucmVnaXN0ZXJJbnN0YW5jZSggTm9kZSwgdGhpcyApO1xuICB9XG5cbiAgZ2V0IGluc3RhbmNlKCk6IENvbXBvbmVudCB7XG4gICAgcmV0dXJuIHRoaXMuX2luc3RhbmNlO1xuICB9XG5cbiAgZ2V0IGNvbnRhaW5lcigpOiBDb250YWluZXIge1xuICAgIHJldHVybiB0aGlzLl9jb250YWluZXI7XG4gIH1cblxuICBsb2FkKCApOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBnZXQgYW4gaW5zdGFuY2UgZnJvbSB0aGUgZmFjdG9yeVxuICAgICAgbWUuX3J1blN0YXRlID0gUnVuU3RhdGUuTE9BRElORztcbiAgICAgIHRoaXMuX2ZhY3RvcnkubG9hZENvbXBvbmVudCggdGhpcywgdGhpcy5faWQgKVxuICAgICAgICAudGhlbiggKGluc3RhbmNlKSA9PiB7XG4gICAgICAgICAgLy8gQ29tcG9uZW50IChhbmQgYW55IGRlcGVuZGVuY2llcykgaGF2ZSBiZWVuIGxvYWRlZFxuICAgICAgICAgIG1lLl9pbnN0YW5jZSA9IGluc3RhbmNlO1xuICAgICAgICAgIG1lLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5MT0FERUQgKTtcblxuICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoZXJyKSA9PiB7XG4gICAgICAgICAgLy8gVW5hYmxlIHRvIGxvYWRcbiAgICAgICAgICBtZS5fcnVuU3RhdGUgPSBSdW5TdGF0ZS5ORVdCT1JOO1xuXG4gICAgICAgICAgcmVqZWN0KCBlcnIgKTtcbiAgICAgICAgfSk7XG4gICAgfSApO1xuICB9XG5cbiAgX3J1blN0YXRlOiBSdW5TdGF0ZSA9IFJ1blN0YXRlLk5FV0JPUk47XG4gIGdldCBydW5TdGF0ZSgpIHtcbiAgICByZXR1cm4gdGhpcy5fcnVuU3RhdGU7XG4gIH1cblxuICBwcml2YXRlIGluU3RhdGUoIHN0YXRlczogUnVuU3RhdGVbXSApOiBib29sZWFuIHtcbiAgICByZXR1cm4gbmV3IFNldDxSdW5TdGF0ZT4oIHN0YXRlcyApLmhhcyggdGhpcy5fcnVuU3RhdGUgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFRyYW5zaXRpb24gY29tcG9uZW50IHRvIG5ldyBzdGF0ZVxuICAqIFN0YW5kYXJkIHRyYW5zaXRpb25zLCBhbmQgcmVzcGVjdGl2ZSBhY3Rpb25zLCBhcmU6XG4gICogICBMT0FERUQgLT4gUkVBRFkgICAgICBpbnN0YW50aWF0ZSBhbmQgaW5pdGlhbGl6ZSBjb21wb25lbnRcbiAgKiAgIFJFQURZIC0+IExPQURFRCAgICAgIHRlYXJkb3duIGFuZCBkZXN0cm95IGNvbXBvbmVudFxuICAqXG4gICogICBSRUFEWSAtPiBSVU5OSU5HICAgICBzdGFydCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICogICBSVU5OSU5HIC0+IFJFQURZICAgICBzdG9wIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKlxuICAqICAgUlVOTklORyAtPiBQQVVTRUQgICAgcGF1c2UgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqICAgUEFVU0VEIC0+IFJVTk5JTkcgICAgcmVzdW1lIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKlxuICAqL1xuICBzZXRSdW5TdGF0ZSggcnVuU3RhdGU6IFJ1blN0YXRlICkge1xuICAgIGxldCBpbnN0ID0gdGhpcy5pbnN0YW5jZTtcblxuICAgIHN3aXRjaCggcnVuU3RhdGUgKSAvLyB0YXJnZXQgc3RhdGUgLi5cbiAgICB7XG4gICAgICBjYXNlIFJ1blN0YXRlLkxPQURFRDogLy8ganVzdCBsb2FkZWQsIG9yIHRlYXJkb3duXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJFQURZLCBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHRlYXJkb3duIGFuZCBkZXN0cm95IGNvbXBvbmVudFxuICAgICAgICAgIGlmICggaW5zdC50ZWFyZG93biApXG4gICAgICAgICAge1xuICAgICAgICAgICAgaW5zdC50ZWFyZG93bigpO1xuXG4gICAgICAgICAgICAvLyBhbmQgZGVzdHJveSBpbnN0YW5jZVxuICAgICAgICAgICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5SRUFEWTogIC8vIGluaXRpYWxpemUgb3Igc3RvcCBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLkxPQURFRCBdICkgKSB7XG4gICAgICAgICAgLy8gaW5pdGlhbGl6ZSBjb21wb25lbnRcblxuICAgICAgICAgIGxldCBlbmRQb2ludHM6IEVuZFBvaW50W10gPSBbXTtcblxuICAgICAgICAgIGlmICggaW5zdC5pbml0aWFsaXplIClcbiAgICAgICAgICAgIGVuZFBvaW50cyA9IHRoaXMuaW5zdGFuY2UuaW5pdGlhbGl6ZSggPEtpbmQ+dGhpcy5fY29uZmlnICk7XG5cbiAgICAgICAgICBpZiAoIHRoaXMuX25vZGUgKVxuICAgICAgICAgICAgdGhpcy5fbm9kZS51cGRhdGVQb3J0cyggZW5kUG9pbnRzICk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHN0b3AgY29tcG9uZW50XG4gICAgICAgICAgaWYgKCBpbnN0LnN0b3AgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5zdG9wKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgaW5pdGlhbGl6ZWQsIG5vdCBsb2FkZWQnICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlJVTk5JTkc6ICAvLyBzdGFydC9yZXN1bWUgbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SRUFEWSwgUnVuU3RhdGUuUlVOTklORyBdICkgKSB7XG4gICAgICAgICAgLy8gc3RhcnQgY29tcG9uZW50IGV4ZWN1dGlvblxuICAgICAgICAgIGlmICggaW5zdC5zdGFydCApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnN0YXJ0KCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHJlc3VtZSBjb21wb25lbnQgZXhlY3V0aW9uIGFmdGVyIHBhdXNlXG4gICAgICAgICAgaWYgKCBpbnN0LnJlc3VtZSApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnJlc3VtZSgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIHN0YXJ0ZWQsIG5vdCByZWFkeScgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUEFVU0VEOiAgLy8gcGF1c2Ugbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HXSApICkge1xuICAgICAgICAgIGlmICggaW5zdC5wYXVzZSApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnBhdXNlKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIGFscmVhZHkgcGF1c2VkXG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgcGF1c2VkJyApO1xuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICB0aGlzLl9ydW5TdGF0ZSA9IHJ1blN0YXRlO1xuICB9XG5cbiAgcmVsZWFzZSgpIHtcbiAgICAvLyByZWxlYXNlIGluc3RhbmNlLCB0byBhdm9pZCBtZW1vcnkgbGVha3NcbiAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gbnVsbFxuICB9XG59XG4iLCJleHBvcnQgaW50ZXJmYWNlIE1vZHVsZUxvYWRlciB7XG4gIGhhc01vZHVsZT8oIGlkOiBzdHJpbmcgKTogYm9vbGVhbjtcblxuICBsb2FkTW9kdWxlKCBpZDogc3RyaW5nICk6IFByb21pc2U8YW55Pjtcbn1cblxuZGVjbGFyZSBpbnRlcmZhY2UgU3lzdGVtIHtcbiAgbm9ybWFsaXplU3luYyggaWQgKTtcbiAgaW1wb3J0KCBpZCApO1xufTtcbmRlY2xhcmUgdmFyIFN5c3RlbTogU3lzdGVtO1xuXG5jbGFzcyBNb2R1bGVSZWdpc3RyeUVudHJ5IHtcbiAgY29uc3RydWN0b3IoIGFkZHJlc3M6IHN0cmluZyApIHtcblxuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTeXN0ZW1Nb2R1bGVMb2FkZXIgaW1wbGVtZW50cyBNb2R1bGVMb2FkZXIge1xuXG4gIHByaXZhdGUgbW9kdWxlUmVnaXN0cnk6IE1hcDxzdHJpbmcsIE1vZHVsZVJlZ2lzdHJ5RW50cnk+O1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMubW9kdWxlUmVnaXN0cnkgPSBuZXcgTWFwPHN0cmluZywgTW9kdWxlUmVnaXN0cnlFbnRyeT4oKTtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0T3JDcmVhdGVNb2R1bGVSZWdpc3RyeUVudHJ5KGFkZHJlc3M6IHN0cmluZyk6IE1vZHVsZVJlZ2lzdHJ5RW50cnkge1xuICAgIHJldHVybiB0aGlzLm1vZHVsZVJlZ2lzdHJ5W2FkZHJlc3NdIHx8ICh0aGlzLm1vZHVsZVJlZ2lzdHJ5W2FkZHJlc3NdID0gbmV3IE1vZHVsZVJlZ2lzdHJ5RW50cnkoYWRkcmVzcykpO1xuICB9XG5cbiAgbG9hZE1vZHVsZSggaWQ6IHN0cmluZyApOiBQcm9taXNlPGFueT4ge1xuICAgIGxldCBuZXdJZCA9IFN5c3RlbS5ub3JtYWxpemVTeW5jKGlkKTtcbiAgICBsZXQgZXhpc3RpbmcgPSB0aGlzLm1vZHVsZVJlZ2lzdHJ5W25ld0lkXTtcblxuICAgIGlmIChleGlzdGluZykge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShleGlzdGluZyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIFN5c3RlbS5pbXBvcnQobmV3SWQpLnRoZW4obSA9PiB7XG4gICAgICB0aGlzLm1vZHVsZVJlZ2lzdHJ5W25ld0lkXSA9IG07XG4gICAgICByZXR1cm4gbTsgLy9lbnN1cmVPcmlnaW5PbkV4cG9ydHMobSwgbmV3SWQpO1xuICAgIH0pO1xuICB9XG5cbn1cbiIsImltcG9ydCB7IENvbXBvbmVudCwgQ29tcG9uZW50Q29uc3RydWN0b3IgfSBmcm9tICcuLi9jb21wb25lbnQvY29tcG9uZW50JztcbmltcG9ydCB7IFJ1bnRpbWVDb250ZXh0IH0gZnJvbSAnLi9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgTW9kdWxlTG9hZGVyIH0gZnJvbSAnLi9tb2R1bGUtbG9hZGVyJztcblxuaW1wb3J0IHsgQ29udGFpbmVyLCBJbmplY3RhYmxlIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcbmltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50RmFjdG9yeSB7XG4gIHByaXZhdGUgX2xvYWRlcjogTW9kdWxlTG9hZGVyO1xuICBwcml2YXRlIF9jb250YWluZXI6IENvbnRhaW5lcjtcbiAgcHJpdmF0ZSBfY29tcG9uZW50czogTWFwPHN0cmluZywgQ29tcG9uZW50Q29uc3RydWN0b3I+O1xuXG4gIGNvbnN0cnVjdG9yKCBjb250YWluZXI/OiBDb250YWluZXIsIGxvYWRlcj86IE1vZHVsZUxvYWRlciApIHtcbiAgICB0aGlzLl9sb2FkZXIgPSBsb2FkZXI7XG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyIHx8IG5ldyBDb250YWluZXIoKTtcbiAgICB0aGlzLl9jb21wb25lbnRzID0gbmV3IE1hcDxzdHJpbmcsIENvbXBvbmVudENvbnN0cnVjdG9yPigpO1xuXG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIHVuZGVmaW5lZCwgT2JqZWN0ICk7XG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIFwiXCIsIE9iamVjdCApO1xuICB9XG5cbiAgY3JlYXRlQ29udGV4dCggaWQ6IHN0cmluZywgY29uZmlnOiB7fSwgZGVwczogSW5qZWN0YWJsZVtdID0gW10gKTogUnVudGltZUNvbnRleHRcbiAge1xuICAgIGxldCBjaGlsZENvbnRhaW5lcjogQ29udGFpbmVyID0gdGhpcy5fY29udGFpbmVyLmNyZWF0ZUNoaWxkKCk7XG5cbiAgICByZXR1cm4gbmV3IFJ1bnRpbWVDb250ZXh0KCB0aGlzLCBjaGlsZENvbnRhaW5lciwgaWQsIGNvbmZpZywgZGVwcyApO1xuICB9XG5cbiAgZ2V0Q2hpbGRDb250YWluZXIoKTogQ29udGFpbmVyIHtcbiAgICByZXR1cm4gO1xuICB9XG5cbiAgbG9hZENvbXBvbmVudCggY3R4OiBSdW50aW1lQ29udGV4dCwgaWQ6IHN0cmluZyApOiBQcm9taXNlPENvbXBvbmVudD5cbiAge1xuICAgIGxldCBjcmVhdGVDb21wb25lbnQgPSBmdW5jdGlvbiggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKTogQ29tcG9uZW50XG4gICAge1xuICAgICAgbGV0IG5ld0luc3RhbmNlOiBDb21wb25lbnQgPSBjdHguY29udGFpbmVyLmludm9rZSggY3RvciApO1xuXG4gICAgICByZXR1cm4gbmV3SW5zdGFuY2U7XG4gICAgfVxuXG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDb21wb25lbnQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBDaGVjayBjYWNoZVxuICAgICAgbGV0IGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yID0gdGhpcy5nZXQoIGlkICk7XG5cbiAgICAgIGlmICggY3RvciApIHtcbiAgICAgICAgLy8gdXNlIGNhY2hlZCBjb25zdHJ1Y3RvclxuICAgICAgICByZXNvbHZlKCBjcmVhdGVDb21wb25lbnQoIGN0b3IgKSApO1xuICAgICAgfVxuICAgICAgZWxzZSBpZiAoIHRoaXMuX2xvYWRlciApIHtcbiAgICAgICAgLy8gZ290IGEgbG9hZGVkLCBzbyB0cnkgdG8gbG9hZCB0aGUgbW9kdWxlIC4uLlxuICAgICAgICB0aGlzLl9sb2FkZXIubG9hZE1vZHVsZSggaWQgKVxuICAgICAgICAgIC50aGVuKCAoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICkgPT4ge1xuXG4gICAgICAgICAgICAvLyByZWdpc3RlciBsb2FkZWQgY29tcG9uZW50XG4gICAgICAgICAgICBtZS5fY29tcG9uZW50cy5zZXQoIGlkLCBjdG9yICk7XG5cbiAgICAgICAgICAgIC8vIGluc3RhbnRpYXRlIGFuZCByZXNvbHZlXG4gICAgICAgICAgICByZXNvbHZlKCBjcmVhdGVDb21wb25lbnQoIGN0b3IgKSApO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLmNhdGNoKCAoIGUgKSA9PiB7XG4gICAgICAgICAgICByZWplY3QoICdDb21wb25lbnRGYWN0b3J5OiBVbmFibGUgdG8gbG9hZCBjb21wb25lbnQgXCInICsgaWQgKyAnXCIgLSAnICsgZSApO1xuICAgICAgICAgIH0gKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBvb3BzLiBubyBsb2FkZXIgLi4gbm8gY29tcG9uZW50XG4gICAgICAgIHJlamVjdCggJ0NvbXBvbmVudEZhY3Rvcnk6IENvbXBvbmVudCBcIicgKyBpZCArICdcIiBub3QgcmVnaXN0ZXJlZCwgYW5kIExvYWRlciBub3QgYXZhaWxhYmxlJyApO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgZ2V0KCBpZDogc3RyaW5nICk6IENvbXBvbmVudENvbnN0cnVjdG9yIHtcbiAgICByZXR1cm4gdGhpcy5fY29tcG9uZW50cy5nZXQoIGlkICk7XG4gIH1cbiAgcmVnaXN0ZXIoIGlkOiBzdHJpbmcsIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICkge1xuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCBpZCwgY3RvciApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbmV4cG9ydCB0eXBlIEVuZFBvaW50UmVmID0geyBub2RlSUQ6IHN0cmluZywgcG9ydElEOiBzdHJpbmcgfTtcblxuZXhwb3J0IGNsYXNzIExpbmtcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NoYW5uZWw6IENoYW5uZWw7XG4gIHByb3RlY3RlZCBfZnJvbTogRW5kUG9pbnRSZWY7XG4gIHByb3RlY3RlZCBfdG86IEVuZFBvaW50UmVmO1xuXG4gIHByb3RlY3RlZCBfcHJvdG9jb2xJRDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCBcIlwiO1xuICAgIC8vdGhpcy5fY2hhbm5lbCA9IG51bGw7XG4gICAgdGhpcy5fZnJvbSA9IGF0dHJpYnV0ZXNbICdmcm9tJyBdO1xuICAgIHRoaXMuX3RvID0gYXR0cmlidXRlc1sgJ3RvJyBdO1xuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBhdHRyaWJ1dGVzWyAncHJvdG9jb2wnIF0gfHwgJ2FueSc7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IHg6IDEwMCwgeTogMTAwIH07XG4gIH1cblxuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIGxldCBsaW5rID0ge1xuICAgICAgaWQ6IHRoaXMuX2lkLFxuICAgICAgcHJvdG9jb2w6ICggdGhpcy5fcHJvdG9jb2xJRCAhPSAnYW55JyApID8gdGhpcy5fcHJvdG9jb2xJRCA6IHVuZGVmaW5lZCxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhLFxuICAgICAgZnJvbTogdGhpcy5fZnJvbSxcbiAgICAgIHRvOiB0aGlzLl90b1xuICAgIH07XG5cbiAgICByZXR1cm4gbGluaztcbiAgfVxuXG4gIHNldCBpZCggaWQ6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuICB9XG5cbiAgY29ubmVjdCggY2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICAvLyBpZGVudGlmeSBmcm9tUG9ydCBpbiBmcm9tTm9kZVxuICAgIGxldCBmcm9tUG9ydDogUG9ydCA9IHRoaXMuZnJvbU5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl9mcm9tLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApO1xuXG4gICAgLy8gaWRlbnRpZnkgdG9Qb3J0IGluIHRvTm9kZVxuICAgIGxldCB0b1BvcnQ6IFBvcnQgPSB0aGlzLnRvTm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX3RvLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApO1xuXG4gICAgdGhpcy5fY2hhbm5lbCA9IGNoYW5uZWw7XG5cbiAgICBmcm9tUG9ydC5lbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgICB0b1BvcnQuZW5kUG9pbnQuYXR0YWNoKCBjaGFubmVsICk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IENoYW5uZWxcbiAge1xuICAgIGxldCBjaGFuID0gdGhpcy5fY2hhbm5lbDtcblxuICAgIGlmICggY2hhbiApXG4gICAge1xuICAgICAgdGhpcy5fY2hhbm5lbC5lbmRQb2ludHMuZm9yRWFjaCggKCBlbmRQb2ludCApID0+IHtcbiAgICAgICAgZW5kUG9pbnQuZGV0YWNoKCB0aGlzLl9jaGFubmVsICk7XG4gICAgICB9ICk7XG5cbiAgICAgIHRoaXMuX2NoYW5uZWwgPSB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIGNoYW47XG4gIH1cblxuICBnZXQgZnJvbU5vZGUoKTogTm9kZVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyLmdldE5vZGVCeUlEKCB0aGlzLl9mcm9tLm5vZGVJRCApO1xuICB9XG5cbiAgZ2V0IGZyb21Qb3J0KCk6IFBvcnRcbiAge1xuICAgIGxldCBub2RlID0gdGhpcy5mcm9tTm9kZTtcblxuICAgIHJldHVybiAobm9kZSkgPyBub2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fZnJvbS5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKSA6IHVuZGVmaW5lZDtcbiAgfVxuXG4gIHNldCBmcm9tUG9ydCggcG9ydDogUG9ydCApXG4gIHtcbiAgICB0aGlzLl9mcm9tID0ge1xuICAgICAgbm9kZUlEOiBwb3J0Lm93bmVyLmlkLFxuICAgICAgcG9ydElEOiBwb3J0LmlkXG4gICAgfTtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBwb3J0LnByb3RvY29sSUQ7XG4gIH1cblxuICBnZXQgdG9Ob2RlKCk6IE5vZGVcbiAge1xuICAgIHJldHVybiB0aGlzLl9vd25lci5nZXROb2RlQnlJRCggdGhpcy5fdG8ubm9kZUlEICk7XG4gIH1cblxuICBnZXQgdG9Qb3J0KCk6IFBvcnRcbiAge1xuICAgIGxldCBub2RlID0gdGhpcy50b05vZGU7XG5cbiAgICByZXR1cm4gKG5vZGUpID8gbm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX3RvLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApIDogdW5kZWZpbmVkO1xuICB9XG5cbiAgc2V0IHRvUG9ydCggcG9ydDogUG9ydCApXG4gIHtcbiAgICB0aGlzLl90byA9IHtcbiAgICAgIG5vZGVJRDogcG9ydC5vd25lci5pZCxcbiAgICAgIHBvcnRJRDogcG9ydC5pZFxuICAgIH07XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gcG9ydC5wcm90b2NvbElEO1xuICB9XG5cbiAgZ2V0IHByb3RvY29sSUQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcHJvdG9jb2xJRDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3RvcnkgfSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IFJ1bnRpbWVDb250ZXh0LCBSdW5TdGF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBMaW5rIH0gZnJvbSAnLi9saW5rJztcbmltcG9ydCB7IFBvcnQsIFB1YmxpY1BvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG5leHBvcnQgY2xhc3MgTmV0d29yayBleHRlbmRzIEV2ZW50SHViXG57XG4gIHN0YXRpYyBFVkVOVF9TVEFURV9DSEFOR0UgPSAnbmV0d29yazpzdGF0ZS1jaGFuZ2UnO1xuICBzdGF0aWMgRVZFTlRfR1JBUEhfQ0hBTkdFID0gJ25ldHdvcms6Z3JhcGgtY2hhbmdlJztcblxuICBwcml2YXRlIF9ncmFwaDogR3JhcGg7XG5cbiAgcHJpdmF0ZSBfZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeTtcblxuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgZ3JhcGg/OiBHcmFwaCApXG4gIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG4gICAgdGhpcy5fZ3JhcGggPSBncmFwaCB8fCBuZXcgR3JhcGgoIG51bGwsIHt9ICk7XG5cbiAgICBsZXQgbWUgPSB0aGlzO1xuICAgIHRoaXMuX2dyYXBoLnN1YnNjcmliZSggR3JhcGguRVZFTlRfQUREX05PREUsICggZGF0YTogeyBub2RlOiBOb2RlIH0gKT0+IHtcbiAgICAgIGxldCBydW5TdGF0ZTogUnVuU3RhdGUgPSBtZS5fZ3JhcGguY29udGV4dC5ydW5TdGF0ZTtcblxuICAgICAgaWYgKCBydW5TdGF0ZSAhPSBSdW5TdGF0ZS5ORVdCT1JOIClcbiAgICAgIHtcbiAgICAgICAgbGV0IHsgbm9kZSB9ID0gZGF0YTtcblxuICAgICAgICBub2RlLmxvYWRDb21wb25lbnQoIG1lLl9mYWN0b3J5IClcbiAgICAgICAgICAudGhlbiggKCk9PiB7XG4gICAgICAgICAgICBpZiAoIE5ldHdvcmsuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQsIFJ1blN0YXRlLlJFQURZIF0sIHJ1blN0YXRlICkgKVxuICAgICAgICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBub2RlLCBSdW5TdGF0ZS5SRUFEWSApO1xuXG4gICAgICAgICAgICBpZiAoIE5ldHdvcmsuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSwgcnVuU3RhdGUgKSApXG4gICAgICAgICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIG5vZGUsIHJ1blN0YXRlICk7XG5cbiAgICAgICAgICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9HUkFQSF9DSEFOR0UsIHsgbm9kZTogbm9kZSB9ICk7XG4gICAgICAgICAgfSlcbiAgICAgIH1cbiAgICB9ICk7XG4gIH1cblxuICBnZXQgZ3JhcGgoKTogR3JhcGgge1xuICAgIHJldHVybiB0aGlzLl9ncmFwaDtcbiAgfVxuXG4gIC8qKlxuICAqIExvYWQgYWxsIGNvbXBvbmVudHNcbiAgKi9cbiAgbG9hZENvbXBvbmVudHMoKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IFJ1blN0YXRlLkxPQURJTkcgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX2dyYXBoLmxvYWRDb21wb25lbnQoIHRoaXMuX2ZhY3RvcnkgKS50aGVuKCAoKT0+IHtcbiAgICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IFJ1blN0YXRlLkxPQURFRCB9ICk7XG4gICAgfSk7XG4gIH1cblxuICBpbml0aWFsaXplKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJFQURZICk7XG4gIH1cblxuICB0ZWFyZG93bigpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5MT0FERUQgKTtcbiAgfVxuXG4gIHN0YXRpYyBpblN0YXRlKCBzdGF0ZXM6IFJ1blN0YXRlW10sIHJ1blN0YXRlOiBSdW5TdGF0ZSApOiBib29sZWFuIHtcbiAgICByZXR1cm4gbmV3IFNldDxSdW5TdGF0ZT4oIHN0YXRlcyApLmhhcyggcnVuU3RhdGUgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFsdGVyIHJ1bi1zdGF0ZSBvZiBhIE5vZGUgLSBMT0FERUQsIFJFQURZLCBSVU5OSU5HIG9yIFBBVVNFRC5cbiAgKiBUcmlnZ2VycyBTZXR1cCBvciBUZWFyZG93biBpZiB0cmFuc2l0aW9uaW5nIGJldHdlZW4gUkVBRFkgYW5kIExPQURFRFxuICAqIFdpcmV1cCBhIGdyYXBoLCBjcmVhdGluZyBDaGFubmVsIGJldHdlZW4gbGlua2VkIE5vZGVzXG4gICogQWN0cyByZWN1cnNpdmVseSwgd2lyaW5nIHVwIGFueSBzdWItZ3JhcGhzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHNldFJ1blN0YXRlKCBub2RlOiBOb2RlLCBydW5TdGF0ZTogUnVuU3RhdGUgKVxuICB7XG4gICAgbGV0IGN0eCA9IG5vZGUuY29udGV4dDtcbiAgICBsZXQgY3VycmVudFN0YXRlID0gY3R4LnJ1blN0YXRlO1xuXG4gICAgaWYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKVxuICAgIHtcbiAgICAgIC8vIDEuIFByZXByb2Nlc3NcbiAgICAgIC8vICAgIGEuIEhhbmRsZSB0ZWFyZG93blxuICAgICAgLy8gICAgYi4gUHJvcGFnYXRlIHN0YXRlIGNoYW5nZSB0byBzdWJuZXRzXG4gICAgICBsZXQgbm9kZXM6IE1hcDxzdHJpbmcsIE5vZGU+ID0gbm9kZS5ub2RlcztcblxuICAgICAgaWYgKCAoIHJ1blN0YXRlID09IFJ1blN0YXRlLkxPQURFRCApICYmICggY3VycmVudFN0YXRlID49IFJ1blN0YXRlLlJFQURZICkgKSB7XG4gICAgICAgIC8vIHRlYXJpbmcgZG93biAuLiB1bmxpbmsgZ3JhcGggZmlyc3RcbiAgICAgICAgbGV0IGxpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPiA9IG5vZGUubGlua3M7XG5cbiAgICAgICAgLy8gdW53aXJlIChkZWFjdGl2YXRlIGFuZCBkZXN0cm95ICkgQ2hhbm5lbHMgYmV0d2VlbiBsaW5rZWQgbm9kZXNcbiAgICAgICAgbGlua3MuZm9yRWFjaCggKCBsaW5rICkgPT5cbiAgICAgICAge1xuICAgICAgICAgIE5ldHdvcmsudW53aXJlTGluayggbGluayApO1xuICAgICAgICB9ICk7XG4gICAgICB9XG5cbiAgICAgIC8vIFByb3BhZ2F0ZSBzdGF0ZSBjaGFuZ2UgdG8gc3ViLW5ldHMgZmlyc3RcbiAgICAgIG5vZGVzLmZvckVhY2goIGZ1bmN0aW9uKCBzdWJOb2RlIClcbiAgICAgIHtcbiAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggc3ViTm9kZSwgcnVuU3RhdGUgKTtcbiAgICAgIH0gKTtcblxuICAgICAgLy8gMi4gQ2hhbmdlIHN0YXRlIC4uLlxuICAgICAgY3R4LnNldFJ1blN0YXRlKCBydW5TdGF0ZSApO1xuXG4gICAgICAvLyAzLiBQb3N0cHJvY2Vzc1xuICAgICAgLy8gICAgYS4gSGFuZGxlIHNldHVwXG4gICAgICBpZiAoICggcnVuU3RhdGUgPT0gUnVuU3RhdGUuUkVBRFkgKSAmJiAoIGN1cnJlbnRTdGF0ZSA+PSBSdW5TdGF0ZS5MT0FERUQgKSApIHtcblxuICAgICAgICAvLyBzZXR0aW5nIHVwIC4uIGxpbmt1cCBncmFwaCBmaXJzdFxuICAgICAgICBsZXQgbGlua3M6IE1hcDxzdHJpbmcsIExpbms+ID0gbm9kZS5saW5rcztcbiAgICAgICAgLy8gdHJlYXQgZ3JhcGggcmVjdXJzaXZlbHlcblxuICAgICAgICAvLyAyLiB3aXJldXAgKGNyZWF0ZSBhbmQgYWN0aXZhdGUpIGEgQ2hhbm5lbCBiZXR3ZWVuIGxpbmtlZCBub2Rlc1xuICAgICAgICBsaW5rcy5mb3JFYWNoKCAoIGxpbmsgKSA9PlxuICAgICAgICB7XG4gICAgICAgICAgTmV0d29yay53aXJlTGluayggbGluayApO1xuICAgICAgICB9ICk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIENoYW5nZSBzdGF0ZSAuLi5cbiAgICAgIGN0eC5zZXRSdW5TdGF0ZSggcnVuU3RhdGUgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBVbndpcmUgYSBsaW5rLCByZW1vdmluZyB0aGUgQ2hhbm5lbCBiZXR3ZWVuIHRoZSBsaW5rZWQgTm9kZXNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgdW53aXJlTGluayggbGluazogTGluayApXG4gIHtcbiAgICAvLyBnZXQgbGlua2VkIG5vZGVzIChMaW5rIGZpbmRzIE5vZGVzIGluIHBhcmVudCBHcmFwaClcbiAgICBsZXQgZnJvbU5vZGUgPSBsaW5rLmZyb21Ob2RlO1xuICAgIGxldCB0b05vZGUgPSBsaW5rLnRvTm9kZTtcblxuICAgIGxldCBjaGFuOiBDaGFubmVsID0gbGluay5kaXNjb25uZWN0KCk7XG5cbiAgICBpZiAoIGNoYW4gKVxuICAgICAgY2hhbi5kZWFjdGl2YXRlKCk7XG4gIH1cblxuICAvKipcbiAgKiBXaXJldXAgYSBsaW5rLCBjcmVhdGluZyBDaGFubmVsIGJldHdlZW4gdGhlIGxpbmtlZCBOb2Rlc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyB3aXJlTGluayggbGluazogTGluayApXG4gIHtcbiAgICAvLyBnZXQgbGlua2VkIG5vZGVzIChMaW5rIGZpbmRzIE5vZGVzIGluIHBhcmVudCBHcmFwaClcbiAgICBsZXQgZnJvbU5vZGUgPSBsaW5rLmZyb21Ob2RlO1xuICAgIGxldCB0b05vZGUgPSBsaW5rLnRvTm9kZTtcblxuICAgIC8vZGVidWdNZXNzYWdlKCBcIkxpbmsoXCIrbGluay5pZCtcIik6IFwiICsgbGluay5mcm9tICsgXCIgLT4gXCIgKyBsaW5rLnRvICsgXCIgcHJvdG89XCIrbGluay5wcm90b2NvbCApO1xuXG4gICAgbGV0IGNoYW5uZWwgPSBuZXcgQ2hhbm5lbCgpO1xuXG4gICAgbGluay5jb25uZWN0KCBjaGFubmVsICk7XG5cbiAgICBjaGFubmVsLmFjdGl2YXRlKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0UnVuU3RhdGUoIHJ1blN0YXRlOiBSdW5TdGF0ZSApXG4gIHtcbiAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCB0aGlzLl9ncmFwaCwgcnVuU3RhdGUgKTtcblxuICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IHJ1blN0YXRlIH0gKTtcbiAgfVxuXG4gIHN0YXJ0KCBpbml0aWFsbHlQYXVzZWQ6IGJvb2xlYW4gPSBmYWxzZSApIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBpbml0aWFsbHlQYXVzZWQgPyBSdW5TdGF0ZS5QQVVTRUQgOiBSdW5TdGF0ZS5SVU5OSU5HICk7XG4gIH1cblxuICBzdGVwKCkge1xuICAgIC8vIFRPRE86IFNpbmdsZS1zdGVwXG4gIH1cblxuICBzdG9wKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJFQURZICk7XG4gIH1cblxuICBwYXVzZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5QQVVTRUQgKTtcbiAgfVxuXG4gIHJlc3VtZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SVU5OSU5HICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcblxuaW1wb3J0IHsgTmV0d29yayB9IGZyb20gJy4vbmV0d29yayc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IExpbmsgfSBmcm9tICcuL2xpbmsnO1xuaW1wb3J0IHsgUG9ydCwgUHVibGljUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbi8qKlxuICogQSBHcmFwaCBpcyBhIGNvbGxlY3Rpb24gb2YgTm9kZXMgaW50ZXJjb25uZWN0ZWQgdmlhIExpbmtzLlxuICogQSBHcmFwaCBpcyBpdHNlbGYgYSBOb2RlLCB3aG9zZSBQb3J0cyBhY3QgYXMgcHVibGlzaGVkIEVuZFBvaW50cywgdG8gdGhlIEdyYXBoLlxuICovXG5leHBvcnQgY2xhc3MgR3JhcGggZXh0ZW5kcyBOb2RlXG57XG4gIHN0YXRpYyBFVkVOVF9BRERfTk9ERSA9ICdncmFwaDphZGQtbm9kZSc7XG4gIHN0YXRpYyBFVkVOVF9VUERfTk9ERSA9ICdncmFwaDp1cGQtbm9kZSc7XG4gIHN0YXRpYyBFVkVOVF9ERUxfTk9ERSA9ICdncmFwaDpkZWwtbm9kZSc7XG5cbiAgc3RhdGljIEVWRU5UX0FERF9MSU5LID0gJ2dyYXBoOmFkZC1saW5rJztcbiAgc3RhdGljIEVWRU5UX1VQRF9MSU5LID0gJ2dyYXBoOnVwZC1saW5rJztcbiAgc3RhdGljIEVWRU5UX0RFTF9MSU5LID0gJ2dyYXBoOmRlbC1saW5rJztcblxuICAvKipcbiAgKiBOb2RlcyBpbiB0aGlzIGdyYXBoLiBFYWNoIG5vZGUgbWF5IGJlOlxuICAqICAgMS4gQSBDb21wb25lbnRcbiAgKiAgIDIuIEEgc3ViLWdyYXBoXG4gICovXG4gIHByb3RlY3RlZCBfbm9kZXM6IE1hcDxzdHJpbmcsIE5vZGU+O1xuXG4gIC8vIExpbmtzIGluIHRoaXMgZ3JhcGguIEVhY2ggbm9kZSBtYXkgYmU6XG4gIHByb3RlY3RlZCBfbGlua3M6IE1hcDxzdHJpbmcsIExpbms+O1xuXG4gIC8vIFB1YmxpYyBQb3J0cyBpbiB0aGlzIGdyYXBoLiBJbmhlcml0ZWQgZnJvbSBOb2RlXG4gIC8vIHByaXZhdGUgUG9ydHM7XG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCBvd25lciwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5pbml0RnJvbU9iamVjdCggYXR0cmlidXRlcyApO1xuICB9XG5cbiAgaW5pdEZyb21TdHJpbmcoIGpzb25TdHJpbmc6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLmluaXRGcm9tT2JqZWN0KCBKU09OLnBhcnNlKCBqc29uU3RyaW5nICkgKTtcbiAgfVxuXG4gIGluaXRGcm9tT2JqZWN0KCBhdHRyaWJ1dGVzOiBhbnkgKSB7XG5cbiAgICB0aGlzLmlkID0gYXR0cmlidXRlcy5pZCB8fCBcIiRncmFwaFwiO1xuXG4gICAgdGhpcy5fbm9kZXMgPSBuZXcgTWFwPHN0cmluZywgTm9kZT4oKTtcbiAgICB0aGlzLl9saW5rcyA9IG5ldyBNYXA8c3RyaW5nLCBMaW5rPigpO1xuXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMubm9kZXMgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkTm9kZSggaWQsIGF0dHJpYnV0ZXMubm9kZXNbIGlkIF0gKTtcbiAgICB9KTtcblxuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLmxpbmtzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZExpbmsoIGlkLCBhdHRyaWJ1dGVzLmxpbmtzWyBpZCBdICk7XG4gICAgfSk7XG4gIH1cblxuICB0b09iamVjdCggb3B0czogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIGdyYXBoID0gc3VwZXIudG9PYmplY3QoKTtcblxuICAgIGxldCBub2RlcyA9IGdyYXBoWyBcIm5vZGVzXCIgXSA9IHt9O1xuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4vLyAgICAgIGlmICggbm9kZSAhPSB0aGlzIClcbiAgICAgICAgbm9kZXNbIGlkIF0gPSBub2RlLnRvT2JqZWN0KCk7XG4gICAgfSk7XG5cbiAgICBsZXQgbGlua3MgPSBncmFwaFsgXCJsaW5rc1wiIF0gPSB7fTtcbiAgICB0aGlzLl9saW5rcy5mb3JFYWNoKCAoIGxpbmssIGlkICkgPT4ge1xuICAgICAgbGlua3NbIGlkIF0gPSBsaW5rLnRvT2JqZWN0KCk7XG4gICAgfSk7XG5cbiAgICByZXR1cm4gZ3JhcGg7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IHBlbmRpbmdDb3VudCA9IDA7XG5cbiAgICAgIGxldCBub2RlcyA9IG5ldyBNYXA8c3RyaW5nLCBOb2RlPiggdGhpcy5fbm9kZXMgKTtcbiAgICAgIG5vZGVzLnNldCggJyRncmFwaCcsIHRoaXMgKTtcblxuICAgICAgbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgICAgbGV0IGRvbmU6IFByb21pc2U8dm9pZD47XG5cbiAgICAgICAgcGVuZGluZ0NvdW50Kys7XG5cbiAgICAgICAgaWYgKCBub2RlID09IHRoaXMgKSB7XG4gICAgICAgICAgZG9uZSA9IHN1cGVyLmxvYWRDb21wb25lbnQoIGZhY3RvcnkgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICBkb25lID0gbm9kZS5sb2FkQ29tcG9uZW50KCBmYWN0b3J5ICk7XG4gICAgICAgIH1cblxuICAgICAgICBkb25lLnRoZW4oICgpID0+IHtcbiAgICAgICAgICAtLXBlbmRpbmdDb3VudDtcbiAgICAgICAgICBpZiAoIHBlbmRpbmdDb3VudCA9PSAwIClcbiAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoIHJlYXNvbiApID0+IHtcbiAgICAgICAgICByZWplY3QoIHJlYXNvbiApO1xuICAgICAgICB9ICk7XG4gICAgICB9ICk7XG4gICAgfSApO1xuICB9XG5cbiAgcHVibGljIGdldCBub2RlcygpOiBNYXA8c3RyaW5nLCBOb2RlPlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX25vZGVzO1xuICB9XG5cbi8qICBwdWJsaWMgZ2V0QWxsTm9kZXMoKTogTm9kZVtdXG4gIHtcbiAgICBsZXQgbm9kZXM6IE5vZGVbXSA9IFtdO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIC8vIERvbid0IHJlY3Vyc2Ugb24gZ3JhcGgncyBwc2V1ZG8tbm9kZVxuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBub2RlcyA9IG5vZGVzLmNvbmNhdCggbm9kZS5nZXRBbGxOb2RlcygpICk7XG5cbiAgICAgIG5vZGVzLnB1c2goIG5vZGUgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbm9kZXM7XG4gIH0qL1xuXG4gIHB1YmxpYyBnZXQgbGlua3MoKTogTWFwPHN0cmluZywgTGluaz5cbiAge1xuICAgIHJldHVybiB0aGlzLl9saW5rcztcbiAgfVxuXG4vKiAgcHVibGljIGdldEFsbExpbmtzKCk6IExpbmtbXVxuICB7XG4gICAgbGV0IGxpbmtzOiBMaW5rW10gPSBbXTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIGxpbmtzID0gbGlua3MuY29uY2F0KCBub2RlLmdldEFsbExpbmtzKCkgKTtcbiAgICB9IClcblxuICAgIHRoaXMuX2xpbmtzLmZvckVhY2goICggbGluaywgaWQgKSA9PiB7XG4gICAgICBsaW5rcy5wdXNoKCBsaW5rICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIGxpbmtzO1xuICB9Ki9cblxuLyogIHB1YmxpYyBnZXRBbGxQb3J0cygpOiBQb3J0W11cbiAge1xuICAgIGxldCBwb3J0czogUG9ydFtdID0gc3VwZXIuZ2V0UG9ydEFycmF5KCk7XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBwb3J0cyA9IHBvcnRzLmNvbmNhdCggbm9kZS5nZXRBbGxQb3J0cygpICk7XG4gICAgICBlbHNlXG4gICAgICAgIHBvcnRzID0gcG9ydHMuY29uY2F0KCBub2RlLmdldFBvcnRBcnJheSgpICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIHBvcnRzO1xuICB9Ki9cblxuICBwdWJsaWMgZ2V0Tm9kZUJ5SUQoIGlkOiBzdHJpbmcgKTogTm9kZVxuICB7XG4gICAgaWYgKCBpZCA9PSAnJGdyYXBoJyApXG4gICAgICByZXR1cm4gdGhpcztcblxuICAgIHJldHVybiB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgYWRkTm9kZSggaWQ6IHN0cmluZywgYXR0cmlidXRlcz86IHt9ICk6IE5vZGUge1xuXG4gICAgbGV0IG5vZGUgPSBuZXcgTm9kZSggdGhpcywgYXR0cmlidXRlcyApO1xuXG4gICAgbm9kZS5pZCA9IGlkO1xuXG4gICAgdGhpcy5fbm9kZXMuc2V0KCBpZCwgbm9kZSApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9BRERfTk9ERSwgeyBub2RlOiBub2RlIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgcHVibGljIHJlbmFtZU5vZGUoIGlkOiBzdHJpbmcsIG5ld0lEOiBzdHJpbmcgKSB7XG5cbiAgICBsZXQgbm9kZSA9IHRoaXMuX25vZGVzLmdldCggaWQgKTtcblxuICAgIGlmICggaWQgIT0gbmV3SUQgKVxuICAgIHtcbiAgICAgIGxldCBldmVudERhdGEgPSB7IG5vZGU6IG5vZGUsIGF0dHJzOiB7IGlkOiBub2RlLmlkIH0gfTtcblxuICAgICAgdGhpcy5fbm9kZXMuZGVsZXRlKCBpZCApO1xuXG4gICAgICBub2RlLmlkID0gbmV3SUQ7XG5cbiAgICAgIHRoaXMuX25vZGVzLnNldCggbmV3SUQsIG5vZGUgKTtcblxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9VUERfTk9ERSwgZXZlbnREYXRhICk7XG4gICAgfVxuICB9XG5cbiAgcHVibGljIHJlbW92ZU5vZGUoIGlkOiBzdHJpbmcgKTogYm9vbGVhbiB7XG5cbiAgICBsZXQgbm9kZSA9IHRoaXMuX25vZGVzLmdldCggaWQgKTtcbiAgICBpZiAoIG5vZGUgKVxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9ERUxfTk9ERSwgeyBub2RlOiBub2RlIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9ub2Rlcy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0TGlua0J5SUQoIGlkOiBzdHJpbmcgKTogTGluayB7XG5cbiAgICByZXR1cm4gdGhpcy5fbGlua3NbIGlkIF07XG4gIH1cblxuICBwdWJsaWMgYWRkTGluayggaWQ6IHN0cmluZywgYXR0cmlidXRlcz86IHt9ICk6IExpbmsge1xuXG4gICAgbGV0IGxpbmsgPSBuZXcgTGluayggdGhpcywgYXR0cmlidXRlcyApO1xuXG4gICAgbGluay5pZCA9IGlkO1xuXG4gICAgdGhpcy5fbGlua3Muc2V0KCBpZCwgbGluayApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9BRERfTElOSywgeyBsaW5rOiBsaW5rIH0gKTtcblxuICAgIHJldHVybiBsaW5rO1xuICB9XG5cbiAgcHVibGljIHJlbmFtZUxpbmsoIGlkOiBzdHJpbmcsIG5ld0lEOiBzdHJpbmcgKSB7XG5cbiAgICBsZXQgbGluayA9IHRoaXMuX2xpbmtzLmdldCggaWQgKTtcblxuICAgIHRoaXMuX2xpbmtzLmRlbGV0ZSggaWQgKTtcblxuICAgIGxldCBldmVudERhdGEgPSB7IGxpbms6IGxpbmssIGF0dHJzOiB7IGlkOiBsaW5rLmlkIH0gfTtcblxuICAgIGxpbmsuaWQgPSBuZXdJRDtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfVVBEX05PREUsIGV2ZW50RGF0YSApO1xuXG4gICAgdGhpcy5fbGlua3Muc2V0KCBuZXdJRCwgbGluayApO1xuICB9XG5cbiAgcHVibGljIHJlbW92ZUxpbmsoIGlkOiBzdHJpbmcgKTogYm9vbGVhbiB7XG5cbiAgICBsZXQgbGluayA9IHRoaXMuX2xpbmtzLmdldCggaWQgKTtcbiAgICBpZiAoIGxpbmsgKVxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9ERUxfTElOSywgeyBsaW5rOiBsaW5rIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9saW5rcy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgYWRkUHVibGljUG9ydCggaWQ6IHN0cmluZywgYXR0cmlidXRlczoge30gKTogUHVibGljUG9ydFxuICB7XG4gICAgYXR0cmlidXRlc1tcImlkXCJdID0gaWQ7XG5cbiAgICBsZXQgcG9ydCA9IG5ldyBQdWJsaWNQb3J0KCB0aGlzLCBudWxsLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLl9wb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlTG9hZGVyIH0gZnJvbSAnLi9tb2R1bGUtbG9hZGVyJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3RvcnkgfSBmcm9tICcuL2NvbXBvbmVudC1mYWN0b3J5JztcblxuaW1wb3J0IHsgQ29udGFpbmVyIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcblxuXG5leHBvcnQgY2xhc3MgU2ltdWxhdGlvbkVuZ2luZVxue1xuICBsb2FkZXI6IE1vZHVsZUxvYWRlcjtcbiAgY29udGFpbmVyOiBDb250YWluZXI7XG5cbiAgLyoqXG4gICogQ3JlYXRlcyBhbiBpbnN0YW5jZSBvZiBTaW11bGF0aW9uRW5naW5lLlxuICAqIEBwYXJhbSBsb2FkZXIgVGhlIG1vZHVsZSBsb2FkZXIuXG4gICogQHBhcmFtIGNvbnRhaW5lciBUaGUgcm9vdCBESSBjb250YWluZXIgZm9yIHRoZSBzaW11bGF0aW9uLlxuICAqL1xuICBjb25zdHJ1Y3RvciggbG9hZGVyOiBNb2R1bGVMb2FkZXIsIGNvbnRhaW5lcjogQ29udGFpbmVyICkge1xuICAgIHRoaXMubG9hZGVyID0gbG9hZGVyO1xuICAgIHRoaXMuY29udGFpbmVyID0gY29udGFpbmVyO1xuICB9XG5cblxuICAvKipcbiAgKiBSZXR1cm4gYSBDb21wb25lbnRGYWN0b3J5IGZhY2FkZVxuICAqL1xuICBnZXRDb21wb25lbnRGYWN0b3J5KCk6IENvbXBvbmVudEZhY3Rvcnkge1xuICAgIHJldHVybiBuZXcgQ29tcG9uZW50RmFjdG9yeSggdGhpcy5jb250YWluZXIsIHRoaXMubG9hZGVyICk7XG4gIH1cblxufVxuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
