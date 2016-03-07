  import { EventAggregator } from 'aurelia-event-aggregator';
  import { Container, autoinject as inject } from 'aurelia-dependency-injection';

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
CryptographicServiceProvider.registerService('DES-ECB', DESCryptographicService, [CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT]);
CryptographicServiceProvider.registerKeyService('DES-ECB', DESCryptographicService, [CryptographicOperation.IMPORT_KEY]);




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

export { Container, inject };


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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeS50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvd2ViY3J5cHRvLnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9kZXMudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS5qcyIsImtpbmQva2luZC50cyIsIm1lc3NhZ2luZy9tZXNzYWdlLnRzIiwicnVudGltZS90YXNrLXNjaGVkdWxlci50cyIsIm1lc3NhZ2luZy9jaGFubmVsLnRzIiwibWVzc2FnaW5nL2VuZC1wb2ludC50cyIsIm1lc3NhZ2luZy9wcm90b2NvbC50cyIsImNvbXBvbmVudC9wb3J0LWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LWluZm8udHMiLCJjb21wb25lbnQvc3RvcmUtaW5mby50cyIsImNvbXBvbmVudC9jb21wb25lbnQudHMiLCJldmVudC1odWIvZXZlbnQtaHViLnRzIiwiZ3JhcGgvcG9ydC50cyIsImdyYXBoL25vZGUudHMiLCJkZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXIudHMiLCJydW50aW1lL3J1bnRpbWUtY29udGV4dC50cyIsInJ1bnRpbWUvbW9kdWxlLWxvYWRlci50cyIsInJ1bnRpbWUvY29tcG9uZW50LWZhY3RvcnkudHMiLCJncmFwaC9saW5rLnRzIiwiZ3JhcGgvbmV0d29yay50cyIsImdyYXBoL2dyYXBoLnRzIiwicnVudGltZS9zaW11bGF0aW9uLWVuZ2luZS50cyJdLCJuYW1lcyI6WyJIZXhDb2RlYyIsIkhleENvZGVjLmRlY29kZSIsIkJBU0U2NFNQRUNJQUxTIiwiQmFzZTY0Q29kZWMiLCJCYXNlNjRDb2RlYy5kZWNvZGUiLCJCYXNlNjRDb2RlYy5kZWNvZGUuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLnB1c2giLCJCYXNlNjRDb2RlYy5lbmNvZGUiLCJCYXNlNjRDb2RlYy5lbmNvZGUuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLnRyaXBsZXRUb0Jhc2U2NCIsIkJ5dGVFbmNvZGluZyIsIkJ5dGVBcnJheSIsIkJ5dGVBcnJheS5jb25zdHJ1Y3RvciIsIkJ5dGVBcnJheS5lbmNvZGluZ1RvU3RyaW5nIiwiQnl0ZUFycmF5LnN0cmluZ1RvRW5jb2RpbmciLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJDcnlwdG9ncmFwaGljT3BlcmF0aW9uIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkuY29uc3RydWN0b3IiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0cnkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmVuY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRpZ2VzdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuc2lnbiIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudmVyaWZ5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5leHBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmdlbmVyYXRlS2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5pbXBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlcml2ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuZGVyaXZlQml0cyIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIud3JhcEtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudW53cmFwS2V5IiwiV2ViQ3J5cHRvU2VydmljZSIsIldlYkNyeXB0b1NlcnZpY2UuY29uc3RydWN0b3IiLCJXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSIsIldlYkNyeXB0b1NlcnZpY2UuZW5jcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGVjcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGlnZXN0IiwiV2ViQ3J5cHRvU2VydmljZS5leHBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLmdlbmVyYXRlS2V5IiwiV2ViQ3J5cHRvU2VydmljZS5pbXBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLnNpZ24iLCJXZWJDcnlwdG9TZXJ2aWNlLnZlcmlmeSIsIkRFU1NlY3JldEtleSIsIkRFU1NlY3JldEtleS5jb25zdHJ1Y3RvciIsIkRFU1NlY3JldEtleS5hbGdvcml0aG0iLCJERVNTZWNyZXRLZXkuZXh0cmFjdGFibGUiLCJERVNTZWNyZXRLZXkudHlwZSIsIkRFU1NlY3JldEtleS51c2FnZXMiLCJERVNTZWNyZXRLZXkua2V5TWF0ZXJpYWwiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZSIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmNvbnN0cnVjdG9yIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZW5jcnlwdCIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlY3J5cHQiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5pbXBvcnRLZXkiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5zaWduIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzLmRlc19jcmVhdGVLZXlzIiwiRW51bSIsIkludGVnZXIiLCJGaWVsZEFycmF5IiwiS2luZEluZm8iLCJLaW5kSW5mby5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyIiwiS2luZEJ1aWxkZXIuY29uc3RydWN0b3IiLCJLaW5kQnVpbGRlci5pbml0IiwiS2luZEJ1aWxkZXIuZmllbGQiLCJLaW5kQnVpbGRlci5ib29sRmllbGQiLCJLaW5kQnVpbGRlci5udW1iZXJGaWVsZCIsIktpbmRCdWlsZGVyLmludGVnZXJGaWVsZCIsIktpbmRCdWlsZGVyLnVpbnQzMkZpZWxkIiwiS2luZEJ1aWxkZXIuYnl0ZUZpZWxkIiwiS2luZEJ1aWxkZXIuc3RyaW5nRmllbGQiLCJLaW5kQnVpbGRlci5raW5kRmllbGQiLCJLaW5kQnVpbGRlci5lbnVtRmllbGQiLCJLaW5kIiwiS2luZC5nZXRLaW5kSW5mbyIsIktpbmQuaW5pdEZpZWxkcyIsIk1lc3NhZ2UiLCJNZXNzYWdlLmNvbnN0cnVjdG9yIiwiTWVzc2FnZS5oZWFkZXIiLCJNZXNzYWdlLnBheWxvYWQiLCJLaW5kTWVzc2FnZSIsIlRhc2tTY2hlZHVsZXIiLCJUYXNrU2NoZWR1bGVyLmNvbnN0cnVjdG9yIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyLnJlcXVlc3RGbHVzaC5oYW5kbGVGbHVzaFRpbWVyIiwiVGFza1NjaGVkdWxlci5zaHV0ZG93biIsIlRhc2tTY2hlZHVsZXIucXVldWVUYXNrIiwiVGFza1NjaGVkdWxlci5mbHVzaFRhc2tRdWV1ZSIsIlRhc2tTY2hlZHVsZXIub25FcnJvciIsIkNoYW5uZWwiLCJDaGFubmVsLmNvbnN0cnVjdG9yIiwiQ2hhbm5lbC5zaHV0ZG93biIsIkNoYW5uZWwuYWN0aXZlIiwiQ2hhbm5lbC5hY3RpdmF0ZSIsIkNoYW5uZWwuZGVhY3RpdmF0ZSIsIkNoYW5uZWwuYWRkRW5kUG9pbnQiLCJDaGFubmVsLnJlbW92ZUVuZFBvaW50IiwiQ2hhbm5lbC5lbmRQb2ludHMiLCJDaGFubmVsLnNlbmRNZXNzYWdlIiwiRGlyZWN0aW9uIiwiRW5kUG9pbnQiLCJFbmRQb2ludC5jb25zdHJ1Y3RvciIsIkVuZFBvaW50LnNodXRkb3duIiwiRW5kUG9pbnQuaWQiLCJFbmRQb2ludC5hdHRhY2giLCJFbmRQb2ludC5kZXRhY2giLCJFbmRQb2ludC5kZXRhY2hBbGwiLCJFbmRQb2ludC5hdHRhY2hlZCIsIkVuZFBvaW50LmRpcmVjdGlvbiIsIkVuZFBvaW50LmhhbmRsZU1lc3NhZ2UiLCJFbmRQb2ludC5zZW5kTWVzc2FnZSIsIkVuZFBvaW50Lm9uTWVzc2FnZSIsIlByb3RvY29sVHlwZUJpdHMiLCJQcm90b2NvbCIsIkNsaWVudFNlcnZlclByb3RvY29sIiwiQVBEVSIsIkFQRFVNZXNzYWdlIiwiQVBEVVByb3RvY29sIiwiUG9ydEluZm8iLCJQb3J0SW5mby5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEluZm8iLCJDb21wb25lbnRJbmZvLmNvbnN0cnVjdG9yIiwiU3RvcmVJbmZvIiwiQ29tcG9uZW50QnVpbGRlciIsIkNvbXBvbmVudEJ1aWxkZXIuY29uc3RydWN0b3IiLCJDb21wb25lbnRCdWlsZGVyLmluaXQiLCJDb21wb25lbnRCdWlsZGVyLmNvbmZpZyIsIkNvbXBvbmVudEJ1aWxkZXIucG9ydCIsIkV2ZW50SHViIiwiRXZlbnRIdWIuY29uc3RydWN0b3IiLCJFdmVudEh1Yi5wdWJsaXNoIiwiRXZlbnRIdWIuc3Vic2NyaWJlIiwiRXZlbnRIdWIuc3Vic2NyaWJlT25jZSIsIlBvcnQiLCJQb3J0LmNvbnN0cnVjdG9yIiwiUG9ydC5lbmRQb2ludCIsIlBvcnQudG9PYmplY3QiLCJQb3J0Lm93bmVyIiwiUG9ydC5wcm90b2NvbElEIiwiUG9ydC5pZCIsIlBvcnQuZGlyZWN0aW9uIiwiUHVibGljUG9ydCIsIlB1YmxpY1BvcnQuY29uc3RydWN0b3IiLCJQdWJsaWNQb3J0LmNvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC5kaXNjb25uZWN0UHJpdmF0ZSIsIlB1YmxpY1BvcnQudG9PYmplY3QiLCJOb2RlIiwiTm9kZS5jb25zdHJ1Y3RvciIsIk5vZGUudG9PYmplY3QiLCJOb2RlLm93bmVyIiwiTm9kZS5pZCIsIk5vZGUudXBkYXRlUG9ydHMiLCJOb2RlLmFkZFBsYWNlaG9sZGVyUG9ydCIsIk5vZGUucG9ydHMiLCJOb2RlLmdldFBvcnRBcnJheSIsIk5vZGUuZ2V0UG9ydEJ5SUQiLCJOb2RlLmlkZW50aWZ5UG9ydCIsIk5vZGUucmVtb3ZlUG9ydCIsIk5vZGUubG9hZENvbXBvbmVudCIsIk5vZGUuY29udGV4dCIsIk5vZGUudW5sb2FkQ29tcG9uZW50IiwiUnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dCIsIlJ1bnRpbWVDb250ZXh0LmNvbnN0cnVjdG9yIiwiUnVudGltZUNvbnRleHQubm9kZSIsIlJ1bnRpbWVDb250ZXh0Lmluc3RhbmNlIiwiUnVudGltZUNvbnRleHQuY29udGFpbmVyIiwiUnVudGltZUNvbnRleHQubG9hZCIsIlJ1bnRpbWVDb250ZXh0LnJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQuaW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnNldFJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQucmVsZWFzZSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkiLCJNb2R1bGVSZWdpc3RyeUVudHJ5LmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeSIsIlN5c3RlbU1vZHVsZUxvYWRlci5sb2FkTW9kdWxlIiwiQ29tcG9uZW50RmFjdG9yeSIsIkNvbXBvbmVudEZhY3RvcnkuY29uc3RydWN0b3IiLCJDb21wb25lbnRGYWN0b3J5LmNyZWF0ZUNvbnRleHQiLCJDb21wb25lbnRGYWN0b3J5LmdldENoaWxkQ29udGFpbmVyIiwiQ29tcG9uZW50RmFjdG9yeS5sb2FkQ29tcG9uZW50IiwiQ29tcG9uZW50RmFjdG9yeS5nZXQiLCJDb21wb25lbnRGYWN0b3J5LnJlZ2lzdGVyIiwiTGluayIsIkxpbmsuY29uc3RydWN0b3IiLCJMaW5rLnRvT2JqZWN0IiwiTGluay5pZCIsIkxpbmsuY29ubmVjdCIsIkxpbmsuZGlzY29ubmVjdCIsIkxpbmsuZnJvbU5vZGUiLCJMaW5rLmZyb21Qb3J0IiwiTGluay50b05vZGUiLCJMaW5rLnRvUG9ydCIsIkxpbmsucHJvdG9jb2xJRCIsIk5ldHdvcmsiLCJOZXR3b3JrLmNvbnN0cnVjdG9yIiwiTmV0d29yay5ncmFwaCIsIk5ldHdvcmsubG9hZENvbXBvbmVudHMiLCJOZXR3b3JrLmluaXRpYWxpemUiLCJOZXR3b3JrLnRlYXJkb3duIiwiTmV0d29yay5pblN0YXRlIiwiTmV0d29yay5zZXRSdW5TdGF0ZSIsIk5ldHdvcmsudW53aXJlTGluayIsIk5ldHdvcmsud2lyZUxpbmsiLCJOZXR3b3JrLnN0YXJ0IiwiTmV0d29yay5zdGVwIiwiTmV0d29yay5zdG9wIiwiTmV0d29yay5wYXVzZSIsIk5ldHdvcmsucmVzdW1lIiwiR3JhcGgiLCJHcmFwaC5jb25zdHJ1Y3RvciIsIkdyYXBoLmluaXRGcm9tU3RyaW5nIiwiR3JhcGguaW5pdEZyb21PYmplY3QiLCJHcmFwaC50b09iamVjdCIsIkdyYXBoLmxvYWRDb21wb25lbnQiLCJHcmFwaC5ub2RlcyIsIkdyYXBoLmxpbmtzIiwiR3JhcGguZ2V0Tm9kZUJ5SUQiLCJHcmFwaC5hZGROb2RlIiwiR3JhcGgucmVuYW1lTm9kZSIsIkdyYXBoLnJlbW92ZU5vZGUiLCJHcmFwaC5nZXRMaW5rQnlJRCIsIkdyYXBoLmFkZExpbmsiLCJHcmFwaC5yZW5hbWVMaW5rIiwiR3JhcGgucmVtb3ZlTGluayIsIkdyYXBoLmFkZFB1YmxpY1BvcnQiLCJTaW11bGF0aW9uRW5naW5lIiwiU2ltdWxhdGlvbkVuZ2luZS5jb25zdHJ1Y3RvciIsIlNpbXVsYXRpb25FbmdpbmUuZ2V0Q29tcG9uZW50RmFjdG9yeSJdLCJtYXBwaW5ncyI6IkFBQUE7SUFJRUEsT0FBT0EsTUFBTUEsQ0FBRUEsQ0FBU0E7UUFFdEJDLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pDQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFHQSxHQUFHQSxrQkFBa0JBLENBQUNBO1lBQzdCQSxJQUFJQSxLQUFLQSxHQUFHQSw2QkFBNkJBLENBQUNBO1lBQzFDQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtZQUN2QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3ZCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsR0FBR0EsR0FBR0EsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7WUFDeEJBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO2dCQUN4QkEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDM0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO2dCQUNqQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLFFBQVFBLENBQUNBLFlBQVlBLEdBQUdBLEdBQUdBLENBQUNBO1FBQzlCQSxDQUFDQTtRQUVEQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtRQUN2QkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDN0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBLEVBQ2pDQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNwQkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsR0FBR0EsQ0FBQ0E7Z0JBQ1RBLEtBQUtBLENBQUNBO1lBQ1ZBLElBQUlBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLFlBQVlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQ2pDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDUkEsUUFBUUEsQ0FBQ0E7WUFDYkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0E7Z0JBQ2ZBLE1BQU1BLDhCQUE4QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDN0NBLElBQUlBLElBQUlBLENBQUNBLENBQUNBO1lBQ1ZBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLFVBQVVBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUNwQkEsR0FBR0EsQ0FBQ0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2pCQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQTtnQkFDVEEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDbkJBLENBQUNBO1lBQUNBLElBQUlBLENBQUNBLENBQUNBO2dCQUNKQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQTtZQUNmQSxDQUFDQTtRQUNIQSxDQUFDQTtRQUVEQSxFQUFFQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQTtZQUNiQSxNQUFNQSx5Q0FBeUNBLENBQUNBO1FBRWxEQSxNQUFNQSxDQUFDQSxVQUFVQSxDQUFDQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtJQUNoQ0EsQ0FBQ0E7QUFDSEQsQ0FBQ0E7QUFBQTtBQzlDRCxJQUFLLGNBUUo7QUFSRCxXQUFLLGNBQWM7SUFDakJFLHdDQUFPQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQSxVQUFBQSxDQUFBQTtJQUN4QkEseUNBQVFBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLFdBQUFBLENBQUFBO0lBQ3pCQSwwQ0FBU0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsWUFBQUEsQ0FBQUE7SUFDMUJBLHlDQUFRQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQSxXQUFBQSxDQUFBQTtJQUN6QkEseUNBQVFBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLFdBQUFBLENBQUFBO0lBQ3pCQSxpREFBZ0JBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLG1CQUFBQSxDQUFBQTtJQUNqQ0Esa0RBQWlCQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQSxvQkFBQUEsQ0FBQUE7QUFDcENBLENBQUNBLEVBUkksY0FBYyxLQUFkLGNBQWMsUUFRbEI7QUFFRDtJQUVFQyxPQUFPQSxNQUFNQSxDQUFFQSxHQUFXQTtRQUV4QkMsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLE1BQU1BLElBQUlBLEtBQUtBLENBQUNBLHVEQUF1REEsQ0FBQ0EsQ0FBQ0E7UUFDM0VBLENBQUNBO1FBRURBLGdCQUFpQkEsR0FBV0E7WUFFMUJDLElBQUlBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBRTdCQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxjQUFjQSxDQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxLQUFLQSxjQUFjQSxDQUFDQSxhQUFhQSxDQUFDQTtnQkFDeEVBLE1BQU1BLENBQUNBLEVBQUVBLENBQUNBO1lBRVpBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLGNBQWNBLENBQUNBLEtBQUtBLElBQUlBLElBQUlBLEtBQUtBLGNBQWNBLENBQUNBLGNBQWNBLENBQUNBO2dCQUMxRUEsTUFBTUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7WUFFWkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsY0FBY0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FDbENBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFDQSxNQUFNQSxHQUFHQSxFQUFFQSxDQUFDQTtvQkFDcENBLE1BQU1BLENBQUNBLElBQUlBLEdBQUdBLGNBQWNBLENBQUNBLE1BQU1BLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO2dCQUVoREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsR0FBR0EsY0FBY0EsQ0FBQ0EsS0FBS0EsR0FBR0EsRUFBRUEsQ0FBQ0E7b0JBQ25DQSxNQUFNQSxDQUFDQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFDQSxLQUFLQSxDQUFDQTtnQkFFckNBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLEdBQUdBLGNBQWNBLENBQUNBLEtBQUtBLEdBQUdBLEVBQUVBLENBQUNBO29CQUNuQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsR0FBR0EsY0FBY0EsQ0FBQ0EsS0FBS0EsR0FBR0EsRUFBRUEsQ0FBQ0E7WUFDNUNBLENBQUNBO1lBRURBLE1BQU1BLElBQUlBLEtBQUtBLENBQUNBLDRDQUE0Q0EsQ0FBQ0EsQ0FBQ0E7UUFDaEVBLENBQUNBO1FBT0RELElBQUlBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBQ3JCQSxJQUFJQSxZQUFZQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUd6RkEsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsWUFBWUEsQ0FBRUEsQ0FBQ0E7UUFHOURBLElBQUlBLENBQUNBLEdBQUdBLFlBQVlBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZEQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVWQSxjQUFlQSxDQUFPQTtZQUNwQkUsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDZkEsQ0FBQ0E7UUFFREYsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFakJBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQzdCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMzSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDN0JBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFFQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzlHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUN4QkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRURELE9BQU9BLE1BQU1BLENBQUVBLEtBQWlCQTtRQUU5QkksSUFBSUEsQ0FBU0EsQ0FBQ0E7UUFDZEEsSUFBSUEsVUFBVUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDbENBLElBQUlBLE1BQU1BLEdBQUdBLEVBQUVBLENBQUNBO1FBRWhCQSxNQUFNQSxNQUFNQSxHQUFHQSxrRUFBa0VBLENBQUNBO1FBQ2xGQSxnQkFBaUJBLEdBQVNBO1lBQ3hCQyxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM1QkEsQ0FBQ0E7UUFFREQseUJBQTBCQSxHQUFXQTtZQUNuQ0UsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDNUdBLENBQUNBO1FBR0RGLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLFVBQVVBLENBQUNBO1FBQ3ZDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQTtZQUMvQkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbkVBLE1BQU1BLElBQUlBLGVBQWVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBO1FBQ2xDQSxDQUFDQTtRQUdEQSxNQUFNQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuQkEsS0FBS0EsQ0FBQ0E7Z0JBQ0pBLElBQUlBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO2dCQUNuQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzVCQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDckNBLE1BQU1BLElBQUlBLElBQUlBLENBQUNBO2dCQUNmQSxLQUFLQSxDQUFBQTtZQUNQQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2xFQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDN0JBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQTtnQkFDZEEsS0FBS0EsQ0FBQUE7WUFDUEE7Z0JBQ0VBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO0lBQ2hCQSxDQUFDQTtBQUNISixDQUFDQTtBQUFBO09DaklNLEVBQUUsUUFBUSxFQUFFLE1BQU0sYUFBYTtPQUMvQixFQUFFLFdBQVcsRUFBRSxNQUFNLGdCQUFnQjtBQUU1QyxXQUFZLFlBS1g7QUFMRCxXQUFZLFlBQVk7SUFDdEJPLDZDQUFHQSxDQUFBQTtJQUNIQSw2Q0FBR0EsQ0FBQUE7SUFDSEEsbURBQU1BLENBQUFBO0lBQ05BLCtDQUFJQSxDQUFBQTtBQUNOQSxDQUFDQSxFQUxXLFlBQVksS0FBWixZQUFZLFFBS3ZCO0FBRUQ7SUEyQ0VDLFlBQWFBLEtBQXFFQSxFQUFFQSxRQUFpQkEsRUFBRUEsR0FBU0E7UUFFOUdDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO1lBRUNBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3ZDQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxRQUFRQSxJQUFJQSxRQUFRQSxJQUFJQSxZQUFZQSxDQUFDQSxHQUFJQSxDQUFDQSxDQUNyREEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsV0FBWUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFlQSxLQUFLQSxDQUFFQSxDQUFDQTtZQUN4REEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsVUFBV0EsQ0FBQ0E7Z0JBQ3JDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUN6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsU0FBVUEsQ0FBQ0E7Z0JBQ3BDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUNuQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsS0FBTUEsQ0FBQ0E7Z0JBQ2hDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtRQUs3Q0EsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsS0FBS0EsSUFBSUEsUUFBU0EsQ0FBQ0EsQ0FDcENBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLE1BQU9BLENBQUNBLENBQ3RDQSxDQUFDQTtnQkFDR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDekRBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQ3hDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLElBQUtBLENBQUNBLENBQ3pDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtnQkFDN0JBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBO29CQUN4QkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBRTVDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxFQUFFQSxDQUFDQTtZQUN0QkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBVUEsQ0FBQ0EsQ0FDdEJBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGdDQUFnQ0EsQ0FBQ0EsQ0FBQUE7UUFDcERBLENBQUNBO0lBQ0hBLENBQUNBO0lBcEZERCxPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQXNCQTtRQUM3Q0UsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLE1BQU1BO2dCQUN0QkEsTUFBTUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLElBQUlBO2dCQUNwQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7WUFDaEJBLEtBQUtBLFlBQVlBLENBQUNBLEdBQUdBO2dCQUNuQkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFDZkE7Z0JBQ0VBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBO1FBQ2pCQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVERixPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQWdCQTtRQUN2Q0csRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsV0FBV0EsRUFBRUEsSUFBSUEsUUFBU0EsQ0FBQ0E7WUFDdkNBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLE1BQU1BLENBQUNBO1FBQzdCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxRQUFRQSxDQUFDQSxXQUFXQSxFQUFFQSxJQUFJQSxNQUFPQSxDQUFDQTtZQUMxQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFDM0JBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFdBQVdBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBO1lBQ3pDQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQSxHQUFHQSxDQUFDQTtRQUMxQkEsSUFBSUE7WUFDRkEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBZ0VESCxJQUFJQSxNQUFNQTtRQUVSSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUMvQkEsQ0FBQ0E7SUFFREosSUFBSUEsTUFBTUEsQ0FBRUEsR0FBV0E7UUFFckJJLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLElBQUlBLEdBQUlBLENBQUNBLENBQ25DQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUNsREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDekJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQ3ZDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFREosSUFBSUEsWUFBWUE7UUFFZEssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURMLE1BQU1BLENBQUVBLEtBQWdCQTtRQUV0Qk0sSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFDeEJBLElBQUlBLEdBQUdBLEdBQUdB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QUFDQSxHQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUN0Q0EsS0FBS0EsWUFBWUEsQ0FBQ0EsR0FBR0E7Z0JBRW5CQSxHQUFHQSxDQUFBQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtvQkFDOUJBLENBQUNBLElBQUlBLENBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLENBQUVBLENBQUNBLFFBQVFBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO2dCQUMvREEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsWUFBWUEsQ0FBQ0EsTUFBTUE7Z0JBQ3RCQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUU5Q0EsS0FBS0EsWUFBWUEsQ0FBQ0EsSUFBSUE7Z0JBQ3BCQSxHQUFHQSxDQUFBQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtvQkFDOUJBLENBQUNBLElBQUlBLE1BQU1BLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dCQUNsREEsS0FBS0EsQ0FBQ0E7WUFFUkE7Z0JBQ0VBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xEQSxLQUFLQSxDQUFDQTtRQUNWQSxDQUFD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Q0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFbkdBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBS09MLEdBQUdBLENBQUVBLEdBQWVBLEVBQUVBLE9BQW1CQSxFQUFFQSxPQUFlQSxFQUFFQSxJQUFZQSxFQUFFQSxFQUFlQSxFQUFFQSxPQUFnQkE7UUFLakhNLHdCQUF5QkEsR0FBR0E7WUFFMUJDLElBQUlBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFFMUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO2dCQUVDQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLEdBQUdBO29CQUN0Q0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBRUEsQ0FBRUE7b0JBQzVLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNySkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzlLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxDQUFDQSxDQUFFQTtvQkFDM0lBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQ3JLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDakxBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUM3SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtvQkFDbkpBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNuTEEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3RLQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxDQUFDQSxDQUFFQTtpQkFDOUdBLENBQUNBO1lBQ0pBLENBQUNBO1lBR0RBLElBQUlBLFVBQVVBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRXhDQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxXQUFXQSxDQUFDQSxFQUFFQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtZQUU1Q0EsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFaEVBLElBQUlBLFFBQVFBLEVBQUVBLFNBQVNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBO1lBRXhDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUMvQkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLEdBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUN6RUEsS0FBS0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBRXpFQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDbkZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUcvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0EsQ0FBQ0E7Z0JBRW5EQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDdEdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBO2dCQUdiQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUNwQ0EsQ0FBQ0E7b0JBRUNBLEVBQUVBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO3dCQUNDQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTt3QkFBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7b0JBQzVFQSxDQUFDQTtvQkFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBTTVCQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDbkVBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUMzRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzFFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtvQkFDL0NBLFNBQVNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNyRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzlFQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDOUVBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUNsREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsU0FBU0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7b0JBQ3BEQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsU0FBU0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3BFQSxDQUFDQTtZQUNIQSxDQUFDQTtZQUVEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtRQUNkQSxDQUFDQTtRQUdERCxJQUFJQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLENBQUNBO1FBRTFDQSxFQUFFQSxDQUFDQSxDQUFFQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUN6QkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsdUJBQXVCQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDdENBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNyb0JBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNqZkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JtQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3pqQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7YUFDdGxCQSxDQUFDQTtRQUNKQSxDQUFDQTtRQUdEQSxJQUFJQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVqQ0EsSUFBSUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsRUFBRUEsT0FBT0EsQ0FBQ0E7UUFDMUNBLElBQUlBLE9BQU9BLEVBQUVBLFFBQVFBLEVBQUVBLFFBQVFBLEVBQUVBLFNBQVNBLENBQUFBO1FBQzFDQSxJQUFJQSxHQUFHQSxHQUFHQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUd6QkEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFM0NBLEVBQUVBLENBQUNBLENBQUNBLFVBQVVBLElBQUlBLENBQUNBLENBQUNBLENBQ3BCQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsT0FBT0EsR0FBR0EsT0FBT0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEdBLENBQUNBO1FBR0RBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLE9BQU9BLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUVBLE9BQU9BLElBQUlBLENBQUNBLENBQUdBLENBQUNBLENBQ25EQSxDQUFDQTtZQUNDQSxJQUFJQSxlQUFlQSxHQUFHQSxPQUFPQSxDQUFDQTtZQUM5QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFFcEJBLE9BQU9BLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO1lBQ3BDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxlQUFlQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVsQ0EsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO2dCQUNDQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7b0JBQ3pGQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsQ0FBQ0E7b0JBQ05BLENBQUNBO3dCQUNDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTt3QkFFOUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUVBLENBQUVBLENBQUNBOzRCQUNYQSxHQUFHQSxJQUFFQSxDQUFDQSxDQUFDQTt3QkFFVEEsS0FBS0EsQ0FBQ0E7b0JBQ1JBLENBQUNBO2dCQUVEQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3ZGQSxLQUFLQSxDQUFDQTtZQUVWQSxDQUFDQTtZQUVEQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFBQTtRQUNsQkEsQ0FBQ0E7UUFHREEsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFbkNBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRVZBLE9BQU9BLEdBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBQ3hFQSxRQUFRQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtRQUMxRUEsQ0FBQ0E7UUFFREEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFHWEEsT0FBT0EsQ0FBQ0EsR0FBR0EsR0FBR0EsRUFDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDekZBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBR3pGQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtnQkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FDWkEsQ0FBQ0E7b0JBQ0NBLElBQUlBLElBQUlBLE9BQU9BLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxRQUFRQSxDQUFDQTtnQkFDckNBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtvQkFDQ0EsUUFBUUEsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQ25CQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtvQkFDckJBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBO29CQUNmQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDbkJBLENBQUNBO1lBQ0hBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUUvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxJQUFFQSxDQUFDQSxFQUM1QkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUMzQkEsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRzNCQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUN6Q0EsQ0FBQ0E7b0JBQ0NBLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUM3QkEsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBR3pEQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDWkEsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0E7b0JBQ2JBLEtBQUtBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNyRkEsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQzVFQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDckZBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQU1BLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUNoR0EsQ0FBQ0E7Z0JBRURBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFBQ0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7WUFDMUNBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBQ3JDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUd4Q0EsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDakZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRy9FQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtnQkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FDWkEsQ0FBQ0E7b0JBQ0NBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBO29CQUNmQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDbkJBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsUUFBUUEsQ0FBQ0E7b0JBQ2pCQSxLQUFLQSxJQUFJQSxTQUFTQSxDQUFDQTtnQkFDckJBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUdBLENBQUVBLENBQUNBLElBQUlBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLElBQUlBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLElBQUlBLEtBQUdBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLEtBQUtBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLEtBQUtBLEtBQUdBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBLEtBQUtB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QSxDQUFFQSxDQUFDQTtJQUN2REEsQ0FBQ0E7SUFFTUwsWUFBWUEsQ0FBRUEsSUFBWUEsRUFBRUEsV0FBbUJBLEVBQUVBLElBQUlBLEdBQWlCQSxFQUFFQTtRQUM3RU0sTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDeERBLENBQUNBO0lBRU1OLFdBQVdBLENBQUVBLElBQVlBLEVBQUVBLFdBQW1CQSxFQUFFQSxJQUFJQSxHQUFpQkEsRUFBRUE7UUFDNUVPLElBQUlBLENBQUNBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBLE9BQU9BLElBQUlBLENBQUNBLENBQUNBO1FBQ2pDQSxJQUFJQSxDQUFDQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQSxPQUFPQSxJQUFJQSxVQUFVQSxDQUFDQTtRQUUxQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDeERBLENBQUNBO0lBRU1QLFNBQVNBLENBQUVBLElBQVlBLEVBQUVBLFdBQW1CQSxFQUFFQSxJQUFJQSxHQUFpQkEsRUFBRUE7UUFDMUVRLElBQUlBLENBQUNBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBLE9BQU9BLElBQUlBLENBQUNBLENBQUNBO1FBQ2pDQSxJQUFJQSxDQUFDQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQSxPQUFPQSxJQUFJQSxHQUFHQSxDQUFDQTtRQUVuQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDeERBLENBQUNBO0lBRU1SLFdBQVdBLENBQUVBLElBQVlBLEVBQUVBLFdBQW1CQSxFQUFFQSxJQUFJQSxHQUFpQkEsRUFBRUE7UUFDNUVTLE1BQU1BLENBQUNBLElBQUlBLENB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QUNBLEVBQ1RBLElBQUlBLENBQUNBO1FBRVRBLE9BQU9BLEtBQUtBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEVBQzNCQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQTtZQUVwQkEsSUFDQUEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBO1lBQ2RBLENBQ0FBO1lBQUFBLEtBQUtBLENBQUNBLENBQUNBLEtBQUtBLENBQUNBLENBQ2JBLENBQUNBO2dCQUNDQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUM1QkEsQ0FBQ0E7WUFFREEsS0FBS0EsRUFBRUEsQ0FBQ0E7WUFFUkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsR0FBR0EsUUFBUUEsQ0FBQ0EsQ0FDckJBLENBQUNBO2dCQUNDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxHQUFHQSxDQUFDQSxFQUFFQSxJQUFJQSxHQUFHQSxLQUFLQSxFQUFFQSxJQUFJQSxFQUFFQSxFQUN2Q0EsQ0FBQ0E7b0JBQ0NBLEtBQUtBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBLENBQUNBO2dCQUNwQ0EsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUNBLE1BQU1BLElBQUlBLEtBQUtBLENBQUNBO2dCQUN0QkEsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDWkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFFREEsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7SUFDbkJBLENBQUNBO0lBRURULE9BQU9BLENBQUNBLEtBQUtBLEVBQUVBLElBQUlBO1FBRWpCVSxFQUFFQSxDQUFDQSxDQUFDQSxTQUFTQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUN0QkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FB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QUFTQSxHQUFHQSxTQUFTQSxDQUFFQSxTQUFTQSxDQUFDQSxXQUFXQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUduREEsUUFBUUEsR0FBR0EsSUFBSUEsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBQ0EsRUFBRUEsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFDdERBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBO1FBQ3BCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtRQUUxQkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsVUFBVUEsQ0FBRUEsVUFBVUEsQ0FBRUEsSUFBSUEsS0FBS0EsQ0FBQ0E7UUFFckRBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFVBQVVBLENBQUNBLFFBQVFBLElBQUlBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO0lBQzVEQSxDQUFDQTtJQUVERCxJQUFXQSxRQUFRQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBQ0RGLElBQVdBLFFBQVFBLENBQUVBLFFBQWtCQTtRQUNyQ0UsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBS0RGLFFBQVFBLENBQUVBLElBQVVBO1FBRWxCRyxJQUFJQSxJQUFJQSxHQUFHQTtZQUNUQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxFQUFFQTtZQUNyQkEsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsU0FBU0E7WUFDbkNBLFFBQVFBLEVBQUVBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLElBQUlBLEtBQUtBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFNBQVNBO1lBQ3RFQSxRQUFRQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQTtTQUN4QkEsQ0FBQ0E7UUFFRkEsTUFB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QVNBLENBQUNBO0lBQ3ZGQSxDQUFDQTtJQUVEUCxJQUFJQSxRQUFRQSxDQUFFQSxJQUFVQTtRQUV0Qk8sSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0E7WUFDWEEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsRUFBRUE7WUFDckJBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ2hCQSxDQUFDQTtRQUVGQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtJQUNyQ0EsQ0FBQ0E7SUFFRFAsSUFBSUEsTUFBTUE7UUFFUlEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDcERBLENBQUNBO0lBRURSLElBQUlBLE1BQU1BO1FBRVJTLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZCQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUNyRkEsQ0FBQ0E7SUFFRFQsSUFBSUEsTUFBTUEsQ0FBRUEsSUFBVUE7UUFFcEJTLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBO1lBQ1RBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLEVBQUVBO1lBQ3JCQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQTtTQUNoQkEsQ0FBQ0E7UUFFRkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7SUFDckNBLENBQUNBO0lBRURULElBQUlBLFVBQVVBO1FBRVpVLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFdBQVdBLENBQUNBO0lBQzFCQSxDQUFDQTtB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USxFQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxJQUFJQSxRQUFTQSxDQUFDQTtZQUNuQkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFFZEEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDL0JBLENBQUNBO0lBRU1SLE9BQU9BLENBQUVBLEVBQVVBLEVBQUVBLFVBQWVBO1FBRXpDUyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUV4Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFYkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNVCxVQUFVQSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ1UsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBLENBQ2xCQSxDQUFDQTtZQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtZQUV2REEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFFekJBLElBQUlBLENBQUNB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O0lBRU1mLGFBQWFBLENBQUVBLEVBQVVBLEVBQUVBLFVBQWNBO1FBRTlDZ0IsVUFBVUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFdEJBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFVBQVVBLENBQUVBLENBQUNBO1FBRXBEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUU1QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7QUFDSGhCLENBQUNBO0FBN1BRLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBRWxDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQXVQekM7O09DMVFNLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxxQkFBcUI7QUFLdEQ7SUFVRWlCLFlBQWFBLE1BQW9CQSxFQUFFQSxTQUFvQkE7UUFDckRDLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3JCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7SUFNREQsbUJBQW1CQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsZ0JBQWdCQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUM3REEsQ0FBQ0E7QUFFSEYsQ0FBQ0E7QUFBQSIsImZpbGUiOiJjcnlwdG9ncmFwaGl4LXNpbS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNsYXNzIEhleENvZGVjXG57XG4gIHByaXZhdGUgc3RhdGljIGhleERlY29kZU1hcDogbnVtYmVyW107XG5cbiAgc3RhdGljIGRlY29kZSggYTogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmICggSGV4Q29kZWMuaGV4RGVjb2RlTWFwID09IHVuZGVmaW5lZCApXG4gICAge1xuICAgICAgdmFyIGhleCA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiO1xuICAgICAgdmFyIGFsbG93ID0gXCIgXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICB2YXIgZGVjOiBudW1iZXJbXSA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBoZXggPSBoZXgudG9Mb3dlckNhc2UoKTtcbiAgICAgIGZvciAodmFyIGkgPSAxMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgZGVjW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYWxsb3cubGVuZ3RoOyArK2kpXG4gICAgICAgICAgZGVjW2FsbG93LmNoYXJBdChpKV0gPSAtMTtcbiAgICAgIEhleENvZGVjLmhleERlY29kZU1hcCA9IGRlYztcbiAgICB9XG5cbiAgICB2YXIgb3V0OiBudW1iZXJbXSA9IFtdO1xuICAgIHZhciBiaXRzID0gMCwgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKVxuICAgIHtcbiAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgYnJlYWs7XG4gICAgICB2YXIgYiA9IEhleENvZGVjLmhleERlY29kZU1hcFtjXTtcbiAgICAgIGlmIChiID09IC0xKVxuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgaWYgKGIgPT0gdW5kZWZpbmVkKVxuICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICBiaXRzIHw9IGI7XG4gICAgICBpZiAoKytjaGFyX2NvdW50ID49IDIpIHtcbiAgICAgICAgICBvdXQucHVzaCggYml0cyApO1xuICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBiaXRzIDw8PSA0O1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChjaGFyX2NvdW50KVxuICAgICAgdGhyb3cgXCJIZXggZW5jb2RpbmcgaW5jb21wbGV0ZTogNCBiaXRzIG1pc3NpbmdcIjtcblxuICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oIG91dCApO1xuICB9XG59XG4iLCJ0eXBlIGJ5dGUgPSBudW1iZXI7XG5cbmVudW0gQkFTRTY0U1BFQ0lBTFMge1xuICBQTFVTID0gJysnLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIID0gJy8nLmNoYXJDb2RlQXQoMCksXG4gIE5VTUJFUiA9ICcwJy5jaGFyQ29kZUF0KDApLFxuICBMT1dFUiA9ICdhJy5jaGFyQ29kZUF0KDApLFxuICBVUFBFUiA9ICdBJy5jaGFyQ29kZUF0KDApLFxuICBQTFVTX1VSTF9TQUZFID0gJy0nLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIX1VSTF9TQUZFID0gJ18nLmNoYXJDb2RlQXQoMClcbn1cblxuZXhwb3J0IGNsYXNzIEJhc2U2NENvZGVjXG57XG4gIHN0YXRpYyBkZWNvZGUoIGI2NDogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmIChiNjQubGVuZ3RoICUgNCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBiYXNlNjQgc3RyaW5nLiBMZW5ndGggbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBkZWNvZGUoIGVsdDogU3RyaW5nICk6IG51bWJlclxuICAgIHtcbiAgICAgIHZhciBjb2RlID0gZWx0LmNoYXJDb2RlQXQoMCk7XG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTIHx8IGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlBMVVNfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MjsgLy8gJysnXG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSCB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSF9VUkxfU0FGRSlcbiAgICAgICAgcmV0dXJuIDYzOyAvLyAnLydcblxuICAgICAgaWYgKGNvZGUgPj0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSKVxuICAgICAge1xuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDEwKVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSICsgMjYgKyAyNjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLlVQUEVSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5VUFBFUjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLkxPV0VSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2O1xuICAgICAgfVxuXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gQ2hhcmFjdGVyIG5vdCB2YWxpZCcpO1xuICAgIH1cblxuICAgIC8vIHRoZSBudW1iZXIgb2YgZXF1YWwgc2lnbnMgKHBsYWNlIGhvbGRlcnMpXG4gICAgLy8gaWYgdGhlcmUgYXJlIHR3byBwbGFjZWhvbGRlcnMsIHRoYW4gdGhlIHR3byBjaGFyYWN0ZXJzIGJlZm9yZSBpdFxuICAgIC8vIHJlcHJlc2VudCBvbmUgYnl0ZVxuICAgIC8vIGlmIHRoZXJlIGlzIG9ubHkgb25lLCB0aGVuIHRoZSB0aHJlZSBjaGFyYWN0ZXJzIGJlZm9yZSBpdCByZXByZXNlbnQgMiBieXRlc1xuICAgIC8vIHRoaXMgaXMganVzdCBhIGNoZWFwIGhhY2sgdG8gbm90IGRvIGluZGV4T2YgdHdpY2VcbiAgICBsZXQgbGVuID0gYjY0Lmxlbmd0aDtcbiAgICBsZXQgcGxhY2VIb2xkZXJzID0gYjY0LmNoYXJBdChsZW4gLSAyKSA9PT0gJz0nID8gMiA6IGI2NC5jaGFyQXQobGVuIC0gMSkgPT09ICc9JyA/IDEgOiAwO1xuXG4gICAgLy8gYmFzZTY0IGlzIDQvMyArIHVwIHRvIHR3byBjaGFyYWN0ZXJzIG9mIHRoZSBvcmlnaW5hbCBkYXRhXG4gICAgbGV0IGFyciA9IG5ldyBVaW50OEFycmF5KCBiNjQubGVuZ3RoICogMyAvIDQgLSBwbGFjZUhvbGRlcnMgKTtcblxuICAgIC8vIGlmIHRoZXJlIGFyZSBwbGFjZWhvbGRlcnMsIG9ubHkgZ2V0IHVwIHRvIHRoZSBsYXN0IGNvbXBsZXRlIDQgY2hhcnNcbiAgICBsZXQgbCA9IHBsYWNlSG9sZGVycyA+IDAgPyBiNjQubGVuZ3RoIC0gNCA6IGI2NC5sZW5ndGg7XG5cbiAgICB2YXIgTCA9IDA7XG5cbiAgICBmdW5jdGlvbiBwdXNoICh2OiBieXRlKSB7XG4gICAgICBhcnJbTCsrXSA9IHY7XG4gICAgfVxuXG4gICAgbGV0IGkgPSAwLCBqID0gMDtcblxuICAgIGZvciAoOyBpIDwgbDsgaSArPSA0LCBqICs9IDMpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDE4KSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDEyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMikpIDw8IDYpIHwgZGVjb2RlKGI2NC5jaGFyQXQoaSArIDMpKTtcbiAgICAgIHB1c2goKHRtcCAmIDB4RkYwMDAwKSA+PiAxNik7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDApID4+IDgpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICBpZiAocGxhY2VIb2xkZXJzID09PSAyKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpID4+IDQpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9IGVsc2UgaWYgKHBsYWNlSG9sZGVycyA9PT0gMSkge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMTApIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPDwgNCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA+PiAyKTtcbiAgICAgIHB1c2goKHRtcCA+PiA4KSAmIDB4RkYpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXJyO1xuICB9XG5cbiAgc3RhdGljIGVuY29kZSggdWludDg6IFVpbnQ4QXJyYXkgKTogc3RyaW5nXG4gIHtcbiAgICB2YXIgaTogbnVtYmVyO1xuICAgIHZhciBleHRyYUJ5dGVzID0gdWludDgubGVuZ3RoICUgMzsgLy8gaWYgd2UgaGF2ZSAxIGJ5dGUgbGVmdCwgcGFkIDIgYnl0ZXNcbiAgICB2YXIgb3V0cHV0ID0gJyc7XG5cbiAgICBjb25zdCBsb29rdXAgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLyc7XG4gICAgZnVuY3Rpb24gZW5jb2RlKCBudW06IGJ5dGUgKSB7XG4gICAgICByZXR1cm4gbG9va3VwLmNoYXJBdChudW0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyaXBsZXRUb0Jhc2U2NCggbnVtOiBudW1iZXIgKSB7XG4gICAgICByZXR1cm4gZW5jb2RlKG51bSA+PiAxOCAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiAxMiAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiA2ICYgMHgzRikgKyBlbmNvZGUobnVtICYgMHgzRik7XG4gICAgfVxuXG4gICAgLy8gZ28gdGhyb3VnaCB0aGUgYXJyYXkgZXZlcnkgdGhyZWUgYnl0ZXMsIHdlJ2xsIGRlYWwgd2l0aCB0cmFpbGluZyBzdHVmZiBsYXRlclxuICAgIGxldCBsZW5ndGggPSB1aW50OC5sZW5ndGggLSBleHRyYUJ5dGVzO1xuICAgIGZvciAoaSA9IDA7IGkgPCBsZW5ndGg7IGkgKz0gMykge1xuICAgICAgbGV0IHRlbXAgPSAodWludDhbaV0gPDwgMTYpICsgKHVpbnQ4W2kgKyAxXSA8PCA4KSArICh1aW50OFtpICsgMl0pO1xuICAgICAgb3V0cHV0ICs9IHRyaXBsZXRUb0Jhc2U2NCh0ZW1wKTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIGVuZCB3aXRoIHplcm9zLCBidXQgbWFrZSBzdXJlIHRvIG5vdCBmb3JnZXQgdGhlIGV4dHJhIGJ5dGVzXG4gICAgc3dpdGNoIChleHRyYUJ5dGVzKSB7XG4gICAgICBjYXNlIDE6XG4gICAgICAgIGxldCB0ZW1wID0gdWludDhbdWludDgubGVuZ3RoIC0gMV07XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAyKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCA0KSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz09JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgdGVtcCA9ICh1aW50OFt1aW50OC5sZW5ndGggLSAyXSA8PCA4KSArICh1aW50OFt1aW50OC5sZW5ndGggLSAxXSk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAxMCk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPj4gNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCAyKSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz0nO1xuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSGV4Q29kZWMgfSBmcm9tICcuL2hleC1jb2RlYyc7XG5pbXBvcnQgeyBCYXNlNjRDb2RlYyB9IGZyb20gJy4vYmFzZTY0LWNvZGVjJztcblxuZXhwb3J0IGVudW0gQnl0ZUVuY29kaW5nIHtcbiAgUkFXLFxuICBIRVgsXG4gIEJBU0U2NCxcbiAgVVRGOFxufVxuXG5leHBvcnQgY2xhc3MgQnl0ZUFycmF5IC8vZXh0ZW5kcyBVaW50OEFycmF5XG57XG4gIHB1YmxpYyBzdGF0aWMgUkFXID0gQnl0ZUVuY29kaW5nLlJBVztcbiAgcHVibGljIHN0YXRpYyBIRVggPSBCeXRlRW5jb2RpbmcuSEVYO1xuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XG4gIHB1YmxpYyBzdGF0aWMgVVRGOCA9IEJ5dGVFbmNvZGluZy5VVEY4O1xuXG4gIHN0YXRpYyBlbmNvZGluZ1RvU3RyaW5nKCBlbmNvZGluZzogQnl0ZUVuY29kaW5nICk6IHN0cmluZyB7XG4gICAgc3dpdGNoKCBlbmNvZGluZyApIHtcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkJBU0U2NDpcbiAgICAgICAgcmV0dXJuICdCQVNFNjQnO1xuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuVVRGODpcbiAgICAgICAgcmV0dXJuICdVVEY4JztcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkhFWDpcbiAgICAgICAgcmV0dXJuICdIRVgnO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuICdSQVcnO1xuICAgIH1cbiAgfVxuXG4gIHN0YXRpYyBzdHJpbmdUb0VuY29kaW5nKCBlbmNvZGluZzogc3RyaW5nICk6IEJ5dGVFbmNvZGluZyB7XG4gICAgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdCQVNFNjQnIClcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuQkFTRTY0O1xuICAgIGVsc2UgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdVVEY4JyApXG4gICAgICByZXR1cm4gQnl0ZUVuY29kaW5nLlVURjg7XG4gICAgZWxzZSBpZiAoIGVuY29kaW5nLnRvVXBwZXJDYXNlKCkgPT0gJ0hFWCcgKVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5IRVg7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5SQVc7XG4gIH1cblxuXG4gIHByaXZhdGUgYnl0ZUFycmF5OiBVaW50OEFycmF5O1xuICAvKipcbiAgICogQ3JlYXRlIGEgQnl0ZUFycmF5XG4gICAqIEBwYXJhbSBieXRlcyAtIGluaXRpYWwgY29udGVudHMsIG9wdGlvbmFsXG4gICAqICAgbWF5IGJlOlxuICAgKiAgICAgYW4gZXhpc3RpbmcgQnl0ZUFycmF5XG4gICAqICAgICBhbiBBcnJheSBvZiBudW1iZXJzICgwLi4yNTUpXG4gICAqICAgICBhIHN0cmluZywgdG8gYmUgY29udmVydGVkXG4gICAqICAgICBhbiBBcnJheUJ1ZmZlclxuICAgKiAgICAgYSBVaW50OEFycmF5XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYnl0ZXM/OiBCeXRlQXJyYXkgfCBBcnJheTxudW1iZXI+IHwgU3RyaW5nIHwgQXJyYXlCdWZmZXIgfCBVaW50OEFycmF5LCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGlmICggIWJ5dGVzIClcbiAgICB7XG4gICAgICAvLyB6ZXJvLWxlbmd0aCBhcnJheVxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggMCApO1xuICAgIH1cbiAgICBlbHNlIGlmICggIWVuY29kaW5nIHx8IGVuY29kaW5nID09IEJ5dGVFbmNvZGluZy5SQVcgKVxuICAgIHtcbiAgICAgIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlciApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxBcnJheUJ1ZmZlcj5ieXRlcyApO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgVWludDhBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYnl0ZXM7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzLmJ5dGVBcnJheTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIEFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggYnl0ZXMgKTtcbiAgICAgIC8vZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICAgIC8ve1xuLy8gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIC8vfVxuICAgIH1cbiAgICBlbHNlIGlmICggdHlwZW9mIGJ5dGVzID09IFwic3RyaW5nXCIgKVxuICAgIHtcbiAgICAgIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLkJBU0U2NCApXG4gICAgICB7XG4gICAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBCYXNlNjRDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuSEVYIClcbiAgICAgIHtcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBIZXhDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuVVRGOCApXG4gICAgICB7XG4gICAgICAgIGxldCBsID0gKCA8c3RyaW5nPmJ5dGVzICkubGVuZ3RoO1xuICAgICAgICBsZXQgYmEgPSBuZXcgVWludDhBcnJheSggbCApO1xuICAgICAgICBmb3IoIGxldCBpID0gMDsgaSA8IGw7ICsraSApXG4gICAgICAgICAgYmFbaV0gPSAoIDxzdHJpbmc+Ynl0ZXMgKS5jaGFyQ29kZUF0KCBpICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBiYTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBNdXN0IGhhdmUgZXhlYyBvbmUgb2YgYWJvdmUgYWxsb2NhdG9yc1xuICAgIGlmICggIXRoaXMuYnl0ZUFycmF5IClcbiAgICB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiSW52YWxpZCBQYXJhbXMgZm9yIEJ5dGVBcnJheSgpXCIpXG4gICAgfVxuICB9XG5cbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XG4gIH1cblxuICBzZXQgbGVuZ3RoKCBsZW46IG51bWJlciApXG4gIHtcbiAgICBpZiAoIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCA+PSBsZW4gKVxuICAgIHtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdGhpcy5ieXRlQXJyYXkuc2xpY2UoIDAsIGxlbiApO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbGV0IG9sZCA9IHRoaXMuYnl0ZUFycmF5O1xuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG4gICAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIG9sZCwgMCApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBiYWNraW5nQXJyYXkoKTogVWludDhBcnJheVxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5O1xuICB9XG5cbiAgZXF1YWxzKCB2YWx1ZTogQnl0ZUFycmF5ICk6IGJvb2xlYW5cbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG4gICAgdmFyIG9rID0gKCBiYS5sZW5ndGggPT0gdmJhLmxlbmd0aCApO1xuXG4gICAgaWYgKCBvayApXG4gICAge1xuICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICAgIG9rID0gb2sgJiYgKCBiYVtpXSA9PSB2YmFbaV0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gb2s7XG4gIH1cblxuICAvKipcbiAgICAqIGdldCBieXRlIGF0IG9mZnNldFxuICAgICovXG4gIGJ5dGVBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdO1xuICB9XG5cbiAgd29yZEF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gPDwgIDggKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gICAgICAgKTtcbiAgfVxuXG4gIGxpdHRsZUVuZGlhbldvcmRBdCggb2Zmc2V0ICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAgOCApO1xuICB9XG5cbiAgZHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8IDI0IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdIDw8IDE2IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMiBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMyBdICAgICAgICk7XG4gIH1cblxuICAvKipcbiAgICAqIHNldCBieXRlIGF0IG9mZnNldFxuICAgICogQGZsdWVudFxuICAgICovXG4gIHNldEJ5dGVBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0IF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0Qnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIHZhbHVlLmJ5dGVBcnJheSwgb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGNsb25lKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEV4dHJhY3QgYSBzZWN0aW9uIChvZmZzZXQsIGNvdW50KSBmcm9tIHRoZSBCeXRlQXJyYXlcbiAgKiBAZmx1ZW50XG4gICogQHJldHVybnMgYSBuZXcgQnl0ZUFycmF5IGNvbnRhaW5pbmcgYSBzZWN0aW9uLlxuICAqL1xuICBieXRlc0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIENyZWF0ZSBhIHZpZXcgaW50byB0aGUgQnl0ZUFycmF5XG4gICpcbiAgKiBAcmV0dXJucyBhIEJ5dGVBcnJheSByZWZlcmVuY2luZyBhIHNlY3Rpb24gb2Ygb3JpZ2luYWwgQnl0ZUFycmF5LlxuICAqL1xuICB2aWV3QXQoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIGlmICggIU51bWJlci5pc0ludGVnZXIoIGNvdW50ICkgKVxuICAgICAgY291bnQgPSAoIHRoaXMubGVuZ3RoIC0gb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gbmV3IEJ5dGVBcnJheSggdGhpcy5ieXRlQXJyYXkuc3ViYXJyYXkoIG9mZnNldCwgb2Zmc2V0ICsgY291bnQgKSApO1xuICB9XG5cbiAgLyoqXG4gICogQXBwZW5kIGJ5dGVcbiAgKiBAZmx1ZW50XG4gICovXG4gIGFkZEJ5dGUoIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgdGhpcy5ieXRlQXJyYXkubGVuZ3RoIF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0TGVuZ3RoKCBsZW46IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIHRoaXMubGVuZ3RoID0gbGVuO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjb25jYXQoIGJ5dGVzOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJhLmxlbmd0aCArIGJ5dGVzLmxlbmd0aCApO1xuXG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBiYSApO1xuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYnl0ZXMuYnl0ZUFycmF5LCBiYS5sZW5ndGggKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgbm90KCApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4weEZGO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBhbmQoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldICYgdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSB8IHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB4b3IoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4gdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHRvU3RyaW5nKCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGxldCBzID0gXCJcIjtcbiAgICBsZXQgaSA9IDA7XG5cbiAgICBzd2l0Y2goIGVuY29kaW5nIHx8IEJ5dGVFbmNvZGluZy5IRVggKSB7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5IRVg6XG4gICAgICAgIC8vcmV0dXJuIEhleENvZGVjLmVuY29kZSggdGhpcy5ieXRlQXJyYXkgKTtcbiAgICAgICAgZm9yKCBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyArK2kgKVxuICAgICAgICAgIHMgKz0gKCBcIjBcIiArIHRoaXMuYnl0ZUFycmF5WyBpIF0udG9TdHJpbmcoIDE2ICkpLnNsaWNlKCAtMiApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuQkFTRTY0OlxuICAgICAgICByZXR1cm4gQmFzZTY0Q29kZWMuZW5jb2RlKCB0aGlzLmJ5dGVBcnJheSApO1xuXG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5VVEY4OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHJldHVybiBzO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgZW51bSBDcnlwdG9ncmFwaGljT3BlcmF0aW9uIHtcbiAgRU5DUllQVCxcbiAgREVDUllQVCxcbiAgRElHRVNULFxuICBTSUdOLFxuICBWRVJJRlksXG4gIERFUklWRV9CSVRTLFxuXG4gIERFUklWRV9LRVksXG4gIElNUE9SVF9LRVksXG4gIEVYUE9SVF9LRVksXG4gIEdFTkVSQVRFX0tFWSxcbiAgV1JBUF9LRVksXG4gIFVOV1JBUF9LRVksXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBlbmNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuICBkZWNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIGRpZ2VzdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIHNpZ24/KCBhbGdvcml0aG06IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG4gIHZlcmlmeT8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG5cbiAgZGVyaXZlQml0cz8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGxlbmd0aDogbnVtYmVyICk6IFByb21pc2U8Qnl0ZUFycmF5Pjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yIHtcbiAgbmV3KCk6IENyeXB0b2dyYXBoaWNTZXJ2aWNlO1xuXG4gIHN1cHBvcnRlZE9wZXJhdGlvbnM/OiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBkZXJpdmVLZXk/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG5cbiAgd3JhcEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSwgd3JhcHBpbmdLZXk6IENyeXB0b0tleSwgd3JhcEFsZ29yaXRobTogQWxnb3JpdGhtICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcbiAgdW53cmFwS2V5PyggZm9ybWF0OiBzdHJpbmcsIHdyYXBwZWRLZXk6IEJ5dGVBcnJheSwgdW53cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB1bndyYXBBbGdvcml0aG06IEFsZ29yaXRobSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuXG4gIGltcG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG4gIGdlbmVyYXRlS2V5PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj47XG4gIGV4cG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3RvciB7XG4gIG5ldygpOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZTtcblxuICBzdXBwb3J0ZWRPcGVyYXRpb25zPzogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdO1xufVxuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSB7XG4gIHByaXZhdGUgX3NlcnZpY2VNYXA6IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3I+O1xuICBwcml2YXRlIF9rZXlTZXJ2aWNlTWFwOiBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPjtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLl9zZXJ2aWNlTWFwID0gbmV3IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNTZXJ2aWNlQ29uc3RydWN0b3I+KCk7XG4gICAgdGhpcy5fa2V5U2VydmljZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPigpO1xuICB9XG5cbiAgZ2V0U2VydmljZSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0gKTogeyBuYW1lOiBzdHJpbmcsIGluc3RhbmNlOiBDcnlwdG9ncmFwaGljU2VydmljZSB9IHtcbiAgICBsZXQgYWxnbyA9ICggYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0ICkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICBsZXQgc2VydmljZSA9IHRoaXMuX3NlcnZpY2VNYXAuZ2V0KCBhbGdvICk7XG5cbiAgICByZXR1cm4geyBuYW1lOiBhbGdvLCBpbnN0YW5jZTogc2VydmljZSA/IG5ldyBzZXJ2aWNlKCkgOiBudWxsIH07XG4gIH1cblxuICBnZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSApOiB7IG5hbWU6IHN0cmluZywgaW5zdGFuY2U6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0ge1xuICAgIGxldCBhbGdvID0gKCBhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QgKSA/ICg8QWxnb3JpdGhtPmFsZ29yaXRobSkubmFtZSA6IDxzdHJpbmc+YWxnb3JpdGhtO1xuICAgIGxldCBzZXJ2aWNlID0gdGhpcy5fa2V5U2VydmljZU1hcC5nZXQoIGFsZ28gKTtcblxuICAgIHJldHVybiB7IG5hbWU6IGFsZ28sIGluc3RhbmNlOiBzZXJ2aWNlID8gbmV3IHNlcnZpY2UoKSA6IG51bGwgfTtcbiAgfVxuXG4gIHNldFNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fc2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG4gIHNldEtleVNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fa2V5U2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgLy8gc2luZ2xldG9uIHJlZ2lzdHJ5XG4gIHByaXZhdGUgc3RhdGljIF9yZWdpc3RyeTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSA9IG5ldyBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5KCk7XG5cbiAgcHVibGljIHN0YXRpYyByZWdpc3RlclNlcnZpY2UoIG5hbWU6IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLl9yZWdpc3RyeS5zZXRTZXJ2aWNlKCBuYW1lLCBjdG9yLCBvcGVycyApO1xuICB9XG4gIHB1YmxpYyBzdGF0aWMgcmVnaXN0ZXJLZXlTZXJ2aWNlKCBuYW1lOiBzdHJpbmcsIGN0b3I6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3IsIG9wZXJzOiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW10gKSB7XG4gICAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnkuc2V0S2V5U2VydmljZSggbmFtZSwgY3Rvciwgb3BlcnMgKTtcbiAgfVxuXG4gIGdldCByZWdpc3RyeSgpOiBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5IHtcbiAgICByZXR1cm4gQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnk7XG4gIH1cblxuICBlbmNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmVuY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5lbmNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5kZWNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kaWdlc3QgKVxuICAgICAgPyBpbnN0YW5jZS5kaWdlc3QoIG5hbWUsIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBzaWduKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2Uuc2lnbiApXG4gICAgICA/IGluc3RhbmNlLnNpZ24oIG5hbWUsIGtleSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIHZlcmlmeShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UudmVyaWZ5IClcbiAgICAgID8gaW5zdGFuY2UudmVyaWZ5KCBuYW1lLCBrZXksIHNpZ25hdHVyZSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSgga2V5LmFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZXhwb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuZXhwb3J0S2V5KCBmb3JtYXQsIGtleSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGdlbmVyYXRlS2V5KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5nZW5lcmF0ZUtleSApXG4gICAgICA/IGluc3RhbmNlLmdlbmVyYXRlS2V5KCBuYW1lLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oIFwiXCIgKTtcbiAgfVxuXG4gIGltcG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSAsIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuaW1wb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuaW1wb3J0S2V5KCBmb3JtYXQsIGtleURhdGEsIG5hbWUsIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxDcnlwdG9LZXk+KCBcIlwiICk7XG4gIH1cblxuICBkZXJpdmVLZXkoIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGRlcml2ZWRLZXlUeXBlOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZXJpdmVLZXkgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVLZXkoIG5hbWUsIGJhc2VLZXksIGRlcml2ZWRLZXlUeXBlLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG5cbiAgZGVyaXZlQml0cyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgbGVuZ3RoOiBudW1iZXIgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlcml2ZUJpdHMgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVCaXRzKCBuYW1lLCBiYXNlS2V5LCBsZW5ndGggKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB3cmFwS2V5KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IEFsZ29yaXRobSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGtleS5hbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS53cmFwS2V5KCBmb3JtYXQsIGtleSwgd3JhcHBpbmdLZXksIHdyYXBBbGdvcml0aG0gKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB1bndyYXBLZXkoIGZvcm1hdDogc3RyaW5nLCB3cmFwcGVkS2V5OiBCeXRlQXJyYXksIHVud3JhcHBpbmdLZXk6IENyeXB0b0tleSwgdW53cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0sIHVud3JhcHBlZEtleUFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggdW53cmFwQWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS51bndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS51bndyYXBLZXkoIGZvcm1hdCwgd3JhcHBlZEtleSwgdW53cmFwcGluZ0tleSwgbmFtZSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiwgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0gZnJvbSAnLi9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnknO1xuXG5kZWNsYXJlIHZhciBtc3JjcnlwdG87XG5cbmV4cG9ydCBjbGFzcyBXZWJDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgcHJvdGVjdGVkIGNyeXB0bzogU3VidGxlQ3J5cHRvO1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICB9XG5cbiAgc3RhdGljIF9zdWJ0bGU6IFN1YnRsZUNyeXB0bztcbiAgc3RhdGljIGdldCBzdWJ0bGUoKTogU3VidGxlQ3J5cHRvIHtcbiAgICBsZXQgc3VidGxlID0gV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlXG4gICAgICB8fCAoIGNyeXB0byAmJiBjcnlwdG8uc3VidGxlIClcbiAgICAgIHx8ICggd2luZG93ICYmIHdpbmRvdy5jcnlwdG8gJiYgd2luZG93LmNyeXB0by5zdWJ0bGUgKVxuICAgICAgfHwgbXNyY3J5cHRvO1xuXG4gICAgaWYgKCAhV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlIClcbiAgICAgICBXZWJDcnlwdG9TZXJ2aWNlLl9zdWJ0bGUgPSBzdWJ0bGU7XG5cbiAgICByZXR1cm4gc3VidGxlO1xuICB9XG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5lbmNyeXB0KGFsZ29yaXRobSwga2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmRlY3J5cHQoYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZGlnZXN0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkpOiBhbnkge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZXhwb3J0S2V5KGZvcm1hdCwga2V5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZ2VuZXJhdGVLZXkoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuXG4gICB9KTtcbiAgfVxuXG4gIGltcG9ydEtleShmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5LCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmltcG9ydEtleShmb3JtYXQsIGtleURhdGEuYmFja2luZ0FycmF5LCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShyZXMpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICB9KTtcbiAgfVxuXG4gIHNpZ24oYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLnNpZ24oYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgdmVyaWZ5KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUudmVyaWZ5KGFsZ29yaXRobSwga2V5LCBzaWduYXR1cmUuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxufVxuXG4vKmNsYXNzIFNIQTFDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBkaWdlc3QoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBUT0RPOiBJbXBsZW1lbnQgU0hBLTFcbiAgICAgIG1zcmNyeXB0by5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cbn1cblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtMScsIFNIQTFDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtMjU2JywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRJR0VTVCBdICk7XG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS01MTInLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcbiovXG5cbmlmICggV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUgKSB7XG4gIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnQUVTLUNCQycsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQgXSApO1xuICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ0FFUy1HQ00nLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ERUNSWVBUIF0gKTtcbiAgLy9DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1JTQVNTQS1YWVonLCBXZWJDcnlwdG9TZXJ2aWNlICk7XG5cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJy4uL2tpbmQvYnl0ZS1hcnJheSc7XG5pbXBvcnQgeyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLCBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2UgfSBmcm9tICcuL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeSc7XG5cbmNsYXNzIERFU1NlY3JldEtleSBpbXBsZW1lbnRzIENyeXB0b0tleSB7XG4gIHByaXZhdGUgX2tleU1hdGVyaWFsOiBCeXRlQXJyYXk7XG4gIHByaXZhdGUgX2V4dHJhY3RhYmxlOiBib29sZWFuO1xuICBwcml2YXRlIF9hbGdvcml0aG06IEtleUFsZ29yaXRobTtcbiAgcHJpdmF0ZSBfdHlwZTogc3RyaW5nO1xuICBwcml2YXRlIF91c2FnZXM6IHN0cmluZ1tdO1xuXG4gIGNvbnN0cnVjdG9yKCBrZXlNYXRlcmlhbDogQnl0ZUFycmF5LCBhbGdvcml0aG06IEtleUFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIHVzYWdlczogc3RyaW5nW10gKSB7XG5cbiAgICB0aGlzLl9rZXlNYXRlcmlhbCA9IGtleU1hdGVyaWFsO1xuXG4gICAgdGhpcy5fYWxnb3JpdGhtID0gYWxnb3JpdGhtO1xuXG4gICAgdGhpcy5fZXh0cmFjdGFibGUgPSBleHRyYWN0YWJsZTtcblxuICAgIHRoaXMuX3R5cGUgPSAnc2VjcmV0JztcblxuICAgIHRoaXMuX3VzYWdlcyA9IHVzYWdlcztcbiAgICBPYmplY3QuZnJlZXplKCB0aGlzLl91c2FnZXMgKTtcbiAgfVxuXG4gIGdldCBhbGdvcml0aG0oKSB7IHJldHVybiB0aGlzLl9hbGdvcml0aG07IH1cbiAgZ2V0IGV4dHJhY3RhYmxlKCk6IGJvb2xlYW4geyByZXR1cm4gdGhpcy5fZXh0cmFjdGFibGU7IH1cbiAgZ2V0IHR5cGUoKSB7IHJldHVybiB0aGlzLl90eXBlOyB9XG4gIGdldCB1c2FnZXMoKTogc3RyaW5nW10geyByZXR1cm4gQXJyYXkuZnJvbSggdGhpcy5fdXNhZ2VzICk7IH1cblxuICBnZXQga2V5TWF0ZXJpYWwoKSB7IHJldHVybiB0aGlzLl9rZXlNYXRlcmlhbCB9O1xufVxuXG5leHBvcnQgY2xhc3MgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UgaW1wbGVtZW50cyBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgfVxuXG4gIGVuY3J5cHQoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGRlc0tleSA9IGtleSBhcyBERVNTZWNyZXRLZXk7XG5cbiAgICAgIHJlc29sdmUoIG5ldyBCeXRlQXJyYXkoIHRoaXMuZGVzKCBkZXNLZXkua2V5TWF0ZXJpYWwuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSwgMSwgMCApICkgKTtcbiAgICB9KTtcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGRlc0tleSA9IGtleSBhcyBERVNTZWNyZXRLZXk7XG5cbiAgICAgIHJlc29sdmUoIG5ldyBCeXRlQXJyYXkoIHRoaXMuZGVzKCBkZXNLZXkua2V5TWF0ZXJpYWwuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSwgMCwgMCApICkgKTtcbiAgICAgIC8vY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBpbXBvcnRLZXkoZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSwgYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q3J5cHRvS2V5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgZGVzS2V5ID0gbmV3IERFU1NlY3JldEtleSgga2V5RGF0YSwgYWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzICk7XG5cbiAgICAgIHJlc29sdmUoIGRlc0tleSApO1xuICAgfSk7XG4gIH1cblxuICBzaWduKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGRlc0tleSA9IGtleSBhcyBERVNTZWNyZXRLZXk7XG5cbiAgICAgIHJlc29sdmUoIG5ldyBCeXRlQXJyYXkoIHRoaXMuZGVzKCBkZXNLZXkua2V5TWF0ZXJpYWwuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSwgMCwgMCApICkgKTtcbiAgICAgIC8vY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBzdGF0aWMgZGVzUEM7XG4gIHN0YXRpYyBkZXNTUDtcblxuICBwcml2YXRlIGRlcygga2V5OiBVaW50OEFycmF5LCBtZXNzYWdlOiBVaW50OEFycmF5LCBlbmNyeXB0OiBudW1iZXIsIG1vZGU6IG51bWJlciwgaXY/OiBVaW50OEFycmF5LCBwYWRkaW5nPzogbnVtYmVyICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIC8vZGVzX2NyZWF0ZUtleXNcbiAgICAvL3RoaXMgdGFrZXMgYXMgaW5wdXQgYSA2NCBiaXQga2V5IChldmVuIHRob3VnaCBvbmx5IDU2IGJpdHMgYXJlIHVzZWQpXG4gICAgLy9hcyBhbiBhcnJheSBvZiAyIGludGVnZXJzLCBhbmQgcmV0dXJucyAxNiA0OCBiaXQga2V5c1xuICAgIGZ1bmN0aW9uIGRlc19jcmVhdGVLZXlzIChrZXkpXG4gICAge1xuICAgICAgbGV0IGRlc1BDID0gREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzUEM7XG5cbiAgICAgIGlmICggIWRlc1BDIClcbiAgICAgIHtcbiAgICAgICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICAgICAgZGVzUEMgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNQQyA9IHtcbiAgICAgICAgICBwYzJieXRlczAgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgyMDAwMDAwMCwweDIwMDAwMDA0LDB4MTAwMDAsMHgxMDAwNCwweDIwMDEwMDAwLDB4MjAwMTAwMDQsMHgyMDAsMHgyMDQsMHgyMDAwMDIwMCwweDIwMDAwMjA0LDB4MTAyMDAsMHgxMDIwNCwweDIwMDEwMjAwLDB4MjAwMTAyMDQgXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MSwweDEwMDAwMCwweDEwMDAwMSwweDQwMDAwMDAsMHg0MDAwMDAxLDB4NDEwMDAwMCwweDQxMDAwMDEsMHgxMDAsMHgxMDEsMHgxMDAxMDAsMHgxMDAxMDEsMHg0MDAwMTAwLDB4NDAwMDEwMSwweDQxMDAxMDAsMHg0MTAwMTAxXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDgsMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAwMDAwLDB4ODAwMDAwMCwweDgyMDAwMDAsMHgyMDAwLDB4MjAyMDAwLDB4ODAwMjAwMCwweDgyMDIwMDAsMHgyMDAwMCwweDIyMDAwMCwweDgwMjAwMDAsMHg4MjIwMDAwLDB4MjIwMDAsMHgyMjIwMDAsMHg4MDIyMDAwLDB4ODIyMjAwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczQgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwLDB4MTAwMCwweDQxMDAwLDB4MTAxMCwweDQxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwLDB4MjAsMHg0MjAsMCwweDQwMCwweDIwLDB4NDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjBdICksXG4gICAgICAgICAgcGMyYnl0ZXM2IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyLDAsMHgxMDAwMDAwMCwweDgwMDAwLDB4MTAwODAwMDAsMHgyLDB4MTAwMDAwMDIsMHg4MDAwMiwweDEwMDgwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNyA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAsMHg4MDAsMHgxMDgwMCwweDIwMDAwMDAwLDB4MjAwMTAwMDAsMHgyMDAwMDgwMCwweDIwMDEwODAwLDB4MjAwMDAsMHgzMDAwMCwweDIwODAwLDB4MzA4MDAsMHgyMDAyMDAwMCwweDIwMDMwMDAwLDB4MjAwMjA4MDAsMHgyMDAzMDgwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczggOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMDAwLDAsMHg0MDAwMCwweDIsMHg0MDAwMiwweDIsMHg0MDAwMiwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAyLDB4MjA0MDAwMiwweDIwMDAwMDIsMHgyMDQwMDAyXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOSA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMCwwLDB4MjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgxMDAwMDAsMHgxMDAwMjAsMHgyMDAwLDB4MjAyMCwweDIwMDAsMHgyMDIwLDB4MTAyMDAwLDB4MTAyMDIwLDB4MTAyMDAwLDB4MTAyMDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTE6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMCwweDIwMCwweDEwMDAyMDAsMHgyMDAwMDAsMHgxMjAwMDAwLDB4MjAwMjAwLDB4MTIwMDIwMCwweDQwMDAwMDAsMHg1MDAwMDAwLDB4NDAwMDIwMCwweDUwMDAyMDAsMHg0MjAwMDAwLDB4NTIwMDAwMCwweDQyMDAyMDAsMHg1MjAwMjAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTI6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMCwweDgwMDAwMDAsMHg4MDAxMDAwLDB4ODAwMDAsMHg4MTAwMCwweDgwODAwMDAsMHg4MDgxMDAwLDB4MTAsMHgxMDEwLDB4ODAwMDAxMCwweDgwMDEwMTAsMHg4MDAxMCwweDgxMDEwLDB4ODA4MDAxMCwweDgwODEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMzogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MTAwLDB4MTA0LDAsMHg0LDB4MTAwLDB4MTA0LDB4MSwweDUsMHgxMDEsMHgxMDUsMHgxLDB4NSwweDEwMSwweDEwNV0gKVxuICAgICAgICB9O1xuICAgICAgfVxuXG4gICAgICAvL2hvdyBtYW55IGl0ZXJhdGlvbnMgKDEgZm9yIGRlcywgMyBmb3IgdHJpcGxlIGRlcylcbiAgICAgIHZhciBpdGVyYXRpb25zID0ga2V5Lmxlbmd0aCA+IDggPyAzIDogMTsgLy9jaGFuZ2VkIGJ5IFBhdWwgMTYvNi8yMDA3IHRvIHVzZSBUcmlwbGUgREVTIGZvciA5KyBieXRlIGtleXNcbiAgICAgIC8vc3RvcmVzIHRoZSByZXR1cm4ga2V5c1xuICAgICAgdmFyIGtleXMgPSBuZXcgVWludDMyQXJyYXkoMzIgKiBpdGVyYXRpb25zKTtcbiAgICAgIC8vbm93IGRlZmluZSB0aGUgbGVmdCBzaGlmdHMgd2hpY2ggbmVlZCB0byBiZSBkb25lXG4gICAgICB2YXIgc2hpZnRzID0gWyAwLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwLCAxLCAxLCAxLCAxLCAxLCAxLCAwIF07XG4gICAgICAvL290aGVyIHZhcmlhYmxlc1xuICAgICAgdmFyIGxlZnR0ZW1wLCByaWdodHRlbXAsIG09MCwgbj0wLCB0ZW1wO1xuXG4gICAgICBmb3IgKHZhciBqPTA7IGo8aXRlcmF0aW9uczsgaisrKVxuICAgICAgeyAvL2VpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuICAgICAgICBsZWZ0ID0gIChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG4gICAgICAgIHJpZ2h0ID0gKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcblxuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDIpIF4gcmlnaHQpICYgMHgzMzMzMzMzMzsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAyKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgICAvL3RoZSByaWdodCBzaWRlIG5lZWRzIHRvIGJlIHNoaWZ0ZWQgYW5kIHRvIGdldCB0aGUgbGFzdCBmb3VyIGJpdHMgb2YgdGhlIGxlZnQgc2lkZVxuICAgICAgICB0ZW1wID0gKGxlZnQgPDwgOCkgfCAoKHJpZ2h0ID4+PiAyMCkgJiAweDAwMDAwMGYwKTtcbiAgICAgICAgLy9sZWZ0IG5lZWRzIHRvIGJlIHB1dCB1cHNpZGUgZG93blxuICAgICAgICBsZWZ0ID0gKHJpZ2h0IDw8IDI0KSB8ICgocmlnaHQgPDwgOCkgJiAweGZmMDAwMCkgfCAoKHJpZ2h0ID4+PiA4KSAmIDB4ZmYwMCkgfCAoKHJpZ2h0ID4+PiAyNCkgJiAweGYwKTtcbiAgICAgICAgcmlnaHQgPSB0ZW1wO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlc2Ugc2hpZnRzIG9uIHRoZSBsZWZ0IGFuZCByaWdodCBrZXlzXG4gICAgICAgIGZvciAodmFyIGk9MDsgaSA8IHNoaWZ0cy5sZW5ndGg7IGkrKylcbiAgICAgICAge1xuICAgICAgICAgIC8vc2hpZnQgdGhlIGtleXMgZWl0aGVyIG9uZSBvciB0d28gYml0cyB0byB0aGUgbGVmdFxuICAgICAgICAgIGlmIChzaGlmdHNbaV0pXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDIpIHwgKGxlZnQgPj4+IDI2KTsgcmlnaHQgPSAocmlnaHQgPDwgMikgfCAocmlnaHQgPj4+IDI2KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgZWxzZVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAyNyk7IHJpZ2h0ID0gKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAyNyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGxlZnQgJj0gLTB4ZjsgcmlnaHQgJj0gLTB4ZjtcblxuICAgICAgICAgIC8vbm93IGFwcGx5IFBDLTIsIGluIHN1Y2ggYSB3YXkgdGhhdCBFIGlzIGVhc2llciB3aGVuIGVuY3J5cHRpbmcgb3IgZGVjcnlwdGluZ1xuICAgICAgICAgIC8vdGhpcyBjb252ZXJzaW9uIHdpbGwgbG9vayBsaWtlIFBDLTIgZXhjZXB0IG9ubHkgdGhlIGxhc3QgNiBiaXRzIG9mIGVhY2ggYnl0ZSBhcmUgdXNlZFxuICAgICAgICAgIC8vcmF0aGVyIHRoYW4gNDggY29uc2VjdXRpdmUgYml0cyBhbmQgdGhlIG9yZGVyIG9mIGxpbmVzIHdpbGwgYmUgYWNjb3JkaW5nIHRvXG4gICAgICAgICAgLy9ob3cgdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9ucyB3aWxsIGJlIGFwcGxpZWQ6IFMyLCBTNCwgUzYsIFM4LCBTMSwgUzMsIFM1LCBTN1xuICAgICAgICAgIGxlZnR0ZW1wID0gZGVzUEMucGMyYnl0ZXMwW2xlZnQgPj4+IDI4XSB8IGRlc1BDLnBjMmJ5dGVzMVsobGVmdCA+Pj4gMjQpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXMyWyhsZWZ0ID4+PiAyMCkgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXMzWyhsZWZ0ID4+PiAxNikgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczRbKGxlZnQgPj4+IDEyKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczVbKGxlZnQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXM2WyhsZWZ0ID4+PiA0KSAmIDB4Zl07XG4gICAgICAgICAgcmlnaHR0ZW1wID0gZGVzUEMucGMyYnl0ZXM3W3JpZ2h0ID4+PiAyOF0gfCBkZXNQQy5wYzJieXRlczhbKHJpZ2h0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXM5WyhyaWdodCA+Pj4gMjApICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzMTBbKHJpZ2h0ID4+PiAxNikgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXMxMVsocmlnaHQgPj4+IDEyKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczEyWyhyaWdodCA+Pj4gOCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXMxM1socmlnaHQgPj4+IDQpICYgMHhmXTtcbiAgICAgICAgICB0ZW1wID0gKChyaWdodHRlbXAgPj4+IDE2KSBeIGxlZnR0ZW1wKSAmIDB4MDAwMGZmZmY7XG4gICAgICAgICAga2V5c1tuKytdID0gbGVmdHRlbXAgXiB0ZW1wOyBrZXlzW24rK10gPSByaWdodHRlbXAgXiAodGVtcCA8PCAxNik7XG4gICAgICAgIH1cbiAgICAgIH0gLy9mb3IgZWFjaCBpdGVyYXRpb25zXG5cbiAgICAgIHJldHVybiBrZXlzO1xuICAgIH0gLy9lbmQgb2YgZGVzX2NyZWF0ZUtleXNcblxuICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgbGV0IGRlc1NQID0gREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzU1A7XG5cbiAgICBpZiAoIGRlc1NQID09IHVuZGVmaW5lZCApXG4gICAge1xuICAgICAgZGVzU1AgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNTUCA9IHtcbiAgICAgICAgc3BmdW5jdGlvbjE6IG5ldyBVaW50MzJBcnJheSggWzB4MTAxMDQwMCwwLDB4MTAwMDAsMHgxMDEwNDA0LDB4MTAxMDAwNCwweDEwNDA0LDB4NCwweDEwMDAwLDB4NDAwLDB4MTAxMDQwMCwweDEwMTA0MDQsMHg0MDAsMHgxMDAwNDA0LDB4MTAxMDAwNCwweDEwMDAwMDAsMHg0LDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMHgxMDQwMCwweDEwNDAwLDB4MTAxMDAwMCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDQsMHgxMDAwMDA0LDB4MTAwMDAwNCwweDEwMDA0LDAsMHg0MDQsMHgxMDQwNCwweDEwMDAwMDAsMHgxMDAwMCwweDEwMTA0MDQsMHg0LDB4MTAxMDAwMCwweDEwMTA0MDAsMHgxMDAwMDAwLDB4MTAwMDAwMCwweDQwMCwweDEwMTAwMDQsMHgxMDAwMCwweDEwNDAwLDB4MTAwMDAwNCwweDQwMCwweDQsMHgxMDAwNDA0LDB4MTA0MDQsMHgxMDEwNDA0LDB4MTAwMDQsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDAwMDQsMHg0MDQsMHgxMDQwNCwweDEwMTA0MDAsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwwLDB4MTAwMDQsMHgxMDQwMCwwLDB4MTAxMDAwNF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjI6IG5ldyBVaW50MzJBcnJheSggWy0weDdmZWY3ZmUwLC0weDdmZmY4MDAwLDB4ODAwMCwweDEwODAyMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLC0weDdmZWY3ZmUwLC0weDdmZWY4MDAwLC0weDgwMDAwMDAwLC0weDdmZmY4MDAwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsMHgxMDgwMDAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsMCwtMHg4MDAwMDAwMCwweDgwMDAsMHgxMDgwMjAsLTB4N2ZmMDAwMDAsMHgxMDAwMjAsLTB4N2ZmZmZmZTAsMCwweDEwODAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsLTB4N2ZmMDAwMDAsMHg4MDIwLDAsMHgxMDgwMjAsLTB4N2ZlZmZmZTAsMHgxMDAwMDAsLTB4N2ZmZjdmZTAsLTB4N2ZmMDAwMDAsLTB4N2ZlZjgwMDAsMHg4MDAwLC0weDdmZjAwMDAwLC0weDdmZmY4MDAwLDB4MjAsLTB4N2ZlZjdmZTAsMHgxMDgwMjAsMHgyMCwweDgwMDAsLTB4ODAwMDAwMDAsMHg4MDIwLC0weDdmZWY4MDAwLDB4MTAwMDAwLC0weDdmZmZmZmUwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLC0weDdmZmZmZmUwLDB4MTAwMDIwLDB4MTA4MDAwLDAsLTB4N2ZmZjgwMDAsMHg4MDIwLC0weDgwMDAwMDAwLC0weDdmZWZmZmUwLC0weDdmZWY3ZmUwLDB4MTA4MDAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uMzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDgsMHg4MDIwMjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwMCwwLDB4MjAyMDgsMHg4MDAwMjAwLDB4MjAwMDgsMHg4MDAwMDA4LDB4ODAwMDAwOCwweDIwMDAwLDB4ODAyMDIwOCwweDIwMDA4LDB4ODAyMDAwMCwweDIwOCwweDgwMDAwMDAsMHg4LDB4ODAyMDIwMCwweDIwMCwweDIwMjAwLDB4ODAyMDAwMCwweDgwMjAwMDgsMHgyMDIwOCwweDgwMDAyMDgsMHgyMDIwMCwweDIwMDAwLDB4ODAwMDIwOCwweDgsMHg4MDIwMjA4LDB4MjAwLDB4ODAwMDAwMCwweDgwMjAyMDAsMHg4MDAwMDAwLDB4MjAwMDgsMHgyMDgsMHgyMDAwMCwweDgwMjAyMDAsMHg4MDAwMjAwLDAsMHgyMDAsMHgyMDAwOCwweDgwMjAyMDgsMHg4MDAwMjAwLDB4ODAwMDAwOCwweDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDgsMHgyMDAwMCwweDgwMDAwMDAsMHg4MDIwMjA4LDB4OCwweDIwMjA4LDB4MjAyMDAsMHg4MDAwMDA4LDB4ODAyMDAwMCwweDgwMDAyMDgsMHgyMDgsMHg4MDIwMDAwLDB4MjAyMDgsMHg4LDB4ODAyMDAwOCwweDIwMjAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNDogbmV3IFVpbnQzMkFycmF5KCBbMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgwLDB4ODAwMDgxLDB4ODAwMDAxLDB4MjAwMSwwLDB4ODAyMDAwLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwweDgwMDA4MCwweDgwMDAwMSwweDEsMHgyMDAwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAxLDB4MjA4MCwweDgwMDA4MSwweDEsMHgyMDgwLDB4ODAwMDgwLDB4MjAwMCwweDgwMjA4MCwweDgwMjA4MSwweDgxLDB4ODAwMDgwLDB4ODAwMDAxLDB4ODAyMDAwLDB4ODAyMDgxLDB4ODEsMCwwLDB4ODAyMDAwLDB4MjA4MCwweDgwMDA4MCwweDgwMDA4MSwweDEsMHg4MDIwMDEsMHgyMDgxLDB4MjA4MSwweDgwLDB4ODAyMDgxLDB4ODEsMHgxLDB4MjAwMCwweDgwMDAwMSwweDIwMDEsMHg4MDIwODAsMHg4MDAwODEsMHgyMDAxLDB4MjA4MCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMCwweDgwMjA4MF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjU6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwLDB4MjA4MDEwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDgwMDAwLDB4MTAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDAwODAxMDAsMHg4MDAwMCwweDIwMDAxMDAsMHg0MDA4MDEwMCwweDQyMDAwMTAwLDB4NDIwODAwMDAsMHg4MDEwMCwweDQwMDAwMDAwLDB4MjAwMDAwMCwweDQwMDgwMDAwLDB4NDAwODAwMDAsMCwweDQwMDAwMTAwLDB4NDIwODAxMDAsMHg0MjA4MDEwMCwweDIwMDAxMDAsMHg0MjA4MDAwMCwweDQwMDAwMTAwLDAsMHg0MjAwMDAwMCwweDIwODAxMDAsMHgyMDAwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDgwMDAwLDB4NDIwMDAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDAwMDAwMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg0MDA4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDAwMCwweDQyMDgwMDAwLDB4MjA4MDEwMCwweDQwMDgwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQyMDgwMDAwLDB4NDIwODAxMDAsMHg4MDEwMCwweDQyMDAwMDAwLDB4NDIwODAxMDAsMHgyMDgwMDAwLDAsMHg0MDA4MDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAxMDAsMHg4MDAwMCwwLDB4NDAwODAwMDAsMHgyMDgwMTAwLDB4NDAwMDAxMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb242OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMDEwLDB4MjA0MDAwMDAsMHg0MDAwLDB4MjA0MDQwMTAsMHgyMDQwMDAwMCwweDEwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDQwNDAxMCwweDQwMDAwMCwweDIwMDAwMDEwLDB4NDAwMDEwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMCwweDQwMDAxMCwweDIwMDA0MDEwLDB4NDAwMCwweDQwNDAwMCwweDIwMDA0MDEwLDB4MTAsMHgyMDQwMDAxMCwweDIwNDAwMDEwLDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwweDQwMTAsMHg0MDQwMDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4MjAwMDQwMDAsMHgxMCwweDIwNDAwMDEwLDB4NDA0MDAwLDB4MjA0MDQwMTAsMHg0MDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHg0MDAwMDAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4MjA0MDQwMTAsMHg0MDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDIwNDA0MDAwLDAsMHgyMDQwMDAxMCwweDEwLDB4NDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4NDAwMCwweDQwMDAxMCwweDIwMDA0MDEwLDAsMHgyMDQwNDAwMCwweDIwMDAwMDAwLDB4NDAwMDEwLDB4MjAwMDQwMTBdICksXG4gICAgICAgIHNwZnVuY3Rpb243OiBuZXcgVWludDMyQXJyYXkoIFsweDIwMDAwMCwweDQyMDAwMDIsMHg0MDAwODAyLDAsMHg4MDAsMHg0MDAwODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDQyMDA4MDIsMHgyMDAwMDAsMCwweDQwMDAwMDIsMHgyLDB4NDAwMDAwMCwweDQyMDAwMDIsMHg4MDIsMHg0MDAwODAwLDB4MjAwODAyLDB4MjAwMDAyLDB4NDAwMDgwMCwweDQwMDAwMDIsMHg0MjAwMDAwLDB4NDIwMDgwMCwweDIwMDAwMiwweDQyMDAwMDAsMHg4MDAsMHg4MDIsMHg0MjAwODAyLDB4MjAwODAwLDB4MiwweDQwMDAwMDAsMHgyMDA4MDAsMHg0MDAwMDAwLDB4MjAwODAwLDB4MjAwMDAwLDB4NDAwMDgwMiwweDQwMDA4MDIsMHg0MjAwMDAyLDB4NDIwMDAwMiwweDIsMHgyMDAwMDIsMHg0MDAwMDAwLDB4NDAwMDgwMCwweDIwMDAwMCwweDQyMDA4MDAsMHg4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4ODAyLDB4NDAwMDAwMiwweDQyMDA4MDIsMHg0MjAwMDAwLDB4MjAwODAwLDAsMHgyLDB4NDIwMDgwMiwwLDB4MjAwODAyLDB4NDIwMDAwMCwweDgwMCwweDQwMDAwMDIsMHg0MDAwODAwLDB4ODAwLDB4MjAwMDAyXSApLFxuICAgICAgICBzcGZ1bmN0aW9uODogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAwMTA0MCwweDEwMDAsMHg0MDAwMCwweDEwMDQxMDQwLDB4MTAwMDAwMDAsMHgxMDAwMTA0MCwweDQwLDB4MTAwMDAwMDAsMHg0MDA0MCwweDEwMDQwMDAwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDEwMDQxMDAwLDB4NDEwNDAsMHgxMDAwLDB4NDAsMHgxMDA0MDAwMCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHgxMDQwLDB4NDEwMDAsMHg0MDA0MCwweDEwMDQwMDQwLDB4MTAwNDEwMDAsMHgxMDQwLDAsMCwweDEwMDQwMDQwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDQxMDQwLDB4NDAwMDAsMHg0MTA0MCwweDQwMDAwLDB4MTAwNDEwMDAsMHgxMDAwLDB4NDAsMHgxMDA0MDA0MCwweDEwMDAsMHg0MTA0MCwweDEwMDAxMDAwLDB4NDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwNDAwNDAsMHgxMDAwMDAwMCwweDQwMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDAwNDAsMHgxMDAwMDA0MCwweDEwMDQwMDAwLDB4MTAwMDEwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MTAwMCwweDQxMDAwLDB4MTA0MCwweDEwNDAsMHg0MDA0MCwweDEwMDAwMDAwLDB4MTAwNDEwMDBdICksXG4gICAgICB9O1xuICAgIH1cblxuICAgIC8vY3JlYXRlIHRoZSAxNiBvciA0OCBzdWJrZXlzIHdlIHdpbGwgbmVlZFxuICAgIHZhciBrZXlzID0gZGVzX2NyZWF0ZUtleXMoIGtleSApO1xuXG4gICAgdmFyIG09MCwgaSwgaiwgdGVtcCwgbGVmdCwgcmlnaHQsIGxvb3Bpbmc7XG4gICAgdmFyIGNiY2xlZnQsIGNiY2xlZnQyLCBjYmNyaWdodCwgY2JjcmlnaHQyXG4gICAgdmFyIGxlbiA9IG1lc3NhZ2UubGVuZ3RoO1xuXG4gICAgLy9zZXQgdXAgdGhlIGxvb3BzIGZvciBzaW5nbGUgYW5kIHRyaXBsZSBkZXNcbiAgICB2YXIgaXRlcmF0aW9ucyA9IGtleXMubGVuZ3RoID09IDMyID8gMyA6IDk7IC8vc2luZ2xlIG9yIHRyaXBsZSBkZXNcblxuICAgIGlmIChpdGVyYXRpb25zID09IDMpXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyIF0gOiBbIDMwLCAtMiwgLTIgXTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiwgNjIsIDMwLCAtMiwgNjQsIDk2LCAyIF0gOiBbIDk0LCA2MiwgLTIsIDMyLCA2NCwgMiwgMzAsIC0yLCAtMiBdO1xuICAgIH1cblxuICAgIC8vIHBhZCB0aGUgbWVzc2FnZSBkZXBlbmRpbmcgb24gdGhlIHBhZGRpbmcgcGFyYW1ldGVyXG4gICAgaWYgKCAoIHBhZGRpbmcgIT0gdW5kZWZpbmVkICkgJiYgKCBwYWRkaW5nICE9IDQgKSApXG4gICAge1xuICAgICAgdmFyIHVucGFkZGVkTWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICB2YXIgcGFkID0gOC0obGVuJTgpO1xuXG4gICAgICBtZXNzYWdlID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiArIDggKTtcbiAgICAgIG1lc3NhZ2Uuc2V0KCB1bnBhZGRlZE1lc3NhZ2UsIDAgKTtcblxuICAgICAgc3dpdGNoKCBwYWRkaW5nIClcbiAgICAgIHtcbiAgICAgICAgY2FzZSAwOiAvLyB6ZXJvLXBhZFxuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwIF0gKSwgbGVuICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgY2FzZSAxOiAvLyBQS0NTNyBwYWRkaW5nXG4gICAgICAgIHtcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWRdICksIDggKTtcblxuICAgICAgICAgIGlmICggcGFkPT04IClcbiAgICAgICAgICAgIGxlbis9ODtcblxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG5cbiAgICAgICAgY2FzZSAyOiAgLy8gcGFkIHRoZSBtZXNzYWdlIHdpdGggc3BhY2VzXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAsIDB4MjAgXSApLCA4ICk7XG4gICAgICAgICAgYnJlYWs7XG5cbiAgICAgIH1cblxuICAgICAgbGVuICs9IDgtKGxlbiU4KVxuICAgIH1cblxuICAgIC8vIHN0b3JlIHRoZSByZXN1bHQgaGVyZVxuICAgIHZhciByZXN1bHQgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG5cbiAgICBpZiAobW9kZSA9PSAxKVxuICAgIHsgLy9DQkMgbW9kZVxuICAgICAgdmFyIG0gPSAwO1xuXG4gICAgICBjYmNsZWZ0ID0gIChpdlttKytdIDw8IDI0KSB8IChpdlttKytdIDw8IDE2KSB8IChpdlttKytdIDw8IDgpIHwgaXZbbSsrXTtcbiAgICAgIGNiY3JpZ2h0ID0gKGl2W20rK10gPDwgMjQpIHwgKGl2W20rK10gPDwgMTYpIHwgKGl2W20rK10gPDwgOCkgfCBpdlttKytdO1xuICAgIH1cblxuICAgIHZhciBybSA9IDA7XG5cbiAgICAvL2xvb3AgdGhyb3VnaCBlYWNoIDY0IGJpdCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgIHdoaWxlIChtIDwgbGVuKVxuICAgIHtcbiAgICAgIGxlZnQgPSAgKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG4gICAgICByaWdodCA9IChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBsZWZ0IF49IGNiY2xlZnQ7IHJpZ2h0IF49IGNiY3JpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGNiY2xlZnQyID0gY2JjbGVmdDtcbiAgICAgICAgICBjYmNyaWdodDIgPSBjYmNyaWdodDtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vZmlyc3QgZWFjaCA2NCBidXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2UgbXVzdCBiZSBwZXJtdXRlZCBhY2NvcmRpbmcgdG8gSVBcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICBsZWZ0ID0gKChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDMxKSk7XG4gICAgICByaWdodCA9ICgocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDMxKSk7XG5cbiAgICAgIC8vZG8gdGhpcyBlaXRoZXIgMSBvciAzIHRpbWVzIGZvciBlYWNoIGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgICBmb3IgKGo9MDsgajxpdGVyYXRpb25zOyBqKz0zKVxuICAgICAge1xuICAgICAgICB2YXIgZW5kbG9vcCA9IGxvb3BpbmdbaisxXTtcbiAgICAgICAgdmFyIGxvb3BpbmMgPSBsb29waW5nW2orMl07XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uXG4gICAgICAgIGZvciAoaT1sb29waW5nW2pdOyBpIT1lbmRsb29wOyBpKz1sb29waW5jKVxuICAgICAgICB7IC8vZm9yIGVmZmljaWVuY3lcbiAgICAgICAgICB2YXIgcmlnaHQxID0gcmlnaHQgXiBrZXlzW2ldO1xuICAgICAgICAgIHZhciByaWdodDIgPSAoKHJpZ2h0ID4+PiA0KSB8IChyaWdodCA8PCAyOCkpIF4ga2V5c1tpKzFdO1xuXG4gICAgICAgICAgLy90aGUgcmVzdWx0IGlzIGF0dGFpbmVkIGJ5IHBhc3NpbmcgdGhlc2UgYnl0ZXMgdGhyb3VnaCB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zXG4gICAgICAgICAgdGVtcCA9IGxlZnQ7XG4gICAgICAgICAgbGVmdCA9IHJpZ2h0O1xuICAgICAgICAgIHJpZ2h0ID0gdGVtcCBeIChkZXNTUC5zcGZ1bmN0aW9uMlsocmlnaHQxID4+PiAyNCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb240WyhyaWdodDEgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IGRlc1NQLnNwZnVuY3Rpb242WyhyaWdodDEgPj4+ICA4KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjhbcmlnaHQxICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgZGVzU1Auc3BmdW5jdGlvbjFbKHJpZ2h0MiA+Pj4gMjQpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uM1socmlnaHQyID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBkZXNTUC5zcGZ1bmN0aW9uNVsocmlnaHQyID4+PiAgOCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb243W3JpZ2h0MiAmIDB4M2ZdKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRlbXAgPSBsZWZ0OyBsZWZ0ID0gcmlnaHQ7IHJpZ2h0ID0gdGVtcDsgLy91bnJldmVyc2UgbGVmdCBhbmQgcmlnaHRcbiAgICAgIH0gLy9mb3IgZWl0aGVyIDEgb3IgMyBpdGVyYXRpb25zXG5cbiAgICAgIC8vbW92ZSB0aGVuIGVhY2ggb25lIGJpdCB0byB0aGUgcmlnaHRcbiAgICAgIGxlZnQgPSAoKGxlZnQgPj4+IDEpIHwgKGxlZnQgPDwgMzEpKTtcbiAgICAgIHJpZ2h0ID0gKChyaWdodCA+Pj4gMSkgfCAocmlnaHQgPDwgMzEpKTtcblxuICAgICAgLy9ub3cgcGVyZm9ybSBJUC0xLCB3aGljaCBpcyBJUCBpbiB0aGUgb3Bwb3NpdGUgZGlyZWN0aW9uXG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gMikgXiBsZWZ0KSAmIDB4MzMzMzMzMzM7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgMik7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxNikgXiByaWdodCkgJiAweDAwMDBmZmZmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDE2KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcblxuICAgICAgLy9mb3IgQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUsIHhvciB0aGUgbWVzc2FnZSB3aXRoIHRoZSBwcmV2aW91cyByZXN1bHRcbiAgICAgIGlmIChtb2RlID09IDEpXG4gICAgICB7XG4gICAgICAgIGlmIChlbmNyeXB0KVxuICAgICAgICB7XG4gICAgICAgICAgY2JjbGVmdCA9IGxlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQgPSByaWdodDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgIHtcbiAgICAgICAgICBsZWZ0IF49IGNiY2xlZnQyO1xuICAgICAgICAgIHJpZ2h0IF49IGNiY3JpZ2h0MjtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICByZXN1bHQuc2V0KCBuZXcgVWludDhBcnJheSAoIFsgKGxlZnQ+Pj4yNCkgJiAweGZmLCAobGVmdD4+PjE2KSAmIDB4ZmYsIChsZWZ0Pj4+OCkgJiAweGZmLCAobGVmdCkgJiAweGZmLCAocmlnaHQ+Pj4yNCkgJiAweGZmLCAocmlnaHQ+Pj4xNikgJiAweGZmLCAocmlnaHQ+Pj44KSAmIDB4ZmYsIChyaWdodCkgJiAweGZmIF0gKSwgcm0gKTtcblxuICAgICAgcm0gKz0gODtcbiAgICB9IC8vZm9yIGV2ZXJ5IDggY2hhcmFjdGVycywgb3IgNjQgYml0cyBpbiB0aGUgbWVzc2FnZVxuXG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSAvL2VuZCBvZiBkZXNcblxufVxuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ0RFUy1FQ0InLFxuICBERVNDcnlwdG9ncmFwaGljU2VydmljZSxcbiAgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkVOQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uREVDUllQVCBdICk7XG5cbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJLZXlTZXJ2aWNlKCAnREVTLUVDQicsXG4gIERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLFxuICBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uSU1QT1JUX0tFWSBdICk7XG4iLG51bGwsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJy4vYnl0ZS1hcnJheSc7XG5cbmV4cG9ydCBjbGFzcyBFbnVtIHtcbn1cblxuZXhwb3J0IGNsYXNzIEludGVnZXIgZXh0ZW5kcyBOdW1iZXIge1xufVxuXG4vKipcbiAqIFNldCBvZiBkYXRhIHR5cGVzIHRoYXQgYXJlIHZhbGlkIGFzIEtpbmQgZmllbGRzXG4gKiBpbmNsdWRlcyBGaWVsZFR5cGVBcnJheSBrbHVkZ2UgcmVxdWlyZWQgZm9yIFRTIHRvIHBhcnNlIHJlY3Vyc2l2ZVxuICogdHlwZSBkZWZpbml0aW9uc1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRBcnJheSBleHRlbmRzIEFycmF5PEZpZWxkVHlwZT4ge31cbmV4cG9ydCB0eXBlIEZpZWxkVHlwZSA9IFN0cmluZyB8IE51bWJlciB8IEludGVnZXIgfCBFbnVtIHwgQnl0ZUFycmF5IHwgS2luZCB8IEZpZWxkQXJyYXk7XG5cbmV4cG9ydCBjbGFzcyBGaWVsZEFycmF5IGltcGxlbWVudHMgRmllbGRBcnJheSB7fVxuXG5leHBvcnQgdmFyIEZpZWxkVHlwZXMgPSB7XG4gIEJvb2xlYW46IEJvb2xlYW4sXG5cbiAgTnVtYmVyOiBOdW1iZXIsXG5cbiAgSW50ZWdlcjogSW50ZWdlcixcblxuICBCeXRlQXJyYXk6IEJ5dGVBcnJheSxcblxuICBFbnVtOiBFbnVtLFxuXG4gIEFycmF5OiBGaWVsZEFycmF5LFxuXG4gIFN0cmluZzogU3RyaW5nLFxuXG4gIEtpbmQ6IEtpbmRcbn1cblxuZXhwb3J0IGludGVyZmFjZSBGaWVsZE9wdGlvbnMge1xuICAvKipcbiAgKiBtaW5pbXVtIGxlbmd0aCBmb3IgU3RyaW5nLCBtaW5pbXVtIHZhbHVlIGZvciBOdW1iZXIvSW50ZWdlclxuICAqL1xuICBtaW5pbXVtPzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIG1heGltdW0gbGVuZ3RoIGZvciBTdHJpbmcsIG1heGltdW0gdmFsdWUgZm9yIE51bWJlci9JbnRlZ2VyXG4gICovXG4gIG1heGltdW0/OiBudW1iZXI7XG5cbiAgLyoqXG4gICogZGVmYXVsdCB2YWx1ZSBkdXJpbmcgaW5pdGlhbGl6YXRpb25cbiAgKi9cbiAgXCJkZWZhdWx0XCI/OiBhbnk7XG5cbiAgLyoqXG4gICogZG9lcyBub3QgZXhpc3QgYXMgYW4gb3duUHJvcGVydHlcbiAgKi9cbiAgY2FsY3VsYXRlZD86IGJvb2xlYW47XG5cbiAgLyoqXG4gICogc3ViLWtpbmQsIHdoZW4gZmllbGQgaXMgdHlwZSBLaW5kXG4gICovXG4gIGtpbmQ/OiBLaW5kO1xuXG4gIC8qKlxuICAqIHN1Yi1maWVsZCBpbmZvLCB3aGVuIGZpZWxkIGlzIHR5cGUgRmllbGRBcnJheVxuICAqL1xuICBhcnJheUluZm8/OiBGaWVsZEluZm87XG5cbiAgLyoqXG4gICogaW5kZXgvdmFsdWUgbWFwLCB3aGVuIGZpZWxkIGlmIHR5cGUgRW51bVxuICAqL1xuICBlbnVtTWFwPzogTWFwPG51bWJlciwgc3RyaW5nPjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBGaWVsZEluZm8gZXh0ZW5kcyBGaWVsZE9wdGlvbnMge1xuICAvKipcbiAgKiBEZXNjcmlwdGlvbiBmb3IgZmllbGRcbiAgKi9cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICAvKipcbiAgKiBUeXBlIG9mIGZpZWxkLCBvbmUgb2YgRmllbGRUeXBlc1xuICAqL1xuICBmaWVsZFR5cGU6IEZpZWxkVHlwZTtcbn1cblxuXG4vKipcbiogTWV0YWRhdGEgYWJvdXQgYSBLaW5kLiBDb250YWlucyBuYW1lLCBkZXNjcmlwdGlvbiBhbmQgYSBtYXAgb2ZcbiogcHJvcGVydHktZGVzY3JpcHRvcnMgdGhhdCBkZXNjcmliZSB0aGUgc2VyaWFsaXphYmxlIGZpZWxkcyBvZlxuKiBhbiBvYmplY3Qgb2YgdGhhdCBLaW5kLlxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kSW5mb1xue1xuICBuYW1lOiBzdHJpbmc7XG5cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICBmaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBGaWVsZEluZm8gfSA9IHt9O1xufVxuXG4vKipcbiogQnVpbGRlciBmb3IgJ0tpbmQnIG1ldGFkYXRhXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRCdWlsZGVyXG57XG4gIHByaXZhdGUgY3RvcjogS2luZENvbnN0cnVjdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKSB7XG4gICAgdGhpcy5jdG9yID0gY3RvcjtcblxuICAgIGN0b3Iua2luZEluZm8gPSB7XG4gICAgICBuYW1lOiBjdG9yLm5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24sXG4gICAgICBmaWVsZHM6IHt9XG4gICAgfVxuICB9XG5cblxuICBwcml2YXRlIGtpbmRJbmZvOiBLaW5kSW5mbztcblxuICBwdWJsaWMgc3RhdGljIGluaXQoIGN0b3I6IEtpbmRDb25zdHJ1Y3RvciwgZGVzY3JpcHRpb246IHN0cmluZyApOiBLaW5kQnVpbGRlclxuICB7XG4gICAgbGV0IGJ1aWxkZXIgPSBuZXcgS2luZEJ1aWxkZXIoIGN0b3IsIGRlc2NyaXB0aW9uICk7XG5cbiAgICByZXR1cm4gYnVpbGRlcjtcbiAgfVxuXG4gIHB1YmxpYyBmaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBmaWVsZFR5cGU6IEZpZWxkVHlwZSwgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBmaWVsZDogRmllbGRJbmZvID0gPEZpZWxkSW5mbz5vcHRzO1xuXG4gICAgZmllbGQuZGVzY3JpcHRpb24gPSBkZXNjcmlwdGlvbjtcbiAgICBmaWVsZC5maWVsZFR5cGUgPSBmaWVsZFR5cGU7XG5cbiAgICB0aGlzLmN0b3Iua2luZEluZm8uZmllbGRzWyBuYW1lIF0gPSBmaWVsZDtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgcHVibGljIGJvb2xGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBCb29sZWFuLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgbnVtYmVyRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgTnVtYmVyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgaW50ZWdlckZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyB1aW50MzJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgb3B0cy5taW5pbXVtID0gb3B0cy5taW5pbXVtIHx8IDA7XG4gICAgb3B0cy5tYXhpbXVtID0gb3B0cy5tYXhpbXVtIHx8IDB4RkZGRkZGRkY7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBieXRlRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMubWluaW11bSA9IG9wdHMubWluaW11bSB8fCAwO1xuICAgIG9wdHMubWF4aW11bSA9IG9wdHMubWF4aW11bSB8fCAyNTU7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdHJpbmdGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBTdHJpbmcsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBraW5kRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywga2luZDogS2luZCwgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMua2luZCA9IGtpbmQ7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEtpbmQsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBlbnVtRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZW51bW06IHsgWyBpZHg6IG51bWJlciBdOiBzdHJpbmcgfSwgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuXG4gICAgb3B0cy5lbnVtTWFwID0gbmV3IE1hcDxudW1iZXIsc3RyaW5nPiggKTtcblxuICAgIGZvciggbGV0IGlkeCBpbiBlbnVtbSApIHtcbiAgICAgIGlmICggMSAqIGlkeCA9PSBpZHggKVxuICAgICAgICBvcHRzLmVudW1NYXAuc2V0KCBpZHgsIGVudW1tWyBpZHggXSApO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgRW51bSwgb3B0cyApO1xuICB9XG59XG5cbi8qICBtYWtlS2luZCgga2luZENvbnN0cnVjdG9yLCBraW5kT3B0aW9ucyApXG4gIHtcbiAgICB2YXIgJGtpbmRJbmZvID0ga2luZE9wdGlvbnMua2luZEluZm87XG5cbiAgICBraW5kQ29uc3RydWN0b3IuJGtpbmROYW1lID0gJGtpbmRJbmZvLnRpdGxlO1xuXG4gICAgdmFyIGtleXMgPSBPYmplY3Qua2V5cygga2luZE9wdGlvbnMua2luZE1ldGhvZHMgKTtcblxuICAgIGZvciAoIHZhciBqID0gMCwgamogPSBrZXlzLmxlbmd0aDsgaiA8IGpqOyBqKysgKSB7XG4gICAgICB2YXIga2V5ID0ga2V5c1tqXTtcbiAgICAgIGtpbmRDb25zdHJ1Y3RvcltrZXldID0ga2luZE9wdGlvbnMua2luZE1ldGhvZHNba2V5XTtcbiAgICB9XG5cbiAgICBraW5kQ29uc3RydWN0b3IuZ2V0S2luZEluZm8gPSBraW5kQ29uc3RydWN0b3IucHJvdG90eXBlLmdldEtpbmRJbmZvID0gZnVuY3Rpb24gZ2V0S2luZEluZm8oKSB7XG4gICAgICByZXR1cm4gJGtpbmRJbmZvO1xuICAgIH1cblxuICAgIHJldHVybiBraW5kQ29uc3RydWN0b3I7XG4gIH1cbiovXG5cbi8qKlxuKiBSZXByZXNlbnRzIGEgc2VyaWFsaXphYmxlIGFuZCBpbnNwZWN0YWJsZSBkYXRhLXR5cGVcbiogaW1wbGVtZW50ZWQgYXMgYSBoYXNoLW1hcCBjb250YWluaW5nIGtleS12YWx1ZSBwYWlycyxcbiogYWxvbmcgd2l0aCBtZXRhZGF0YSB0aGF0IGRlc2NyaWJlcyBlYWNoIGZpZWxkIHVzaW5nIGEganNvbi1zY2hlbWUgbGlrZVxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgS2luZFxue1xufVxuXG5leHBvcnQgY2xhc3MgS2luZCBpbXBsZW1lbnRzIEtpbmQge1xuICBzdGF0aWMgZ2V0S2luZEluZm8oIGtpbmQ6IEtpbmQgKTogS2luZEluZm8ge1xuICAgIHJldHVybiAoPEtpbmRDb25zdHJ1Y3Rvcj4oa2luZC5jb25zdHJ1Y3RvcikpLmtpbmRJbmZvO1xuICB9XG5cbiAgc3RhdGljIGluaXRGaWVsZHMoIGtpbmQ6IEtpbmQsIGF0dHJpYnV0ZXM6IHt9ID0ge30gICkge1xuICAgIGxldCBraW5kSW5mbyA9IEtpbmQuZ2V0S2luZEluZm8oIGtpbmQgKTtcblxuICAgIGZvciggbGV0IGlkIGluIGtpbmRJbmZvLmZpZWxkcyApIHtcbiAgICAgIGxldCBmaWVsZCA9IGtpbmRJbmZvLmZpZWxkc1sgaWQgXTtcbiAgICAgIGxldCBmaWVsZFR5cGUgPSBmaWVsZC5maWVsZFR5cGU7XG5cbi8vICAgICAgY29uc29sZS5sb2coIGlkICsgJzonICsgZmllbGRUeXBlICk7XG4vLyAgICAgIGNvbnNvbGUubG9nKCBraW5kLmhhc093blByb3BlcnR5KGlkKSAgKTtcblxuICAgICAgbGV0IHZhbDogYW55O1xuXG4gICAgICBpZiAoICFmaWVsZC5jYWxjdWxhdGVkICkge1xuICAgICAgICAvLyB3ZSBvbmx5IHNldCAnbm9uJy1jYWxjdWxhdGVkIGZpZWxkLCBzaW5jZSBjYWxjdWxhdGVkIGZpZWxkIGhhdmVcbiAgICAgICAgLy8gbm8gc2V0dGVyXG5cbiAgICAgICAgLy8gZ290IGEgdmFsdWUgZm9yIHRoaXMgZmllbGQgP1xuICAgICAgICBpZiAoIGF0dHJpYnV0ZXNbIGlkIF0gKVxuICAgICAgICAgIHZhbCA9IGF0dHJpYnV0ZXNbIGlkIF07XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZC5kZWZhdWx0ICE9IHVuZGVmaW5lZCApXG4gICAgICAgICAgdmFsID0gZmllbGQuZGVmYXVsdDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBTdHJpbmcgKVxuICAgICAgICAgIHZhbCA9ICcnO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IE51bWJlciApXG4gICAgICAgICAgdmFsID0gMDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBJbnRlZ2VyIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5taW5pbXVtIHx8IDA7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gQm9vbGVhbiApXG4gICAgICAgICAgdmFsID0gZmFsc2U7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gQnl0ZUFycmF5IClcbiAgICAgICAgICB2YWwgPSBuZXcgQnl0ZUFycmF5KCk7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gRW51bSApXG4gICAgICAgICAgdmFsID0gZmllbGQuZW51bU1hcC5rZXlzWzBdO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEtpbmQgKSB7XG4gICAgICAgICAgbGV0IHh4ID0gKDxLaW5kPmZpZWxkVHlwZSkuY29uc3RydWN0b3I7XG4gICAgICAgICAgdmFsID0gT2JqZWN0LmNyZWF0ZSggeHggKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGtpbmRbIGlkIF0gPSB2YWw7XG5cbi8vICAgICAgICBjb25zb2xlLmxvZygga2luZFtpZF0gKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBLaW5kQ29uc3RydWN0b3JcbntcbiAgbmV3ICggLi4uYXJncyApOiBLaW5kO1xuXG4gIGtpbmRJbmZvPzogS2luZEluZm87XG59XG4iLCJpbXBvcnQgeyBLaW5kIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuXG4vKlxuKiBNZXNzYWdlIEhlYWRlclxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgTWVzc2FnZUhlYWRlclxue1xuICAvKlxuICAqIE1lc3NhZ2UgTmFtZSwgaW5kaWNhdGVzIGEgY29tbWFuZCAvIG1ldGhvZCAvIHJlc3BvbnNlIHRvIGV4ZWN1dGVcbiAgKi9cbiAgbWV0aG9kPzogc3RyaW5nO1xuXG4gIC8qXG4gICogTWVzc2FnZSBJZGVudGlmaWVyICh1bmlxdWUpIGZvciBlYWNoIHNlbnQgbWVzc2FnZSAob3IgQ01ELVJFU1AgcGFpcilcbiAgKi9cbiAgaWQ/OiBudW1iZXI7XG5cblxuICAvKlxuICAqIERlc2NyaXB0aW9uLCB1c2VmdWwgZm9yIHRyYWNpbmcgYW5kIGxvZ2dpbmdcbiAgKi9cbiAgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG5cbiAgLypcbiAgKiBGb3IgQ01EL1JFU1Agc3R5bGUgcHJvdG9jb2xzLCBpbmRpY2F0ZXMgdGhhdCBtZXNzYWdlIGRpc3BhdGNoZWRcbiAgKiBpbiByZXNwb25zZSB0byBhIHByZXZpb3VzIGNvbW1hbmRcbiAgKi9cbiAgaXNSZXNwb25zZT86IGJvb2xlYW47XG5cbiAgLypcbiAgKiBFbmRQb2ludCB0aGF0IG9yaWdpbmF0ZWQgdGhlIG1lc3NhZ2VcbiAgKi9cbiAgb3JpZ2luPzogRW5kUG9pbnQ7XG5cblxuICAvKlxuICAqIEluZGljYXRlcyB0aGUgS2luZCBvZiBkYXRhICh3aGVuIHNlcmlhbGl6ZWQpXG4gICovXG4gIGtpbmROYW1lPzogc3RyaW5nO1xufVxuXG4vKlxuKiBBIFR5cGVkIE1lc3NhZ2UsIHdpdGggaGVhZGVyIGFuZCBwYXlsb2FkXG4qL1xuZXhwb3J0IGNsYXNzIE1lc3NhZ2U8VD5cbntcbiAgcHJpdmF0ZSBfaGVhZGVyOiBNZXNzYWdlSGVhZGVyO1xuICBwcml2YXRlIF9wYXlsb2FkOiBUO1xuXG4gIGNvbnN0cnVjdG9yKCBoZWFkZXI6IE1lc3NhZ2VIZWFkZXIsIHBheWxvYWQ6IFQgKVxuICB7XG4gICAgdGhpcy5faGVhZGVyID0gaGVhZGVyIHx8IHt9O1xuICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICB9XG5cbiAgZ2V0IGhlYWRlcigpOiBNZXNzYWdlSGVhZGVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faGVhZGVyO1xuICB9XG5cbiAgZ2V0IHBheWxvYWQoKTogVFxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BheWxvYWQ7XG4gIH1cbn1cblxuLypcbiogQSB0eXBlZCBNZXNzYWdlIHdob3NlIHBheWxvYWQgaXMgYSBLaW5kXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRNZXNzYWdlPEsgZXh0ZW5kcyBLaW5kPiBleHRlbmRzIE1lc3NhZ2U8Sz5cbntcbn1cbiIsImV4cG9ydCB0eXBlIFRhc2sgPSAoKSA9PiB2b2lkO1xuZXhwb3J0IHR5cGUgRmx1c2hGdW5jID0gKCkgPT4gdm9pZDtcbnZhciB3aW5kb3cgPSB3aW5kb3cgfHwge307XG5cbmV4cG9ydCBjbGFzcyBUYXNrU2NoZWR1bGVyXG57XG4gIHN0YXRpYyBtYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpOiBGbHVzaEZ1bmNcbiAge1xuICAgIHZhciB0b2dnbGUgPSAxO1xuXG4gICAgdmFyIG9ic2VydmVyID0gbmV3IFRhc2tTY2hlZHVsZXIuQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpO1xuXG4gICAgdmFyIG5vZGU6IE9iamVjdCA9IGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKCcnKTtcblxuICAgIG9ic2VydmVyLm9ic2VydmUobm9kZSwgeyBjaGFyYWN0ZXJEYXRhOiB0cnVlIH0pO1xuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpXG4gICAge1xuICAgICAgdG9nZ2xlID0gLXRvZ2dsZTtcbiAgICAgIG5vZGVbXCJkYXRhXCJdID0gdG9nZ2xlO1xuICAgIH07XG4gIH1cblxuICBzdGF0aWMgbWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lcihmbHVzaCk6IEZsdXNoRnVuY1xuICB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpIHtcbiAgICAgIHZhciB0aW1lb3V0SGFuZGxlID0gc2V0VGltZW91dChoYW5kbGVGbHVzaFRpbWVyLCAwKTtcblxuICAgICAgdmFyIGludGVydmFsSGFuZGxlID0gc2V0SW50ZXJ2YWwoaGFuZGxlRmx1c2hUaW1lciwgNTApO1xuICAgICAgZnVuY3Rpb24gaGFuZGxlRmx1c2hUaW1lcigpXG4gICAgICB7XG4gICAgICAgIGNsZWFyVGltZW91dCh0aW1lb3V0SGFuZGxlKTtcbiAgICAgICAgY2xlYXJJbnRlcnZhbChpbnRlcnZhbEhhbmRsZSk7XG4gICAgICAgIGZsdXNoKCk7XG4gICAgICB9XG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBCcm93c2VyTXV0YXRpb25PYnNlcnZlciA9IHdpbmRvd1sgXCJNdXRhdGlvbk9ic2VydmVyXCIgXSB8fCB3aW5kb3dbIFwiV2ViS2l0TXV0YXRpb25PYnNlcnZlclwiXTtcbiAgc3RhdGljIGhhc1NldEltbWVkaWF0ZSA9IHR5cGVvZiBzZXRJbW1lZGlhdGUgPT09ICdmdW5jdGlvbic7XG5cbiAgc3RhdGljIHRhc2tRdWV1ZUNhcGFjaXR5ID0gMTAyNDtcbiAgdGFza1F1ZXVlOiBUYXNrW107XG5cbiAgcmVxdWVzdEZsdXNoVGFza1F1ZXVlOiBGbHVzaEZ1bmM7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy50YXNrUXVldWUgPSBbXTtcblxuICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgIGlmICh0eXBlb2YgVGFza1NjaGVkdWxlci5Ccm93c2VyTXV0YXRpb25PYnNlcnZlciA9PT0gJ2Z1bmN0aW9uJylcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSA9IFRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHNlbGYuZmx1c2hUYXNrUXVldWUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUgPSBUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIoZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gc2VsZi5mbHVzaFRhc2tRdWV1ZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgVGFza1NjaGVkdWxlciwgY2FuY2VsbGluZyBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgc2h1dGRvd24oKVxuICB7XG4gIH1cblxuICBxdWV1ZVRhc2soIHRhc2spXG4gIHtcbiAgICBpZiAoIHRoaXMudGFza1F1ZXVlLmxlbmd0aCA8IDEgKVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlKCk7XG4gICAgfVxuXG4gICAgdGhpcy50YXNrUXVldWUucHVzaCh0YXNrKTtcbiAgfVxuXG4gIGZsdXNoVGFza1F1ZXVlKClcbiAge1xuICAgIHZhciBxdWV1ZSA9IHRoaXMudGFza1F1ZXVlLFxuICAgICAgICBjYXBhY2l0eSA9IFRhc2tTY2hlZHVsZXIudGFza1F1ZXVlQ2FwYWNpdHksXG4gICAgICAgIGluZGV4ID0gMCxcbiAgICAgICAgdGFzaztcblxuICAgIHdoaWxlIChpbmRleCA8IHF1ZXVlLmxlbmd0aClcbiAgICB7XG4gICAgICB0YXNrID0gcXVldWVbaW5kZXhdO1xuXG4gICAgICB0cnlcbiAgICAgIHtcbiAgICAgICAgdGFzay5jYWxsKCk7XG4gICAgICB9XG4gICAgICBjYXRjaCAoZXJyb3IpXG4gICAgICB7XG4gICAgICAgIHRoaXMub25FcnJvcihlcnJvciwgdGFzayk7XG4gICAgICB9XG5cbiAgICAgIGluZGV4Kys7XG5cbiAgICAgIGlmIChpbmRleCA+IGNhcGFjaXR5KVxuICAgICAge1xuICAgICAgICBmb3IgKHZhciBzY2FuID0gMDsgc2NhbiA8IGluZGV4OyBzY2FuKyspXG4gICAgICAgIHtcbiAgICAgICAgICBxdWV1ZVtzY2FuXSA9IHF1ZXVlW3NjYW4gKyBpbmRleF07XG4gICAgICAgIH1cblxuICAgICAgICBxdWV1ZS5sZW5ndGggLT0gaW5kZXg7XG4gICAgICAgIGluZGV4ID0gMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBxdWV1ZS5sZW5ndGggPSAwO1xuICB9XG5cbiAgb25FcnJvcihlcnJvciwgdGFzaylcbiAge1xuICAgIGlmICgnb25FcnJvcicgaW4gdGFzaykge1xuICAgICAgdGFzay5vbkVycm9yKGVycm9yKTtcbiAgICB9XG4gICAgZWxzZSBpZiAoIFRhc2tTY2hlZHVsZXIuaGFzU2V0SW1tZWRpYXRlIClcbiAgICB7XG4gICAgICBzZXRJbW1lZGlhdGUoZnVuY3Rpb24gKCkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgc2V0VGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSwgMCk7XG4gICAgfVxuICB9XG59XG4iLCJpbXBvcnQgeyBUYXNrU2NoZWR1bGVyIH0gZnJvbSAnLi4vcnVudGltZS90YXNrLXNjaGVkdWxlcic7XG5pbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5cbi8qKlxuKiBBIG1lc3NhZ2UtcGFzc2luZyBjaGFubmVsIGJldHdlZW4gbXVsdGlwbGUgRW5kUG9pbnRzXG4qXG4qIEVuZFBvaW50cyBtdXN0IGZpcnN0IHJlZ2lzdGVyIHdpdGggdGhlIENoYW5uZWwuIFdoZW5ldmVyIHRoZSBDaGFubmVsIGlzIGluXG4qIGFuIGFjdGl2ZSBzdGF0ZSwgY2FsbHMgdG8gc2VuZE1lc3NhZ2Ugd2lsbCBmb3J3YXJkIHRoZSBtZXNzYWdlIHRvIGFsbFxuKiByZWdpc3RlcmVkIEVuZFBvaW50cyAoZXhjZXB0IHRoZSBvcmlnaW5hdG9yIEVuZFBvaW50KS5cbiovXG5leHBvcnQgY2xhc3MgQ2hhbm5lbFxue1xuICAvKipcbiAgKiBUcnVlIGlmIENoYW5uZWwgaXMgYWN0aXZlXG4gICovXG4gIHByaXZhdGUgX2FjdGl2ZTogYm9vbGVhbjtcblxuICAvKipcbiAgKiBBcnJheSBvZiBFbmRQb2ludHMgYXR0YWNoZWQgdG8gdGhpcyBDaGFubmVsXG4gICovXG4gIHByaXZhdGUgX2VuZFBvaW50czogRW5kUG9pbnRbXTtcblxuICAvKipcbiAgKiBQcml2YXRlIFRhc2tTY2hlZHVsZXIgdXNlZCB0byBtYWtlIG1lc3NhZ2Utc2VuZHMgYXN5bmNocm9ub3VzLlxuICAqL1xuICBwcml2YXRlIF90YXNrU2NoZWR1bGVyOiBUYXNrU2NoZWR1bGVyO1xuXG4gIC8qKlxuICAqIENyZWF0ZSBhIG5ldyBDaGFubmVsLCBpbml0aWFsbHkgaW5hY3RpdmVcbiAgKi9cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBDaGFubmVsLCBkZWFjdGl2YXRlLCByZW1vdmUgYWxsIEVuZFBvaW50cyBhbmRcbiAgKiBhYm9ydCBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG5cbiAgICBpZiAoIHRoaXMuX3Rhc2tTY2hlZHVsZXIgKVxuICAgIHtcbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIuc2h1dGRvd24oKTtcblxuICAgICAgdGhpcy5fdGFza1NjaGVkdWxlciA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBJcyBDaGFubmVsIGFjdGl2ZT9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgY2hhbm5lbCBpcyBhY3RpdmUsIGZhbHNlIG90aGVyd2lzZVxuICAqL1xuICBwdWJsaWMgZ2V0IGFjdGl2ZSgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fYWN0aXZlO1xuICB9XG5cbiAgLyoqXG4gICogQWN0aXZhdGUgdGhlIENoYW5uZWwsIGVuYWJsaW5nIGNvbW11bmljYXRpb25cbiAgKi9cbiAgcHVibGljIGFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSBuZXcgVGFza1NjaGVkdWxlcigpO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gdHJ1ZTtcbiAgfVxuXG4gIC8qKlxuICAqIERlYWN0aXZhdGUgdGhlIENoYW5uZWwsIGRpc2FibGluZyBhbnkgZnVydGhlciBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBkZWFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG5cbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGFuIEVuZFBvaW50IHRvIHNlbmQgYW5kIHJlY2VpdmUgbWVzc2FnZXMgdmlhIHRoaXMgQ2hhbm5lbC5cbiAgKlxuICAqIEBwYXJhbSBlbmRQb2ludCAtIHRoZSBFbmRQb2ludCB0byByZWdpc3RlclxuICAqL1xuICBwdWJsaWMgYWRkRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICB0aGlzLl9lbmRQb2ludHMucHVzaCggZW5kUG9pbnQgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFVucmVnaXN0ZXIgYW4gRW5kUG9pbnQuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gdW5yZWdpc3RlclxuICAqL1xuICBwdWJsaWMgcmVtb3ZlRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fZW5kUG9pbnRzLmluZGV4T2YoIGVuZFBvaW50ICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICB0aGlzLl9lbmRQb2ludHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBHZXQgRW5kUG9pbnRzIHJlZ2lzdGVyZWQgd2l0aCB0aGlzIENoYW5uZWxcbiAgKlxuICAqIEByZXR1cm4gQXJyYXkgb2YgRW5kUG9pbnRzXG4gICovXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnRzKCk6IEVuZFBvaW50W11cbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludHM7XG4gIH1cblxuICAvKipcbiAgKiBTZW5kIGEgbWVzc2FnZSB0byBhbGwgbGlzdGVuZXJzIChleGNlcHQgb3JpZ2luKVxuICAqXG4gICogQHBhcmFtIG9yaWdpbiAtIEVuZFBvaW50IHRoYXQgaXMgc2VuZGluZyB0aGUgbWVzc2FnZVxuICAqIEBwYXJhbSBtZXNzYWdlIC0gTWVzc2FnZSB0byBiZSBzZW50XG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggb3JpZ2luOiBFbmRQb2ludCwgbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIGxldCBpc1Jlc3BvbnNlID0gKCBtZXNzYWdlLmhlYWRlciAmJiBtZXNzYWdlLmhlYWRlci5pc1Jlc3BvbnNlICk7XG5cbiAgICBpZiAoICF0aGlzLl9hY3RpdmUgKVxuICAgICAgcmV0dXJuO1xuXG4gICAgaWYgKCBvcmlnaW4uZGlyZWN0aW9uID09IERpcmVjdGlvbi5JTiAmJiAhaXNSZXNwb25zZSApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdVbmFibGUgdG8gc2VuZCBvbiBJTiBwb3J0Jyk7XG5cbiAgICB0aGlzLl9lbmRQb2ludHMuZm9yRWFjaCggZW5kUG9pbnQgPT4ge1xuICAgICAgLy8gU2VuZCB0byBhbGwgbGlzdGVuZXJzLCBleGNlcHQgZm9yIG9yaWdpbmF0b3IgLi4uXG4gICAgICBpZiAoIG9yaWdpbiAhPSBlbmRQb2ludCApXG4gICAgICB7XG4gICAgICAgIC8vIE9ubHkgc2VuZCB0byBJTiBvciBJTk9VVCBsaXN0ZW5lcnMsIFVOTEVTUyBtZXNzYWdlIGlzIGFcbiAgICAgICAgLy8gcmVwbHkgKGluIGEgY2xpZW50LXNlcnZlcikgY29uZmlndXJhdGlvblxuICAgICAgICBpZiAoIGVuZFBvaW50LmRpcmVjdGlvbiAhPSBEaXJlY3Rpb24uT1VUIHx8IGlzUmVzcG9uc2UgKVxuICAgICAgICB7XG4gICAgICAgICAgdGhpcy5fdGFza1NjaGVkdWxlci5xdWV1ZVRhc2soICgpID0+IHtcbiAgICAgICAgICAgIGVuZFBvaW50LmhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2UsIG9yaWdpbiwgdGhpcyApO1xuICAgICAgICAgIH0gKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuL2NoYW5uZWwnO1xuXG5leHBvcnQgZW51bSBEaXJlY3Rpb24ge1xuICBJTiA9IDEsXG4gIE9VVCA9IDIsXG4gIElOT1VUID0gM1xufTtcblxuZXhwb3J0IHR5cGUgSGFuZGxlTWVzc2FnZURlbGVnYXRlID0gKCBtZXNzYWdlOiBNZXNzYWdlPGFueT4sIHJlY2VpdmluZ0VuZFBvaW50PzogRW5kUG9pbnQsIHJlY2VpdmluZ0NoYW5uZWw/OiBDaGFubmVsICkgPT4gdm9pZDtcblxuLyoqXG4qIEFuIEVuZFBvaW50IGlzIGEgc2VuZGVyL3JlY2VpdmVyIGZvciBtZXNzYWdlLXBhc3NpbmcuIEl0IGhhcyBhbiBpZGVudGlmaWVyXG4qIGFuZCBhbiBvcHRpb25hbCBkaXJlY3Rpb24sIHdoaWNoIG1heSBiZSBJTiwgT1VUIG9yIElOL09VVCAoZGVmYXVsdCkuXG4qXG4qIEVuZFBvaW50cyBtYXkgaGF2ZSBtdWx0aXBsZSBjaGFubmVscyBhdHRhY2hlZCwgYW5kIHdpbGwgZm9yd2FyZCBtZXNzYWdlc1xuKiB0byBhbGwgb2YgdGhlbS5cbiovXG5leHBvcnQgY2xhc3MgRW5kUG9pbnRcbntcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX2NoYW5uZWxzOiBDaGFubmVsW107XG5cbiAgLyoqXG4gICogQSBsaXN0IG9mIGF0dGFjaGVkIENoYW5uZWxzXG4gICovXG4gIHByb3RlY3RlZCBfbWVzc2FnZUxpc3RlbmVyczogSGFuZGxlTWVzc2FnZURlbGVnYXRlW107XG5cbiAgcHJpdmF0ZSBfZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgY29uc3RydWN0b3IoIGlkOiBzdHJpbmcsIGRpcmVjdGlvbjogRGlyZWN0aW9uID0gRGlyZWN0aW9uLklOT1VUIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG5cbiAgICB0aGlzLl9kaXJlY3Rpb24gPSBkaXJlY3Rpb247XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuXG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgRW5kUG9pbnQsIGRldGFjaGluZyBhbnkgYXR0YWNoZWQgQ2hhbm5lbHMgYW5kIHJlbW92aW5nIGFueVxuICAqIG1lc3NhZ2UtbGlzdGVuZXJzLiBDYWxsaW5nIHNodXRkb3duKCkgaXMgbWFuZGF0b3J5IHRvIGF2b2lkIG1lbW9yeS1sZWFrc1xuICAqIGR1ZSB0byB0aGUgY2lyY3VsYXIgcmVmZXJlbmNlcyB0aGF0IGV4aXN0IGJldHdlZW4gQ2hhbm5lbHMgYW5kIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgc2h1dGRvd24oKVxuICB7XG4gICAgdGhpcy5kZXRhY2hBbGwoKTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIEVuZFBvaW50J3MgaWRcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9pZDtcbiAgfVxuXG4gIC8qKlxuICAqIEF0dGFjaCBhIENoYW5uZWwgdG8gdGhpcyBFbmRQb2ludC4gT25jZSBhdHRhY2hlZCwgdGhlIENoYW5uZWwgd2lsbCBmb3J3YXJkXG4gICogbWVzc2FnZXMgdG8gdGhpcyBFbmRQb2ludCwgYW5kIHdpbGwgYWNjZXB0IG1lc3NhZ2VzIG9yaWdpbmF0ZWQgaGVyZS5cbiAgKiBBbiBFbmRQb2ludCBjYW4gaGF2ZSBtdWx0aXBsZSBDaGFubmVscyBhdHRhY2hlZCwgaW4gd2hpY2ggY2FzZSBpdCB3aWxsXG4gICogYnJvYWRjYXN0IHRvIHRoZW0gYWxsIHdoZW4gc2VuZGluZywgYW5kIHdpbGwgcmVjZWl2ZSBtZXNzYWdlcyBpblxuICAqIGFycml2YWwtb3JkZXIuXG4gICovXG4gIHB1YmxpYyBhdHRhY2goIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMucHVzaCggY2hhbm5lbCApO1xuXG4gICAgY2hhbm5lbC5hZGRFbmRQb2ludCggdGhpcyApO1xuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGEgc3BlY2lmaWMgQ2hhbm5lbCBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2goIGNoYW5uZWxUb0RldGFjaDogQ2hhbm5lbCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fY2hhbm5lbHMuaW5kZXhPZiggY2hhbm5lbFRvRGV0YWNoICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICBjaGFubmVsVG9EZXRhY2gucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBEZXRhY2ggYWxsIENoYW5uZWxzIGZyb20gdGhpcyBFbmRQb2ludC5cbiAgKi9cbiAgcHVibGljIGRldGFjaEFsbCgpXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcbiAgICB9ICk7XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQXJlIGFueSBjaGFubmVscyBhdHRhY2hlZCB0byB0aGlzIEVuZFBvaW50P1xuICAqXG4gICogQHJldHVybnMgdHJ1ZSBpZiBFbmRwb2ludCBpcyBhdHRhY2hlZCB0byBhdC1sZWFzdC1vbmUgQ2hhbm5lbFxuICAqL1xuICBnZXQgYXR0YWNoZWQoKVxuICB7XG4gICAgcmV0dXJuICggdGhpcy5fY2hhbm5lbHMubGVuZ3RoID4gMCApO1xuICB9XG5cbiAgZ2V0IGRpcmVjdGlvbigpOiBEaXJlY3Rpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9kaXJlY3Rpb247XG4gIH1cblxuICAvKipcbiAgKiBIYW5kbGUgYW4gaW5jb21pbmcgTWVzc2FnZSwgbWV0aG9kIGNhbGxlZCBieSBDaGFubmVsLlxuICAqL1xuICBwdWJsaWMgaGFuZGxlTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCBmcm9tRW5kUG9pbnQ6IEVuZFBvaW50LCBmcm9tQ2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzLmZvckVhY2goIG1lc3NhZ2VMaXN0ZW5lciA9PiB7XG4gICAgICBtZXNzYWdlTGlzdGVuZXIoIG1lc3NhZ2UsIHRoaXMsIGZyb21DaGFubmVsICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIE1lc3NhZ2UuXG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLmZvckVhY2goIGNoYW5uZWwgPT4ge1xuICAgICAgY2hhbm5lbC5zZW5kTWVzc2FnZSggdGhpcywgbWVzc2FnZSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGEgZGVsZWdhdGUgdG8gcmVjZWl2ZSBpbmNvbWluZyBNZXNzYWdlc1xuICAqXG4gICogQHBhcmFtIG1lc3NhZ2VMaXN0ZW5lciAtIGRlbGVnYXRlIHRvIGJlIGNhbGxlZCB3aXRoIHJlY2VpdmVkIE1lc3NhZ2VcbiAgKi9cbiAgcHVibGljIG9uTWVzc2FnZSggbWVzc2FnZUxpc3RlbmVyOiBIYW5kbGVNZXNzYWdlRGVsZWdhdGUgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5wdXNoKCBtZXNzYWdlTGlzdGVuZXIgKTtcbiAgfVxufVxuXG4vKipcbiogQW4gaW5kZXhlZCBjb2xsZWN0aW9uIG9mIEVuZFBvaW50IG9iamVjdHMsIG5vcm1hbGx5IGluZGV4ZWQgdmlhIEVuZFBvaW50J3NcbiogdW5pcXVlIGlkZW50aWZpZXJcbiovXG5leHBvcnQgdHlwZSBFbmRQb2ludENvbGxlY3Rpb24gPSB7IFtpZDogc3RyaW5nXTogRW5kUG9pbnQ7IH07XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IEtpbmQsIEtpbmRJbmZvIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuZXhwb3J0IGVudW0gUHJvdG9jb2xUeXBlQml0c1xue1xuICBQQUNLRVQgPSAwLCAgICAgICAgIC8qKiBEYXRhZ3JhbS1vcmllbnRlZCAoYWx3YXlzIGNvbm5lY3RlZC4uLikgKi9cbiAgU1RSRUFNID0gMSwgICAgICAgICAvKiogQ29ubmVjdGlvbi1vcmllbnRlZCAqL1xuXG4gIE9ORVdBWSA9IDAsICAgICAgICAgLyoqIFVuaWRpcmVjdGlvbmFsIE9VVCAoc291cmNlKSAtPiBJTiAoc2luaykgKi9cbiAgQ0xJRU5UU0VSVkVSID0gNCwgICAvKiogQ29tbWFuZCBPVVQtPklOLCBSZXNwb25zZSBJTi0+T1VUICovXG4gIFBFRVIyUEVFUiA9IDYsICAgICAgLyoqIEJpZGlyZWN0aW9uYWw6IElOT1VUIDwtPiBJTk9VVCAqL1xuXG4gIFVOVFlQRUQgPSAwLCAgICAgICAgLyoqIFVudHlwZWQgZGF0YSAqL1xuICBUWVBFRCA9IDgsICAgICAgICAgIC8qKiBUeXBlZCBkYXRhICoqL1xufVxuXG5leHBvcnQgdHlwZSBQcm90b2NvbFR5cGUgPSBudW1iZXI7XG5cbmV4cG9ydCBjbGFzcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSAwO1xufVxuXG4vKipcbiogQSBDbGllbnQtU2VydmVyIFByb3RvY29sLCB0byBiZSB1c2VkIGJldHdlZW5cbiovXG5jbGFzcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxUPiBleHRlbmRzIFByb3RvY29sPFQ+XG57XG4gIHN0YXRpYyBwcm90b2NvbFR5cGU6IFByb3RvY29sVHlwZSA9IFByb3RvY29sVHlwZUJpdHMuQ0xJRU5UU0VSVkVSIHwgUHJvdG9jb2xUeXBlQml0cy5UWVBFRDtcbn1cblxuY2xhc3MgQVBEVSBpbXBsZW1lbnRzIEtpbmQge1xuICBraW5kSW5mbzogS2luZEluZm87XG4gIHByb3BlcnRpZXM7XG59XG5cbmNsYXNzIEFQRFVNZXNzYWdlIGV4dGVuZHMgTWVzc2FnZTxBUERVPlxue1xufVxuXG5jbGFzcyBBUERVUHJvdG9jb2wgZXh0ZW5kcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxBUERVTWVzc2FnZT5cbntcblxufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuLyoqXG4qIEBjbGFzcyBQb3J0SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIGNvbXBvbmVudCdzIFBvcnRcbiovXG5leHBvcnQgY2xhc3MgUG9ydEluZm9cbntcbiAgLyoqXG4gICogQnJpZWYgZGVzY3JpcHRpb24gZm9yIHRoZSBwb3J0LCB0byBhcHBlYXIgaW4gJ2hpbnQnXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogRGlyZWN0aW9uOiBJTiwgT1VULCBvciBJTk9VVFxuICAqICAgZm9yIGNsaWVudC1zZXJ2ZXIsIE9VVD1DbGllbnQsIElOPVNlcnZlclxuICAqL1xuICBkaXJlY3Rpb246IERpcmVjdGlvbjtcblxuICAvKipcbiAgKiBQcm90b2NvbCBpbXBsZW1lbnRlZCBieSB0aGUgcG9ydFxuICAqL1xuICBwcm90b2NvbDogUHJvdG9jb2w8YW55PjtcblxuICAvKipcbiAgKiBSRlUgLSBpbmRleGFibGUgcG9ydHNcbiAgKi9cbiAgY291bnQ6IG51bWJlciA9IDA7XG5cbiAgLyoqXG4gICogdHJ1ZSBpcyBwb3J0IG11c3QgYmUgY29ubmVjdGVkIGZvciBjb21wb25lbnQgdG8gZXhlY3V0ZVxuICAqL1xuICByZXF1aXJlZDogYm9vbGVhbiA9IGZhbHNlO1xufVxuIiwiaW1wb3J0IHsgS2luZCwgS2luZENvbnN0cnVjdG9yIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5cbmltcG9ydCB7IFBvcnRJbmZvIH0gZnJvbSAnLi9wb3J0LWluZm8nO1xuXG4vKipcbiogQGNsYXNzIENvbXBvbmVudEluZm9cbipcbiogTWV0YWRhdGEgYWJvdXQgYSBDb21wb25lbnRcbiovXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50SW5mb1xue1xuICAvKipcbiAgKiBDb21wb25lbnQgTmFtZVxuICAqL1xuICBuYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogQnJpZWYgZGVzY3JpcHRpb24gZm9yIHRoZSBjb21wb25lbnQsIHRvIGFwcGVhciBpbiAnaGludCdcbiAgKi9cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICAvKipcbiAgKiBMaW5rIHRvIGRldGFpbGVkIGluZm9ybWF0aW9uIGZvciB0aGUgY29tcG9uZW50XG4gICovXG4gIGRldGFpbExpbms6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIENhdGVnb3J5IG5hbWUgZm9yIHRoZSBjb21wb25lbnQsIGdyb3VwcyBzYW1lIGNhdGVnb3JpZXMgdG9nZXRoZXJcbiAgKi9cbiAgY2F0ZWdvcnk6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIEF1dGhvcidzIG5hbWVcbiAgKi9cbiAgYXV0aG9yOiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBBcnJheSBvZiBQb3J0IGRlc2NyaXB0b3JzLiBXaGVuIGFjdGl2ZSwgdGhlIGNvbXBvbmVudCB3aWxsIGNvbW11bmljYXRlXG4gICogdGhyb3VnaCBjb3JyZXNwb25kaW5nIEVuZFBvaW50c1xuICAqL1xuICBwb3J0czogeyBbaWQ6IHN0cmluZ106IFBvcnRJbmZvIH0gPSB7fTtcbiAgc3RvcmVzOiB7IFtpZDogc3RyaW5nXTogUG9ydEluZm8gfSA9IHt9O1xuXG4gIC8qKlxuICAqXG4gICovXG4gIGNvbmZpZ0tpbmQ6IEtpbmRDb25zdHJ1Y3RvcjtcbiAgZGVmYXVsdENvbmZpZzogS2luZDtcblxuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgfVxufVxuIiwiXG4vKipcbiogTWV0YWRhdGEgYWJvdXQgYSBjb21wb25lbnQncyBTdG9yZVxuKiBUT0RPOiBcbiovXG5leHBvcnQgY2xhc3MgU3RvcmVJbmZvXG57XG59XG4iLCJpbXBvcnQgeyBQb3J0SW5mbyB9IGZyb20gJy4vcG9ydC1pbmZvJztcbmltcG9ydCB7IFN0b3JlSW5mbyB9IGZyb20gJy4vc3RvcmUtaW5mbyc7XG5pbXBvcnQgeyBDb21wb25lbnRJbmZvIH0gZnJvbSAnLi9jb21wb25lbnQtaW5mbyc7XG5pbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5pbXBvcnQgeyBLaW5kLCBLaW5kQ29uc3RydWN0b3IgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuXG4vKipcbiogQnVpbGRlciBmb3IgJ0NvbXBvbmVudCcgbWV0YWRhdGEgKHN0YXRpYyBjb21wb25lbnRJbmZvKVxuKi9cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRCdWlsZGVyXG57XG4gIHByaXZhdGUgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3I7XG5cbiAgY29uc3RydWN0b3IoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yLCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGNhdGVnb3J5Pzogc3RyaW5nICkge1xuXG4gICAgdGhpcy5jdG9yID0gY3RvcjtcblxuICAgIGN0b3IuY29tcG9uZW50SW5mbyA9IHtcbiAgICAgIG5hbWU6IG5hbWUgfHwgY3Rvci5uYW1lLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZGV0YWlsTGluazogJycsXG4gICAgICBjYXRlZ29yeTogY2F0ZWdvcnksXG4gICAgICBhdXRob3I6ICcnLFxuICAgICAgcG9ydHM6IHt9LFxuICAgICAgc3RvcmVzOiB7fSxcbiAgICAgIGNvbmZpZ0tpbmQ6IEtpbmQsXG4gICAgICBkZWZhdWx0Q29uZmlnOiB7fVxuICAgIH07XG4gIH1cblxuICBwdWJsaWMgc3RhdGljIGluaXQoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yLCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGNhdGVnb3J5Pzogc3RyaW5nICk6IENvbXBvbmVudEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IENvbXBvbmVudEJ1aWxkZXIoIGN0b3IsIG5hbWUsIGRlc2NyaXB0aW9uLCBjYXRlZ29yeSApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgY29uZmlnKCBjb25maWdLaW5kOiBLaW5kQ29uc3RydWN0b3IsIGRlZmF1bHRDb25maWc/OiBLaW5kICk6IHRoaXMge1xuXG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8uY29uZmlnS2luZCA9IGNvbmZpZ0tpbmQ7XG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8uZGVmYXVsdENvbmZpZyA9IGRlZmF1bHRDb25maWc7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBwb3J0KCBpZDogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBkaXJlY3Rpb246IERpcmVjdGlvbiwgb3B0cz86IHsgcHJvdG9jb2w/OiBQcm90b2NvbDxhbnk+OyBjb3VudD86IG51bWJlcjsgcmVxdWlyZWQ/OiBib29sZWFuIH0gKTogdGhpc1xuICB7XG4gICAgb3B0cyA9IG9wdHMgfHwge307XG5cbiAgICB0aGlzLmN0b3IuY29tcG9uZW50SW5mby5wb3J0c1sgaWQgXSA9IHtcbiAgICAgIGRpcmVjdGlvbjogZGlyZWN0aW9uLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgcHJvdG9jb2w6IG9wdHMucHJvdG9jb2wsXG4gICAgICBjb3VudDogb3B0cy5jb3VudCxcbiAgICAgIHJlcXVpcmVkOiBvcHRzLnJlcXVpcmVkXG4gICAgfTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG59XG5cbi8qKlxuKiBDb21wb25lbnRzIGFyZSBydW50aW1lIG9iamVjdHMgdGhhdCBleGVjdXRlIHdpdGhpbiBhIEdyYXBoLlxuKlxuKiBBIGdyYXBoIE5vZGUgaXMgYSBwbGFjZWhvbGRlciBmb3IgdGhlIGFjdHVhbCBDb21wb25lbnQgdGhhdFxuKiB3aWxsIGV4ZWN1dGUuXG4qXG4qIFRoaXMgaW50ZXJmYWNlIGRlZmluZXMgdGhlIHN0YW5kYXJkIG1ldGhvZHMgYW5kIHByb3BlcnRpZXMgdGhhdCBhIENvbXBvbmVudFxuKiBjYW4gb3B0aW9uYWxseSBpbXBsZW1lbnQuXG4qL1xuZXhwb3J0IGludGVyZmFjZSBDb21wb25lbnRcbntcbiAgLy8gSW5pdGlhbGl6YXRpb24gYW5kIHNodXRkb3duXG4gIGluaXRpYWxpemU/KCBjb25maWc/OiBLaW5kICk6IEVuZFBvaW50W107XG4gIHRlYXJkb3duPygpO1xuXG4gIC8vIFJ1bm5pbmdcbiAgc3RhcnQ/KCk7XG4gIHN0b3A/KCk7XG5cbiAgLy8gUGF1c2luZyBhbmQgY29udGludWluZyBleGVjdXRpb24gKHdpdGhvdXQgcmVzZXR0aW5nIC4uKVxuICBwYXVzZT8oKTtcbiAgcmVzdW1lPygpO1xuXG4gIGJpbmRWaWV3PyggdmlldzogYW55ICk7XG4gIHVuYmluZFZpZXc/KCk7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29tcG9uZW50Q29uc3RydWN0b3JcbntcbiAgbmV3ICggLi4uYXJncyApOiBDb21wb25lbnQ7XG5cbiAgY29tcG9uZW50SW5mbz86IENvbXBvbmVudEluZm87XG59XG4iLCJpbXBvcnQgeyBFdmVudEFnZ3JlZ2F0b3IsIFN1YnNjcmlwdGlvbiwgSGFuZGxlciBhcyBFdmVudEhhbmRsZXIgfSBmcm9tICdhdXJlbGlhLWV2ZW50LWFnZ3JlZ2F0b3InO1xuXG4vL2V4cG9ydCB7IEV2ZW50SGFuZGxlciB9O1xuXG5leHBvcnQgY2xhc3MgRXZlbnRIdWJcbntcbiAgX2V2ZW50QWdncmVnYXRvcjogRXZlbnRBZ2dyZWdhdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IgPSBuZXcgRXZlbnRBZ2dyZWdhdG9yKCk7XG4gIH1cblxuICBwdWJsaWMgcHVibGlzaCggZXZlbnQ6IHN0cmluZywgZGF0YT86IGFueSApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IucHVibGlzaCggZXZlbnQsIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmUoIGV2ZW50OiBzdHJpbmcsIGhhbmRsZXI6IEZ1bmN0aW9uICk6IFN1YnNjcmlwdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2V2ZW50QWdncmVnYXRvci5zdWJzY3JpYmUoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cblxuICBwdWJsaWMgc3Vic2NyaWJlT25jZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZU9uY2UoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cbn1cblxuLypmdW5jdGlvbiBldmVudEh1YigpOiBhbnkge1xuICByZXR1cm4gZnVuY3Rpb24gZXZlbnRIdWI8VEZ1bmN0aW9uIGV4dGVuZHMgRnVuY3Rpb24sIEV2ZW50SHViPih0YXJnZXQ6IFRGdW5jdGlvbik6IFRGdW5jdGlvbiB7XG5cbiAgICB0YXJnZXQucHJvdG90eXBlLnN1YnNjcmliZSA9IG5ld0NvbnN0cnVjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUodGFyZ2V0LnByb3RvdHlwZSk7XG4gICAgbmV3Q29uc3RydWN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gdGFyZ2V0O1xuXG4gICAgcmV0dXJuIDxhbnk+IG5ld0NvbnN0cnVjdG9yO1xuICB9XG59XG5cbkBldmVudEh1YigpXG5jbGFzcyBNeUNsYXNzIHt9O1xuKi9cbiIsImltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcblxuLyoqXG4qIEEgUG9ydCBpcyBhIHBsYWNlaG9sZGVyIGZvciBhbiBFbmRQb2ludCBwdWJsaXNoZWQgYnkgdGhlIHVuZGVybHlpbmdcbiogY29tcG9uZW50IG9mIGEgTm9kZS5cbiovXG5leHBvcnQgY2xhc3MgUG9ydFxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBOb2RlO1xuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2VuZFBvaW50OiBFbmRQb2ludDtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IE5vZGUsIGVuZFBvaW50OiBFbmRQb2ludCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgLy8gV2FzIGFuIEVuZFBvaW50IHN1cHBsaWVkP1xuICAgIGlmICggIWVuZFBvaW50IClcbiAgICB7XG4gICAgICBsZXQgZGlyZWN0aW9uID0gYXR0cmlidXRlcy5kaXJlY3Rpb24gfHwgRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgICBpZiAoIHR5cGVvZiBhdHRyaWJ1dGVzLmRpcmVjdGlvbiA9PSBcInN0cmluZ1wiIClcbiAgICAgICAgZGlyZWN0aW9uID0gRGlyZWN0aW9uWyBkaXJlY3Rpb24udG9VcHBlckNhc2UoKSBdO1xuXG4gICAgICAvLyBDcmVhdGUgYSBcImR1bW15XCIgZW5kUG9pbnQgd2l0aCBjb3JyZWN0IGlkICsgZGlyZWN0aW9uXG4gICAgICBlbmRQb2ludCA9IG5ldyBFbmRQb2ludCggYXR0cmlidXRlcy5pZCwgZGlyZWN0aW9uICk7XG4gICAgfVxuXG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnQoKSB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50O1xuICB9XG4gIHB1YmxpYyBzZXQgZW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApIHtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0ge1xuICAgICAgaWQ6IHRoaXMuX2VuZFBvaW50LmlkLFxuICAgICAgZGlyZWN0aW9uOiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24sXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgfTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIG93bmVyXG4gICAqL1xuICBnZXQgb3duZXIoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyXG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgcHJvdG9jb2wgSURcbiAgICovXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgRW5kUG9pbnQgSURcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5pZDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBEaXJlY3Rpb25cbiAgICovXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uO1xuICB9XG5cbn1cblxuZXhwb3J0IGNsYXNzIFB1YmxpY1BvcnQgZXh0ZW5kcyBQb3J0XG57XG4gIHByb3h5RW5kUG9pbnQ6IEVuZFBvaW50O1xuICBwcm94eUNoYW5uZWw6IENoYW5uZWw7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGVuZFBvaW50LCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsZXQgcHJveHlEaXJlY3Rpb24gPVxuICAgICAgKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLklOIClcbiAgICAgICAgPyBEaXJlY3Rpb24uT1VUXG4gICAgICAgIDogKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLk9VVCApXG4gICAgICAgICAgPyBEaXJlY3Rpb24uSU5cbiAgICAgICAgICA6IERpcmVjdGlvbi5JTk9VVDtcblxuICAgIC8vIENyZWF0ZSBhbiBFbmRQb2ludCB0byBwcm94eSBiZXR3ZWVuIHRoZSBQdWJsaWMgYW5kIFByaXZhdGUgKGludGVybmFsKVxuICAgIC8vIHNpZGVzIG9mIHRoZSBQb3J0LlxuICAgIHRoaXMucHJveHlFbmRQb2ludCA9IG5ldyBFbmRQb2ludCggdGhpcy5fZW5kUG9pbnQuaWQsIHByb3h5RGlyZWN0aW9uICk7XG5cbiAgICAvLyBXaXJlLXVwIHByb3h5IC1cblxuICAgIC8vIEZvcndhcmQgaW5jb21pbmcgcGFja2V0cyAoZnJvbSBwdWJsaWMgaW50ZXJmYWNlKSB0byBwcml2YXRlXG4gICAgdGhpcy5wcm94eUVuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5fZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgdGhpcy5wcm94eUVuZFBvaW50LCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICAgIH0pO1xuXG4gICAgLy8gRm9yd2FyZCBvdXRnb2luZyBwYWNrZXRzIChmcm9tIHByaXZhdGUgaW50ZXJmYWNlKSB0byBwdWJsaWNcbiAgICB0aGlzLl9lbmRQb2ludC5vbk1lc3NhZ2UoICggbWVzc2FnZSApID0+IHtcbiAgICAgIHRoaXMucHJveHlFbmRQb2ludC5zZW5kTWVzc2FnZSggbWVzc2FnZSApO1xuICAgIH0pO1xuXG4gICAgLy8gbm90IHlldCBjb25uZWN0ZWRcbiAgICB0aGlzLnByb3h5Q2hhbm5lbCA9IG51bGw7XG4gIH1cblxuICAvLyBDb25uZWN0IHRvIFByaXZhdGUgKGludGVybmFsKSBFbmRQb2ludC4gVG8gYmUgY2FsbGVkIGR1cmluZyBncmFwaFxuICAvLyB3aXJlVXAgcGhhc2VcbiAgcHVibGljIGNvbm5lY3RQcml2YXRlKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMucHJveHlDaGFubmVsID0gY2hhbm5lbDtcblxuICAgIHRoaXMucHJveHlFbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIHB1YmxpYyBkaXNjb25uZWN0UHJpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQuZGV0YWNoKCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgcG9ydCA9IHN1cGVyLnRvT2JqZWN0KCBvcHRzICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBOb2RlIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NvbXBvbmVudDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgX2luaXRpYWxEYXRhOiBPYmplY3Q7XG5cbiAgcHJvdGVjdGVkIF9wb3J0czogTWFwPHN0cmluZywgUG9ydD47XG5cbiAgcHVibGljIG1ldGFkYXRhOiBhbnk7XG5cbiAgLyoqXG4gICAqIFJ1bnRpbWUgYW5kIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICAqL1xuICBwcm90ZWN0ZWQgX2NvbnRleHQ6IFJ1bnRpbWVDb250ZXh0O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCAnJztcbiAgICB0aGlzLl9jb21wb25lbnQgPSBhdHRyaWJ1dGVzLmNvbXBvbmVudDtcbiAgICB0aGlzLl9pbml0aWFsRGF0YSA9IGF0dHJpYnV0ZXMuaW5pdGlhbERhdGEgfHwge307XG5cbiAgICB0aGlzLl9wb3J0cyA9IG5ldyBNYXA8c3RyaW5nLCBQb3J0PigpO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB9O1xuXG4gICAgLy8gSW5pdGlhbGx5IGNyZWF0ZSAncGxhY2Vob2xkZXInIHBvcnRzLiBPbmNlIGNvbXBvbmVudCBoYXMgYmVlblxuICAgIC8vIGxvYWRlZCBhbmQgaW5zdGFudGlhdGVkLCB0aGV5IHdpbGwgYmUgY29ubmVjdGVkIGNvbm5lY3RlZCB0b1xuICAgIC8vIHRoZSBjb21wb25lbnQncyBjb21tdW5pY2F0aW9uIGVuZC1wb2ludHNcbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5wb3J0cyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGRQbGFjZWhvbGRlclBvcnQoIGlkLCBhdHRyaWJ1dGVzLnBvcnRzWyBpZCBdICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBub2RlID0ge1xuICAgICAgaWQ6IHRoaXMuaWQsXG4gICAgICBjb21wb25lbnQ6IHRoaXMuX2NvbXBvbmVudCxcbiAgICAgIGluaXRpYWxEYXRhOiB0aGlzLl9pbml0aWFsRGF0YSxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhXG4gICAgfTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICBub2RlLnBvcnRzWyBpZCBdID0gcG9ydC50b09iamVjdCgpO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIG93bmVyXG4gICAqL1xuICBwdWJsaWMgZ2V0IG93bmVyKCk6IEdyYXBoIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXJcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIE5vZGUncyBpZFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2lkO1xuICB9XG4gIC8qKlxuICAgKiBTZXQgdGhlIE5vZGUncyBpZFxuICAgKiBAcGFyYW0gaWQgLSBuZXcgaWRlbnRpZmllclxuICAgKi9cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBwdWJsaWMgdXBkYXRlUG9ydHMoIGVuZFBvaW50czogRW5kUG9pbnRbXSApIHtcbiAgICBsZXQgY3VycmVudFBvcnRzID0gdGhpcy5fcG9ydHM7XG4gICAgbGV0IG5ld1BvcnRzOiBNYXA8c3RyaW5nLFBvcnQ+ID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICAvLyBQYXJhbSBlbmRQb2ludHMgaXMgYW4gYXJyYXkgb2YgRW5kUG9pbnRzIGV4cG9ydGVkIGJ5IGEgY29tcG9uZW50XG4gICAgLy8gdXBkYXRlIG91ciBtYXAgb2YgUG9ydHMgdG8gcmVmbGVjdCB0aGlzIGFycmF5XG4gICAgLy8gVGhpcyBtYXkgbWVhbiBpbmNsdWRpbmcgYSBuZXcgUG9ydCwgdXBkYXRpbmcgYW4gZXhpc3RpbmcgUG9ydCB0b1xuICAgIC8vIHVzZSB0aGlzIHN1cHBsaWVkIEVuZFBvaW50LCBvciBldmVuIGRlbGV0aW5nIGEgJ25vLWxvbmdlcicgdmFsaWQgUG9ydFxuICAgIGVuZFBvaW50cy5mb3JFYWNoKCAoZXA6IEVuZFBvaW50ICkgPT4ge1xuICAgICAgbGV0IGlkID0gZXAuaWQ7XG5cbiAgICAgIGlmICggY3VycmVudFBvcnRzLmhhcyggaWQgKSApIHtcbiAgICAgICAgbGV0IHBvcnQgPSBjdXJyZW50UG9ydHMuZ2V0KCBpZCApO1xuXG4gICAgICAgIHBvcnQuZW5kUG9pbnQgPSBlcDtcblxuICAgICAgICBuZXdQb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICAgICAgY3VycmVudFBvcnRzLmRlbGV0ZSggaWQgKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBlbmRQb2ludCBub3QgZm91bmQsIGNyZWF0ZSBhIHBvcnQgZm9yIGl0XG4gICAgICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIGVwLCB7IGlkOiBpZCwgZGlyZWN0aW9uOiBlcC5kaXJlY3Rpb24gfSApO1xuXG4gICAgICAgIG5ld1BvcnRzLnNldCggaWQsIHBvcnQgKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3UG9ydHM7XG4gIH1cblxuXG4gIC8qKlxuICAgKiBBZGQgYSBwbGFjZWhvbGRlciBQb3J0XG4gICAqL1xuICBwcm90ZWN0ZWQgYWRkUGxhY2Vob2xkZXJQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBwb3J0cyBhcyBhbiBhcnJheSBvZiBQb3J0c1xuICAgKlxuICAgKiBAcmV0dXJuIFBvcnRbXVxuICAgKi9cbiAgZ2V0IHBvcnRzKCk6IE1hcDxzdHJpbmcsIFBvcnQ+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHM7XG4gIH1cblxuICBnZXRQb3J0QXJyYXkoKTogUG9ydFtdIHtcbiAgICBsZXQgeHBvcnRzOiBQb3J0W10gPSBbXTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICB4cG9ydHMucHVzaCggcG9ydCApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiB4cG9ydHM7XG4gIH1cblxuICAvKipcbiAgICogTG9va3VwIGEgUG9ydCBieSBpdCdzIElEXG4gICAqIEBwYXJhbSBpZCAtIHBvcnQgaWRlbnRpZmllclxuICAgKlxuICAgKiBAcmV0dXJuIFBvcnQgb3IgdW5kZWZpbmVkXG4gICAqL1xuICBnZXRQb3J0QnlJRCggaWQ6IHN0cmluZyApOiBQb3J0XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICB9XG5cbiAgaWRlbnRpZnlQb3J0KCBpZDogc3RyaW5nLCBwcm90b2NvbElEPzogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHZhciBwb3J0OiBQb3J0O1xuXG4gICAgaWYgKCBpZCApXG4gICAgICBwb3J0ID0gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICAgIGVsc2UgaWYgKCBwcm90b2NvbElEIClcbiAgICB7XG4gICAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHAsIGlkICkgPT4ge1xuICAgICAgICBpZiAoIHAucHJvdG9jb2xJRCA9PSBwcm90b2NvbElEIClcbiAgICAgICAgICBwb3J0ID0gcDtcbiAgICAgIH0sIHRoaXMgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmUgYSBQb3J0IGZyb20gdGhpcyBOb2RlXG4gICAqIEBwYXJhbSBpZCAtIGlkZW50aWZpZXIgb2YgUG9ydCB0byBiZSByZW1vdmVkXG4gICAqIEByZXR1cm4gdHJ1ZSAtIHBvcnQgcmVtb3ZlZFxuICAgKiAgICAgICAgIGZhbHNlIC0gcG9ydCBpbmV4aXN0ZW50XG4gICAqL1xuICByZW1vdmVQb3J0KCBpZDogc3RyaW5nICk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMudW5sb2FkQ29tcG9uZW50KCk7XG5cbiAgICAvLyBHZXQgYSBDb21wb25lbnRDb250ZXh0IHJlc3BvbnNhYmxlIGZvciBDb21wb25lbnQncyBsaWZlLWN5Y2xlIGNvbnRyb2xcbiAgICBsZXQgY3R4ID0gdGhpcy5fY29udGV4dCA9IGZhY3RvcnkuY3JlYXRlQ29udGV4dCggdGhpcy5fY29tcG9uZW50LCB0aGlzLl9pbml0aWFsRGF0YSApO1xuXG4gICAgLy8gTWFrZSBvdXJzZWx2ZXMgdmlzaWJsZSB0byBjb250ZXh0IChhbmQgaW5zdGFuY2UpXG4gICAgY3R4Lm5vZGUgPSB0aGlzO1xuXG4gICAgLy9sZXQgbWUgPSB0aGlzO1xuXG4gICAgLy8gTG9hZCBjb21wb25lbnRcbiAgICByZXR1cm4gY3R4LmxvYWQoKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgY29udGV4dCgpOiBSdW50aW1lQ29udGV4dCB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbnRleHQ7XG4gIH1cblxuICB1bmxvYWRDb21wb25lbnQoKVxuICB7XG4gICAgaWYgKCB0aGlzLl9jb250ZXh0IClcbiAgICB7XG4gICAgICB0aGlzLl9jb250ZXh0LnJlbGVhc2UoKTtcblxuICAgICAgdGhpcy5fY29udGV4dCA9IG51bGw7XG4gICAgfVxuICB9XG5cbn1cbiIsImltcG9ydCB7IENvbnRhaW5lciwgYXV0b2luamVjdCBhcyBpbmplY3QgfSBmcm9tICdhdXJlbGlhLWRlcGVuZGVuY3ktaW5qZWN0aW9uJztcbmltcG9ydCB7IG1ldGFkYXRhIH0gZnJvbSAnYXVyZWxpYS1tZXRhZGF0YSc7XG5cbmV4cG9ydCB7IENvbnRhaW5lciwgaW5qZWN0IH07XG5leHBvcnQgaW50ZXJmYWNlIEluamVjdGFibGUge1xuICBuZXcoIC4uLmFyZ3MgKTogT2JqZWN0O1xufVxuIiwiaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludCwgRW5kUG9pbnRDb2xsZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi4vZ3JhcGgvbm9kZSc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi4vZ3JhcGgvcG9ydCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IENvbXBvbmVudCB9IGZyb20gJy4uL2NvbXBvbmVudC9jb21wb25lbnQnO1xuXG5pbXBvcnQgeyBDb250YWluZXIsIEluamVjdGFibGUgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuXG5leHBvcnQgZW51bSBSdW5TdGF0ZSB7XG4gIE5FV0JPUk4sICAgICAgLy8gTm90IHlldCBsb2FkZWRcbiAgTE9BRElORywgICAgICAvLyBXYWl0aW5nIGZvciBhc3luYyBsb2FkIHRvIGNvbXBsZXRlXG4gIExPQURFRCwgICAgICAgLy8gQ29tcG9uZW50IGxvYWRlZCwgbm90IHlldCBleGVjdXRhYmxlXG4gIFJFQURZLCAgICAgICAgLy8gUmVhZHkgZm9yIEV4ZWN1dGlvblxuICBSVU5OSU5HLCAgICAgIC8vIE5ldHdvcmsgYWN0aXZlLCBhbmQgcnVubmluZ1xuICBQQVVTRUQgICAgICAgIC8vIE5ldHdvcmsgdGVtcG9yYXJpbHkgcGF1c2VkXG59XG5cbi8qKlxuKiBUaGUgcnVudGltZSBjb250ZXh0IGluZm9ybWF0aW9uIGZvciBhIENvbXBvbmVudCBpbnN0YW5jZVxuKi9cbmV4cG9ydCBjbGFzcyBSdW50aW1lQ29udGV4dFxue1xuICAvKipcbiAgKiBUaGUgY29tcG9uZW50IGlkIC8gYWRkcmVzc1xuICAqL1xuICBwcml2YXRlIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIFRoZSBydW50aW1lIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICovXG4gIHByaXZhdGUgX2luc3RhbmNlOiBDb21wb25lbnQ7XG5cbiAgLyoqXG4gICogSW5pdGlhbCBEYXRhIGZvciB0aGUgY29tcG9uZW50IGluc3RhbmNlXG4gICovXG4gIHByaXZhdGUgX2NvbmZpZzoge307XG5cbiAgLyoqXG4gICogVGhlIHJ1bnRpbWUgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgKi9cbiAgcHJpdmF0ZSBfY29udGFpbmVyOiBDb250YWluZXI7XG5cbiAgLyoqXG4gICogVGhlIGNvbXBvbmVudCBmYWN0b3J5IHRoYXQgY3JlYXRlZCB1c1xuICAqL1xuICBwcml2YXRlIF9mYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5O1xuXG4gIC8qKlxuICAqIFRoZSBub2RlXG4gICovXG4gIHByaXZhdGUgX25vZGU6IE5vZGU7XG5cbiAgLyoqXG4gICpcbiAgKlxuICAqL1xuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgY29udGFpbmVyOiBDb250YWluZXIsIGlkOiBzdHJpbmcsIGNvbmZpZzoge30sIGRlcHM6IEluamVjdGFibGVbXSA9IFtdICkge1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG5cbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fY29uZmlnID0gY29uZmlnO1xuXG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyO1xuXG4gICAgLy8gUmVnaXN0ZXIgYW55IGNvbnRleHQgZGVwZW5kZW5jaWVzXG4gICAgZm9yKCBsZXQgaSBpbiBkZXBzIClcbiAgICB7XG4gICAgICBpZiAoICF0aGlzLl9jb250YWluZXIuaGFzUmVzb2x2ZXIoIGRlcHNbaV0gKSApXG4gICAgICAgIHRoaXMuX2NvbnRhaW5lci5yZWdpc3RlclNpbmdsZXRvbiggZGVwc1tpXSwgZGVwc1tpXSApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBub2RlKCk6IE5vZGUge1xuICAgIHJldHVybiB0aGlzLl9ub2RlO1xuICB9XG4gIHNldCBub2RlKCBub2RlOiBOb2RlICkge1xuICAgIHRoaXMuX25vZGUgPSBub2RlO1xuXG4gICAgLy8gbWFrZSBub2RlICdpbmplY3RhYmxlJyBpbiBjb250YWluZXJcbiAgICB0aGlzLl9jb250YWluZXIucmVnaXN0ZXJJbnN0YW5jZSggTm9kZSwgdGhpcyApO1xuICB9XG5cbiAgZ2V0IGluc3RhbmNlKCk6IENvbXBvbmVudCB7XG4gICAgcmV0dXJuIHRoaXMuX2luc3RhbmNlO1xuICB9XG5cbiAgZ2V0IGNvbnRhaW5lcigpOiBDb250YWluZXIge1xuICAgIHJldHVybiB0aGlzLl9jb250YWluZXI7XG4gIH1cblxuICBsb2FkKCApOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBnZXQgYW4gaW5zdGFuY2UgZnJvbSB0aGUgZmFjdG9yeVxuICAgICAgbWUuX3J1blN0YXRlID0gUnVuU3RhdGUuTE9BRElORztcbiAgICAgIHRoaXMuX2ZhY3RvcnkubG9hZENvbXBvbmVudCggdGhpcywgdGhpcy5faWQgKVxuICAgICAgICAudGhlbiggKGluc3RhbmNlKSA9PiB7XG4gICAgICAgICAgLy8gQ29tcG9uZW50IChhbmQgYW55IGRlcGVuZGVuY2llcykgaGF2ZSBiZWVuIGxvYWRlZFxuICAgICAgICAgIG1lLl9pbnN0YW5jZSA9IGluc3RhbmNlO1xuICAgICAgICAgIG1lLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5MT0FERUQgKTtcblxuICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoZXJyKSA9PiB7XG4gICAgICAgICAgLy8gVW5hYmxlIHRvIGxvYWRcbiAgICAgICAgICBtZS5fcnVuU3RhdGUgPSBSdW5TdGF0ZS5ORVdCT1JOO1xuXG4gICAgICAgICAgcmVqZWN0KCBlcnIgKTtcbiAgICAgICAgfSk7XG4gICAgfSApO1xuICB9XG5cbiAgX3J1blN0YXRlOiBSdW5TdGF0ZSA9IFJ1blN0YXRlLk5FV0JPUk47XG4gIGdldCBydW5TdGF0ZSgpIHtcbiAgICByZXR1cm4gdGhpcy5fcnVuU3RhdGU7XG4gIH1cblxuICBwcml2YXRlIGluU3RhdGUoIHN0YXRlczogUnVuU3RhdGVbXSApOiBib29sZWFuIHtcbiAgICByZXR1cm4gbmV3IFNldDxSdW5TdGF0ZT4oIHN0YXRlcyApLmhhcyggdGhpcy5fcnVuU3RhdGUgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFRyYW5zaXRpb24gY29tcG9uZW50IHRvIG5ldyBzdGF0ZVxuICAqIFN0YW5kYXJkIHRyYW5zaXRpb25zLCBhbmQgcmVzcGVjdGl2ZSBhY3Rpb25zLCBhcmU6XG4gICogICBMT0FERUQgLT4gUkVBRFkgICAgICBpbnN0YW50aWF0ZSBhbmQgaW5pdGlhbGl6ZSBjb21wb25lbnRcbiAgKiAgIFJFQURZIC0+IExPQURFRCAgICAgIHRlYXJkb3duIGFuZCBkZXN0cm95IGNvbXBvbmVudFxuICAqXG4gICogICBSRUFEWSAtPiBSVU5OSU5HICAgICBzdGFydCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICogICBSVU5OSU5HIC0+IFJFQURZICAgICBzdG9wIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKlxuICAqICAgUlVOTklORyAtPiBQQVVTRUQgICAgcGF1c2UgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqICAgUEFVU0VEIC0+IFJVTk5JTkcgICAgcmVzdW1lIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKlxuICAqL1xuICBzZXRSdW5TdGF0ZSggcnVuU3RhdGU6IFJ1blN0YXRlICkge1xuICAgIGxldCBpbnN0ID0gdGhpcy5pbnN0YW5jZTtcblxuICAgIHN3aXRjaCggcnVuU3RhdGUgKSAvLyB0YXJnZXQgc3RhdGUgLi5cbiAgICB7XG4gICAgICBjYXNlIFJ1blN0YXRlLkxPQURFRDogLy8ganVzdCBsb2FkZWQsIG9yIHRlYXJkb3duXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJFQURZLCBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHRlYXJkb3duIGFuZCBkZXN0cm95IGNvbXBvbmVudFxuICAgICAgICAgIGlmICggaW5zdC50ZWFyZG93biApXG4gICAgICAgICAge1xuICAgICAgICAgICAgaW5zdC50ZWFyZG93bigpO1xuXG4gICAgICAgICAgICAvLyBhbmQgZGVzdHJveSBpbnN0YW5jZVxuICAgICAgICAgICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5SRUFEWTogIC8vIGluaXRpYWxpemUgb3Igc3RvcCBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLkxPQURFRCBdICkgKSB7XG4gICAgICAgICAgLy8gaW5pdGlhbGl6ZSBjb21wb25lbnRcblxuICAgICAgICAgIGxldCBlbmRQb2ludHM6IEVuZFBvaW50W10gPSBbXTtcblxuICAgICAgICAgIGlmICggaW5zdC5pbml0aWFsaXplIClcbiAgICAgICAgICAgIGVuZFBvaW50cyA9IHRoaXMuaW5zdGFuY2UuaW5pdGlhbGl6ZSggPEtpbmQ+dGhpcy5fY29uZmlnICk7XG5cbiAgICAgICAgICBpZiAoIHRoaXMuX25vZGUgKVxuICAgICAgICAgICAgdGhpcy5fbm9kZS51cGRhdGVQb3J0cyggZW5kUG9pbnRzICk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHN0b3AgY29tcG9uZW50XG4gICAgICAgICAgaWYgKCBpbnN0LnN0b3AgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5zdG9wKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgaW5pdGlhbGl6ZWQsIG5vdCBsb2FkZWQnICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlJVTk5JTkc6ICAvLyBzdGFydC9yZXN1bWUgbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SRUFEWSwgUnVuU3RhdGUuUlVOTklORyBdICkgKSB7XG4gICAgICAgICAgLy8gc3RhcnQgY29tcG9uZW50IGV4ZWN1dGlvblxuICAgICAgICAgIGlmICggaW5zdC5zdGFydCApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnN0YXJ0KCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHJlc3VtZSBjb21wb25lbnQgZXhlY3V0aW9uIGFmdGVyIHBhdXNlXG4gICAgICAgICAgaWYgKCBpbnN0LnJlc3VtZSApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnJlc3VtZSgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIHN0YXJ0ZWQsIG5vdCByZWFkeScgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUEFVU0VEOiAgLy8gcGF1c2Ugbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HXSApICkge1xuICAgICAgICAgIGlmICggaW5zdC5wYXVzZSApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnBhdXNlKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIGFscmVhZHkgcGF1c2VkXG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgcGF1c2VkJyApO1xuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICB0aGlzLl9ydW5TdGF0ZSA9IHJ1blN0YXRlO1xuICB9XG5cbiAgcmVsZWFzZSgpIHtcbiAgICAvLyByZWxlYXNlIGluc3RhbmNlLCB0byBhdm9pZCBtZW1vcnkgbGVha3NcbiAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gbnVsbFxuICB9XG59XG4iLCJleHBvcnQgaW50ZXJmYWNlIE1vZHVsZUxvYWRlciB7XG4gIGhhc01vZHVsZT8oIGlkOiBzdHJpbmcgKTogYm9vbGVhbjtcblxuICBsb2FkTW9kdWxlKCBpZDogc3RyaW5nICk6IFByb21pc2U8YW55Pjtcbn1cblxuZGVjbGFyZSBpbnRlcmZhY2UgU3lzdGVtIHtcbiAgbm9ybWFsaXplU3luYyggaWQgKTtcbiAgaW1wb3J0KCBpZCApO1xufTtcbmRlY2xhcmUgdmFyIFN5c3RlbTogU3lzdGVtO1xuXG5jbGFzcyBNb2R1bGVSZWdpc3RyeUVudHJ5IHtcbiAgY29uc3RydWN0b3IoIGFkZHJlc3M6IHN0cmluZyApIHtcblxuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTeXN0ZW1Nb2R1bGVMb2FkZXIgaW1wbGVtZW50cyBNb2R1bGVMb2FkZXIge1xuXG4gIHByaXZhdGUgbW9kdWxlUmVnaXN0cnk6IE1hcDxzdHJpbmcsIE1vZHVsZVJlZ2lzdHJ5RW50cnk+O1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMubW9kdWxlUmVnaXN0cnkgPSBuZXcgTWFwPHN0cmluZywgTW9kdWxlUmVnaXN0cnlFbnRyeT4oKTtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0T3JDcmVhdGVNb2R1bGVSZWdpc3RyeUVudHJ5KGFkZHJlc3M6IHN0cmluZyk6IE1vZHVsZVJlZ2lzdHJ5RW50cnkge1xuICAgIHJldHVybiB0aGlzLm1vZHVsZVJlZ2lzdHJ5W2FkZHJlc3NdIHx8ICh0aGlzLm1vZHVsZVJlZ2lzdHJ5W2FkZHJlc3NdID0gbmV3IE1vZHVsZVJlZ2lzdHJ5RW50cnkoYWRkcmVzcykpO1xuICB9XG5cbiAgbG9hZE1vZHVsZSggaWQ6IHN0cmluZyApOiBQcm9taXNlPGFueT4ge1xuICAgIGxldCBuZXdJZCA9IFN5c3RlbS5ub3JtYWxpemVTeW5jKGlkKTtcbiAgICBsZXQgZXhpc3RpbmcgPSB0aGlzLm1vZHVsZVJlZ2lzdHJ5W25ld0lkXTtcblxuICAgIGlmIChleGlzdGluZykge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShleGlzdGluZyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIFN5c3RlbS5pbXBvcnQobmV3SWQpLnRoZW4obSA9PiB7XG4gICAgICB0aGlzLm1vZHVsZVJlZ2lzdHJ5W25ld0lkXSA9IG07XG4gICAgICByZXR1cm4gbTsgLy9lbnN1cmVPcmlnaW5PbkV4cG9ydHMobSwgbmV3SWQpO1xuICAgIH0pO1xuICB9XG5cbn1cbiIsImltcG9ydCB7IENvbXBvbmVudCwgQ29tcG9uZW50Q29uc3RydWN0b3IgfSBmcm9tICcuLi9jb21wb25lbnQvY29tcG9uZW50JztcbmltcG9ydCB7IFJ1bnRpbWVDb250ZXh0IH0gZnJvbSAnLi9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgTW9kdWxlTG9hZGVyIH0gZnJvbSAnLi9tb2R1bGUtbG9hZGVyJztcblxuaW1wb3J0IHsgQ29udGFpbmVyLCBJbmplY3RhYmxlIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcbmltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50RmFjdG9yeSB7XG4gIHByaXZhdGUgX2xvYWRlcjogTW9kdWxlTG9hZGVyO1xuICBwcml2YXRlIF9jb250YWluZXI6IENvbnRhaW5lcjtcbiAgcHJpdmF0ZSBfY29tcG9uZW50czogTWFwPHN0cmluZywgQ29tcG9uZW50Q29uc3RydWN0b3I+O1xuXG4gIGNvbnN0cnVjdG9yKCBjb250YWluZXI/OiBDb250YWluZXIsIGxvYWRlcj86IE1vZHVsZUxvYWRlciApIHtcbiAgICB0aGlzLl9sb2FkZXIgPSBsb2FkZXI7XG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyIHx8IG5ldyBDb250YWluZXIoKTtcbiAgICB0aGlzLl9jb21wb25lbnRzID0gbmV3IE1hcDxzdHJpbmcsIENvbXBvbmVudENvbnN0cnVjdG9yPigpO1xuXG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIHVuZGVmaW5lZCwgT2JqZWN0ICk7XG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIFwiXCIsIE9iamVjdCApO1xuICB9XG5cbiAgY3JlYXRlQ29udGV4dCggaWQ6IHN0cmluZywgY29uZmlnOiB7fSwgZGVwczogSW5qZWN0YWJsZVtdID0gW10gKTogUnVudGltZUNvbnRleHRcbiAge1xuICAgIGxldCBjaGlsZENvbnRhaW5lcjogQ29udGFpbmVyID0gdGhpcy5fY29udGFpbmVyLmNyZWF0ZUNoaWxkKCk7XG5cbiAgICByZXR1cm4gbmV3IFJ1bnRpbWVDb250ZXh0KCB0aGlzLCBjaGlsZENvbnRhaW5lciwgaWQsIGNvbmZpZywgZGVwcyApO1xuICB9XG5cbiAgZ2V0Q2hpbGRDb250YWluZXIoKTogQ29udGFpbmVyIHtcbiAgICByZXR1cm4gO1xuICB9XG5cbiAgbG9hZENvbXBvbmVudCggY3R4OiBSdW50aW1lQ29udGV4dCwgaWQ6IHN0cmluZyApOiBQcm9taXNlPENvbXBvbmVudD5cbiAge1xuICAgIGxldCBjcmVhdGVDb21wb25lbnQgPSBmdW5jdGlvbiggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKTogQ29tcG9uZW50XG4gICAge1xuICAgICAgbGV0IG5ld0luc3RhbmNlOiBDb21wb25lbnQgPSBjdHguY29udGFpbmVyLmludm9rZSggY3RvciApO1xuXG4gICAgICByZXR1cm4gbmV3SW5zdGFuY2U7XG4gICAgfVxuXG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDb21wb25lbnQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBDaGVjayBjYWNoZVxuICAgICAgbGV0IGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yID0gdGhpcy5nZXQoIGlkICk7XG5cbiAgICAgIGlmICggY3RvciApIHtcbiAgICAgICAgLy8gdXNlIGNhY2hlZCBjb25zdHJ1Y3RvclxuICAgICAgICByZXNvbHZlKCBjcmVhdGVDb21wb25lbnQoIGN0b3IgKSApO1xuICAgICAgfVxuICAgICAgZWxzZSBpZiAoIHRoaXMuX2xvYWRlciApIHtcbiAgICAgICAgLy8gZ290IGEgbG9hZGVkLCBzbyB0cnkgdG8gbG9hZCB0aGUgbW9kdWxlIC4uLlxuICAgICAgICB0aGlzLl9sb2FkZXIubG9hZE1vZHVsZSggaWQgKVxuICAgICAgICAgIC50aGVuKCAoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICkgPT4ge1xuXG4gICAgICAgICAgICAvLyByZWdpc3RlciBsb2FkZWQgY29tcG9uZW50XG4gICAgICAgICAgICBtZS5fY29tcG9uZW50cy5zZXQoIGlkLCBjdG9yICk7XG5cbiAgICAgICAgICAgIC8vIGluc3RhbnRpYXRlIGFuZCByZXNvbHZlXG4gICAgICAgICAgICByZXNvbHZlKCBjcmVhdGVDb21wb25lbnQoIGN0b3IgKSApO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLmNhdGNoKCAoIGUgKSA9PiB7XG4gICAgICAgICAgICByZWplY3QoICdDb21wb25lbnRGYWN0b3J5OiBVbmFibGUgdG8gbG9hZCBjb21wb25lbnQgXCInICsgaWQgKyAnXCIgLSAnICsgZSApO1xuICAgICAgICAgIH0gKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBvb3BzLiBubyBsb2FkZXIgLi4gbm8gY29tcG9uZW50XG4gICAgICAgIHJlamVjdCggJ0NvbXBvbmVudEZhY3Rvcnk6IENvbXBvbmVudCBcIicgKyBpZCArICdcIiBub3QgcmVnaXN0ZXJlZCwgYW5kIExvYWRlciBub3QgYXZhaWxhYmxlJyApO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgZ2V0KCBpZDogc3RyaW5nICk6IENvbXBvbmVudENvbnN0cnVjdG9yIHtcbiAgICByZXR1cm4gdGhpcy5fY29tcG9uZW50cy5nZXQoIGlkICk7XG4gIH1cbiAgcmVnaXN0ZXIoIGlkOiBzdHJpbmcsIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICkge1xuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCBpZCwgY3RvciApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbmV4cG9ydCB0eXBlIEVuZFBvaW50UmVmID0geyBub2RlSUQ6IHN0cmluZywgcG9ydElEOiBzdHJpbmcgfTtcblxuZXhwb3J0IGNsYXNzIExpbmtcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NoYW5uZWw6IENoYW5uZWw7XG4gIHByb3RlY3RlZCBfZnJvbTogRW5kUG9pbnRSZWY7XG4gIHByb3RlY3RlZCBfdG86IEVuZFBvaW50UmVmO1xuXG4gIHByb3RlY3RlZCBfcHJvdG9jb2xJRDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCBcIlwiO1xuICAgIC8vdGhpcy5fY2hhbm5lbCA9IG51bGw7XG4gICAgdGhpcy5fZnJvbSA9IGF0dHJpYnV0ZXNbICdmcm9tJyBdO1xuICAgIHRoaXMuX3RvID0gYXR0cmlidXRlc1sgJ3RvJyBdO1xuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBhdHRyaWJ1dGVzWyAncHJvdG9jb2wnIF0gfHwgJ2FueSc7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IHg6IDEwMCwgeTogMTAwIH07XG4gIH1cblxuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIGxldCBsaW5rID0ge1xuICAgICAgaWQ6IHRoaXMuX2lkLFxuICAgICAgcHJvdG9jb2w6ICggdGhpcy5fcHJvdG9jb2xJRCAhPSAnYW55JyApID8gdGhpcy5fcHJvdG9jb2xJRCA6IHVuZGVmaW5lZCxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhLFxuICAgICAgZnJvbTogdGhpcy5fZnJvbSxcbiAgICAgIHRvOiB0aGlzLl90b1xuICAgIH07XG5cbiAgICByZXR1cm4gbGluaztcbiAgfVxuXG4gIHNldCBpZCggaWQ6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuICB9XG5cbiAgY29ubmVjdCggY2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICAvLyBpZGVudGlmeSBmcm9tUG9ydCBpbiBmcm9tTm9kZVxuICAgIGxldCBmcm9tUG9ydDogUG9ydCA9IHRoaXMuZnJvbU5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl9mcm9tLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApO1xuXG4gICAgLy8gaWRlbnRpZnkgdG9Qb3J0IGluIHRvTm9kZVxuICAgIGxldCB0b1BvcnQ6IFBvcnQgPSB0aGlzLnRvTm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX3RvLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApO1xuXG4gICAgdGhpcy5fY2hhbm5lbCA9IGNoYW5uZWw7XG5cbiAgICBmcm9tUG9ydC5lbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgICB0b1BvcnQuZW5kUG9pbnQuYXR0YWNoKCBjaGFubmVsICk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IENoYW5uZWxcbiAge1xuICAgIGxldCBjaGFuID0gdGhpcy5fY2hhbm5lbDtcblxuICAgIGlmICggY2hhbiApXG4gICAge1xuICAgICAgdGhpcy5fY2hhbm5lbC5lbmRQb2ludHMuZm9yRWFjaCggKCBlbmRQb2ludCApID0+IHtcbiAgICAgICAgZW5kUG9pbnQuZGV0YWNoKCB0aGlzLl9jaGFubmVsICk7XG4gICAgICB9ICk7XG5cbiAgICAgIHRoaXMuX2NoYW5uZWwgPSB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIGNoYW47XG4gIH1cblxuICBnZXQgZnJvbU5vZGUoKTogTm9kZVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyLmdldE5vZGVCeUlEKCB0aGlzLl9mcm9tLm5vZGVJRCApO1xuICB9XG5cbiAgZ2V0IGZyb21Qb3J0KCk6IFBvcnRcbiAge1xuICAgIGxldCBub2RlID0gdGhpcy5mcm9tTm9kZTtcblxuICAgIHJldHVybiAobm9kZSkgPyBub2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fZnJvbS5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKSA6IHVuZGVmaW5lZDtcbiAgfVxuXG4gIHNldCBmcm9tUG9ydCggcG9ydDogUG9ydCApXG4gIHtcbiAgICB0aGlzLl9mcm9tID0ge1xuICAgICAgbm9kZUlEOiBwb3J0Lm93bmVyLmlkLFxuICAgICAgcG9ydElEOiBwb3J0LmlkXG4gICAgfTtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBwb3J0LnByb3RvY29sSUQ7XG4gIH1cblxuICBnZXQgdG9Ob2RlKCk6IE5vZGVcbiAge1xuICAgIHJldHVybiB0aGlzLl9vd25lci5nZXROb2RlQnlJRCggdGhpcy5fdG8ubm9kZUlEICk7XG4gIH1cblxuICBnZXQgdG9Qb3J0KCk6IFBvcnRcbiAge1xuICAgIGxldCBub2RlID0gdGhpcy50b05vZGU7XG5cbiAgICByZXR1cm4gKG5vZGUpID8gbm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX3RvLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApIDogdW5kZWZpbmVkO1xuICB9XG5cbiAgc2V0IHRvUG9ydCggcG9ydDogUG9ydCApXG4gIHtcbiAgICB0aGlzLl90byA9IHtcbiAgICAgIG5vZGVJRDogcG9ydC5vd25lci5pZCxcbiAgICAgIHBvcnRJRDogcG9ydC5pZFxuICAgIH07XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gcG9ydC5wcm90b2NvbElEO1xuICB9XG5cbiAgZ2V0IHByb3RvY29sSUQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcHJvdG9jb2xJRDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3RvcnkgfSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IFJ1bnRpbWVDb250ZXh0LCBSdW5TdGF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBMaW5rIH0gZnJvbSAnLi9saW5rJztcbmltcG9ydCB7IFBvcnQsIFB1YmxpY1BvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG5leHBvcnQgY2xhc3MgTmV0d29yayBleHRlbmRzIEV2ZW50SHViXG57XG4gIHN0YXRpYyBFVkVOVF9TVEFURV9DSEFOR0UgPSAnbmV0d29yazpzdGF0ZS1jaGFuZ2UnO1xuICBzdGF0aWMgRVZFTlRfR1JBUEhfQ0hBTkdFID0gJ25ldHdvcms6Z3JhcGgtY2hhbmdlJztcblxuICBwcml2YXRlIF9ncmFwaDogR3JhcGg7XG5cbiAgcHJpdmF0ZSBfZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeTtcblxuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgZ3JhcGg/OiBHcmFwaCApXG4gIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG4gICAgdGhpcy5fZ3JhcGggPSBncmFwaCB8fCBuZXcgR3JhcGgoIG51bGwsIHt9ICk7XG5cbiAgICBsZXQgbWUgPSB0aGlzO1xuICAgIHRoaXMuX2dyYXBoLnN1YnNjcmliZSggR3JhcGguRVZFTlRfQUREX05PREUsICggZGF0YTogeyBub2RlOiBOb2RlIH0gKT0+IHtcbiAgICAgIGxldCBydW5TdGF0ZTogUnVuU3RhdGUgPSBtZS5fZ3JhcGguY29udGV4dC5ydW5TdGF0ZTtcblxuICAgICAgaWYgKCBydW5TdGF0ZSAhPSBSdW5TdGF0ZS5ORVdCT1JOIClcbiAgICAgIHtcbiAgICAgICAgbGV0IHsgbm9kZSB9ID0gZGF0YTtcblxuICAgICAgICBub2RlLmxvYWRDb21wb25lbnQoIG1lLl9mYWN0b3J5IClcbiAgICAgICAgICAudGhlbiggKCk9PiB7XG4gICAgICAgICAgICBpZiAoIE5ldHdvcmsuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQsIFJ1blN0YXRlLlJFQURZIF0sIHJ1blN0YXRlICkgKVxuICAgICAgICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBub2RlLCBSdW5TdGF0ZS5SRUFEWSApO1xuXG4gICAgICAgICAgICBpZiAoIE5ldHdvcmsuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSwgcnVuU3RhdGUgKSApXG4gICAgICAgICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIG5vZGUsIHJ1blN0YXRlICk7XG5cbiAgICAgICAgICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9HUkFQSF9DSEFOR0UsIHsgbm9kZTogbm9kZSB9ICk7XG4gICAgICAgICAgfSlcbiAgICAgIH1cbiAgICB9ICk7XG4gIH1cblxuICBnZXQgZ3JhcGgoKTogR3JhcGgge1xuICAgIHJldHVybiB0aGlzLl9ncmFwaDtcbiAgfVxuXG4gIC8qKlxuICAqIExvYWQgYWxsIGNvbXBvbmVudHNcbiAgKi9cbiAgbG9hZENvbXBvbmVudHMoKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IFJ1blN0YXRlLkxPQURJTkcgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX2dyYXBoLmxvYWRDb21wb25lbnQoIHRoaXMuX2ZhY3RvcnkgKS50aGVuKCAoKT0+IHtcbiAgICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IFJ1blN0YXRlLkxPQURFRCB9ICk7XG4gICAgfSk7XG4gIH1cblxuICBpbml0aWFsaXplKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJFQURZICk7XG4gIH1cblxuICB0ZWFyZG93bigpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5MT0FERUQgKTtcbiAgfVxuXG4gIHN0YXRpYyBpblN0YXRlKCBzdGF0ZXM6IFJ1blN0YXRlW10sIHJ1blN0YXRlOiBSdW5TdGF0ZSApOiBib29sZWFuIHtcbiAgICByZXR1cm4gbmV3IFNldDxSdW5TdGF0ZT4oIHN0YXRlcyApLmhhcyggcnVuU3RhdGUgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFsdGVyIHJ1bi1zdGF0ZSBvZiBhIE5vZGUgLSBMT0FERUQsIFJFQURZLCBSVU5OSU5HIG9yIFBBVVNFRC5cbiAgKiBUcmlnZ2VycyBTZXR1cCBvciBUZWFyZG93biBpZiB0cmFuc2l0aW9uaW5nIGJldHdlZW4gUkVBRFkgYW5kIExPQURFRFxuICAqIFdpcmV1cCBhIGdyYXBoLCBjcmVhdGluZyBDaGFubmVsIGJldHdlZW4gbGlua2VkIE5vZGVzXG4gICogQWN0cyByZWN1cnNpdmVseSwgd2lyaW5nIHVwIGFueSBzdWItZ3JhcGhzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHNldFJ1blN0YXRlKCBub2RlOiBOb2RlLCBydW5TdGF0ZTogUnVuU3RhdGUgKVxuICB7XG4gICAgbGV0IGN0eCA9IG5vZGUuY29udGV4dDtcbiAgICBsZXQgY3VycmVudFN0YXRlID0gY3R4LnJ1blN0YXRlO1xuXG4gICAgaWYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKVxuICAgIHtcbiAgICAgIC8vIDEuIFByZXByb2Nlc3NcbiAgICAgIC8vICAgIGEuIEhhbmRsZSB0ZWFyZG93blxuICAgICAgLy8gICAgYi4gUHJvcGFnYXRlIHN0YXRlIGNoYW5nZSB0byBzdWJuZXRzXG4gICAgICBsZXQgbm9kZXM6IE1hcDxzdHJpbmcsIE5vZGU+ID0gbm9kZS5ub2RlcztcblxuICAgICAgaWYgKCAoIHJ1blN0YXRlID09IFJ1blN0YXRlLkxPQURFRCApICYmICggY3VycmVudFN0YXRlID49IFJ1blN0YXRlLlJFQURZICkgKSB7XG4gICAgICAgIC8vIHRlYXJpbmcgZG93biAuLiB1bmxpbmsgZ3JhcGggZmlyc3RcbiAgICAgICAgbGV0IGxpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPiA9IG5vZGUubGlua3M7XG5cbiAgICAgICAgLy8gdW53aXJlIChkZWFjdGl2YXRlIGFuZCBkZXN0cm95ICkgQ2hhbm5lbHMgYmV0d2VlbiBsaW5rZWQgbm9kZXNcbiAgICAgICAgbGlua3MuZm9yRWFjaCggKCBsaW5rICkgPT5cbiAgICAgICAge1xuICAgICAgICAgIE5ldHdvcmsudW53aXJlTGluayggbGluayApO1xuICAgICAgICB9ICk7XG4gICAgICB9XG5cbiAgICAgIC8vIFByb3BhZ2F0ZSBzdGF0ZSBjaGFuZ2UgdG8gc3ViLW5ldHMgZmlyc3RcbiAgICAgIG5vZGVzLmZvckVhY2goIGZ1bmN0aW9uKCBzdWJOb2RlIClcbiAgICAgIHtcbiAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggc3ViTm9kZSwgcnVuU3RhdGUgKTtcbiAgICAgIH0gKTtcblxuICAgICAgLy8gMi4gQ2hhbmdlIHN0YXRlIC4uLlxuICAgICAgY3R4LnNldFJ1blN0YXRlKCBydW5TdGF0ZSApO1xuXG4gICAgICAvLyAzLiBQb3N0cHJvY2Vzc1xuICAgICAgLy8gICAgYS4gSGFuZGxlIHNldHVwXG4gICAgICBpZiAoICggcnVuU3RhdGUgPT0gUnVuU3RhdGUuUkVBRFkgKSAmJiAoIGN1cnJlbnRTdGF0ZSA+PSBSdW5TdGF0ZS5MT0FERUQgKSApIHtcblxuICAgICAgICAvLyBzZXR0aW5nIHVwIC4uIGxpbmt1cCBncmFwaCBmaXJzdFxuICAgICAgICBsZXQgbGlua3M6IE1hcDxzdHJpbmcsIExpbms+ID0gbm9kZS5saW5rcztcbiAgICAgICAgLy8gdHJlYXQgZ3JhcGggcmVjdXJzaXZlbHlcblxuICAgICAgICAvLyAyLiB3aXJldXAgKGNyZWF0ZSBhbmQgYWN0aXZhdGUpIGEgQ2hhbm5lbCBiZXR3ZWVuIGxpbmtlZCBub2Rlc1xuICAgICAgICBsaW5rcy5mb3JFYWNoKCAoIGxpbmsgKSA9PlxuICAgICAgICB7XG4gICAgICAgICAgTmV0d29yay53aXJlTGluayggbGluayApO1xuICAgICAgICB9ICk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIENoYW5nZSBzdGF0ZSAuLi5cbiAgICAgIGN0eC5zZXRSdW5TdGF0ZSggcnVuU3RhdGUgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBVbndpcmUgYSBsaW5rLCByZW1vdmluZyB0aGUgQ2hhbm5lbCBiZXR3ZWVuIHRoZSBsaW5rZWQgTm9kZXNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgdW53aXJlTGluayggbGluazogTGluayApXG4gIHtcbiAgICAvLyBnZXQgbGlua2VkIG5vZGVzIChMaW5rIGZpbmRzIE5vZGVzIGluIHBhcmVudCBHcmFwaClcbiAgICBsZXQgZnJvbU5vZGUgPSBsaW5rLmZyb21Ob2RlO1xuICAgIGxldCB0b05vZGUgPSBsaW5rLnRvTm9kZTtcblxuICAgIGxldCBjaGFuOiBDaGFubmVsID0gbGluay5kaXNjb25uZWN0KCk7XG5cbiAgICBpZiAoIGNoYW4gKVxuICAgICAgY2hhbi5kZWFjdGl2YXRlKCk7XG4gIH1cblxuICAvKipcbiAgKiBXaXJldXAgYSBsaW5rLCBjcmVhdGluZyBDaGFubmVsIGJldHdlZW4gdGhlIGxpbmtlZCBOb2Rlc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyB3aXJlTGluayggbGluazogTGluayApXG4gIHtcbiAgICAvLyBnZXQgbGlua2VkIG5vZGVzIChMaW5rIGZpbmRzIE5vZGVzIGluIHBhcmVudCBHcmFwaClcbiAgICBsZXQgZnJvbU5vZGUgPSBsaW5rLmZyb21Ob2RlO1xuICAgIGxldCB0b05vZGUgPSBsaW5rLnRvTm9kZTtcblxuICAgIC8vZGVidWdNZXNzYWdlKCBcIkxpbmsoXCIrbGluay5pZCtcIik6IFwiICsgbGluay5mcm9tICsgXCIgLT4gXCIgKyBsaW5rLnRvICsgXCIgcHJvdG89XCIrbGluay5wcm90b2NvbCApO1xuXG4gICAgbGV0IGNoYW5uZWwgPSBuZXcgQ2hhbm5lbCgpO1xuXG4gICAgbGluay5jb25uZWN0KCBjaGFubmVsICk7XG5cbiAgICBjaGFubmVsLmFjdGl2YXRlKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0UnVuU3RhdGUoIHJ1blN0YXRlOiBSdW5TdGF0ZSApXG4gIHtcbiAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCB0aGlzLl9ncmFwaCwgcnVuU3RhdGUgKTtcblxuICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IHJ1blN0YXRlIH0gKTtcbiAgfVxuXG4gIHN0YXJ0KCBpbml0aWFsbHlQYXVzZWQ6IGJvb2xlYW4gPSBmYWxzZSApIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBpbml0aWFsbHlQYXVzZWQgPyBSdW5TdGF0ZS5QQVVTRUQgOiBSdW5TdGF0ZS5SVU5OSU5HICk7XG4gIH1cblxuICBzdGVwKCkge1xuICAgIC8vIFRPRE86IFNpbmdsZS1zdGVwXG4gIH1cblxuICBzdG9wKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJFQURZICk7XG4gIH1cblxuICBwYXVzZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5QQVVTRUQgKTtcbiAgfVxuXG4gIHJlc3VtZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SVU5OSU5HICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcblxuaW1wb3J0IHsgTmV0d29yayB9IGZyb20gJy4vbmV0d29yayc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IExpbmsgfSBmcm9tICcuL2xpbmsnO1xuaW1wb3J0IHsgUG9ydCwgUHVibGljUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbi8qKlxuICogQSBHcmFwaCBpcyBhIGNvbGxlY3Rpb24gb2YgTm9kZXMgaW50ZXJjb25uZWN0ZWQgdmlhIExpbmtzLlxuICogQSBHcmFwaCBpcyBpdHNlbGYgYSBOb2RlLCB3aG9zZSBQb3J0cyBhY3QgYXMgcHVibGlzaGVkIEVuZFBvaW50cywgdG8gdGhlIEdyYXBoLlxuICovXG5leHBvcnQgY2xhc3MgR3JhcGggZXh0ZW5kcyBOb2RlXG57XG4gIHN0YXRpYyBFVkVOVF9BRERfTk9ERSA9ICdncmFwaDphZGQtbm9kZSc7XG4gIHN0YXRpYyBFVkVOVF9VUERfTk9ERSA9ICdncmFwaDp1cGQtbm9kZSc7XG4gIHN0YXRpYyBFVkVOVF9ERUxfTk9ERSA9ICdncmFwaDpkZWwtbm9kZSc7XG5cbiAgc3RhdGljIEVWRU5UX0FERF9MSU5LID0gJ2dyYXBoOmFkZC1saW5rJztcbiAgc3RhdGljIEVWRU5UX1VQRF9MSU5LID0gJ2dyYXBoOnVwZC1saW5rJztcbiAgc3RhdGljIEVWRU5UX0RFTF9MSU5LID0gJ2dyYXBoOmRlbC1saW5rJztcblxuICAvKipcbiAgKiBOb2RlcyBpbiB0aGlzIGdyYXBoLiBFYWNoIG5vZGUgbWF5IGJlOlxuICAqICAgMS4gQSBDb21wb25lbnRcbiAgKiAgIDIuIEEgc3ViLWdyYXBoXG4gICovXG4gIHByb3RlY3RlZCBfbm9kZXM6IE1hcDxzdHJpbmcsIE5vZGU+O1xuXG4gIC8vIExpbmtzIGluIHRoaXMgZ3JhcGguIEVhY2ggbm9kZSBtYXkgYmU6XG4gIHByb3RlY3RlZCBfbGlua3M6IE1hcDxzdHJpbmcsIExpbms+O1xuXG4gIC8vIFB1YmxpYyBQb3J0cyBpbiB0aGlzIGdyYXBoLiBJbmhlcml0ZWQgZnJvbSBOb2RlXG4gIC8vIHByaXZhdGUgUG9ydHM7XG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCBvd25lciwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5pbml0RnJvbU9iamVjdCggYXR0cmlidXRlcyApO1xuICB9XG5cbiAgaW5pdEZyb21TdHJpbmcoIGpzb25TdHJpbmc6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLmluaXRGcm9tT2JqZWN0KCBKU09OLnBhcnNlKCBqc29uU3RyaW5nICkgKTtcbiAgfVxuXG4gIGluaXRGcm9tT2JqZWN0KCBhdHRyaWJ1dGVzOiBhbnkgKSB7XG5cbiAgICB0aGlzLmlkID0gYXR0cmlidXRlcy5pZCB8fCBcIiRncmFwaFwiO1xuXG4gICAgdGhpcy5fbm9kZXMgPSBuZXcgTWFwPHN0cmluZywgTm9kZT4oKTtcbiAgICB0aGlzLl9saW5rcyA9IG5ldyBNYXA8c3RyaW5nLCBMaW5rPigpO1xuXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMubm9kZXMgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkTm9kZSggaWQsIGF0dHJpYnV0ZXMubm9kZXNbIGlkIF0gKTtcbiAgICB9KTtcblxuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLmxpbmtzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZExpbmsoIGlkLCBhdHRyaWJ1dGVzLmxpbmtzWyBpZCBdICk7XG4gICAgfSk7XG4gIH1cblxuICB0b09iamVjdCggb3B0czogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIGdyYXBoID0gc3VwZXIudG9PYmplY3QoKTtcblxuICAgIGxldCBub2RlcyA9IGdyYXBoWyBcIm5vZGVzXCIgXSA9IHt9O1xuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4vLyAgICAgIGlmICggbm9kZSAhPSB0aGlzIClcbiAgICAgICAgbm9kZXNbIGlkIF0gPSBub2RlLnRvT2JqZWN0KCk7XG4gICAgfSk7XG5cbiAgICBsZXQgbGlua3MgPSBncmFwaFsgXCJsaW5rc1wiIF0gPSB7fTtcbiAgICB0aGlzLl9saW5rcy5mb3JFYWNoKCAoIGxpbmssIGlkICkgPT4ge1xuICAgICAgbGlua3NbIGlkIF0gPSBsaW5rLnRvT2JqZWN0KCk7XG4gICAgfSk7XG5cbiAgICByZXR1cm4gZ3JhcGg7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IHBlbmRpbmdDb3VudCA9IDA7XG5cbiAgICAgIGxldCBub2RlcyA9IG5ldyBNYXA8c3RyaW5nLCBOb2RlPiggdGhpcy5fbm9kZXMgKTtcbiAgICAgIG5vZGVzLnNldCggJyRncmFwaCcsIHRoaXMgKTtcblxuICAgICAgbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgICAgbGV0IGRvbmU6IFByb21pc2U8dm9pZD47XG5cbiAgICAgICAgcGVuZGluZ0NvdW50Kys7XG5cbiAgICAgICAgaWYgKCBub2RlID09IHRoaXMgKSB7XG4gICAgICAgICAgZG9uZSA9IHN1cGVyLmxvYWRDb21wb25lbnQoIGZhY3RvcnkgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICBkb25lID0gbm9kZS5sb2FkQ29tcG9uZW50KCBmYWN0b3J5ICk7XG4gICAgICAgIH1cblxuICAgICAgICBkb25lLnRoZW4oICgpID0+IHtcbiAgICAgICAgICAtLXBlbmRpbmdDb3VudDtcbiAgICAgICAgICBpZiAoIHBlbmRpbmdDb3VudCA9PSAwIClcbiAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoIHJlYXNvbiApID0+IHtcbiAgICAgICAgICByZWplY3QoIHJlYXNvbiApO1xuICAgICAgICB9ICk7XG4gICAgICB9ICk7XG4gICAgfSApO1xuICB9XG5cbiAgcHVibGljIGdldCBub2RlcygpOiBNYXA8c3RyaW5nLCBOb2RlPlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX25vZGVzO1xuICB9XG5cbi8qICBwdWJsaWMgZ2V0QWxsTm9kZXMoKTogTm9kZVtdXG4gIHtcbiAgICBsZXQgbm9kZXM6IE5vZGVbXSA9IFtdO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIC8vIERvbid0IHJlY3Vyc2Ugb24gZ3JhcGgncyBwc2V1ZG8tbm9kZVxuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBub2RlcyA9IG5vZGVzLmNvbmNhdCggbm9kZS5nZXRBbGxOb2RlcygpICk7XG5cbiAgICAgIG5vZGVzLnB1c2goIG5vZGUgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbm9kZXM7XG4gIH0qL1xuXG4gIHB1YmxpYyBnZXQgbGlua3MoKTogTWFwPHN0cmluZywgTGluaz5cbiAge1xuICAgIHJldHVybiB0aGlzLl9saW5rcztcbiAgfVxuXG4vKiAgcHVibGljIGdldEFsbExpbmtzKCk6IExpbmtbXVxuICB7XG4gICAgbGV0IGxpbmtzOiBMaW5rW10gPSBbXTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIGxpbmtzID0gbGlua3MuY29uY2F0KCBub2RlLmdldEFsbExpbmtzKCkgKTtcbiAgICB9IClcblxuICAgIHRoaXMuX2xpbmtzLmZvckVhY2goICggbGluaywgaWQgKSA9PiB7XG4gICAgICBsaW5rcy5wdXNoKCBsaW5rICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIGxpbmtzO1xuICB9Ki9cblxuLyogIHB1YmxpYyBnZXRBbGxQb3J0cygpOiBQb3J0W11cbiAge1xuICAgIGxldCBwb3J0czogUG9ydFtdID0gc3VwZXIuZ2V0UG9ydEFycmF5KCk7XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBwb3J0cyA9IHBvcnRzLmNvbmNhdCggbm9kZS5nZXRBbGxQb3J0cygpICk7XG4gICAgICBlbHNlXG4gICAgICAgIHBvcnRzID0gcG9ydHMuY29uY2F0KCBub2RlLmdldFBvcnRBcnJheSgpICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIHBvcnRzO1xuICB9Ki9cblxuICBwdWJsaWMgZ2V0Tm9kZUJ5SUQoIGlkOiBzdHJpbmcgKTogTm9kZVxuICB7XG4gICAgaWYgKCBpZCA9PSAnJGdyYXBoJyApXG4gICAgICByZXR1cm4gdGhpcztcblxuICAgIHJldHVybiB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgYWRkTm9kZSggaWQ6IHN0cmluZywgYXR0cmlidXRlcz86IHt9ICk6IE5vZGUge1xuXG4gICAgbGV0IG5vZGUgPSBuZXcgTm9kZSggdGhpcywgYXR0cmlidXRlcyApO1xuXG4gICAgbm9kZS5pZCA9IGlkO1xuXG4gICAgdGhpcy5fbm9kZXMuc2V0KCBpZCwgbm9kZSApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9BRERfTk9ERSwgeyBub2RlOiBub2RlIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgcHVibGljIHJlbmFtZU5vZGUoIGlkOiBzdHJpbmcsIG5ld0lEOiBzdHJpbmcgKSB7XG5cbiAgICBsZXQgbm9kZSA9IHRoaXMuX25vZGVzLmdldCggaWQgKTtcblxuICAgIGlmICggaWQgIT0gbmV3SUQgKVxuICAgIHtcbiAgICAgIGxldCBldmVudERhdGEgPSB7IG5vZGU6IG5vZGUsIGF0dHJzOiB7IGlkOiBub2RlLmlkIH0gfTtcblxuICAgICAgdGhpcy5fbm9kZXMuZGVsZXRlKCBpZCApO1xuXG4gICAgICBub2RlLmlkID0gbmV3SUQ7XG5cbiAgICAgIHRoaXMuX25vZGVzLnNldCggbmV3SUQsIG5vZGUgKTtcblxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9VUERfTk9ERSwgZXZlbnREYXRhICk7XG4gICAgfVxuICB9XG5cbiAgcHVibGljIHJlbW92ZU5vZGUoIGlkOiBzdHJpbmcgKTogYm9vbGVhbiB7XG5cbiAgICBsZXQgbm9kZSA9IHRoaXMuX25vZGVzLmdldCggaWQgKTtcbiAgICBpZiAoIG5vZGUgKVxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9ERUxfTk9ERSwgeyBub2RlOiBub2RlIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9ub2Rlcy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0TGlua0J5SUQoIGlkOiBzdHJpbmcgKTogTGluayB7XG5cbiAgICByZXR1cm4gdGhpcy5fbGlua3NbIGlkIF07XG4gIH1cblxuICBwdWJsaWMgYWRkTGluayggaWQ6IHN0cmluZywgYXR0cmlidXRlcz86IHt9ICk6IExpbmsge1xuXG4gICAgbGV0IGxpbmsgPSBuZXcgTGluayggdGhpcywgYXR0cmlidXRlcyApO1xuXG4gICAgbGluay5pZCA9IGlkO1xuXG4gICAgdGhpcy5fbGlua3Muc2V0KCBpZCwgbGluayApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9BRERfTElOSywgeyBsaW5rOiBsaW5rIH0gKTtcblxuICAgIHJldHVybiBsaW5rO1xuICB9XG5cbiAgcHVibGljIHJlbmFtZUxpbmsoIGlkOiBzdHJpbmcsIG5ld0lEOiBzdHJpbmcgKSB7XG5cbiAgICBsZXQgbGluayA9IHRoaXMuX2xpbmtzLmdldCggaWQgKTtcblxuICAgIHRoaXMuX2xpbmtzLmRlbGV0ZSggaWQgKTtcblxuICAgIGxldCBldmVudERhdGEgPSB7IGxpbms6IGxpbmssIGF0dHJzOiB7IGlkOiBsaW5rLmlkIH0gfTtcblxuICAgIGxpbmsuaWQgPSBuZXdJRDtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfVVBEX05PREUsIGV2ZW50RGF0YSApO1xuXG4gICAgdGhpcy5fbGlua3Muc2V0KCBuZXdJRCwgbGluayApO1xuICB9XG5cbiAgcHVibGljIHJlbW92ZUxpbmsoIGlkOiBzdHJpbmcgKTogYm9vbGVhbiB7XG5cbiAgICBsZXQgbGluayA9IHRoaXMuX2xpbmtzLmdldCggaWQgKTtcbiAgICBpZiAoIGxpbmsgKVxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9ERUxfTElOSywgeyBsaW5rOiBsaW5rIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9saW5rcy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgYWRkUHVibGljUG9ydCggaWQ6IHN0cmluZywgYXR0cmlidXRlczoge30gKTogUHVibGljUG9ydFxuICB7XG4gICAgYXR0cmlidXRlc1tcImlkXCJdID0gaWQ7XG5cbiAgICBsZXQgcG9ydCA9IG5ldyBQdWJsaWNQb3J0KCB0aGlzLCBudWxsLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLl9wb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlTG9hZGVyIH0gZnJvbSAnLi9tb2R1bGUtbG9hZGVyJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3RvcnkgfSBmcm9tICcuL2NvbXBvbmVudC1mYWN0b3J5JztcblxuaW1wb3J0IHsgQ29udGFpbmVyIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcblxuXG5leHBvcnQgY2xhc3MgU2ltdWxhdGlvbkVuZ2luZVxue1xuICBsb2FkZXI6IE1vZHVsZUxvYWRlcjtcbiAgY29udGFpbmVyOiBDb250YWluZXI7XG5cbiAgLyoqXG4gICogQ3JlYXRlcyBhbiBpbnN0YW5jZSBvZiBTaW11bGF0aW9uRW5naW5lLlxuICAqIEBwYXJhbSBsb2FkZXIgVGhlIG1vZHVsZSBsb2FkZXIuXG4gICogQHBhcmFtIGNvbnRhaW5lciBUaGUgcm9vdCBESSBjb250YWluZXIgZm9yIHRoZSBzaW11bGF0aW9uLlxuICAqL1xuICBjb25zdHJ1Y3RvciggbG9hZGVyOiBNb2R1bGVMb2FkZXIsIGNvbnRhaW5lcjogQ29udGFpbmVyICkge1xuICAgIHRoaXMubG9hZGVyID0gbG9hZGVyO1xuICAgIHRoaXMuY29udGFpbmVyID0gY29udGFpbmVyO1xuICB9XG5cblxuICAvKipcbiAgKiBSZXR1cm4gYSBDb21wb25lbnRGYWN0b3J5IGZhY2FkZVxuICAqL1xuICBnZXRDb21wb25lbnRGYWN0b3J5KCk6IENvbXBvbmVudEZhY3Rvcnkge1xuICAgIHJldHVybiBuZXcgQ29tcG9uZW50RmFjdG9yeSggdGhpcy5jb250YWluZXIsIHRoaXMubG9hZGVyICk7XG4gIH1cblxufVxuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
