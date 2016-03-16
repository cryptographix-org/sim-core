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
            let alg = (algorithm instanceof Object) ? algorithm.name : algorithm;
            let desKey = key;
            let mode = 0, padding = 4;
            let iv;
            if (alg != desKey.algorithm.name)
                reject(new Error('Key (' + desKey.algorithm.name + ') cannot be used for DES decrypt'));
            if (desKey.algorithm.name == 'DES-CBC') {
                let ivx = algorithm['iv'] || [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                iv = new ByteArray(ivx).backingArray;
                mode = 1;
            }
            if ((data.length >= 8) || (padding != 4))
                resolve(new ByteArray(this.des(desKey.keyMaterial.backingArray, data.backingArray, 1, mode, iv, padding)));
            else
                resolve(new ByteArray());
        });
    }
    decrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            let alg = (algorithm instanceof Object) ? algorithm.name : algorithm;
            let desKey = key;
            let mode = 0, padding = 4;
            let iv;
            if (alg != desKey.algorithm.name)
                reject(new Error('Key (' + desKey.algorithm.name + ') cannot be used for DES decrypt'));
            if (desKey.algorithm.name == 'DES-CBC') {
                let ivx = algorithm['iv'] || [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                iv = new ByteArray(ivx).backingArray;
                mode = 1;
            }
            if (data.length >= 8)
                resolve(new ByteArray(this.des(desKey.keyMaterial.backingArray, data.backingArray, 0, mode, iv, padding)));
            else
                resolve(new ByteArray());
        });
    }
    importKey(format, keyData, algorithm, extractable, keyUsages) {
        if (!(algorithm instanceof Object))
            algorithm = { name: algorithm };
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
            let mm = 0;
            cbcleft = (iv[mm++] << 24) | (iv[mm++] << 16) | (iv[mm++] << 8) | iv[mm++];
            cbcright = (iv[mm++] << 24) | (iv[mm++] << 16) | (iv[mm++] << 8) | iv[mm++];
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
CryptographicServiceProvider.registerService('DES-CBC', DESCryptographicService, [CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT, CryptographicOperation.SIGN, CryptographicOperation.VERIFY]);
CryptographicServiceProvider.registerKeyService('DES-ECB', DESCryptographicService, [CryptographicOperation.IMPORT_KEY]);
CryptographicServiceProvider.registerKeyService('DES-CBC', DESCryptographicService, [CryptographicOperation.IMPORT_KEY]);



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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeS50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvd2ViY3J5cHRvLnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9kZXMudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS5qcyIsImRlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lci50cyIsImtpbmQva2luZC50cyIsIm1lc3NhZ2luZy9tZXNzYWdlLnRzIiwicnVudGltZS90YXNrLXNjaGVkdWxlci50cyIsIm1lc3NhZ2luZy9jaGFubmVsLnRzIiwibWVzc2FnaW5nL2VuZC1wb2ludC50cyIsIm1lc3NhZ2luZy9wcm90b2NvbC50cyIsImNvbXBvbmVudC9wb3J0LWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LWluZm8udHMiLCJjb21wb25lbnQvc3RvcmUtaW5mby50cyIsImNvbXBvbmVudC9jb21wb25lbnQudHMiLCJldmVudC1odWIvZXZlbnQtaHViLnRzIiwiZ3JhcGgvcG9ydC50cyIsImdyYXBoL25vZGUudHMiLCJydW50aW1lL3J1bnRpbWUtY29udGV4dC50cyIsInJ1bnRpbWUvbW9kdWxlLWxvYWRlci50cyIsInJ1bnRpbWUvY29tcG9uZW50LWZhY3RvcnkudHMiLCJncmFwaC9saW5rLnRzIiwiZ3JhcGgvbmV0d29yay50cyIsImdyYXBoL2dyYXBoLnRzIiwicnVudGltZS9zaW11bGF0aW9uLWVuZ2luZS50cyJdLCJuYW1lcyI6WyJIZXhDb2RlYyIsIkhleENvZGVjLmRlY29kZSIsIkJBU0U2NFNQRUNJQUxTIiwiQmFzZTY0Q29kZWMiLCJCYXNlNjRDb2RlYy5kZWNvZGUiLCJCYXNlNjRDb2RlYy5kZWNvZGUuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLnB1c2giLCJCYXNlNjRDb2RlYy5lbmNvZGUiLCJCYXNlNjRDb2RlYy5lbmNvZGUuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLnRyaXBsZXRUb0Jhc2U2NCIsIkJ5dGVFbmNvZGluZyIsIkJ5dGVBcnJheSIsIkJ5dGVBcnJheS5jb25zdHJ1Y3RvciIsIkJ5dGVBcnJheS5lbmNvZGluZ1RvU3RyaW5nIiwiQnl0ZUFycmF5LnN0cmluZ1RvRW5jb2RpbmciLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJDcnlwdG9ncmFwaGljT3BlcmF0aW9uIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkuY29uc3RydWN0b3IiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0cnkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmVuY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRpZ2VzdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuc2lnbiIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudmVyaWZ5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5leHBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmdlbmVyYXRlS2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5pbXBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlcml2ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuZGVyaXZlQml0cyIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIud3JhcEtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudW53cmFwS2V5IiwiV2ViQ3J5cHRvU2VydmljZSIsIldlYkNyeXB0b1NlcnZpY2UuY29uc3RydWN0b3IiLCJXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSIsIldlYkNyeXB0b1NlcnZpY2UuZW5jcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGVjcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGlnZXN0IiwiV2ViQ3J5cHRvU2VydmljZS5leHBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLmdlbmVyYXRlS2V5IiwiV2ViQ3J5cHRvU2VydmljZS5pbXBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLnNpZ24iLCJXZWJDcnlwdG9TZXJ2aWNlLnZlcmlmeSIsIkRFU1NlY3JldEtleSIsIkRFU1NlY3JldEtleS5jb25zdHJ1Y3RvciIsIkRFU1NlY3JldEtleS5hbGdvcml0aG0iLCJERVNTZWNyZXRLZXkuZXh0cmFjdGFibGUiLCJERVNTZWNyZXRLZXkudHlwZSIsIkRFU1NlY3JldEtleS51c2FnZXMiLCJERVNTZWNyZXRLZXkua2V5TWF0ZXJpYWwiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZSIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmNvbnN0cnVjdG9yIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZW5jcnlwdCIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlY3J5cHQiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5pbXBvcnRLZXkiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5zaWduIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzLmRlc19jcmVhdGVLZXlzIiwiRW51bSIsIkludGVnZXIiLCJGaWVsZEFycmF5IiwiS2luZEluZm8iLCJLaW5kSW5mby5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyIiwiS2luZEJ1aWxkZXIuY29uc3RydWN0b3IiLCJLaW5kQnVpbGRlci5pbml0IiwiS2luZEJ1aWxkZXIuZmllbGQiLCJLaW5kQnVpbGRlci5ib29sRmllbGQiLCJLaW5kQnVpbGRlci5udW1iZXJGaWVsZCIsIktpbmRCdWlsZGVyLmludGVnZXJGaWVsZCIsIktpbmRCdWlsZGVyLnVpbnQzMkZpZWxkIiwiS2luZEJ1aWxkZXIuYnl0ZUZpZWxkIiwiS2luZEJ1aWxkZXIuc3RyaW5nRmllbGQiLCJLaW5kQnVpbGRlci5raW5kRmllbGQiLCJLaW5kQnVpbGRlci5lbnVtRmllbGQiLCJLaW5kIiwiS2luZC5nZXRLaW5kSW5mbyIsIktpbmQuaW5pdEZpZWxkcyIsIk1lc3NhZ2UiLCJNZXNzYWdlLmNvbnN0cnVjdG9yIiwiTWVzc2FnZS5oZWFkZXIiLCJNZXNzYWdlLnBheWxvYWQiLCJLaW5kTWVzc2FnZSIsIlRhc2tTY2hlZHVsZXIiLCJUYXNrU2NoZWR1bGVyLmNvbnN0cnVjdG9yIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyLnJlcXVlc3RGbHVzaC5oYW5kbGVGbHVzaFRpbWVyIiwiVGFza1NjaGVkdWxlci5zaHV0ZG93biIsIlRhc2tTY2hlZHVsZXIucXVldWVUYXNrIiwiVGFza1NjaGVkdWxlci5mbHVzaFRhc2tRdWV1ZSIsIlRhc2tTY2hlZHVsZXIub25FcnJvciIsIkNoYW5uZWwiLCJDaGFubmVsLmNvbnN0cnVjdG9yIiwiQ2hhbm5lbC5zaHV0ZG93biIsIkNoYW5uZWwuYWN0aXZlIiwiQ2hhbm5lbC5hY3RpdmF0ZSIsIkNoYW5uZWwuZGVhY3RpdmF0ZSIsIkNoYW5uZWwuYWRkRW5kUG9pbnQiLCJDaGFubmVsLnJlbW92ZUVuZFBvaW50IiwiQ2hhbm5lbC5lbmRQb2ludHMiLCJDaGFubmVsLnNlbmRNZXNzYWdlIiwiRGlyZWN0aW9uIiwiRW5kUG9pbnQiLCJFbmRQb2ludC5jb25zdHJ1Y3RvciIsIkVuZFBvaW50LnNodXRkb3duIiwiRW5kUG9pbnQuaWQiLCJFbmRQb2ludC5hdHRhY2giLCJFbmRQb2ludC5kZXRhY2giLCJFbmRQb2ludC5kZXRhY2hBbGwiLCJFbmRQb2ludC5hdHRhY2hlZCIsIkVuZFBvaW50LmRpcmVjdGlvbiIsIkVuZFBvaW50LmhhbmRsZU1lc3NhZ2UiLCJFbmRQb2ludC5zZW5kTWVzc2FnZSIsIkVuZFBvaW50Lm9uTWVzc2FnZSIsIlByb3RvY29sVHlwZUJpdHMiLCJQcm90b2NvbCIsIkNsaWVudFNlcnZlclByb3RvY29sIiwiQVBEVSIsIkFQRFVNZXNzYWdlIiwiQVBEVVByb3RvY29sIiwiUG9ydEluZm8iLCJQb3J0SW5mby5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEluZm8iLCJDb21wb25lbnRJbmZvLmNvbnN0cnVjdG9yIiwiU3RvcmVJbmZvIiwiQ29tcG9uZW50QnVpbGRlciIsIkNvbXBvbmVudEJ1aWxkZXIuY29uc3RydWN0b3IiLCJDb21wb25lbnRCdWlsZGVyLmluaXQiLCJDb21wb25lbnRCdWlsZGVyLmNvbmZpZyIsIkNvbXBvbmVudEJ1aWxkZXIucG9ydCIsIkV2ZW50SHViIiwiRXZlbnRIdWIuY29uc3RydWN0b3IiLCJFdmVudEh1Yi5wdWJsaXNoIiwiRXZlbnRIdWIuc3Vic2NyaWJlIiwiRXZlbnRIdWIuc3Vic2NyaWJlT25jZSIsIlBvcnQiLCJQb3J0LmNvbnN0cnVjdG9yIiwiUG9ydC5lbmRQb2ludCIsIlBvcnQudG9PYmplY3QiLCJQb3J0Lm93bmVyIiwiUG9ydC5wcm90b2NvbElEIiwiUG9ydC5pZCIsIlBvcnQuZGlyZWN0aW9uIiwiUHVibGljUG9ydCIsIlB1YmxpY1BvcnQuY29uc3RydWN0b3IiLCJQdWJsaWNQb3J0LmNvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC5kaXNjb25uZWN0UHJpdmF0ZSIsIlB1YmxpY1BvcnQudG9PYmplY3QiLCJOb2RlIiwiTm9kZS5jb25zdHJ1Y3RvciIsIk5vZGUudG9PYmplY3QiLCJOb2RlLm93bmVyIiwiTm9kZS5pZCIsIk5vZGUudXBkYXRlUG9ydHMiLCJOb2RlLmFkZFBsYWNlaG9sZGVyUG9ydCIsIk5vZGUucG9ydHMiLCJOb2RlLmdldFBvcnRBcnJheSIsIk5vZGUuZ2V0UG9ydEJ5SUQiLCJOb2RlLmlkZW50aWZ5UG9ydCIsIk5vZGUucmVtb3ZlUG9ydCIsIk5vZGUubG9hZENvbXBvbmVudCIsIk5vZGUuY29udGV4dCIsIk5vZGUudW5sb2FkQ29tcG9uZW50IiwiUnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dCIsIlJ1bnRpbWVDb250ZXh0LmNvbnN0cnVjdG9yIiwiUnVudGltZUNvbnRleHQubm9kZSIsIlJ1bnRpbWVDb250ZXh0Lmluc3RhbmNlIiwiUnVudGltZUNvbnRleHQuY29udGFpbmVyIiwiUnVudGltZUNvbnRleHQubG9hZCIsIlJ1bnRpbWVDb250ZXh0LnJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQuaW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnNldFJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQucmVsZWFzZSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkiLCJNb2R1bGVSZWdpc3RyeUVudHJ5LmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeSIsIlN5c3RlbU1vZHVsZUxvYWRlci5sb2FkTW9kdWxlIiwiQ29tcG9uZW50RmFjdG9yeSIsIkNvbXBvbmVudEZhY3RvcnkuY29uc3RydWN0b3IiLCJDb21wb25lbnRGYWN0b3J5LmNyZWF0ZUNvbnRleHQiLCJDb21wb25lbnRGYWN0b3J5LmdldENoaWxkQ29udGFpbmVyIiwiQ29tcG9uZW50RmFjdG9yeS5sb2FkQ29tcG9uZW50IiwiQ29tcG9uZW50RmFjdG9yeS5nZXQiLCJDb21wb25lbnRGYWN0b3J5LnJlZ2lzdGVyIiwiTGluayIsIkxpbmsuY29uc3RydWN0b3IiLCJMaW5rLnRvT2JqZWN0IiwiTGluay5pZCIsIkxpbmsuY29ubmVjdCIsIkxpbmsuZGlzY29ubmVjdCIsIkxpbmsuZnJvbU5vZGUiLCJMaW5rLmZyb21Qb3J0IiwiTGluay50b05vZGUiLCJMaW5rLnRvUG9ydCIsIkxpbmsucHJvdG9jb2xJRCIsIk5ldHdvcmsiLCJOZXR3b3JrLmNvbnN0cnVjdG9yIiwiTmV0d29yay5ncmFwaCIsIk5ldHdvcmsubG9hZENvbXBvbmVudHMiLCJOZXR3b3JrLmluaXRpYWxpemUiLCJOZXR3b3JrLnRlYXJkb3duIiwiTmV0d29yay5pblN0YXRlIiwiTmV0d29yay5zZXRSdW5TdGF0ZSIsIk5ldHdvcmsudW53aXJlTGluayIsIk5ldHdvcmsud2lyZUxpbmsiLCJOZXR3b3JrLnN0YXJ0IiwiTmV0d29yay5zdGVwIiwiTmV0d29yay5zdG9wIiwiTmV0d29yay5wYXVzZSIsIk5ldHdvcmsucmVzdW1lIiwiR3JhcGgiLCJHcmFwaC5jb25zdHJ1Y3RvciIsIkdyYXBoLmluaXRGcm9tU3RyaW5nIiwiR3JhcGguaW5pdEZyb21PYmplY3QiLCJHcmFwaC50b09iamVjdCIsIkdyYXBoLmxvYWRDb21wb25lbnQiLCJHcmFwaC5ub2RlcyIsIkdyYXBoLmxpbmtzIiwiR3JhcGguZ2V0Tm9kZUJ5SUQiLCJHcmFwaC5hZGROb2RlIiwiR3JhcGgucmVuYW1lTm9kZSIsIkdyYXBoLnJlbW92ZU5vZGUiLCJHcmFwaC5nZXRMaW5rQnlJRCIsIkdyYXBoLmFkZExpbmsiLCJHcmFwaC5yZW5hbWVMaW5rIiwiR3JhcGgucmVtb3ZlTGluayIsIkdyYXBoLmFkZFB1YmxpY1BvcnQiLCJTaW11bGF0aW9uRW5naW5lIiwiU2ltdWxhdGlvbkVuZ2luZS5jb25zdHJ1Y3RvciIsIlNpbXVsYXRpb25FbmdpbmUuZ2V0Q29tcG9uZW50RmFjdG9yeSJdLCJtYXBwaW5ncyI6IkFBQUE7SUFJRUEsT0FBT0EsTUFBTUEsQ0FBRUEsQ0FBU0E7UUFFdEJDLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pDQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFHQSxHQUFHQSxrQkFBa0JBLENBQUNBO1lBQzdCQSxJQUFJQSxLQUFLQSxHQUFHQSw2QkFBNkJBLENBQUNBO1lBQzFDQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtZQUN2QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3ZCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsR0FBR0EsR0FBR0EsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7WUFDeEJBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO2dCQUN4QkEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDM0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO2dCQUNqQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLFFBQVFBLENBQUNBLFlBQVlBLEdBQUdBLEdBQUdBLENBQUNBO1FBQzlCQSxDQUFDQTtRQUVEQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtRQUN2QkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDN0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBLEVBQ2pDQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNwQkEsRUFBRUEsQ0FBQ0EsQ0FB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LENBQUNBLEdBQUdBLFlBQVlBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZEQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVWQSxjQUFlQSxDQUFPQTtZQUNwQkUsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDZkEsQ0FBQ0E7UUFFREYsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFakJBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQzdCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMzSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDN0JBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFFQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzlHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUN4QkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRURELE9BQU9BLE1BQU1BLENBQUVBLEtBQWlCQTtRQUU5QkksSUFBSUEsQ0FBU0EsQ0FBQ0E7UUFDZEEsSUFBSUEsVUFBVUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDbENBLElBQUlBLE1BQU1BLEdBQUdBLEVBQUVBLENBQUNBO1FBRWhCQSxNQUFNQSxNQUFNQSxHQUFHQSxrRUFBa0VBLENBQUNBO1FBQ2xGQSxnQkFBaUJBLEdBQVNBO1lBQ3hCQyxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM1QkEsQ0FBQ0E7UUFFREQseUJBQTBCQSxHQUFXQTtZQUNuQ0UsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDNUdBLENBQUNBO1FBR0RGLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLFVBQVVBLENBQUNBO1FBQ3ZDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQTtZQUMvQkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbkVBLE1BQU1BLElBQUlBLGVBQWVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBO1FBQ2xDQSxDQUFDQTtRQUdEQSxNQUFNQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuQkEsS0FBS0EsQ0FBQ0E7Z0JBQ0pBLElBQUlBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO2dCQUNuQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzVCQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDckNBLE1BQU1BLElBQUlBLElBQUlBLENBQUNBO2dCQUNmQSxLQUFLQSxDQUFBQTtZQUNQQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2xFQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDN0JBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQTtnQkFDZEEsS0FBS0EsQ0FBQUE7WUFDUEE7Z0JBQ0VBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO0lBQ2hCQSxDQUFDQTtBQUNISixDQUFDQTtBQUFBO09DaklNLEVBQUUsUUFBUSxFQUFFLE1BQU0sYUFBYTtPQUMvQixFQUFFLFdBQVcsRUFBRSxNQUFNLGdCQUFnQjtBQUU1QyxXQUFZLFlBS1g7QUFMRCxXQUFZLFlBQVk7SUFDdEJPLDZDQUFHQSxDQUFBQTtJQUNIQSw2Q0FBR0EsQ0FBQUE7SUFDSEEsbURBQU1BLENBQUFBO0lBQ05BLCtDQUFJQSxDQUFBQTtBQUNOQSxDQUFDQSxFQUxXLFlBQVksS0FBWixZQUFZLFFBS3ZCO0FBRUQ7SUEyQ0VDLFlBQWFBLEtBQXFFQSxFQUFFQSxRQUFpQkEsRUFBRUEsR0FBU0E7UUFFOUdDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO1lBRUNBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3ZDQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxRQUFRQSxJQUFJQSxRQUFRQSxJQUFJQSxZQUFZQSxDQUFDQSxHQUFJQSxDQUFDQSxDQUNyREEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsV0FBWUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFlQSxLQUFLQSxDQUFFQSxDQUFDQTtZQUN4REEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsVUFBV0EsQ0FBQ0E7Z0JBQ3JDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUN6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsU0FBVUEsQ0FBQ0E7Z0JBQ3BDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUNuQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsS0FBTUEsQ0FBQ0E7Z0JBQ2hDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtRQUs3Q0EsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsS0FBS0EsSUFBSUEsUUFBU0EsQ0FBQ0EsQ0FDcENBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLE1BQU9BLENBQUNBLENBQ3RDQSxDQUFDQTtnQkFDR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDekRBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQ3hDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLElBQUtBLENBQUNBLENBQ3pDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtnQkFDN0JBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBO29CQUN4QkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBRTVDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxFQUFFQSxDQUFDQTtZQUN0QkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBVUEsQ0FBQ0EsQ0FDdEJBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGdDQUFnQ0EsQ0FBQ0EsQ0FBQUE7UUFDcERBLENBQUNBO0lBQ0hBLENBQUNBO0lBcEZERCxPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQXNCQTtRQUM3Q0UsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLE1BQU1BO2dCQUN0QkEsTUFBTUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLElBQUlBO2dCQUNwQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7WUFDaEJBLEtBQUtBLFlBQVlBLENBQUNBLEdBQUdBO2dCQUNuQkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFDZkE7Z0JBQ0VBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBO1FBQ2pCQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVERixPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQWdCQTtRQUN2Q0csRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsV0FBV0EsRUFBRUEsSUFBSUEsUUFBU0EsQ0FBQ0E7WUFDdkNBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLE1BQU1BLENBQUNBO1FBQzdCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxRQUFRQSxDQUFDQSxXQUFXQSxFQUFFQSxJQUFJQSxNQUFPQSxDQUFDQTtZQUMxQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFDM0JBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFdBQVdBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBO1lBQ3pDQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQSxHQUFHQSxDQUFDQTtRQUMxQkEsSUFBSUE7WUFDRkEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBZ0VESCxJQUFJQSxNQUFNQTtRQUVSSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUMvQkEsQ0FBQ0E7SUFFREosSUFBSUEsTUFBTUEsQ0FBRUEsR0FBV0E7UUFFckJJLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLElBQUlBLEdBQUlBLENBQUNBLENBQ25DQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUNsREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDekJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQ3ZDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFREosSUFBSUEsWUFBWUE7UUFFZEssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURMLE1BQU1BLENBQUVBLEtBQWdCQTtRQUV0Qk0sSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFDeEJBLElBQUlBLEdBQUdBLEdBQUdB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QUFDQSxHQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUN0Q0EsS0FBS0EsWUFBWUEsQ0FBQ0EsR0FBR0E7Z0JBRW5CQSxHQUFHQSxDQUFBQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtvQkFDOUJBLENBQUNBLElBQUlBLENBQUVBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLENBQUVBLENBQUNBLFFBQVFBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO2dCQUMvREEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsWUFBWUEsQ0FBQ0EsTUFBTUE7Z0JBQ3RCQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUU5Q0EsS0FBS0EsWUFBWUEsQ0FBQ0EsSUFBSUE7Z0JBQ3BCQSxHQUFHQSxDQUFBQSxDQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtvQkFDOUJBLENBQUNBLElBQUlBLE1BQU1BLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBLENBQUVBLENBQUVBLENBQUNBO2dCQUNsREEsS0FBS0EsQ0FBQ0E7WUFFUkE7Z0JBQ0VBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xEQSxLQUFLQSxDQUFDQTtRQUNWQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNYQSxDQUFDQTtBQUNIdkIsQ0FBQ0E7QUFwVGUsYUFBRyxHQUFHLFlBQVksQ0FBQyxHQUFHLENBQUM7QUFDdkIsYUFBRyxHQUFHLFlBQVksQ0FBQyxHQUFHLENBQUM7QUFDdkIsZ0JBQU0sR0FBRyxZQUFZLENBQUMsTUFBTSxDQUFDO0FBQzdCLGNBQUksR0FBRyxZQUFZLENBQUMsSUFBSSxDQWlUdkM7O0FDOVRELFdBQVksc0JBY1g7QUFkRCxXQUFZLHNCQUFzQjtJQUNoQ3dCLHlFQUFPQSxDQUFBQTtJQUNQQSx5RUFBT0EsQ0FBQUE7SUFDUEEsdUVBQU1BLENBQUFBO0lBQ05BLG1FQUFJQSxDQUFBQTtJQUNKQSx1RUFBTUEsQ0FBQUE7SUFDTkEsaUZBQVdBLENBQUFBO0lBRVhBLCtFQUFVQSxDQUFBQTtJQUNWQSwrRUFBVUEsQ0FBQUE7SUFDVkEsK0VBQVVBLENBQUFBO0lBQ1ZBLG1GQUFZQSxDQUFBQTtJQUNaQSw0RUFBUUEsQ0FBQUE7SUFDUkEsZ0ZBQVVBLENBQUFBO0FBQ1pBLENBQUNBLEVBZFcsc0JBQXNCLEtBQXRCLHNCQUFzQixRQWNqQztBQXFDRDtJQUlFQztRQUNFQyxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxHQUFHQSxFQUEyQ0EsQ0FBQ0E7UUFDdEVBLElBQUlBLENBQUNBLGNBQWNBLEdBQUdBLElBQUlBLEdBQUdBLEVBQThDQSxDQUFDQTtJQUM5RUEsQ0FBQ0E7SUFFREQsVUFBVUEsQ0FBRUEsU0FBNkJBO1FBQ3ZDRSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFFQSxTQUFTQSxZQUFZQSxNQUFNQSxDQUFFQSxHQUFlQSxTQUFVQSxDQUFDQSxJQUFJQSxHQUFXQSxTQUFTQSxDQUFDQTtRQUM3RkEsSUFBSUEsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFM0NBLE1BQU1BLENBQUNBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLE9BQU9BLEdBQUdBLElBQUlBLE9BQU9BLEVBQUVBLEdBQUdBLElBQUlBLEVBQUVBLENBQUNBO0lBQ2xFQSxDQUFDQTtJQUVERixhQUFhQSxDQUFFQSxTQUE2QkE7UUFDMUNHLElBQUlBLElBQUlBLEdBQUdBLENBQUVBLFNBQVNBLFlBQVlBLE1BQU1BLENBQUVBLEdBQWVBLFNBQVVBLENBQUNBLElBQUlBLEdBQVdBLFNBQVNBLENBQUNBO1FBQzdGQSxJQUFJQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQSxjQUFjQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUU5Q0EsTUFBTUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsUUFBUUEsRUFBRUEsT0FBT0EsR0FBR0EsSUFBSUEsT0FBT0EsRUFBRUEsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0E7SUFDbEVBLENBQUNBO0lBRURILFVBQVVBLENBQUVBLFNBQWlCQSxFQUFFQSxJQUFxQ0EsRUFBRUEsS0FBK0JBO1FBQ25HSSxJQUFJQSxDQUFDQSxtQkFBbUJBLEdBQUdBLEtBQUtBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxHQUFHQSxDQUFFQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQUMxQ0EsQ0FBQ0E7SUFDREosYUFBYUEsQ0FBRUEsU0FBaUJBLEVBQUVBLElBQXFDQSxFQUFFQSxLQUErQkE7UUFDdEdLLElBQUlBLENBQUNBLG1CQUFtQkEsR0FBR0EsS0FBS0EsQ0FBQ0E7UUFFakNBLElBQUlBLENBQUNBLGNBQWNBLENBQUNBLEdBQUdBLENBQUVBLFNBQVNBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO0lBQzdDQSxDQUFDQTtBQUNITCxDQUFDQTtBQUVEO0lBSUVNLE9BQWNBLGVBQWVBLENBQUVBLElBQVlBLEVBQUVBLElBQXFDQSxFQUFFQSxLQUErQkE7UUFDakhDLDRCQUE0QkEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7SUFDekVBLENBQUNBO0lBQ0RELE9BQWNBLGtCQUFrQkEsQ0FBRUEsSUFBWUEsRUFBRUEsSUFBd0NBLEVBQUVBLEtBQStCQTtRQUN2SEUsNEJBQTRCQSxDQUFDQSxTQUFTQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtJQUM1RUEsQ0FBQ0E7SUFFREYsSUFBSUEsUUFBUUE7UUFDVkcsTUFBTUEsQ0FBQ0EsNEJBQTRCQSxDQUFDQSxTQUFTQSxDQUFDQTtJQUNoREEsQ0FBQ0E7SUFFREgsT0FBT0EsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBQ3BFSSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUUvREEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBRUE7Y0FDbkNBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLElBQUlBLEVBQUVBLEdBQUdBLEVBQUVBLElBQUlBLENBQUVBO2NBQ25DQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFREosT0FBT0EsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBQ3BFSyxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUUvREEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBRUE7Y0FDbkNBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLElBQUlBLEVBQUVBLEdBQUdBLEVBQUVBLElBQUlBLENBQUVBO2NBQ25DQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFREwsTUFBTUEsQ0FBQ0EsU0FBNkJBLEVBQUVBLElBQWVBO1FBQ25ETSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUUvREEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUE7Y0FDbENBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUVBO2NBQzdCQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFRE4sSUFBSUEsQ0FBRUEsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBQ2xFTyxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxVQUFVQSxDQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUUvREEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsSUFBSUEsQ0FBRUE7Y0FDaENBLFFBQVFBLENBQUNBLElBQUlBLENBQUVBLElBQUlBLEVBQUVBLEdBQUdBLEVBQUVBLElBQUlBLENBQUVBO2NBQ2hDQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFRFAsTUFBTUEsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLFNBQW9CQSxFQUFFQSxJQUFlQTtRQUN6RlEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsUUFBUUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFL0RBLE1BQU1BLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBO2NBQ2xDQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxFQUFFQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFFQTtjQUM3Q0EsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBYUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lBRURSLFNBQVNBLENBQUVBLE1BQWNBLEVBQUVBLEdBQWNBO1FBQ3ZDUyxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxhQUFhQSxDQUFFQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUV0RUEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUE7Y0FDckNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLEVBQUVBLEdBQUdBLENBQUVBO2NBQ2pDQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFRFQsV0FBV0EsQ0FBRUEsU0FBNkJBLEVBQUVBLFdBQW9CQSxFQUFFQSxTQUFtQkE7UUFDbkZVLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLGFBQWFBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRWxFQSxNQUFNQSxDQUFDQSxDQUFFQSxRQUFRQSxJQUFJQSxRQUFRQSxDQUFDQSxXQUFXQSxDQUFFQTtjQUN2Q0EsUUFBUUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsU0FBU0EsQ0FBRUE7Y0FDcERBLE9BQU9BLENBQUNBLE1BQU1BLENBQTZCQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0REEsQ0FBQ0E7SUFFRFYsU0FBU0EsQ0FBRUEsTUFBY0EsRUFBRUEsT0FBa0JBLEVBQUdBLFNBQTZCQSxFQUFFQSxXQUFvQkEsRUFBRUEsU0FBbUJBO1FBQ3RIVyxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxhQUFhQSxDQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUVsRUEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUE7Y0FDckNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLEVBQUVBLE9BQU9BLEVBQUVBLElBQUlBLEVBQUVBLFdBQVdBLEVBQUVBLFNBQVNBLENBQUVBO2NBQ25FQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFRFgsU0FBU0EsQ0FBRUEsU0FBb0JBLEVBQUVBLE9BQWtCQSxFQUFFQSxjQUF5QkEsRUFBRUEsV0FBb0JBLEVBQUVBLFNBQW1CQTtRQUN2SFksSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsUUFBUUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFbEVBLE1BQU1BLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBO2NBQ3JDQSxRQUFRQSxDQUFDQSxTQUFTQSxDQUFFQSxJQUFJQSxFQUFFQSxPQUFPQSxFQUFFQSxjQUFjQSxFQUFFQSxXQUFXQSxFQUFFQSxTQUFTQSxDQUFFQTtjQUMzRUEsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBYUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lBRURaLFVBQVVBLENBQUVBLFNBQW9CQSxFQUFFQSxPQUFrQkEsRUFBRUEsTUFBY0E7UUFDbEVhLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRS9EQSxNQUFNQSxDQUFDQSxDQUFFQSxRQUFRQSxJQUFJQSxRQUFRQSxDQUFDQSxVQUFVQSxDQUFFQTtjQUN0Q0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsRUFBRUEsT0FBT0EsRUFBRUEsTUFBTUEsQ0FBRUE7Y0FDNUNBLE9BQU9BLENBQUNBLE1BQU1BLENBQWFBLEVBQUVBLENBQUVBLENBQUNBO0lBQ3RDQSxDQUFDQTtJQUVEYixPQUFPQSxDQUFFQSxNQUFjQSxFQUFFQSxHQUFjQSxFQUFFQSxXQUFzQkEsRUFBRUEsYUFBd0JBO1FBQ3ZGYyxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxhQUFhQSxDQUFFQSxHQUFHQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUV0RUEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBRUE7Y0FDbkNBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLE1BQU1BLEVBQUVBLEdBQUdBLEVBQUVBLFdBQVdBLEVBQUVBLGFBQWFBLENBQUVBO2NBQzNEQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFhQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFRGQsU0FBU0EsQ0FBRUEsTUFBY0EsRUFBRUEsVUFBcUJBLEVBQUVBLGFBQXdCQSxFQUFFQSxlQUEwQkEsRUFBRUEscUJBQWdDQSxFQUFFQSxXQUFvQkEsRUFBRUEsU0FBbUJBO1FBQ2pMZSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxhQUFhQSxDQUFFQSxlQUFlQSxDQUFFQSxDQUFDQTtRQUV4RUEsTUFBTUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBRUE7Y0FDckNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLEVBQUVBLFVBQVVBLEVBQUVBLGFBQWFBLEVBQUVBLElBQUlBLEVBQUVBLHFCQUFxQkEsRUFBRUEsV0FBV0EsRUFBRUEsU0FBU0EsQ0FBRUE7Y0FDNUdBLE9BQU9BLENBQUNBLE1BQU1BLENBQWFBLEVBQUVBLENBQUVBLENBQUNBO0lBQ3RDQSxDQUFDQTtBQUNIZixDQUFDQTtBQTVHZ0Isc0NBQVMsR0FBaUMsSUFBSSw0QkFBNEIsRUFBRSxDQTRHNUY7O09DdE1NLEVBQUUsU0FBUyxFQUFFLE1BQU0sb0JBQW9CO09BQ3ZDLEVBQUUsNEJBQTRCLEVBQUUsc0JBQXNCLEVBQWlELE1BQU0sa0NBQWtDO0FBSXRKO0lBR0VnQjtJQUNBQyxDQUFDQTtJQUdERCxXQUFXQSxNQUFNQTtRQUNmRSxJQUFJQSxNQUFNQSxHQUFHQSxnQkFBZ0JBLENBQUNBLE9BQU9BO2VBQ2hDQSxDQUFFQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQTtlQUMzQkEsQ0FBRUEsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUE7ZUFDbkRBLFNBQVNBLENBQUNBO1FBRWZBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLGdCQUFnQkEsQ0FBQ0EsT0FBUUEsQ0FBQ0E7WUFDN0JBLGdCQUFnQkEsQ0FBQ0EsT0FBT0EsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFFckNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO0lBQ2hCQSxDQUFDQTtJQUVERixPQUFPQSxDQUFFQSxTQUE2QkEsRUFBRUEsR0FBY0EsRUFBRUEsSUFBZUE7UUFDckVHLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxnQkFBZ0JBLENBQUNBLE1BQU1BLENBQUNBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLEdBQUdBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBLENBQUNBO2lCQUMvREEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsT0FBT0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7aUJBQy9DQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUN0Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFFREgsT0FBT0EsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBQ3BFSSxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsZ0JBQWdCQSxDQUFDQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFDQTtpQkFDL0RBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE9BQU9BLENBQUNBLElBQUlBLFNBQVNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2lCQUMvQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDdENBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBRURKLE1BQU1BLENBQUNBLFNBQTZCQSxFQUFFQSxJQUFlQTtRQUNuREssTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLGdCQUFnQkEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBQ0E7aUJBQzFEQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxPQUFPQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtpQkFDL0NBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1FBQ3JDQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtJQUVETCxTQUFTQSxDQUFFQSxNQUFjQSxFQUFFQSxHQUFjQTtRQUN2Q00sTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLGdCQUFnQkEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsTUFBTUEsRUFBRUEsR0FBR0EsQ0FBQ0E7aUJBQzNDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxPQUFPQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtpQkFDL0NBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1FBQ3RDQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtJQUVETixXQUFXQSxDQUFFQSxTQUE2QkEsRUFBRUEsV0FBb0JBLEVBQUVBLFNBQW1CQTtRQUNuRk8sTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBNEJBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1FBRS9EQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNKQSxDQUFDQTtJQUVEUCxTQUFTQSxDQUFDQSxNQUFjQSxFQUFFQSxPQUFrQkEsRUFBRUEsU0FBNkJBLEVBQUVBLFdBQW9CQSxFQUFFQSxTQUFtQkE7UUFDcEhRLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxnQkFBZ0JBLENBQUNBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLEVBQUVBLE9BQU9BLENBQUNBLFlBQVlBLEVBQUVBLFNBQVNBLEVBQUVBLFdBQVdBLEVBQUVBLFNBQVNBLENBQUNBO2lCQUMvRkEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7aUJBQ2hDQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUN2Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDSkEsQ0FBQ0E7SUFFRFIsSUFBSUEsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBQ2pFUyxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsZ0JBQWdCQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFDQTtpQkFDNURBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE9BQU9BLENBQUNBLElBQUlBLFNBQVNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2lCQUMvQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDdENBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBRURULE1BQU1BLENBQUNBLFNBQTZCQSxFQUFFQSxHQUFjQSxFQUFFQSxTQUFvQkEsRUFBRUEsSUFBZUE7UUFDekZVLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxnQkFBZ0JBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLFNBQVNBLEVBQUVBLEdBQUdBLEVBQUVBLFNBQVNBLENBQUNBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBLENBQUNBO2lCQUN0RkEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsT0FBT0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7aUJBQy9DQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUN0Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7QUFDSFYsQ0FBQ0E7QUFtQkQsRUFBRSxDQUFDLENBQUUsZ0JBQWdCLENBQUMsTUFBTyxDQUFDLENBQUMsQ0FBQztJQUM5Qiw0QkFBNEIsQ0FBQyxlQUFlLENBQUUsU0FBUyxFQUFFLGdCQUFnQixFQUFFLENBQUUsc0JBQXNCLENBQUMsT0FBTyxFQUFFLHNCQUFzQixDQUFDLE9BQU8sQ0FBRSxDQUFFLENBQUM7SUFDaEosNEJBQTRCLENBQUMsZUFBZSxDQUFFLFNBQVMsRUFBRSxnQkFBZ0IsRUFBRSxDQUFFLHNCQUFzQixDQUFDLE9BQU8sRUFBRSxzQkFBc0IsQ0FBQyxPQUFPLENBQUUsQ0FBRSxDQUFDO0FBR2xKLENBQUM7O09DN0dNLEVBQUUsU0FBUyxFQUFFLE1BQU0sb0JBQW9CO09BQ3ZDLEVBQUUsNEJBQTRCLEVBQUUsc0JBQXNCLEVBQWlELE1BQU0sa0NBQWtDO0FBRXRKO0lBT0VXLFlBQWFBLFdBQXNCQSxFQUFFQSxTQUF1QkEsRUFBRUEsV0FBb0JBLEVBQUVBLE1BQWdCQTtRQUVsR0MsSUFBSUEsQ0FBQ0EsWUFBWUEsR0FBR0EsV0FBV0EsQ0FBQ0E7UUFFaENBLElBQUlBLENBQUNBLFVBQVVBLEdBQUdBLFNBQVNBLENBQUNBO1FBRTVCQSxJQUFJQSxDQUFDQSxZQUFZQSxHQUFHQSxXQUFXQSxDQUFDQTtRQUVoQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsUUFBUUEsQ0FBQ0E7UUFFdEJBLElBQUlBLENBQUNBLE9BQU9BLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3RCQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFDQTtJQUNoQ0EsQ0FBQ0E7SUFFREQsSUFBSUEsU0FBU0EsS0FBS0UsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDM0NGLElBQUlBLFdBQVdBLEtBQWNHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFlBQVlBLENBQUNBLENBQUNBLENBQUNBO0lBQ3hESCxJQUFJQSxJQUFJQSxLQUFLSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNqQ0osSUFBSUEsTUFBTUEsS0FBZUssTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFFN0RMLElBQUlBLFdBQVdBLEtBQUtNLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFlBQVlBLENBQUFBLENBQUNBLENBQUNBOztBQUNoRE4sQ0FBQ0E7QUFFRDtJQUNFTztJQUNBQyxDQUFDQTtJQVFERCxPQUFPQSxDQUFFQSxTQUE2QkEsRUFBRUEsR0FBY0EsRUFBRUEsSUFBZUE7UUFDckVFLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxTQUFTQSxZQUFZQSxNQUFNQSxDQUFDQSxHQUFlQSxTQUFVQSxDQUFDQSxJQUFJQSxHQUFXQSxTQUFTQSxDQUFDQTtZQUMxRkEsSUFBSUEsTUFBTUEsR0FBR0EsR0FBbUJBLENBQUNBO1lBQ2pDQSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFDQSxFQUFFQSxPQUFPQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMxQkEsSUFBSUEsRUFBRUEsQ0FBQ0E7WUFFUEEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBSUEsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsSUFBS0EsQ0FBQ0E7Z0JBQ2pDQSxNQUFNQSxDQUFFQSxJQUFJQSxLQUFLQSxDQUFFQSxPQUFPQSxHQUFHQSxNQUFNQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFJQSxHQUFHQSxrQ0FBa0NBLENBQUNBLENBQUVBLENBQUNBO1lBRTdGQSxFQUFFQSxDQUFDQSxDQUFFQSxNQUFNQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFJQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDekNBLElBQUlBLEdBQUdBLEdBQWVBLFNBQVVBLENBQUNBLElBQUlBLENBQUNBLElBQUlBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO2dCQUU3RkEsRUFBRUEsR0FBR0EsSUFBSUEsU0FBU0EsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsWUFBWUEsQ0FBQ0E7Z0JBRXZDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUNYQSxDQUFDQTtZQUVEQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFFQSxPQUFPQSxJQUFJQSxDQUFDQSxDQUFHQSxDQUFDQTtnQkFDN0NBLE9BQU9BLENBQUVBLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUVBLE1BQU1BLENBQUNBLFdBQVdBLENBQUNBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBLEVBQUVBLENBQUNBLEVBQUVBLElBQUlBLEVBQUVBLEVBQUVBLEVBQUVBLE9BQU9BLENBQUVBLENBQUVBLENBQUVBLENBQUNBO1lBQ25IQSxJQUFJQTtnQkFDRkEsT0FBT0EsQ0FBRUEsSUFBSUEsU0FBU0EsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDL0JBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBRURGLE9BQU9BLENBQUNBLFNBQTZCQSxFQUFFQSxHQUFjQSxFQUFFQSxJQUFlQTtRQUVwRUcsTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLFlBQVlBLE1BQU1BLENBQUNBLEdBQWVBLFNBQVVBLENBQUNBLElBQUlBLEdBQVdBLFNBQVNBLENBQUNBO1lBQzFGQSxJQUFJQSxNQUFNQSxHQUFHQSxHQUFtQkEsQ0FBQ0E7WUFDakNBLElBQUlBLElBQUlBLEdBQUdBLENBQUNBLEVBQUVBLE9BQU9BLEdBQUdBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxFQUFFQSxDQUFDQTtZQUVQQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxNQUFNQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFLQSxDQUFDQTtnQkFDakNBLE1BQU1BLENBQUVBLElBQUlBLEtBQUtBLENBQUVBLE9BQU9BLEdBQUdBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEdBQUdBLGtDQUFrQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFN0ZBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLElBQUlBLFNBQVVBLENBQUNBLENBQUNBLENBQUNBO2dCQUN6Q0EsSUFBSUEsR0FBR0EsR0FBZUEsU0FBVUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBRTdGQSxFQUFFQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQSxZQUFZQSxDQUFDQTtnQkFFdkNBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBO1lBQ1hBLENBQUNBO1lBRURBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE1BQU1BLElBQUlBLENBQUVBLENBQUNBO2dCQUNyQkEsT0FBT0EsQ0FBRUEsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsRUFBRUEsRUFBRUEsT0FBT0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7WUFDbkhBLElBQUlBO2dCQUNGQSxPQUFPQSxDQUFFQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUUvQkEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFFREgsU0FBU0EsQ0FBQ0EsTUFBY0EsRUFBRUEsT0FBa0JBLEVBQUVBLFNBQTZCQSxFQUFFQSxXQUFvQkEsRUFBRUEsU0FBbUJBO1FBQ3BISSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxZQUFZQSxNQUFNQSxDQUFHQSxDQUFDQTtZQUNyQ0EsU0FBU0EsR0FBY0EsRUFBRUEsSUFBSUEsRUFBVUEsU0FBU0EsRUFBRUEsQ0FBQ0E7UUFFckRBLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxZQUFZQSxDQUFFQSxPQUFPQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxFQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtZQUU1RUEsT0FBT0EsQ0FBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFDckJBLENBQUNBLENBQUNBLENBQUNBO0lBQ0pBLENBQUNBO0lBRURKLElBQUlBLENBQUVBLFNBQTZCQSxFQUFFQSxHQUFjQSxFQUFFQSxJQUFlQTtRQUNsRUssTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLE1BQU1BLEdBQUdBLEdBQW1CQSxDQUFDQTtZQUVqQ0EsT0FBT0EsQ0FBRUEsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFbkdBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBS09MLEdBQUdBLENBQUVBLEdBQWVBLEVBQUVBLE9BQW1CQSxFQUFFQSxPQUFlQSxFQUFFQSxJQUFZQSxFQUFFQSxFQUFlQSxFQUFFQSxPQUFnQkE7UUFLakhNLHdCQUF5QkEsR0FBR0E7WUFFMUJDLElBQUlBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFFMUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO2dCQUVDQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLEdBQUdBO29CQUN0Q0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBRUEsQ0FBRUE7b0JBQzVLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNySkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzlLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxDQUFDQSxDQUFFQTtvQkFDM0lBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQ3JLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDakxBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUM3SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtvQkFDbkpBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNuTEEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3RLQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxDQUFDQSxDQUFFQTtpQkFDOUdBLENBQUNBO1lBQ0pBLENBQUNBO1lBR0RBLElBQUlBLFVBQVVBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRXhDQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxXQUFXQSxDQUFDQSxFQUFFQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtZQUU1Q0EsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFaEVBLElBQUlBLFFBQVFBLEVBQUVBLFNBQVNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBO1lBRXhDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUMvQkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLEdBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUN6RUEsS0FBS0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBRXpFQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDbkZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUcvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0EsQ0FBQ0E7Z0JBRW5EQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDdEdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBO2dCQUdiQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUNwQ0EsQ0FBQ0E7b0JBRUNBLEVBQUVBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO3dCQUNDQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTt3QkFBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7b0JBQzVFQSxDQUFDQTtvQkFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBTTVCQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDbkVBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUMzRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzFFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtvQkFDL0NBLFNBQVNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNyRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzlFQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDOUVBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUNsREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsU0FBU0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7b0JBQ3BEQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsU0FBU0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3BFQSxDQUFDQTtZQUNIQSxDQUFDQTtZQUVEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtRQUNkQSxDQUFDQTtRQUdERCxJQUFJQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLENBQUNBO1FBRTFDQSxFQUFFQSxDQUFDQSxDQUFFQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUN6QkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsdUJBQXVCQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDdENBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNyb0JBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNqZkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JtQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3pqQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7YUFDdGxCQSxDQUFDQTtRQUNKQSxDQUFDQTtRQUdEQSxJQUFJQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVqQ0EsSUFBSUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsRUFBRUEsT0FBT0EsQ0FBQ0E7UUFDMUNBLElBQUlBLE9BQU9BLEVBQUVBLFFBQVFBLEVBQUVBLFFBQVFBLEVBQUVBLFNBQVNBLENBQUFBO1FBQzFDQSxJQUFJQSxHQUFHQSxHQUFHQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUd6QkEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFM0NBLEVBQUVBLENBQUNBLENBQUNBLFVBQVVBLElBQUlBLENBQUNBLENBQUNBLENBQ3BCQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsT0FBT0EsR0FBR0EsT0FBT0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEdBLENBQUNBO1FBR0RBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLE9BQU9BLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUVBLE9BQU9BLElBQUlBLENBQUNBLENBQUdBLENBQUNBLENBQ25EQSxDQUFDQTtZQUNDQSxJQUFJQSxlQUFlQSxHQUFHQSxPQUFPQSxDQUFDQTtZQUM5QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFFcEJBLE9BQU9BLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO1lBQ3BDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxlQUFlQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVsQ0EsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO2dCQUNDQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7b0JBQ3pGQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsQ0FBQ0E7b0JBQ05BLENBQUNBO3dCQUNDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTt3QkFFOUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUVBLENBQUVBLENBQUNBOzRCQUNYQSxHQUFHQSxJQUFFQSxDQUFDQSxDQUFDQTt3QkFFVEEsS0FBS0EsQ0FBQ0E7b0JBQ1JBLENBQUNBO2dCQUVEQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3ZGQSxLQUFLQSxDQUFDQTtZQUVWQSxDQUFDQTtZQUVEQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFBQTtRQUNsQkEsQ0FBQ0E7UUFHREEsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFbkNBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO1lBQ0NBLElBQUlBLEVBQUVBLEdBQUdBLENBQUNBLENBQUNBO1lBRVhBLE9BQU9BLEdBQUlBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBO1lBQzVFQSxRQUFRQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQTtRQUM5RUEsQ0FBQ0E7UUFFREEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFHWEEsT0FBT0EsQ0FBQ0EsR0FBR0EsR0FBR0EsRUFDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDekZBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBR3pGQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtnQkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FDWkEsQ0FBQ0E7b0JBQ0NBLElBQUlBLElBQUlBLE9BQU9BLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxRQUFRQSxDQUFDQTtnQkFDckNBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtvQkFDQ0EsUUFBUUEsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQ25CQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtvQkFDckJBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBO29CQUNmQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDbkJBLENBQUNBO1lBQ0hBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUUvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxJQUFFQSxDQUFDQSxFQUM1QkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUMzQkEsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRzNCQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUN6Q0EsQ0FBQ0E7b0JBQ0NBLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUM3QkEsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBR3pEQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDWkEsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0E7b0JBQ2JBLEtBQUtBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNyRkEsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQzVFQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDckZBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQU1BLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUNoR0EsQ0FBQ0E7Z0JBRURBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFBQ0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7WUFDMUNBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBQ3JDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUd4Q0EsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJ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QUFRQSxDQUFDQSxVQUFVQSxDQUFRQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFDQTtvQkFFN0RBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLEtBQU1BLENBQUNBO3dCQUNmQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtnQkFDeENBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFDQSxPQUFPQSxFQUFFQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFFakVBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLElBQUtBLENBQUNBO3dCQUNkQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQTtnQkFDekJBLENBQUNBO2dCQUNEQSxJQUFJQTtvQkFDRkEsTUFBTUEsSUFBSUEsS0FBS0EsQ0FBRUEsNkNBQTZDQSxDQUFFQSxDQUFDQTtnQkFDbkVBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLFFBQVFBLENBQUNBLE9BQU9BO2dCQUNuQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsS0FBS0EsRUFBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRTNEQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFNQSxDQUFDQTt3QkFDZkEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsS0FBS0EsRUFBRUEsQ0FBQ0E7Z0JBQzFCQSxDQUFDQTtnQkFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7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QSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVETCxJQUFJQSxRQUFRQTtRQUVWTSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUN0REEsQ0FBQ0E7SUFFRE4sSUFBSUEsUUFBUUE7UUFFVk8sSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7UUFFekJBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLEdBQUdBLFNBQVNBLENBQUNBO0lBQ3ZGQSxDQUFDQTtJQUVEUCxJQUFJQSxRQUFRQSxDQUFFQSxJQUFVQTtRQUV0Qk8sSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0E7WUFDWEEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsRUFBRUE7WUFDckJBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ2hCQSxDQUFDQTtRQUVGQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtJQUNyQ0EsQ0FBQ0E7SUFFRFAsSUFBSUEsTUFBTUE7UUFFUlEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDcERBLENBQUNBO0lBRURSLElBQUlBLE1BQU1BO1FBRVJTLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZCQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxN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QUdBLEVBQWdCQSxDQUFDQTtRQUN0Q0EsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsR0FBR0EsRUFBZ0JBLENBQUNBO1FBRXRDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFFQSxVQUFVQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFDQSxFQUFFQTtZQUNoREEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsRUFBRUEsRUFBRUEsVUFBVUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFDN0NBLENBQUNBLENBQUNBLENBQUNBO1FBRUhBLE1BQU1BLENBQUNBLElBQUlBLENBQUVBLFVBQVVBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBLEVBQUVBO1lBQ2hEQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxFQUFFQSxFQUFFQSxVQUFVQSxDQUFDQSxLQUFLQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUM3Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFFREgsUUFBUUEsQ0FBRUEsSUFBU0E7UUFFakJJLElBQUlBLEtBQUtBLEdBQUdBLEtBQUtBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO1FBRTdCQSxJQUFJQSxLQUFLQSxHQUFHQSxLQUFLQSxDQUFFQSxPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNsQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUE7WUFFM0JBLEtBQUtBLENBQUVBLEVBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO1FBQ2xDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUVIQSxJQUFJQSxLQUFLQSxHQUFHQSxLQUFLQSxDQUFFQSxPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNsQ0EsSUFBSUEsQ0FBQ0Es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QSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ1UsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBLENBQ2xCQSxDQUFDQTtZQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtZQUV2REEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFFekJBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEtBQUtBLENBQUNBO1lBRWhCQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtZQUUvQkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFDbERBLENBQUNBO0lBQ0hBLENBQUNBO0lBRU1WLFVBQVVBLENBQUVBLEVBQVVBO1FBRTNCVyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBS0EsQ0FBQ0E7WUFDVEEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFdkRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQ2xDQSxDQUFDQTtJQUVNWCxXQUFXQSxDQUFFQSxFQUFVQTtRQUU1QlksTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDM0JBLENBQUNBO0lBRU1aLE9BQU9BLENBQUVBLEVBQVVBLEVBQUVBLFVBQWVBO1FBRXpDYSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUV4Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFYkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNYixVQUFVQSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ2MsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBRXpCQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtRQUV2REEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsS0FBS0EsQ0FBQ0E7UUFFaEJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRWhEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQUNqQ0EsQ0FBQ0E7SUFFTWQsVUFBVUEsQ0FBRUEsRUFBVUE7UUFFM0JlLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBQ2pDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQTtZQUNUQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV2REEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDbENBLENBQUNBO0lBRU1mLGFBQWFBLENBQUVBLEVBQVVBLEVBQUVBLFVBQWNBO1FBRTlDZ0IsVUFBVUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFdEJBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFVBQVVBLENBQUVBLENBQUNBO1FBRXBEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUU1QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7QUFDSGhCLENBQUNBO0FBN1BRLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBRWxDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQXVQekM7O09DMVFNLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxxQkFBcUI7QUFLdEQ7SUFVRWlCLFlBQWFBLE1BQW9CQSxFQUFFQSxTQUFvQkE7UUFDckRDLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3JCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7SUFNREQsbUJBQW1CQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsZ0JBQWdCQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUM3REEsQ0FBQ0E7QUFFSEYsQ0FBQ0E7QUFBQSIsImZpbGUiOiJjcnlwdG9ncmFwaGl4LXNpbS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNsYXNzIEhleENvZGVjXG57XG4gIHByaXZhdGUgc3RhdGljIGhleERlY29kZU1hcDogbnVtYmVyW107XG5cbiAgc3RhdGljIGRlY29kZSggYTogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmICggSGV4Q29kZWMuaGV4RGVjb2RlTWFwID09IHVuZGVmaW5lZCApXG4gICAge1xuICAgICAgdmFyIGhleCA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiO1xuICAgICAgdmFyIGFsbG93ID0gXCIgXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICB2YXIgZGVjOiBudW1iZXJbXSA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBoZXggPSBoZXgudG9Mb3dlckNhc2UoKTtcbiAgICAgIGZvciAodmFyIGkgPSAxMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgZGVjW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYWxsb3cubGVuZ3RoOyArK2kpXG4gICAgICAgICAgZGVjW2FsbG93LmNoYXJBdChpKV0gPSAtMTtcbiAgICAgIEhleENvZGVjLmhleERlY29kZU1hcCA9IGRlYztcbiAgICB9XG5cbiAgICB2YXIgb3V0OiBudW1iZXJbXSA9IFtdO1xuICAgIHZhciBiaXRzID0gMCwgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKVxuICAgIHtcbiAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgYnJlYWs7XG4gICAgICB2YXIgYiA9IEhleENvZGVjLmhleERlY29kZU1hcFtjXTtcbiAgICAgIGlmIChiID09IC0xKVxuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgaWYgKGIgPT0gdW5kZWZpbmVkKVxuICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICBiaXRzIHw9IGI7XG4gICAgICBpZiAoKytjaGFyX2NvdW50ID49IDIpIHtcbiAgICAgICAgICBvdXQucHVzaCggYml0cyApO1xuICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBiaXRzIDw8PSA0O1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChjaGFyX2NvdW50KVxuICAgICAgdGhyb3cgXCJIZXggZW5jb2RpbmcgaW5jb21wbGV0ZTogNCBiaXRzIG1pc3NpbmdcIjtcblxuICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oIG91dCApO1xuICB9XG59XG4iLCJ0eXBlIGJ5dGUgPSBudW1iZXI7XG5cbmVudW0gQkFTRTY0U1BFQ0lBTFMge1xuICBQTFVTID0gJysnLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIID0gJy8nLmNoYXJDb2RlQXQoMCksXG4gIE5VTUJFUiA9ICcwJy5jaGFyQ29kZUF0KDApLFxuICBMT1dFUiA9ICdhJy5jaGFyQ29kZUF0KDApLFxuICBVUFBFUiA9ICdBJy5jaGFyQ29kZUF0KDApLFxuICBQTFVTX1VSTF9TQUZFID0gJy0nLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIX1VSTF9TQUZFID0gJ18nLmNoYXJDb2RlQXQoMClcbn1cblxuZXhwb3J0IGNsYXNzIEJhc2U2NENvZGVjXG57XG4gIHN0YXRpYyBkZWNvZGUoIGI2NDogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmIChiNjQubGVuZ3RoICUgNCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBiYXNlNjQgc3RyaW5nLiBMZW5ndGggbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBkZWNvZGUoIGVsdDogU3RyaW5nICk6IG51bWJlclxuICAgIHtcbiAgICAgIHZhciBjb2RlID0gZWx0LmNoYXJDb2RlQXQoMCk7XG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTIHx8IGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlBMVVNfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MjsgLy8gJysnXG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSCB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSF9VUkxfU0FGRSlcbiAgICAgICAgcmV0dXJuIDYzOyAvLyAnLydcblxuICAgICAgaWYgKGNvZGUgPj0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSKVxuICAgICAge1xuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDEwKVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSICsgMjYgKyAyNjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLlVQUEVSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5VUFBFUjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLkxPV0VSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2O1xuICAgICAgfVxuXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gQ2hhcmFjdGVyIG5vdCB2YWxpZCcpO1xuICAgIH1cblxuICAgIC8vIHRoZSBudW1iZXIgb2YgZXF1YWwgc2lnbnMgKHBsYWNlIGhvbGRlcnMpXG4gICAgLy8gaWYgdGhlcmUgYXJlIHR3byBwbGFjZWhvbGRlcnMsIHRoYW4gdGhlIHR3byBjaGFyYWN0ZXJzIGJlZm9yZSBpdFxuICAgIC8vIHJlcHJlc2VudCBvbmUgYnl0ZVxuICAgIC8vIGlmIHRoZXJlIGlzIG9ubHkgb25lLCB0aGVuIHRoZSB0aHJlZSBjaGFyYWN0ZXJzIGJlZm9yZSBpdCByZXByZXNlbnQgMiBieXRlc1xuICAgIC8vIHRoaXMgaXMganVzdCBhIGNoZWFwIGhhY2sgdG8gbm90IGRvIGluZGV4T2YgdHdpY2VcbiAgICBsZXQgbGVuID0gYjY0Lmxlbmd0aDtcbiAgICBsZXQgcGxhY2VIb2xkZXJzID0gYjY0LmNoYXJBdChsZW4gLSAyKSA9PT0gJz0nID8gMiA6IGI2NC5jaGFyQXQobGVuIC0gMSkgPT09ICc9JyA/IDEgOiAwO1xuXG4gICAgLy8gYmFzZTY0IGlzIDQvMyArIHVwIHRvIHR3byBjaGFyYWN0ZXJzIG9mIHRoZSBvcmlnaW5hbCBkYXRhXG4gICAgbGV0IGFyciA9IG5ldyBVaW50OEFycmF5KCBiNjQubGVuZ3RoICogMyAvIDQgLSBwbGFjZUhvbGRlcnMgKTtcblxuICAgIC8vIGlmIHRoZXJlIGFyZSBwbGFjZWhvbGRlcnMsIG9ubHkgZ2V0IHVwIHRvIHRoZSBsYXN0IGNvbXBsZXRlIDQgY2hhcnNcbiAgICBsZXQgbCA9IHBsYWNlSG9sZGVycyA+IDAgPyBiNjQubGVuZ3RoIC0gNCA6IGI2NC5sZW5ndGg7XG5cbiAgICB2YXIgTCA9IDA7XG5cbiAgICBmdW5jdGlvbiBwdXNoICh2OiBieXRlKSB7XG4gICAgICBhcnJbTCsrXSA9IHY7XG4gICAgfVxuXG4gICAgbGV0IGkgPSAwLCBqID0gMDtcblxuICAgIGZvciAoOyBpIDwgbDsgaSArPSA0LCBqICs9IDMpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDE4KSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDEyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMikpIDw8IDYpIHwgZGVjb2RlKGI2NC5jaGFyQXQoaSArIDMpKTtcbiAgICAgIHB1c2goKHRtcCAmIDB4RkYwMDAwKSA+PiAxNik7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDApID4+IDgpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICBpZiAocGxhY2VIb2xkZXJzID09PSAyKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpID4+IDQpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9IGVsc2UgaWYgKHBsYWNlSG9sZGVycyA9PT0gMSkge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMTApIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPDwgNCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA+PiAyKTtcbiAgICAgIHB1c2goKHRtcCA+PiA4KSAmIDB4RkYpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXJyO1xuICB9XG5cbiAgc3RhdGljIGVuY29kZSggdWludDg6IFVpbnQ4QXJyYXkgKTogc3RyaW5nXG4gIHtcbiAgICB2YXIgaTogbnVtYmVyO1xuICAgIHZhciBleHRyYUJ5dGVzID0gdWludDgubGVuZ3RoICUgMzsgLy8gaWYgd2UgaGF2ZSAxIGJ5dGUgbGVmdCwgcGFkIDIgYnl0ZXNcbiAgICB2YXIgb3V0cHV0ID0gJyc7XG5cbiAgICBjb25zdCBsb29rdXAgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLyc7XG4gICAgZnVuY3Rpb24gZW5jb2RlKCBudW06IGJ5dGUgKSB7XG4gICAgICByZXR1cm4gbG9va3VwLmNoYXJBdChudW0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyaXBsZXRUb0Jhc2U2NCggbnVtOiBudW1iZXIgKSB7XG4gICAgICByZXR1cm4gZW5jb2RlKG51bSA+PiAxOCAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiAxMiAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiA2ICYgMHgzRikgKyBlbmNvZGUobnVtICYgMHgzRik7XG4gICAgfVxuXG4gICAgLy8gZ28gdGhyb3VnaCB0aGUgYXJyYXkgZXZlcnkgdGhyZWUgYnl0ZXMsIHdlJ2xsIGRlYWwgd2l0aCB0cmFpbGluZyBzdHVmZiBsYXRlclxuICAgIGxldCBsZW5ndGggPSB1aW50OC5sZW5ndGggLSBleHRyYUJ5dGVzO1xuICAgIGZvciAoaSA9IDA7IGkgPCBsZW5ndGg7IGkgKz0gMykge1xuICAgICAgbGV0IHRlbXAgPSAodWludDhbaV0gPDwgMTYpICsgKHVpbnQ4W2kgKyAxXSA8PCA4KSArICh1aW50OFtpICsgMl0pO1xuICAgICAgb3V0cHV0ICs9IHRyaXBsZXRUb0Jhc2U2NCh0ZW1wKTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIGVuZCB3aXRoIHplcm9zLCBidXQgbWFrZSBzdXJlIHRvIG5vdCBmb3JnZXQgdGhlIGV4dHJhIGJ5dGVzXG4gICAgc3dpdGNoIChleHRyYUJ5dGVzKSB7XG4gICAgICBjYXNlIDE6XG4gICAgICAgIGxldCB0ZW1wID0gdWludDhbdWludDgubGVuZ3RoIC0gMV07XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAyKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCA0KSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz09JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgdGVtcCA9ICh1aW50OFt1aW50OC5sZW5ndGggLSAyXSA8PCA4KSArICh1aW50OFt1aW50OC5sZW5ndGggLSAxXSk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAxMCk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPj4gNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCAyKSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz0nO1xuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSGV4Q29kZWMgfSBmcm9tICcuL2hleC1jb2RlYyc7XG5pbXBvcnQgeyBCYXNlNjRDb2RlYyB9IGZyb20gJy4vYmFzZTY0LWNvZGVjJztcblxuZXhwb3J0IGVudW0gQnl0ZUVuY29kaW5nIHtcbiAgUkFXLFxuICBIRVgsXG4gIEJBU0U2NCxcbiAgVVRGOFxufVxuXG5leHBvcnQgY2xhc3MgQnl0ZUFycmF5IC8vZXh0ZW5kcyBVaW50OEFycmF5XG57XG4gIHB1YmxpYyBzdGF0aWMgUkFXID0gQnl0ZUVuY29kaW5nLlJBVztcbiAgcHVibGljIHN0YXRpYyBIRVggPSBCeXRlRW5jb2RpbmcuSEVYO1xuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XG4gIHB1YmxpYyBzdGF0aWMgVVRGOCA9IEJ5dGVFbmNvZGluZy5VVEY4O1xuXG4gIHN0YXRpYyBlbmNvZGluZ1RvU3RyaW5nKCBlbmNvZGluZzogQnl0ZUVuY29kaW5nICk6IHN0cmluZyB7XG4gICAgc3dpdGNoKCBlbmNvZGluZyApIHtcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkJBU0U2NDpcbiAgICAgICAgcmV0dXJuICdCQVNFNjQnO1xuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuVVRGODpcbiAgICAgICAgcmV0dXJuICdVVEY4JztcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkhFWDpcbiAgICAgICAgcmV0dXJuICdIRVgnO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuICdSQVcnO1xuICAgIH1cbiAgfVxuXG4gIHN0YXRpYyBzdHJpbmdUb0VuY29kaW5nKCBlbmNvZGluZzogc3RyaW5nICk6IEJ5dGVFbmNvZGluZyB7XG4gICAgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdCQVNFNjQnIClcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuQkFTRTY0O1xuICAgIGVsc2UgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdVVEY4JyApXG4gICAgICByZXR1cm4gQnl0ZUVuY29kaW5nLlVURjg7XG4gICAgZWxzZSBpZiAoIGVuY29kaW5nLnRvVXBwZXJDYXNlKCkgPT0gJ0hFWCcgKVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5IRVg7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5SQVc7XG4gIH1cblxuXG4gIHByaXZhdGUgYnl0ZUFycmF5OiBVaW50OEFycmF5O1xuICAvKipcbiAgICogQ3JlYXRlIGEgQnl0ZUFycmF5XG4gICAqIEBwYXJhbSBieXRlcyAtIGluaXRpYWwgY29udGVudHMsIG9wdGlvbmFsXG4gICAqICAgbWF5IGJlOlxuICAgKiAgICAgYW4gZXhpc3RpbmcgQnl0ZUFycmF5XG4gICAqICAgICBhbiBBcnJheSBvZiBudW1iZXJzICgwLi4yNTUpXG4gICAqICAgICBhIHN0cmluZywgdG8gYmUgY29udmVydGVkXG4gICAqICAgICBhbiBBcnJheUJ1ZmZlclxuICAgKiAgICAgYSBVaW50OEFycmF5XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYnl0ZXM/OiBCeXRlQXJyYXkgfCBBcnJheTxudW1iZXI+IHwgU3RyaW5nIHwgQXJyYXlCdWZmZXIgfCBVaW50OEFycmF5LCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGlmICggIWJ5dGVzIClcbiAgICB7XG4gICAgICAvLyB6ZXJvLWxlbmd0aCBhcnJheVxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggMCApO1xuICAgIH1cbiAgICBlbHNlIGlmICggIWVuY29kaW5nIHx8IGVuY29kaW5nID09IEJ5dGVFbmNvZGluZy5SQVcgKVxuICAgIHtcbiAgICAgIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlciApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxBcnJheUJ1ZmZlcj5ieXRlcyApO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgVWludDhBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYnl0ZXM7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzLmJ5dGVBcnJheTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIEFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggYnl0ZXMgKTtcbiAgICAgIC8vZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICAgIC8ve1xuLy8gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIC8vfVxuICAgIH1cbiAgICBlbHNlIGlmICggdHlwZW9mIGJ5dGVzID09IFwic3RyaW5nXCIgKVxuICAgIHtcbiAgICAgIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLkJBU0U2NCApXG4gICAgICB7XG4gICAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBCYXNlNjRDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuSEVYIClcbiAgICAgIHtcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBIZXhDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuVVRGOCApXG4gICAgICB7XG4gICAgICAgIGxldCBsID0gKCA8c3RyaW5nPmJ5dGVzICkubGVuZ3RoO1xuICAgICAgICBsZXQgYmEgPSBuZXcgVWludDhBcnJheSggbCApO1xuICAgICAgICBmb3IoIGxldCBpID0gMDsgaSA8IGw7ICsraSApXG4gICAgICAgICAgYmFbaV0gPSAoIDxzdHJpbmc+Ynl0ZXMgKS5jaGFyQ29kZUF0KCBpICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBiYTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBNdXN0IGhhdmUgZXhlYyBvbmUgb2YgYWJvdmUgYWxsb2NhdG9yc1xuICAgIGlmICggIXRoaXMuYnl0ZUFycmF5IClcbiAgICB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiSW52YWxpZCBQYXJhbXMgZm9yIEJ5dGVBcnJheSgpXCIpXG4gICAgfVxuICB9XG5cbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XG4gIH1cblxuICBzZXQgbGVuZ3RoKCBsZW46IG51bWJlciApXG4gIHtcbiAgICBpZiAoIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCA+PSBsZW4gKVxuICAgIHtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdGhpcy5ieXRlQXJyYXkuc2xpY2UoIDAsIGxlbiApO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbGV0IG9sZCA9IHRoaXMuYnl0ZUFycmF5O1xuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG4gICAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIG9sZCwgMCApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBiYWNraW5nQXJyYXkoKTogVWludDhBcnJheVxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5O1xuICB9XG5cbiAgZXF1YWxzKCB2YWx1ZTogQnl0ZUFycmF5ICk6IGJvb2xlYW5cbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG4gICAgdmFyIG9rID0gKCBiYS5sZW5ndGggPT0gdmJhLmxlbmd0aCApO1xuXG4gICAgaWYgKCBvayApXG4gICAge1xuICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICAgIG9rID0gb2sgJiYgKCBiYVtpXSA9PSB2YmFbaV0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gb2s7XG4gIH1cblxuICAvKipcbiAgICAqIGdldCBieXRlIGF0IG9mZnNldFxuICAgICovXG4gIGJ5dGVBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdO1xuICB9XG5cbiAgd29yZEF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gPDwgIDggKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gICAgICAgKTtcbiAgfVxuXG4gIGxpdHRsZUVuZGlhbldvcmRBdCggb2Zmc2V0ICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAgOCApO1xuICB9XG5cbiAgZHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8IDI0IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdIDw8IDE2IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMiBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMyBdICAgICAgICk7XG4gIH1cblxuICAvKipcbiAgICAqIHNldCBieXRlIGF0IG9mZnNldFxuICAgICogQGZsdWVudFxuICAgICovXG4gIHNldEJ5dGVBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0IF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0Qnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIHZhbHVlLmJ5dGVBcnJheSwgb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGNsb25lKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEV4dHJhY3QgYSBzZWN0aW9uIChvZmZzZXQsIGNvdW50KSBmcm9tIHRoZSBCeXRlQXJyYXlcbiAgKiBAZmx1ZW50XG4gICogQHJldHVybnMgYSBuZXcgQnl0ZUFycmF5IGNvbnRhaW5pbmcgYSBzZWN0aW9uLlxuICAqL1xuICBieXRlc0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIENyZWF0ZSBhIHZpZXcgaW50byB0aGUgQnl0ZUFycmF5XG4gICpcbiAgKiBAcmV0dXJucyBhIEJ5dGVBcnJheSByZWZlcmVuY2luZyBhIHNlY3Rpb24gb2Ygb3JpZ2luYWwgQnl0ZUFycmF5LlxuICAqL1xuICB2aWV3QXQoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIGlmICggIU51bWJlci5pc0ludGVnZXIoIGNvdW50ICkgKVxuICAgICAgY291bnQgPSAoIHRoaXMubGVuZ3RoIC0gb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gbmV3IEJ5dGVBcnJheSggdGhpcy5ieXRlQXJyYXkuc3ViYXJyYXkoIG9mZnNldCwgb2Zmc2V0ICsgY291bnQgKSApO1xuICB9XG5cbiAgLyoqXG4gICogQXBwZW5kIGJ5dGVcbiAgKiBAZmx1ZW50XG4gICovXG4gIGFkZEJ5dGUoIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgdGhpcy5ieXRlQXJyYXkubGVuZ3RoIF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0TGVuZ3RoKCBsZW46IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIHRoaXMubGVuZ3RoID0gbGVuO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjb25jYXQoIGJ5dGVzOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJhLmxlbmd0aCArIGJ5dGVzLmxlbmd0aCApO1xuXG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBiYSApO1xuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYnl0ZXMuYnl0ZUFycmF5LCBiYS5sZW5ndGggKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgbm90KCApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4weEZGO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBhbmQoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldICYgdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSB8IHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB4b3IoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4gdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHRvU3RyaW5nKCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGxldCBzID0gXCJcIjtcbiAgICBsZXQgaSA9IDA7XG5cbiAgICBzd2l0Y2goIGVuY29kaW5nIHx8IEJ5dGVFbmNvZGluZy5IRVggKSB7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5IRVg6XG4gICAgICAgIC8vcmV0dXJuIEhleENvZGVjLmVuY29kZSggdGhpcy5ieXRlQXJyYXkgKTtcbiAgICAgICAgZm9yKCBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyArK2kgKVxuICAgICAgICAgIHMgKz0gKCBcIjBcIiArIHRoaXMuYnl0ZUFycmF5WyBpIF0udG9TdHJpbmcoIDE2ICkpLnNsaWNlKCAtMiApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuQkFTRTY0OlxuICAgICAgICByZXR1cm4gQmFzZTY0Q29kZWMuZW5jb2RlKCB0aGlzLmJ5dGVBcnJheSApO1xuXG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5VVEY4OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHJldHVybiBzO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgZW51bSBDcnlwdG9ncmFwaGljT3BlcmF0aW9uIHtcbiAgRU5DUllQVCxcbiAgREVDUllQVCxcbiAgRElHRVNULFxuICBTSUdOLFxuICBWRVJJRlksXG4gIERFUklWRV9CSVRTLFxuXG4gIERFUklWRV9LRVksXG4gIElNUE9SVF9LRVksXG4gIEVYUE9SVF9LRVksXG4gIEdFTkVSQVRFX0tFWSxcbiAgV1JBUF9LRVksXG4gIFVOV1JBUF9LRVksXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBlbmNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuICBkZWNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIGRpZ2VzdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIHNpZ24/KCBhbGdvcml0aG06IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG4gIHZlcmlmeT8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG5cbiAgZGVyaXZlQml0cz8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGxlbmd0aDogbnVtYmVyICk6IFByb21pc2U8Qnl0ZUFycmF5Pjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yIHtcbiAgbmV3KCk6IENyeXB0b2dyYXBoaWNTZXJ2aWNlO1xuXG4gIHN1cHBvcnRlZE9wZXJhdGlvbnM/OiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBkZXJpdmVLZXk/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG5cbiAgd3JhcEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSwgd3JhcHBpbmdLZXk6IENyeXB0b0tleSwgd3JhcEFsZ29yaXRobTogQWxnb3JpdGhtICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcbiAgdW53cmFwS2V5PyggZm9ybWF0OiBzdHJpbmcsIHdyYXBwZWRLZXk6IEJ5dGVBcnJheSwgdW53cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB1bndyYXBBbGdvcml0aG06IEFsZ29yaXRobSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuXG4gIGltcG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG4gIGdlbmVyYXRlS2V5PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj47XG4gIGV4cG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3RvciB7XG4gIG5ldygpOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZTtcblxuICBzdXBwb3J0ZWRPcGVyYXRpb25zPzogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdO1xufVxuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSB7XG4gIHByaXZhdGUgX3NlcnZpY2VNYXA6IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3I+O1xuICBwcml2YXRlIF9rZXlTZXJ2aWNlTWFwOiBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPjtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLl9zZXJ2aWNlTWFwID0gbmV3IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNTZXJ2aWNlQ29uc3RydWN0b3I+KCk7XG4gICAgdGhpcy5fa2V5U2VydmljZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPigpO1xuICB9XG5cbiAgZ2V0U2VydmljZSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0gKTogeyBuYW1lOiBzdHJpbmcsIGluc3RhbmNlOiBDcnlwdG9ncmFwaGljU2VydmljZSB9IHtcbiAgICBsZXQgYWxnbyA9ICggYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0ICkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICBsZXQgc2VydmljZSA9IHRoaXMuX3NlcnZpY2VNYXAuZ2V0KCBhbGdvICk7XG5cbiAgICByZXR1cm4geyBuYW1lOiBhbGdvLCBpbnN0YW5jZTogc2VydmljZSA/IG5ldyBzZXJ2aWNlKCkgOiBudWxsIH07XG4gIH1cblxuICBnZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSApOiB7IG5hbWU6IHN0cmluZywgaW5zdGFuY2U6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0ge1xuICAgIGxldCBhbGdvID0gKCBhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QgKSA/ICg8QWxnb3JpdGhtPmFsZ29yaXRobSkubmFtZSA6IDxzdHJpbmc+YWxnb3JpdGhtO1xuICAgIGxldCBzZXJ2aWNlID0gdGhpcy5fa2V5U2VydmljZU1hcC5nZXQoIGFsZ28gKTtcblxuICAgIHJldHVybiB7IG5hbWU6IGFsZ28sIGluc3RhbmNlOiBzZXJ2aWNlID8gbmV3IHNlcnZpY2UoKSA6IG51bGwgfTtcbiAgfVxuXG4gIHNldFNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fc2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG4gIHNldEtleVNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fa2V5U2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgLy8gc2luZ2xldG9uIHJlZ2lzdHJ5XG4gIHByaXZhdGUgc3RhdGljIF9yZWdpc3RyeTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSA9IG5ldyBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5KCk7XG5cbiAgcHVibGljIHN0YXRpYyByZWdpc3RlclNlcnZpY2UoIG5hbWU6IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLl9yZWdpc3RyeS5zZXRTZXJ2aWNlKCBuYW1lLCBjdG9yLCBvcGVycyApO1xuICB9XG4gIHB1YmxpYyBzdGF0aWMgcmVnaXN0ZXJLZXlTZXJ2aWNlKCBuYW1lOiBzdHJpbmcsIGN0b3I6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3IsIG9wZXJzOiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW10gKSB7XG4gICAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnkuc2V0S2V5U2VydmljZSggbmFtZSwgY3Rvciwgb3BlcnMgKTtcbiAgfVxuXG4gIGdldCByZWdpc3RyeSgpOiBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5IHtcbiAgICByZXR1cm4gQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnk7XG4gIH1cblxuICBlbmNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmVuY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5lbmNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5kZWNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kaWdlc3QgKVxuICAgICAgPyBpbnN0YW5jZS5kaWdlc3QoIG5hbWUsIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBzaWduKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2Uuc2lnbiApXG4gICAgICA/IGluc3RhbmNlLnNpZ24oIG5hbWUsIGtleSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIHZlcmlmeShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UudmVyaWZ5IClcbiAgICAgID8gaW5zdGFuY2UudmVyaWZ5KCBuYW1lLCBrZXksIHNpZ25hdHVyZSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSgga2V5LmFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZXhwb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuZXhwb3J0S2V5KCBmb3JtYXQsIGtleSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGdlbmVyYXRlS2V5KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5nZW5lcmF0ZUtleSApXG4gICAgICA/IGluc3RhbmNlLmdlbmVyYXRlS2V5KCBuYW1lLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oIFwiXCIgKTtcbiAgfVxuXG4gIGltcG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSAsIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuaW1wb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuaW1wb3J0S2V5KCBmb3JtYXQsIGtleURhdGEsIG5hbWUsIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxDcnlwdG9LZXk+KCBcIlwiICk7XG4gIH1cblxuICBkZXJpdmVLZXkoIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGRlcml2ZWRLZXlUeXBlOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZXJpdmVLZXkgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVLZXkoIG5hbWUsIGJhc2VLZXksIGRlcml2ZWRLZXlUeXBlLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG5cbiAgZGVyaXZlQml0cyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgbGVuZ3RoOiBudW1iZXIgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlcml2ZUJpdHMgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVCaXRzKCBuYW1lLCBiYXNlS2V5LCBsZW5ndGggKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB3cmFwS2V5KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IEFsZ29yaXRobSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGtleS5hbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS53cmFwS2V5KCBmb3JtYXQsIGtleSwgd3JhcHBpbmdLZXksIHdyYXBBbGdvcml0aG0gKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB1bndyYXBLZXkoIGZvcm1hdDogc3RyaW5nLCB3cmFwcGVkS2V5OiBCeXRlQXJyYXksIHVud3JhcHBpbmdLZXk6IENyeXB0b0tleSwgdW53cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0sIHVud3JhcHBlZEtleUFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggdW53cmFwQWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS51bndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS51bndyYXBLZXkoIGZvcm1hdCwgd3JhcHBlZEtleSwgdW53cmFwcGluZ0tleSwgbmFtZSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiwgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0gZnJvbSAnLi9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnknO1xuXG5kZWNsYXJlIHZhciBtc3JjcnlwdG87XG5cbmV4cG9ydCBjbGFzcyBXZWJDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgcHJvdGVjdGVkIGNyeXB0bzogU3VidGxlQ3J5cHRvO1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICB9XG5cbiAgc3RhdGljIF9zdWJ0bGU6IFN1YnRsZUNyeXB0bztcbiAgc3RhdGljIGdldCBzdWJ0bGUoKTogU3VidGxlQ3J5cHRvIHtcbiAgICBsZXQgc3VidGxlID0gV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlXG4gICAgICB8fCAoIGNyeXB0byAmJiBjcnlwdG8uc3VidGxlIClcbiAgICAgIHx8ICggd2luZG93ICYmIHdpbmRvdy5jcnlwdG8gJiYgd2luZG93LmNyeXB0by5zdWJ0bGUgKVxuICAgICAgfHwgbXNyY3J5cHRvO1xuXG4gICAgaWYgKCAhV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlIClcbiAgICAgICBXZWJDcnlwdG9TZXJ2aWNlLl9zdWJ0bGUgPSBzdWJ0bGU7XG5cbiAgICByZXR1cm4gc3VidGxlO1xuICB9XG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5lbmNyeXB0KGFsZ29yaXRobSwga2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmRlY3J5cHQoYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZGlnZXN0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkpOiBhbnkge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZXhwb3J0S2V5KGZvcm1hdCwga2V5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZ2VuZXJhdGVLZXkoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuXG4gICB9KTtcbiAgfVxuXG4gIGltcG9ydEtleShmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5LCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmltcG9ydEtleShmb3JtYXQsIGtleURhdGEuYmFja2luZ0FycmF5LCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShyZXMpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICB9KTtcbiAgfVxuXG4gIHNpZ24oYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLnNpZ24oYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgdmVyaWZ5KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUudmVyaWZ5KGFsZ29yaXRobSwga2V5LCBzaWduYXR1cmUuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxufVxuXG4vKmNsYXNzIFNIQTFDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBkaWdlc3QoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBUT0RPOiBJbXBsZW1lbnQgU0hBLTFcbiAgICAgIG1zcmNyeXB0by5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cbn1cblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtMScsIFNIQTFDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtMjU2JywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRJR0VTVCBdICk7XG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS01MTInLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcbiovXG5cbmlmICggV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUgKSB7XG4gIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnQUVTLUNCQycsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQgXSApO1xuICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ0FFUy1HQ00nLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ERUNSWVBUIF0gKTtcbiAgLy9DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1JTQVNTQS1YWVonLCBXZWJDcnlwdG9TZXJ2aWNlICk7XG5cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJy4uL2tpbmQvYnl0ZS1hcnJheSc7XG5pbXBvcnQgeyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLCBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2UgfSBmcm9tICcuL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeSc7XG5cbmNsYXNzIERFU1NlY3JldEtleSBpbXBsZW1lbnRzIENyeXB0b0tleSB7XG4gIHByaXZhdGUgX2tleU1hdGVyaWFsOiBCeXRlQXJyYXk7XG4gIHByaXZhdGUgX2V4dHJhY3RhYmxlOiBib29sZWFuO1xuICBwcml2YXRlIF9hbGdvcml0aG06IEtleUFsZ29yaXRobTtcbiAgcHJpdmF0ZSBfdHlwZTogc3RyaW5nO1xuICBwcml2YXRlIF91c2FnZXM6IHN0cmluZ1tdO1xuXG4gIGNvbnN0cnVjdG9yKCBrZXlNYXRlcmlhbDogQnl0ZUFycmF5LCBhbGdvcml0aG06IEtleUFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIHVzYWdlczogc3RyaW5nW10gKSB7XG5cbiAgICB0aGlzLl9rZXlNYXRlcmlhbCA9IGtleU1hdGVyaWFsO1xuXG4gICAgdGhpcy5fYWxnb3JpdGhtID0gYWxnb3JpdGhtO1xuXG4gICAgdGhpcy5fZXh0cmFjdGFibGUgPSBleHRyYWN0YWJsZTtcblxuICAgIHRoaXMuX3R5cGUgPSAnc2VjcmV0JztcblxuICAgIHRoaXMuX3VzYWdlcyA9IHVzYWdlcztcbiAgICBPYmplY3QuZnJlZXplKCB0aGlzLl91c2FnZXMgKTtcbiAgfVxuXG4gIGdldCBhbGdvcml0aG0oKSB7IHJldHVybiB0aGlzLl9hbGdvcml0aG07IH1cbiAgZ2V0IGV4dHJhY3RhYmxlKCk6IGJvb2xlYW4geyByZXR1cm4gdGhpcy5fZXh0cmFjdGFibGU7IH1cbiAgZ2V0IHR5cGUoKSB7IHJldHVybiB0aGlzLl90eXBlOyB9XG4gIGdldCB1c2FnZXMoKTogc3RyaW5nW10geyByZXR1cm4gQXJyYXkuZnJvbSggdGhpcy5fdXNhZ2VzICk7IH1cblxuICBnZXQga2V5TWF0ZXJpYWwoKSB7IHJldHVybiB0aGlzLl9rZXlNYXRlcmlhbCB9O1xufVxuXG5leHBvcnQgY2xhc3MgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UgaW1wbGVtZW50cyBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgfVxuXG4gIC8vIHBhZGRpbmc6XG4gIC8vIDAgPSB6ZXJvLXBhZFxuICAvLyAxID0gUEtDUzdcbiAgLy8gMiA9IHNwYWNlc1xuICAvLyA0ID0gbm8tcGFkXG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgYWxnID0gKGFsZ29yaXRobSBpbnN0YW5jZW9mIE9iamVjdCkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuICAgICAgbGV0IG1vZGUgPSAwLCBwYWRkaW5nID0gNDtcbiAgICAgIGxldCBpdjtcblxuICAgICAgaWYgKCBhbGcgIT0gZGVzS2V5LmFsZ29yaXRobS5uYW1lIClcbiAgICAgICAgcmVqZWN0KCBuZXcgRXJyb3IoICdLZXkgKCcgKyBkZXNLZXkuYWxnb3JpdGhtLm5hbWUgKyAnKSBjYW5ub3QgYmUgdXNlZCBmb3IgREVTIGRlY3J5cHQnKSApO1xuXG4gICAgICBpZiAoIGRlc0tleS5hbGdvcml0aG0ubmFtZSA9PSAnREVTLUNCQycgKSB7XG4gICAgICAgIGxldCBpdnggPSAoPEFsZ29yaXRobT5hbGdvcml0aG0pWydpdiddIHx8IFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdO1xuXG4gICAgICAgIGl2ID0gbmV3IEJ5dGVBcnJheSggaXZ4ICkuYmFja2luZ0FycmF5O1xuXG4gICAgICAgIG1vZGUgPSAxO1xuICAgICAgfVxuXG4gICAgICBpZiAoICggZGF0YS5sZW5ndGggPj0gOCApIHx8ICggcGFkZGluZyAhPSA0ICkgKVxuICAgICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDEsIG1vZGUsIGl2LCBwYWRkaW5nICkgKSApO1xuICAgICAgZWxzZVxuICAgICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCkgKTtcbiAgICB9KTtcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGFsZyA9IChhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QpID8gKDxBbGdvcml0aG0+YWxnb3JpdGhtKS5uYW1lIDogPHN0cmluZz5hbGdvcml0aG07XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcbiAgICAgIGxldCBtb2RlID0gMCwgcGFkZGluZyA9IDQ7XG4gICAgICBsZXQgaXY7XG5cbiAgICAgIGlmICggYWxnICE9IGRlc0tleS5hbGdvcml0aG0ubmFtZSApXG4gICAgICAgIHJlamVjdCggbmV3IEVycm9yKCAnS2V5ICgnICsgZGVzS2V5LmFsZ29yaXRobS5uYW1lICsgJykgY2Fubm90IGJlIHVzZWQgZm9yIERFUyBkZWNyeXB0JykgKTtcblxuICAgICAgaWYgKCBkZXNLZXkuYWxnb3JpdGhtLm5hbWUgPT0gJ0RFUy1DQkMnICkge1xuICAgICAgICBsZXQgaXZ4ID0gKDxBbGdvcml0aG0+YWxnb3JpdGhtKVsnaXYnXSB8fCBbIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAgXTtcblxuICAgICAgICBpdiA9IG5ldyBCeXRlQXJyYXkoIGl2eCApLmJhY2tpbmdBcnJheTtcblxuICAgICAgICBtb2RlID0gMTtcbiAgICAgIH1cblxuICAgICAgaWYgKCBkYXRhLmxlbmd0aCA+PSA4IClcbiAgICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAwLCBtb2RlLCBpdiwgcGFkZGluZyApICkgKTtcbiAgICAgIGVsc2VcbiAgICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSgpICk7XG4gICAgICAvL2NhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgaW1wb3J0S2V5KGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgaWYgKCAhKCBhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QgKSApXG4gICAgICBhbGdvcml0aG0gPSA8QWxnb3JpdGhtPnsgbmFtZTogPHN0cmluZz5hbGdvcml0aG0gfTtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBuZXcgREVTU2VjcmV0S2V5KCBrZXlEYXRhLCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKTtcblxuICAgICAgcmVzb2x2ZSggZGVzS2V5ICk7XG4gICB9KTtcbiAgfVxuXG4gIHNpZ24oIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcblxuICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAwLCAwICkgKSApO1xuICAgICAgLy9jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHN0YXRpYyBkZXNQQztcbiAgc3RhdGljIGRlc1NQO1xuXG4gIHByaXZhdGUgZGVzKCBrZXk6IFVpbnQ4QXJyYXksIG1lc3NhZ2U6IFVpbnQ4QXJyYXksIGVuY3J5cHQ6IG51bWJlciwgbW9kZTogbnVtYmVyLCBpdj86IFVpbnQ4QXJyYXksIHBhZGRpbmc/OiBudW1iZXIgKTogVWludDhBcnJheVxuICB7XG4gICAgLy9kZXNfY3JlYXRlS2V5c1xuICAgIC8vdGhpcyB0YWtlcyBhcyBpbnB1dCBhIDY0IGJpdCBrZXkgKGV2ZW4gdGhvdWdoIG9ubHkgNTYgYml0cyBhcmUgdXNlZClcbiAgICAvL2FzIGFuIGFycmF5IG9mIDIgaW50ZWdlcnMsIGFuZCByZXR1cm5zIDE2IDQ4IGJpdCBrZXlzXG4gICAgZnVuY3Rpb24gZGVzX2NyZWF0ZUtleXMgKGtleSlcbiAgICB7XG4gICAgICBsZXQgZGVzUEMgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNQQztcblxuICAgICAgaWYgKCAhZGVzUEMgKVxuICAgICAge1xuICAgICAgICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICAgICAgICBkZXNQQyA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1BDID0ge1xuICAgICAgICAgIHBjMmJ5dGVzMCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NCwweDIwMDAwMDAwLDB4MjAwMDAwMDQsMHgxMDAwMCwweDEwMDA0LDB4MjAwMTAwMDAsMHgyMDAxMDAwNCwweDIwMCwweDIwNCwweDIwMDAwMjAwLDB4MjAwMDAyMDQsMHgxMDIwMCwweDEwMjA0LDB4MjAwMTAyMDAsMHgyMDAxMDIwNCBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxLDB4MTAwMDAwLDB4MTAwMDAxLDB4NDAwMDAwMCwweDQwMDAwMDEsMHg0MTAwMDAwLDB4NDEwMDAwMSwweDEwMCwweDEwMSwweDEwMDEwMCwweDEwMDEwMSwweDQwMDAxMDAsMHg0MDAwMTAxLDB4NDEwMDEwMCwweDQxMDAxMDFdICksXG4gICAgICAgICAgcGMyYnl0ZXMyIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOCwwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMzIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMDAwMDAsMHg4MDAwMDAwLDB4ODIwMDAwMCwweDIwMDAsMHgyMDIwMDAsMHg4MDAyMDAwLDB4ODIwMjAwMCwweDIwMDAwLDB4MjIwMDAwLDB4ODAyMDAwMCwweDgyMjAwMDAsMHgyMjAwMCwweDIyMjAwMCwweDgwMjIwMDAsMHg4MjIyMDAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMHgxMDAwLDB4NDEwMDAsMHgxMDEwLDB4NDEwMTAsMHgxMDAwLDB4NDEwMDAsMHgxMDEwLDB4NDEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXM1IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAsMHgyMCwweDQyMCwwLDB4NDAwLDB4MjAsMHg0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMF0gKSxcbiAgICAgICAgICBwYzJieXRlczYgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDIsMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDJdICksXG4gICAgICAgICAgcGMyYnl0ZXM3IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMCwweDgwMCwweDEwODAwLDB4MjAwMDAwMDAsMHgyMDAxMDAwMCwweDIwMDAwODAwLDB4MjAwMTA4MDAsMHgyMDAwMCwweDMwMDAwLDB4MjA4MDAsMHgzMDgwMCwweDIwMDIwMDAwLDB4MjAwMzAwMDAsMHgyMDAyMDgwMCwweDIwMDMwODAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwMDAsMCwweDQwMDAwLDB4MiwweDQwMDAyLDB4MiwweDQwMDAyLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDIsMHgyMDQwMDAyLDB4MjAwMDAwMiwweDIwNDAwMDJdICksXG4gICAgICAgICAgcGMyYnl0ZXM5IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOF0gKSxcbiAgICAgICAgICBwYzJieXRlczEwOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDIwLDAsMHgyMCwweDEwMDAwMCwweDEwMDAyMCwweDEwMDAwMCwweDEwMDAyMCwweDIwMDAsMHgyMDIwLDB4MjAwMCwweDIwMjAsMHgxMDIwMDAsMHgxMDIwMjAsMHgxMDIwMDAsMHgxMDIwMjBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMTogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwLDB4MjAwLDB4MTAwMDIwMCwweDIwMDAwMCwweDEyMDAwMDAsMHgyMDAyMDAsMHgxMjAwMjAwLDB4NDAwMDAwMCwweDUwMDAwMDAsMHg0MDAwMjAwLDB4NTAwMDIwMCwweDQyMDAwMDAsMHg1MjAwMDAwLDB4NDIwMDIwMCwweDUyMDAyMDBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMjogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwLDB4ODAwMDAwMCwweDgwMDEwMDAsMHg4MDAwMCwweDgxMDAwLDB4ODA4MDAwMCwweDgwODEwMDAsMHgxMCwweDEwMTAsMHg4MDAwMDEwLDB4ODAwMTAxMCwweDgwMDEwLDB4ODEwMTAsMHg4MDgwMDEwLDB4ODA4MTAxMF0gKSxcbiAgICAgICAgICBwYzJieXRlczEzOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgxMDAsMHgxMDQsMCwweDQsMHgxMDAsMHgxMDQsMHgxLDB4NSwweDEwMSwweDEwNSwweDEsMHg1LDB4MTAxLDB4MTA1XSApXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIC8vaG93IG1hbnkgaXRlcmF0aW9ucyAoMSBmb3IgZGVzLCAzIGZvciB0cmlwbGUgZGVzKVxuICAgICAgdmFyIGl0ZXJhdGlvbnMgPSBrZXkubGVuZ3RoID4gOCA/IDMgOiAxOyAvL2NoYW5nZWQgYnkgUGF1bCAxNi82LzIwMDcgdG8gdXNlIFRyaXBsZSBERVMgZm9yIDkrIGJ5dGUga2V5c1xuICAgICAgLy9zdG9yZXMgdGhlIHJldHVybiBrZXlzXG4gICAgICB2YXIga2V5cyA9IG5ldyBVaW50MzJBcnJheSgzMiAqIGl0ZXJhdGlvbnMpO1xuICAgICAgLy9ub3cgZGVmaW5lIHRoZSBsZWZ0IHNoaWZ0cyB3aGljaCBuZWVkIHRvIGJlIGRvbmVcbiAgICAgIHZhciBzaGlmdHMgPSBbIDAsIDAsIDEsIDEsIDEsIDEsIDEsIDEsIDAsIDEsIDEsIDEsIDEsIDEsIDEsIDAgXTtcbiAgICAgIC8vb3RoZXIgdmFyaWFibGVzXG4gICAgICB2YXIgbGVmdHRlbXAsIHJpZ2h0dGVtcCwgbT0wLCBuPTAsIHRlbXA7XG5cbiAgICAgIGZvciAodmFyIGo9MDsgajxpdGVyYXRpb25zOyBqKyspXG4gICAgICB7IC8vZWl0aGVyIDEgb3IgMyBpdGVyYXRpb25zXG4gICAgICAgIGxlZnQgPSAgKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcbiAgICAgICAgcmlnaHQgPSAoa2V5W20rK10gPDwgMjQpIHwgKGtleVttKytdIDw8IDE2KSB8IChrZXlbbSsrXSA8PCA4KSB8IGtleVttKytdO1xuXG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMikgXiByaWdodCkgJiAweDMzMzMzMzMzOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICAgIC8vdGhlIHJpZ2h0IHNpZGUgbmVlZHMgdG8gYmUgc2hpZnRlZCBhbmQgdG8gZ2V0IHRoZSBsYXN0IGZvdXIgYml0cyBvZiB0aGUgbGVmdCBzaWRlXG4gICAgICAgIHRlbXAgPSAobGVmdCA8PCA4KSB8ICgocmlnaHQgPj4+IDIwKSAmIDB4MDAwMDAwZjApO1xuICAgICAgICAvL2xlZnQgbmVlZHMgdG8gYmUgcHV0IHVwc2lkZSBkb3duXG4gICAgICAgIGxlZnQgPSAocmlnaHQgPDwgMjQpIHwgKChyaWdodCA8PCA4KSAmIDB4ZmYwMDAwKSB8ICgocmlnaHQgPj4+IDgpICYgMHhmZjAwKSB8ICgocmlnaHQgPj4+IDI0KSAmIDB4ZjApO1xuICAgICAgICByaWdodCA9IHRlbXA7XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGVzZSBzaGlmdHMgb24gdGhlIGxlZnQgYW5kIHJpZ2h0IGtleXNcbiAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgc2hpZnRzLmxlbmd0aDsgaSsrKVxuICAgICAgICB7XG4gICAgICAgICAgLy9zaGlmdCB0aGUga2V5cyBlaXRoZXIgb25lIG9yIHR3byBiaXRzIHRvIHRoZSBsZWZ0XG4gICAgICAgICAgaWYgKHNoaWZ0c1tpXSlcbiAgICAgICAgICB7XG4gICAgICAgICAgICBsZWZ0ID0gKGxlZnQgPDwgMikgfCAobGVmdCA+Pj4gMjYpOyByaWdodCA9IChyaWdodCA8PCAyKSB8IChyaWdodCA+Pj4gMjYpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBlbHNlXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDI3KTsgcmlnaHQgPSAocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDI3KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgbGVmdCAmPSAtMHhmOyByaWdodCAmPSAtMHhmO1xuXG4gICAgICAgICAgLy9ub3cgYXBwbHkgUEMtMiwgaW4gc3VjaCBhIHdheSB0aGF0IEUgaXMgZWFzaWVyIHdoZW4gZW5jcnlwdGluZyBvciBkZWNyeXB0aW5nXG4gICAgICAgICAgLy90aGlzIGNvbnZlcnNpb24gd2lsbCBsb29rIGxpa2UgUEMtMiBleGNlcHQgb25seSB0aGUgbGFzdCA2IGJpdHMgb2YgZWFjaCBieXRlIGFyZSB1c2VkXG4gICAgICAgICAgLy9yYXRoZXIgdGhhbiA0OCBjb25zZWN1dGl2ZSBiaXRzIGFuZCB0aGUgb3JkZXIgb2YgbGluZXMgd2lsbCBiZSBhY2NvcmRpbmcgdG9cbiAgICAgICAgICAvL2hvdyB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zIHdpbGwgYmUgYXBwbGllZDogUzIsIFM0LCBTNiwgUzgsIFMxLCBTMywgUzUsIFM3XG4gICAgICAgICAgbGVmdHRlbXAgPSBkZXNQQy5wYzJieXRlczBbbGVmdCA+Pj4gMjhdIHwgZGVzUEMucGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczJbKGxlZnQgPj4+IDIwKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczNbKGxlZnQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzNFsobGVmdCA+Pj4gMTIpICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzNVsobGVmdCA+Pj4gOCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczZbKGxlZnQgPj4+IDQpICYgMHhmXTtcbiAgICAgICAgICByaWdodHRlbXAgPSBkZXNQQy5wYzJieXRlczdbcmlnaHQgPj4+IDI4XSB8IGRlc1BDLnBjMmJ5dGVzOFsocmlnaHQgPj4+IDI0KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczlbKHJpZ2h0ID4+PiAyMCkgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczExWyhyaWdodCA+Pj4gMTIpICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzMTJbKHJpZ2h0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczEzWyhyaWdodCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjtcbiAgICAgICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICAgICAgfVxuICAgICAgfSAvL2ZvciBlYWNoIGl0ZXJhdGlvbnNcblxuICAgICAgcmV0dXJuIGtleXM7XG4gICAgfSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG4gICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICBsZXQgZGVzU1AgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNTUDtcblxuICAgIGlmICggZGVzU1AgPT0gdW5kZWZpbmVkIClcbiAgICB7XG4gICAgICBkZXNTUCA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1NQID0ge1xuICAgICAgICBzcGZ1bmN0aW9uMTogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDEwNDAwLDAsMHgxMDAwMCwweDEwMTA0MDQsMHgxMDEwMDA0LDB4MTA0MDQsMHg0LDB4MTAwMDAsMHg0MDAsMHgxMDEwNDAwLDB4MTAxMDQwNCwweDQwMCwweDEwMDA0MDQsMHgxMDEwMDA0LDB4MTAwMDAwMCwweDQsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwweDEwNDAwLDB4MTA0MDAsMHgxMDEwMDAwLDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwNCwweDEwMDAwMDQsMHgxMDAwMDA0LDB4MTAwMDQsMCwweDQwNCwweDEwNDA0LDB4MTAwMDAwMCwweDEwMDAwLDB4MTAxMDQwNCwweDQsMHgxMDEwMDAwLDB4MTAxMDQwMCwweDEwMDAwMDAsMHgxMDAwMDAwLDB4NDAwLDB4MTAxMDAwNCwweDEwMDAwLDB4MTA0MDAsMHgxMDAwMDA0LDB4NDAwLDB4NCwweDEwMDA0MDQsMHgxMDQwNCwweDEwMTA0MDQsMHgxMDAwNCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDAwNCwweDQwNCwweDEwNDA0LDB4MTAxMDQwMCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDAsMHgxMDAwNCwweDEwNDAwLDAsMHgxMDEwMDA0XSApLFxuICAgICAgICBzcGZ1bmN0aW9uMjogbmV3IFVpbnQzMkFycmF5KCBbLTB4N2ZlZjdmZTAsLTB4N2ZmZjgwMDAsMHg4MDAwLDB4MTA4MDIwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsLTB4N2ZlZjdmZTAsLTB4N2ZlZjgwMDAsLTB4ODAwMDAwMDAsLTB4N2ZmZjgwMDAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwweDEwODAwMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwwLC0weDgwMDAwMDAwLDB4ODAwMCwweDEwODAyMCwtMHg3ZmYwMDAwMCwweDEwMDAyMCwtMHg3ZmZmZmZlMCwwLDB4MTA4MDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwtMHg3ZmYwMDAwMCwweDgwMjAsMCwweDEwODAyMCwtMHg3ZmVmZmZlMCwweDEwMDAwMCwtMHg3ZmZmN2ZlMCwtMHg3ZmYwMDAwMCwtMHg3ZmVmODAwMCwweDgwMDAsLTB4N2ZmMDAwMDAsLTB4N2ZmZjgwMDAsMHgyMCwtMHg3ZmVmN2ZlMCwweDEwODAyMCwweDIwLDB4ODAwMCwtMHg4MDAwMDAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsMHgxMDAwMDAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsMHgxMDgwMDAsMCwtMHg3ZmZmODAwMCwweDgwMjAsLTB4ODAwMDAwMDAsLTB4N2ZlZmZmZTAsLTB4N2ZlZjdmZTAsMHgxMDgwMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb24zOiBuZXcgVWludDMyQXJyYXkoIFsweDIwOCwweDgwMjAyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjAwLDAsMHgyMDIwOCwweDgwMDAyMDAsMHgyMDAwOCwweDgwMDAwMDgsMHg4MDAwMDA4LDB4MjAwMDAsMHg4MDIwMjA4LDB4MjAwMDgsMHg4MDIwMDAwLDB4MjA4LDB4ODAwMDAwMCwweDgsMHg4MDIwMjAwLDB4MjAwLDB4MjAyMDAsMHg4MDIwMDAwLDB4ODAyMDAwOCwweDIwMjA4LDB4ODAwMDIwOCwweDIwMjAwLDB4MjAwMDAsMHg4MDAwMjA4LDB4OCwweDgwMjAyMDgsMHgyMDAsMHg4MDAwMDAwLDB4ODAyMDIwMCwweDgwMDAwMDAsMHgyMDAwOCwweDIwOCwweDIwMDAwLDB4ODAyMDIwMCwweDgwMDAyMDAsMCwweDIwMCwweDIwMDA4LDB4ODAyMDIwOCwweDgwMDAyMDAsMHg4MDAwMDA4LDB4MjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwOCwweDIwMDAwLDB4ODAwMDAwMCwweDgwMjAyMDgsMHg4LDB4MjAyMDgsMHgyMDIwMCwweDgwMDAwMDgsMHg4MDIwMDAwLDB4ODAwMDIwOCwweDIwOCwweDgwMjAwMDAsMHgyMDIwOCwweDgsMHg4MDIwMDA4LDB4MjAyMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb240OiBuZXcgVWludDMyQXJyYXkoIFsweDgwMjAwMSwweDIwODEsMHgyMDgxLDB4ODAsMHg4MDIwODAsMHg4MDAwODEsMHg4MDAwMDEsMHgyMDAxLDAsMHg4MDIwMDAsMHg4MDIwMDAsMHg4MDIwODEsMHg4MSwwLDB4ODAwMDgwLDB4ODAwMDAxLDB4MSwweDIwMDAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDEsMHgyMDgwLDB4ODAwMDgxLDB4MSwweDIwODAsMHg4MDAwODAsMHgyMDAwLDB4ODAyMDgwLDB4ODAyMDgxLDB4ODEsMHg4MDAwODAsMHg4MDAwMDEsMHg4MDIwMDAsMHg4MDIwODEsMHg4MSwwLDAsMHg4MDIwMDAsMHgyMDgwLDB4ODAwMDgwLDB4ODAwMDgxLDB4MSwweDgwMjAwMSwweDIwODEsMHgyMDgxLDB4ODAsMHg4MDIwODEsMHg4MSwweDEsMHgyMDAwLDB4ODAwMDAxLDB4MjAwMSwweDgwMjA4MCwweDgwMDA4MSwweDIwMDEsMHgyMDgwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAwLDB4ODAyMDgwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNTogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAsMHgyMDgwMTAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4ODAwMDAsMHgxMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MDA4MDEwMCwweDgwMDAwLDB4MjAwMDEwMCwweDQwMDgwMTAwLDB4NDIwMDAxMDAsMHg0MjA4MDAwMCwweDgwMTAwLDB4NDAwMDAwMDAsMHgyMDAwMDAwLDB4NDAwODAwMDAsMHg0MDA4MDAwMCwwLDB4NDAwMDAxMDAsMHg0MjA4MDEwMCwweDQyMDgwMTAwLDB4MjAwMDEwMCwweDQyMDgwMDAwLDB4NDAwMDAxMDAsMCwweDQyMDAwMDAwLDB4MjA4MDEwMCwweDIwMDAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4ODAwMDAsMHg0MjAwMDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDQwMDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMDAwLDB4NDIwODAwMDAsMHgyMDgwMTAwLDB4NDAwODAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDIwODAwMDAsMHg0MjA4MDEwMCwweDgwMTAwLDB4NDIwMDAwMDAsMHg0MjA4MDEwMCwweDIwODAwMDAsMCwweDQwMDgwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDEwMCwweDgwMDAwLDAsMHg0MDA4MDAwMCwweDIwODAxMDAsMHg0MDAwMDEwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjY6IG5ldyBVaW50MzJBcnJheSggWzB4MjAwMDAwMTAsMHgyMDQwMDAwMCwweDQwMDAsMHgyMDQwNDAxMCwweDIwNDAwMDAwLDB4MTAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4NDA0MDEwLDB4NDAwMDAwLDB4MjAwMDAwMTAsMHg0MDAwMTAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMHg0MDAwLDB4NDA0MDAwLDB4MjAwMDQwMTAsMHgxMCwweDIwNDAwMDEwLDB4MjA0MDAwMTAsMCwweDQwNDAxMCwweDIwNDA0MDAwLDB4NDAxMCwweDQwNDAwMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHgyMDAwNDAwMCwweDEwLDB4MjA0MDAwMTAsMHg0MDQwMDAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHgyMDQwNDAxMCwweDQwNDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMCwweDIwNDAwMDEwLDB4MTAsMHg0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHg0MDAwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjc6IG5ldyBVaW50MzJBcnJheSggWzB4MjAwMDAwLDB4NDIwMDAwMiwweDQwMDA4MDIsMCwweDgwMCwweDQwMDA4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4NDIwMDgwMiwweDIwMDAwMCwwLDB4NDAwMDAwMiwweDIsMHg0MDAwMDAwLDB4NDIwMDAwMiwweDgwMiwweDQwMDA4MDAsMHgyMDA4MDIsMHgyMDAwMDIsMHg0MDAwODAwLDB4NDAwMDAwMiwweDQyMDAwMDAsMHg0MjAwODAwLDB4MjAwMDAyLDB4NDIwMDAwMCwweDgwMCwweDgwMiwweDQyMDA4MDIsMHgyMDA4MDAsMHgyLDB4NDAwMDAwMCwweDIwMDgwMCwweDQwMDAwMDAsMHgyMDA4MDAsMHgyMDAwMDAsMHg0MDAwODAyLDB4NDAwMDgwMiwweDQyMDAwMDIsMHg0MjAwMDAyLDB4MiwweDIwMDAwMiwweDQwMDAwMDAsMHg0MDAwODAwLDB4MjAwMDAwLDB4NDIwMDgwMCwweDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg4MDIsMHg0MDAwMDAyLDB4NDIwMDgwMiwweDQyMDAwMDAsMHgyMDA4MDAsMCwweDIsMHg0MjAwODAyLDAsMHgyMDA4MDIsMHg0MjAwMDAwLDB4ODAwLDB4NDAwMDAwMiwweDQwMDA4MDAsMHg4MDAsMHgyMDAwMDJdICksXG4gICAgICAgIHNwZnVuY3Rpb244OiBuZXcgVWludDMyQXJyYXkoIFsweDEwMDAxMDQwLDB4MTAwMCwweDQwMDAwLDB4MTAwNDEwNDAsMHgxMDAwMDAwMCwweDEwMDAxMDQwLDB4NDAsMHgxMDAwMDAwMCwweDQwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4MTAwNDEwMDAsMHg0MTA0MCwweDEwMDAsMHg0MCwweDEwMDQwMDAwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDEwNDAsMHg0MTAwMCwweDQwMDQwLDB4MTAwNDAwNDAsMHgxMDA0MTAwMCwweDEwNDAsMCwwLDB4MTAwNDAwNDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4NDEwNDAsMHg0MDAwMCwweDQxMDQwLDB4NDAwMDAsMHgxMDA0MTAwMCwweDEwMDAsMHg0MCwweDEwMDQwMDQwLDB4MTAwMCwweDQxMDQwLDB4MTAwMDEwMDAsMHg0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MDA0MCwweDEwMDAwMDAwLDB4NDAwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MDA0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDAwMTAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4NDEwMDAsMHgxMDQwLDB4MTA0MCwweDQwMDQwLDB4MTAwMDAwMDAsMHgxMDA0MTAwMF0gKSxcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy9jcmVhdGUgdGhlIDE2IG9yIDQ4IHN1YmtleXMgd2Ugd2lsbCBuZWVkXG4gICAgdmFyIGtleXMgPSBkZXNfY3JlYXRlS2V5cygga2V5ICk7XG5cbiAgICB2YXIgbT0wLCBpLCBqLCB0ZW1wLCBsZWZ0LCByaWdodCwgbG9vcGluZztcbiAgICB2YXIgY2JjbGVmdCwgY2JjbGVmdDIsIGNiY3JpZ2h0LCBjYmNyaWdodDJcbiAgICB2YXIgbGVuID0gbWVzc2FnZS5sZW5ndGg7XG5cbiAgICAvL3NldCB1cCB0aGUgbG9vcHMgZm9yIHNpbmdsZSBhbmQgdHJpcGxlIGRlc1xuICAgIHZhciBpdGVyYXRpb25zID0ga2V5cy5sZW5ndGggPT0gMzIgPyAzIDogOTsgLy9zaW5nbGUgb3IgdHJpcGxlIGRlc1xuXG4gICAgaWYgKGl0ZXJhdGlvbnMgPT0gMylcbiAgICB7XG4gICAgICBsb29waW5nID0gZW5jcnlwdCA/IFsgMCwgMzIsIDIgXSA6IFsgMzAsIC0yLCAtMiBdO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyLCA2MiwgMzAsIC0yLCA2NCwgOTYsIDIgXSA6IFsgOTQsIDYyLCAtMiwgMzIsIDY0LCAyLCAzMCwgLTIsIC0yIF07XG4gICAgfVxuXG4gICAgLy8gcGFkIHRoZSBtZXNzYWdlIGRlcGVuZGluZyBvbiB0aGUgcGFkZGluZyBwYXJhbWV0ZXJcbiAgICBpZiAoICggcGFkZGluZyAhPSB1bmRlZmluZWQgKSAmJiAoIHBhZGRpbmcgIT0gNCApIClcbiAgICB7XG4gICAgICB2YXIgdW5wYWRkZWRNZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgIHZhciBwYWQgPSA4LShsZW4lOCk7XG5cbiAgICAgIG1lc3NhZ2UgPSBuZXcgVWludDhBcnJheSggbGVuICsgOCApO1xuICAgICAgbWVzc2FnZS5zZXQoIHVucGFkZGVkTWVzc2FnZSwgMCApO1xuXG4gICAgICBzd2l0Y2goIHBhZGRpbmcgKVxuICAgICAge1xuICAgICAgICBjYXNlIDA6IC8vIHplcm8tcGFkXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAgXSApLCBsZW4gKTtcbiAgICAgICAgICBicmVhaztcblxuICAgICAgICBjYXNlIDE6IC8vIFBLQ1M3IHBhZGRpbmdcbiAgICAgICAge1xuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZF0gKSwgOCApO1xuXG4gICAgICAgICAgaWYgKCBwYWQ9PTggKVxuICAgICAgICAgICAgbGVuKz04O1xuXG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cblxuICAgICAgICBjYXNlIDI6ICAvLyBwYWQgdGhlIG1lc3NhZ2Ugd2l0aCBzcGFjZXNcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCBdICksIDggKTtcbiAgICAgICAgICBicmVhaztcblxuICAgICAgfVxuXG4gICAgICBsZW4gKz0gOC0obGVuJTgpXG4gICAgfVxuXG4gICAgLy8gc3RvcmUgdGhlIHJlc3VsdCBoZXJlXG4gICAgdmFyIHJlc3VsdCA9IG5ldyBVaW50OEFycmF5KCBsZW4gKTtcblxuICAgIGlmIChtb2RlID09IDEpXG4gICAgeyAvL0NCQyBtb2RlXG4gICAgICBsZXQgbW0gPSAwO1xuXG4gICAgICBjYmNsZWZ0ID0gIChpdlttbSsrXSA8PCAyNCkgfCAoaXZbbW0rK10gPDwgMTYpIHwgKGl2W21tKytdIDw8IDgpIHwgaXZbbW0rK107XG4gICAgICBjYmNyaWdodCA9IChpdlttbSsrXSA8PCAyNCkgfCAoaXZbbW0rK10gPDwgMTYpIHwgKGl2W21tKytdIDw8IDgpIHwgaXZbbW0rK107XG4gICAgfVxuXG4gICAgdmFyIHJtID0gMDtcblxuICAgIC8vbG9vcCB0aHJvdWdoIGVhY2ggNjQgYml0IGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgd2hpbGUgKG0gPCBsZW4pXG4gICAge1xuICAgICAgbGVmdCA9ICAobWVzc2FnZVttKytdIDw8IDI0KSB8IChtZXNzYWdlW20rK10gPDwgMTYpIHwgKG1lc3NhZ2VbbSsrXSA8PCA4KSB8IG1lc3NhZ2VbbSsrXTtcbiAgICAgIHJpZ2h0ID0gKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG5cbiAgICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgICBpZiAobW9kZSA9PSAxKVxuICAgICAge1xuICAgICAgICBpZiAoZW5jcnlwdClcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDsgcmlnaHQgXj0gY2JjcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICB7XG4gICAgICAgICAgY2JjbGVmdDIgPSBjYmNsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0MiA9IGNiY3JpZ2h0O1xuICAgICAgICAgIGNiY2xlZnQgPSBsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0ID0gcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy9maXJzdCBlYWNoIDY0IGJ1dCBjaHVuayBvZiB0aGUgbWVzc2FnZSBtdXN0IGJlIHBlcm11dGVkIGFjY29yZGluZyB0byBJUFxuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMTYpIF4gcmlnaHQpICYgMHgwMDAwZmZmZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxNik7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gMikgXiBsZWZ0KSAmIDB4MzMzMzMzMzM7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgMik7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAgIGxlZnQgPSAoKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMzEpKTtcbiAgICAgIHJpZ2h0ID0gKChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMzEpKTtcblxuICAgICAgLy9kbyB0aGlzIGVpdGhlciAxIG9yIDMgdGltZXMgZm9yIGVhY2ggY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICAgIGZvciAoaj0wOyBqPGl0ZXJhdGlvbnM7IGorPTMpXG4gICAgICB7XG4gICAgICAgIHZhciBlbmRsb29wID0gbG9vcGluZ1tqKzFdO1xuICAgICAgICB2YXIgbG9vcGluYyA9IGxvb3BpbmdbaisyXTtcblxuICAgICAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZSBlbmNyeXB0aW9uIG9yIGRlY3J5cHRpb25cbiAgICAgICAgZm9yIChpPWxvb3Bpbmdbal07IGkhPWVuZGxvb3A7IGkrPWxvb3BpbmMpXG4gICAgICAgIHsgLy9mb3IgZWZmaWNpZW5jeVxuICAgICAgICAgIHZhciByaWdodDEgPSByaWdodCBeIGtleXNbaV07XG4gICAgICAgICAgdmFyIHJpZ2h0MiA9ICgocmlnaHQgPj4+IDQpIHwgKHJpZ2h0IDw8IDI4KSkgXiBrZXlzW2krMV07XG5cbiAgICAgICAgICAvL3RoZSByZXN1bHQgaXMgYXR0YWluZWQgYnkgcGFzc2luZyB0aGVzZSBieXRlcyB0aHJvdWdoIHRoZSBTIHNlbGVjdGlvbiBmdW5jdGlvbnNcbiAgICAgICAgICB0ZW1wID0gbGVmdDtcbiAgICAgICAgICBsZWZ0ID0gcmlnaHQ7XG4gICAgICAgICAgcmlnaHQgPSB0ZW1wIF4gKGRlc1NQLnNwZnVuY3Rpb24yWyhyaWdodDEgPj4+IDI0KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjRbKHJpZ2h0MSA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgZGVzU1Auc3BmdW5jdGlvbjZbKHJpZ2h0MSA+Pj4gIDgpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uOFtyaWdodDEgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBkZXNTUC5zcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb24zWyhyaWdodDIgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IGRlc1NQLnNwZnVuY3Rpb241WyhyaWdodDIgPj4+ICA4KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjdbcmlnaHQyICYgMHgzZl0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdGVtcCA9IGxlZnQ7IGxlZnQgPSByaWdodDsgcmlnaHQgPSB0ZW1wOyAvL3VucmV2ZXJzZSBsZWZ0IGFuZCByaWdodFxuICAgICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgICAgbGVmdCA9ICgobGVmdCA+Pj4gMSkgfCAobGVmdCA8PCAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpO1xuXG4gICAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDI7XG4gICAgICAgICAgcmlnaHQgXj0gY2JjcmlnaHQyO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc3VsdC5zZXQoIG5ldyBVaW50OEFycmF5ICggWyAobGVmdD4+PjI0KSAmIDB4ZmYsIChsZWZ0Pj4+MTYpICYgMHhmZiwgKGxlZnQ+Pj44KSAmIDB4ZmYsIChsZWZ0KSAmIDB4ZmYsIChyaWdodD4+PjI0KSAmIDB4ZmYsIChyaWdodD4+PjE2KSAmIDB4ZmYsIChyaWdodD4+PjgpICYgMHhmZiwgKHJpZ2h0KSAmIDB4ZmYgXSApLCBybSApO1xuXG4gICAgICBybSArPSA4O1xuICAgIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9IC8vZW5kIG9mIGRlc1xuXG59XG5cbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnREVTLUVDQicsXG4gIERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLFxuICBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ERUNSWVBUIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdERVMtQ0JDJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQsICBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLlNJR04sIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uVkVSSUZZIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlcktleVNlcnZpY2UoICdERVMtRUNCJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5JTVBPUlRfS0VZIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlcktleVNlcnZpY2UoICdERVMtQ0JDJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5JTVBPUlRfS0VZIF0gKTtcbiIsbnVsbCwiaW1wb3J0IHsgQ29udGFpbmVyLCBhdXRvaW5qZWN0IGFzIGluamVjdCB9IGZyb20gJ2F1cmVsaWEtZGVwZW5kZW5jeS1pbmplY3Rpb24nO1xuaW1wb3J0IHsgbWV0YWRhdGEgfSBmcm9tICdhdXJlbGlhLW1ldGFkYXRhJztcblxuZXhwb3J0IHsgQ29udGFpbmVyLCBpbmplY3QgfTtcbmV4cG9ydCBpbnRlcmZhY2UgSW5qZWN0YWJsZSB7XG4gIG5ldyggLi4uYXJncyApOiBPYmplY3Q7XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgY2xhc3MgRW51bSB7XG59XG5cbmV4cG9ydCBjbGFzcyBJbnRlZ2VyIGV4dGVuZHMgTnVtYmVyIHtcbn1cblxuLyoqXG4gKiBTZXQgb2YgZGF0YSB0eXBlcyB0aGF0IGFyZSB2YWxpZCBhcyBLaW5kIGZpZWxkc1xuICogaW5jbHVkZXMgRmllbGRUeXBlQXJyYXkga2x1ZGdlIHJlcXVpcmVkIGZvciBUUyB0byBwYXJzZSByZWN1cnNpdmVcbiAqIHR5cGUgZGVmaW5pdGlvbnNcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkQXJyYXkgZXh0ZW5kcyBBcnJheTxGaWVsZFR5cGU+IHt9XG5leHBvcnQgdHlwZSBGaWVsZFR5cGUgPSBTdHJpbmcgfCBOdW1iZXIgfCBJbnRlZ2VyIHwgRW51bSB8IEJ5dGVBcnJheSB8IEtpbmQgfCBGaWVsZEFycmF5O1xuXG5leHBvcnQgY2xhc3MgRmllbGRBcnJheSBpbXBsZW1lbnRzIEZpZWxkQXJyYXkge31cblxuZXhwb3J0IHZhciBGaWVsZFR5cGVzID0ge1xuICBCb29sZWFuOiBCb29sZWFuLFxuXG4gIE51bWJlcjogTnVtYmVyLFxuXG4gIEludGVnZXI6IEludGVnZXIsXG5cbiAgQnl0ZUFycmF5OiBCeXRlQXJyYXksXG5cbiAgRW51bTogRW51bSxcblxuICBBcnJheTogRmllbGRBcnJheSxcblxuICBTdHJpbmc6IFN0cmluZyxcblxuICBLaW5kOiBLaW5kXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRPcHRpb25zIHtcbiAgLyoqXG4gICogbWluaW11bSBsZW5ndGggZm9yIFN0cmluZywgbWluaW11bSB2YWx1ZSBmb3IgTnVtYmVyL0ludGVnZXJcbiAgKi9cbiAgbWluaW11bT86IG51bWJlcjtcblxuICAvKipcbiAgKiBtYXhpbXVtIGxlbmd0aCBmb3IgU3RyaW5nLCBtYXhpbXVtIHZhbHVlIGZvciBOdW1iZXIvSW50ZWdlclxuICAqL1xuICBtYXhpbXVtPzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIGRlZmF1bHQgdmFsdWUgZHVyaW5nIGluaXRpYWxpemF0aW9uXG4gICovXG4gIFwiZGVmYXVsdFwiPzogYW55O1xuXG4gIC8qKlxuICAqIGRvZXMgbm90IGV4aXN0IGFzIGFuIG93blByb3BlcnR5XG4gICovXG4gIGNhbGN1bGF0ZWQ/OiBib29sZWFuO1xuXG4gIC8qKlxuICAqIHN1Yi1raW5kLCB3aGVuIGZpZWxkIGlzIHR5cGUgS2luZFxuICAqL1xuICBraW5kPzogS2luZDtcblxuICAvKipcbiAgKiBzdWItZmllbGQgaW5mbywgd2hlbiBmaWVsZCBpcyB0eXBlIEZpZWxkQXJyYXlcbiAgKi9cbiAgYXJyYXlJbmZvPzogRmllbGRJbmZvO1xuXG4gIC8qKlxuICAqIGluZGV4L3ZhbHVlIG1hcCwgd2hlbiBmaWVsZCBpZiB0eXBlIEVudW1cbiAgKi9cbiAgZW51bU1hcD86IE1hcDxudW1iZXIsIHN0cmluZz47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRJbmZvIGV4dGVuZHMgRmllbGRPcHRpb25zIHtcbiAgLyoqXG4gICogRGVzY3JpcHRpb24gZm9yIGZpZWxkXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogVHlwZSBvZiBmaWVsZCwgb25lIG9mIEZpZWxkVHlwZXNcbiAgKi9cbiAgZmllbGRUeXBlOiBGaWVsZFR5cGU7XG59XG5cblxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgS2luZC4gQ29udGFpbnMgbmFtZSwgZGVzY3JpcHRpb24gYW5kIGEgbWFwIG9mXG4qIHByb3BlcnR5LWRlc2NyaXB0b3JzIHRoYXQgZGVzY3JpYmUgdGhlIHNlcmlhbGl6YWJsZSBmaWVsZHMgb2ZcbiogYW4gb2JqZWN0IG9mIHRoYXQgS2luZC5cbiovXG5leHBvcnQgY2xhc3MgS2luZEluZm9cbntcbiAgbmFtZTogc3RyaW5nO1xuXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgZmllbGRzOiB7IFtpZDogc3RyaW5nXTogRmllbGRJbmZvIH0gPSB7fTtcbn1cblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdLaW5kJyBtZXRhZGF0YVxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kQnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IEtpbmRDb25zdHJ1Y3RvcjtcblxuICBjb25zdHJ1Y3RvciggY3RvcjogS2luZENvbnN0cnVjdG9yLCBkZXNjcmlwdGlvbjogc3RyaW5nICkge1xuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmtpbmRJbmZvID0ge1xuICAgICAgbmFtZTogY3Rvci5uYW1lLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZmllbGRzOiB7fVxuICAgIH1cbiAgfVxuXG5cbiAgcHJpdmF0ZSBraW5kSW5mbzogS2luZEluZm87XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IEtpbmRCdWlsZGVyKCBjdG9yLCBkZXNjcmlwdGlvbiApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgZmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZmllbGRUeXBlOiBGaWVsZFR5cGUsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyXG4gIHtcbiAgICBsZXQgZmllbGQ6IEZpZWxkSW5mbyA9IDxGaWVsZEluZm8+b3B0cztcblxuICAgIGZpZWxkLmRlc2NyaXB0aW9uID0gZGVzY3JpcHRpb247XG4gICAgZmllbGQuZmllbGRUeXBlID0gZmllbGRUeXBlO1xuXG4gICAgdGhpcy5jdG9yLmtpbmRJbmZvLmZpZWxkc1sgbmFtZSBdID0gZmllbGQ7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBib29sRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgQm9vbGVhbiwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIG51bWJlckZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIE51bWJlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGludGVnZXJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgdWludDMyRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMubWluaW11bSA9IG9wdHMubWluaW11bSB8fCAwO1xuICAgIG9wdHMubWF4aW11bSA9IG9wdHMubWF4aW11bSB8fCAweEZGRkZGRkZGO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgYnl0ZUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLm1pbmltdW0gPSBvcHRzLm1pbmltdW0gfHwgMDtcbiAgICBvcHRzLm1heGltdW0gPSBvcHRzLm1heGltdW0gfHwgMjU1O1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgc3RyaW5nRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgU3RyaW5nLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMga2luZEZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGtpbmQ6IEtpbmQsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLmtpbmQgPSBraW5kO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBLaW5kLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgZW51bUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGVudW1tOiB7IFsgaWR4OiBudW1iZXIgXTogc3RyaW5nIH0sIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcblxuICAgIG9wdHMuZW51bU1hcCA9IG5ldyBNYXA8bnVtYmVyLHN0cmluZz4oICk7XG5cbiAgICBmb3IoIGxldCBpZHggaW4gZW51bW0gKSB7XG4gICAgICBpZiAoIDEgKiBpZHggPT0gaWR4IClcbiAgICAgICAgb3B0cy5lbnVtTWFwLnNldCggaWR4LCBlbnVtbVsgaWR4IF0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEVudW0sIG9wdHMgKTtcbiAgfVxufVxuXG4vKiAgbWFrZUtpbmQoIGtpbmRDb25zdHJ1Y3Rvciwga2luZE9wdGlvbnMgKVxuICB7XG4gICAgdmFyICRraW5kSW5mbyA9IGtpbmRPcHRpb25zLmtpbmRJbmZvO1xuXG4gICAga2luZENvbnN0cnVjdG9yLiRraW5kTmFtZSA9ICRraW5kSW5mby50aXRsZTtcblxuICAgIHZhciBrZXlzID0gT2JqZWN0LmtleXMoIGtpbmRPcHRpb25zLmtpbmRNZXRob2RzICk7XG5cbiAgICBmb3IgKCB2YXIgaiA9IDAsIGpqID0ga2V5cy5sZW5ndGg7IGogPCBqajsgaisrICkge1xuICAgICAgdmFyIGtleSA9IGtleXNbal07XG4gICAgICBraW5kQ29uc3RydWN0b3Jba2V5XSA9IGtpbmRPcHRpb25zLmtpbmRNZXRob2RzW2tleV07XG4gICAgfVxuXG4gICAga2luZENvbnN0cnVjdG9yLmdldEtpbmRJbmZvID0ga2luZENvbnN0cnVjdG9yLnByb3RvdHlwZS5nZXRLaW5kSW5mbyA9IGZ1bmN0aW9uIGdldEtpbmRJbmZvKCkge1xuICAgICAgcmV0dXJuICRraW5kSW5mbztcbiAgICB9XG5cbiAgICByZXR1cm4ga2luZENvbnN0cnVjdG9yO1xuICB9XG4qL1xuXG4vKipcbiogUmVwcmVzZW50cyBhIHNlcmlhbGl6YWJsZSBhbmQgaW5zcGVjdGFibGUgZGF0YS10eXBlXG4qIGltcGxlbWVudGVkIGFzIGEgaGFzaC1tYXAgY29udGFpbmluZyBrZXktdmFsdWUgcGFpcnMsXG4qIGFsb25nIHdpdGggbWV0YWRhdGEgdGhhdCBkZXNjcmliZXMgZWFjaCBmaWVsZCB1c2luZyBhIGpzb24tc2NoZW1lIGxpa2VcbiovXG5leHBvcnQgaW50ZXJmYWNlIEtpbmRcbntcbn1cblxuZXhwb3J0IGNsYXNzIEtpbmQgaW1wbGVtZW50cyBLaW5kIHtcbiAgc3RhdGljIGdldEtpbmRJbmZvKCBraW5kOiBLaW5kICk6IEtpbmRJbmZvIHtcbiAgICByZXR1cm4gKDxLaW5kQ29uc3RydWN0b3I+KGtpbmQuY29uc3RydWN0b3IpKS5raW5kSW5mbztcbiAgfVxuXG4gIHN0YXRpYyBpbml0RmllbGRzKCBraW5kOiBLaW5kLCBhdHRyaWJ1dGVzOiB7fSA9IHt9ICApIHtcbiAgICBsZXQga2luZEluZm8gPSBLaW5kLmdldEtpbmRJbmZvKCBraW5kICk7XG5cbiAgICBmb3IoIGxldCBpZCBpbiBraW5kSW5mby5maWVsZHMgKSB7XG4gICAgICBsZXQgZmllbGQgPSBraW5kSW5mby5maWVsZHNbIGlkIF07XG4gICAgICBsZXQgZmllbGRUeXBlID0gZmllbGQuZmllbGRUeXBlO1xuXG4vLyAgICAgIGNvbnNvbGUubG9nKCBpZCArICc6JyArIGZpZWxkVHlwZSApO1xuLy8gICAgICBjb25zb2xlLmxvZygga2luZC5oYXNPd25Qcm9wZXJ0eShpZCkgICk7XG5cbiAgICAgIGxldCB2YWw6IGFueTtcblxuICAgICAgaWYgKCAhZmllbGQuY2FsY3VsYXRlZCApIHtcbiAgICAgICAgLy8gd2Ugb25seSBzZXQgJ25vbictY2FsY3VsYXRlZCBmaWVsZCwgc2luY2UgY2FsY3VsYXRlZCBmaWVsZCBoYXZlXG4gICAgICAgIC8vIG5vIHNldHRlclxuXG4gICAgICAgIC8vIGdvdCBhIHZhbHVlIGZvciB0aGlzIGZpZWxkID9cbiAgICAgICAgaWYgKCBhdHRyaWJ1dGVzWyBpZCBdIClcbiAgICAgICAgICB2YWwgPSBhdHRyaWJ1dGVzWyBpZCBdO1xuICAgICAgICBlbHNlIGlmICggZmllbGQuZGVmYXVsdCAhPSB1bmRlZmluZWQgKVxuICAgICAgICAgIHZhbCA9IGZpZWxkLmRlZmF1bHQ7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gU3RyaW5nIClcbiAgICAgICAgICB2YWwgPSAnJztcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBOdW1iZXIgKVxuICAgICAgICAgIHZhbCA9IDA7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gSW50ZWdlciApXG4gICAgICAgICAgdmFsID0gZmllbGQubWluaW11bSB8fCAwO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEJvb2xlYW4gKVxuICAgICAgICAgIHZhbCA9IGZhbHNlO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEJ5dGVBcnJheSApXG4gICAgICAgICAgdmFsID0gbmV3IEJ5dGVBcnJheSgpO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEVudW0gKVxuICAgICAgICAgIHZhbCA9IGZpZWxkLmVudW1NYXAua2V5c1swXTtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBLaW5kICkge1xuICAgICAgICAgIGxldCB4eCA9ICg8S2luZD5maWVsZFR5cGUpLmNvbnN0cnVjdG9yO1xuICAgICAgICAgIHZhbCA9IE9iamVjdC5jcmVhdGUoIHh4ICk7XG4gICAgICAgIH1cblxuICAgICAgICBraW5kWyBpZCBdID0gdmFsO1xuXG4vLyAgICAgICAgY29uc29sZS5sb2coIGtpbmRbaWRdICk7XG4gICAgICB9XG4gICAgfVxuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2luZENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIC4uLmFyZ3MgKTogS2luZDtcblxuICBraW5kSW5mbz86IEtpbmRJbmZvO1xufVxuIiwiaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4vZW5kLXBvaW50JztcblxuLypcbiogTWVzc2FnZSBIZWFkZXJcbiovXG5leHBvcnQgaW50ZXJmYWNlIE1lc3NhZ2VIZWFkZXJcbntcbiAgLypcbiAgKiBNZXNzYWdlIE5hbWUsIGluZGljYXRlcyBhIGNvbW1hbmQgLyBtZXRob2QgLyByZXNwb25zZSB0byBleGVjdXRlXG4gICovXG4gIG1ldGhvZD86IHN0cmluZztcblxuICAvKlxuICAqIE1lc3NhZ2UgSWRlbnRpZmllciAodW5pcXVlKSBmb3IgZWFjaCBzZW50IG1lc3NhZ2UgKG9yIENNRC1SRVNQIHBhaXIpXG4gICovXG4gIGlkPzogbnVtYmVyO1xuXG5cbiAgLypcbiAgKiBEZXNjcmlwdGlvbiwgdXNlZnVsIGZvciB0cmFjaW5nIGFuZCBsb2dnaW5nXG4gICovXG4gIGRlc2NyaXB0aW9uPzogc3RyaW5nO1xuXG4gIC8qXG4gICogRm9yIENNRC9SRVNQIHN0eWxlIHByb3RvY29scywgaW5kaWNhdGVzIHRoYXQgbWVzc2FnZSBkaXNwYXRjaGVkXG4gICogaW4gcmVzcG9uc2UgdG8gYSBwcmV2aW91cyBjb21tYW5kXG4gICovXG4gIGlzUmVzcG9uc2U/OiBib29sZWFuO1xuXG4gIC8qXG4gICogRW5kUG9pbnQgdGhhdCBvcmlnaW5hdGVkIHRoZSBtZXNzYWdlXG4gICovXG4gIG9yaWdpbj86IEVuZFBvaW50O1xuXG5cbiAgLypcbiAgKiBJbmRpY2F0ZXMgdGhlIEtpbmQgb2YgZGF0YSAod2hlbiBzZXJpYWxpemVkKVxuICAqL1xuICBraW5kTmFtZT86IHN0cmluZztcbn1cblxuLypcbiogQSBUeXBlZCBNZXNzYWdlLCB3aXRoIGhlYWRlciBhbmQgcGF5bG9hZFxuKi9cbmV4cG9ydCBjbGFzcyBNZXNzYWdlPFQ+XG57XG4gIHByaXZhdGUgX2hlYWRlcjogTWVzc2FnZUhlYWRlcjtcbiAgcHJpdmF0ZSBfcGF5bG9hZDogVDtcblxuICBjb25zdHJ1Y3RvciggaGVhZGVyOiBNZXNzYWdlSGVhZGVyLCBwYXlsb2FkOiBUIClcbiAge1xuICAgIHRoaXMuX2hlYWRlciA9IGhlYWRlciB8fCB7fTtcbiAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgfVxuXG4gIGdldCBoZWFkZXIoKTogTWVzc2FnZUhlYWRlclxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2hlYWRlcjtcbiAgfVxuXG4gIGdldCBwYXlsb2FkKCk6IFRcbiAge1xuICAgIHJldHVybiB0aGlzLl9wYXlsb2FkO1xuICB9XG59XG5cbi8qXG4qIEEgdHlwZWQgTWVzc2FnZSB3aG9zZSBwYXlsb2FkIGlzIGEgS2luZFxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kTWVzc2FnZTxLIGV4dGVuZHMgS2luZD4gZXh0ZW5kcyBNZXNzYWdlPEs+XG57XG59XG4iLCJleHBvcnQgdHlwZSBUYXNrID0gKCkgPT4gdm9pZDtcbmV4cG9ydCB0eXBlIEZsdXNoRnVuYyA9ICgpID0+IHZvaWQ7XG52YXIgd2luZG93ID0gd2luZG93IHx8IHt9O1xuXG5leHBvcnQgY2xhc3MgVGFza1NjaGVkdWxlclxue1xuICBzdGF0aWMgbWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyKGZsdXNoKTogRmx1c2hGdW5jXG4gIHtcbiAgICB2YXIgdG9nZ2xlID0gMTtcblxuICAgIHZhciBvYnNlcnZlciA9IG5ldyBUYXNrU2NoZWR1bGVyLkJyb3dzZXJNdXRhdGlvbk9ic2VydmVyKGZsdXNoKTtcblxuICAgIHZhciBub2RlOiBPYmplY3QgPSBkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZSgnJyk7XG5cbiAgICBvYnNlcnZlci5vYnNlcnZlKG5vZGUsIHsgY2hhcmFjdGVyRGF0YTogdHJ1ZSB9KTtcblxuICAgIHJldHVybiBmdW5jdGlvbiByZXF1ZXN0Rmx1c2goKVxuICAgIHtcbiAgICAgIHRvZ2dsZSA9IC10b2dnbGU7XG4gICAgICBub2RlW1wiZGF0YVwiXSA9IHRvZ2dsZTtcbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIG1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIoZmx1c2gpOiBGbHVzaEZ1bmNcbiAge1xuICAgIHJldHVybiBmdW5jdGlvbiByZXF1ZXN0Rmx1c2goKSB7XG4gICAgICB2YXIgdGltZW91dEhhbmRsZSA9IHNldFRpbWVvdXQoaGFuZGxlRmx1c2hUaW1lciwgMCk7XG5cbiAgICAgIHZhciBpbnRlcnZhbEhhbmRsZSA9IHNldEludGVydmFsKGhhbmRsZUZsdXNoVGltZXIsIDUwKTtcbiAgICAgIGZ1bmN0aW9uIGhhbmRsZUZsdXNoVGltZXIoKVxuICAgICAge1xuICAgICAgICBjbGVhclRpbWVvdXQodGltZW91dEhhbmRsZSk7XG4gICAgICAgIGNsZWFySW50ZXJ2YWwoaW50ZXJ2YWxIYW5kbGUpO1xuICAgICAgICBmbHVzaCgpO1xuICAgICAgfVxuICAgIH07XG4gIH1cblxuICBzdGF0aWMgQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIgPSB3aW5kb3dbIFwiTXV0YXRpb25PYnNlcnZlclwiIF0gfHwgd2luZG93WyBcIldlYktpdE11dGF0aW9uT2JzZXJ2ZXJcIl07XG4gIHN0YXRpYyBoYXNTZXRJbW1lZGlhdGUgPSB0eXBlb2Ygc2V0SW1tZWRpYXRlID09PSAnZnVuY3Rpb24nO1xuXG4gIHN0YXRpYyB0YXNrUXVldWVDYXBhY2l0eSA9IDEwMjQ7XG4gIHRhc2tRdWV1ZTogVGFza1tdO1xuXG4gIHJlcXVlc3RGbHVzaFRhc2tRdWV1ZTogRmx1c2hGdW5jO1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMudGFza1F1ZXVlID0gW107XG5cbiAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICBpZiAodHlwZW9mIFRhc2tTY2hlZHVsZXIuQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIgPT09ICdmdW5jdGlvbicpXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUgPSBUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlcihmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBzZWxmLmZsdXNoVGFza1F1ZXVlKCk7XG4gICAgICB9KTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlID0gVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHNlbGYuZmx1c2hUYXNrUXVldWUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIENsZWFudXAgdGhlIFRhc2tTY2hlZHVsZXIsIGNhbmNlbGxpbmcgYW55IHBlbmRpbmcgY29tbXVuaWNhdGlvbnMuXG4gICovXG4gIHNodXRkb3duKClcbiAge1xuICB9XG5cbiAgcXVldWVUYXNrKCB0YXNrKVxuICB7XG4gICAgaWYgKCB0aGlzLnRhc2tRdWV1ZS5sZW5ndGggPCAxIClcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSgpO1xuICAgIH1cblxuICAgIHRoaXMudGFza1F1ZXVlLnB1c2godGFzayk7XG4gIH1cblxuICBmbHVzaFRhc2tRdWV1ZSgpXG4gIHtcbiAgICB2YXIgcXVldWUgPSB0aGlzLnRhc2tRdWV1ZSxcbiAgICAgICAgY2FwYWNpdHkgPSBUYXNrU2NoZWR1bGVyLnRhc2tRdWV1ZUNhcGFjaXR5LFxuICAgICAgICBpbmRleCA9IDAsXG4gICAgICAgIHRhc2s7XG5cbiAgICB3aGlsZSAoaW5kZXggPCBxdWV1ZS5sZW5ndGgpXG4gICAge1xuICAgICAgdGFzayA9IHF1ZXVlW2luZGV4XTtcblxuICAgICAgdHJ5XG4gICAgICB7XG4gICAgICAgIHRhc2suY2FsbCgpO1xuICAgICAgfVxuICAgICAgY2F0Y2ggKGVycm9yKVxuICAgICAge1xuICAgICAgICB0aGlzLm9uRXJyb3IoZXJyb3IsIHRhc2spO1xuICAgICAgfVxuXG4gICAgICBpbmRleCsrO1xuXG4gICAgICBpZiAoaW5kZXggPiBjYXBhY2l0eSlcbiAgICAgIHtcbiAgICAgICAgZm9yICh2YXIgc2NhbiA9IDA7IHNjYW4gPCBpbmRleDsgc2NhbisrKVxuICAgICAgICB7XG4gICAgICAgICAgcXVldWVbc2Nhbl0gPSBxdWV1ZVtzY2FuICsgaW5kZXhdO1xuICAgICAgICB9XG5cbiAgICAgICAgcXVldWUubGVuZ3RoIC09IGluZGV4O1xuICAgICAgICBpbmRleCA9IDA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcXVldWUubGVuZ3RoID0gMDtcbiAgfVxuXG4gIG9uRXJyb3IoZXJyb3IsIHRhc2spXG4gIHtcbiAgICBpZiAoJ29uRXJyb3InIGluIHRhc2spIHtcbiAgICAgIHRhc2sub25FcnJvcihlcnJvcik7XG4gICAgfVxuICAgIGVsc2UgaWYgKCBUYXNrU2NoZWR1bGVyLmhhc1NldEltbWVkaWF0ZSApXG4gICAge1xuICAgICAgc2V0SW1tZWRpYXRlKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9KTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0sIDApO1xuICAgIH1cbiAgfVxufVxuIiwiaW1wb3J0IHsgVGFza1NjaGVkdWxlciB9IGZyb20gJy4uL3J1bnRpbWUvdGFzay1zY2hlZHVsZXInO1xuaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4vZW5kLXBvaW50JztcbmltcG9ydCB7IE1lc3NhZ2UgfSBmcm9tICcuL21lc3NhZ2UnO1xuXG4vKipcbiogQSBtZXNzYWdlLXBhc3NpbmcgY2hhbm5lbCBiZXR3ZWVuIG11bHRpcGxlIEVuZFBvaW50c1xuKlxuKiBFbmRQb2ludHMgbXVzdCBmaXJzdCByZWdpc3RlciB3aXRoIHRoZSBDaGFubmVsLiBXaGVuZXZlciB0aGUgQ2hhbm5lbCBpcyBpblxuKiBhbiBhY3RpdmUgc3RhdGUsIGNhbGxzIHRvIHNlbmRNZXNzYWdlIHdpbGwgZm9yd2FyZCB0aGUgbWVzc2FnZSB0byBhbGxcbiogcmVnaXN0ZXJlZCBFbmRQb2ludHMgKGV4Y2VwdCB0aGUgb3JpZ2luYXRvciBFbmRQb2ludCkuXG4qL1xuZXhwb3J0IGNsYXNzIENoYW5uZWxcbntcbiAgLyoqXG4gICogVHJ1ZSBpZiBDaGFubmVsIGlzIGFjdGl2ZVxuICAqL1xuICBwcml2YXRlIF9hY3RpdmU6IGJvb2xlYW47XG5cbiAgLyoqXG4gICogQXJyYXkgb2YgRW5kUG9pbnRzIGF0dGFjaGVkIHRvIHRoaXMgQ2hhbm5lbFxuICAqL1xuICBwcml2YXRlIF9lbmRQb2ludHM6IEVuZFBvaW50W107XG5cbiAgLyoqXG4gICogUHJpdmF0ZSBUYXNrU2NoZWR1bGVyIHVzZWQgdG8gbWFrZSBtZXNzYWdlLXNlbmRzIGFzeW5jaHJvbm91cy5cbiAgKi9cbiAgcHJpdmF0ZSBfdGFza1NjaGVkdWxlcjogVGFza1NjaGVkdWxlcjtcblxuICAvKipcbiAgKiBDcmVhdGUgYSBuZXcgQ2hhbm5lbCwgaW5pdGlhbGx5IGluYWN0aXZlXG4gICovXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuICAgIHRoaXMuX2VuZFBvaW50cyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgQ2hhbm5lbCwgZGVhY3RpdmF0ZSwgcmVtb3ZlIGFsbCBFbmRQb2ludHMgYW5kXG4gICogYWJvcnQgYW55IHBlbmRpbmcgY29tbXVuaWNhdGlvbnMuXG4gICovXG4gIHB1YmxpYyBzaHV0ZG93bigpXG4gIHtcbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcblxuICAgIHRoaXMuX2VuZFBvaW50cyA9IFtdO1xuXG4gICAgaWYgKCB0aGlzLl90YXNrU2NoZWR1bGVyIClcbiAgICB7XG4gICAgICB0aGlzLl90YXNrU2NoZWR1bGVyLnNodXRkb3duKCk7XG5cbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogSXMgQ2hhbm5lbCBhY3RpdmU/XG4gICpcbiAgKiBAcmV0dXJucyB0cnVlIGlmIGNoYW5uZWwgaXMgYWN0aXZlLCBmYWxzZSBvdGhlcndpc2VcbiAgKi9cbiAgcHVibGljIGdldCBhY3RpdmUoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2FjdGl2ZTtcbiAgfVxuXG4gIC8qKlxuICAqIEFjdGl2YXRlIHRoZSBDaGFubmVsLCBlbmFibGluZyBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBhY3RpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gbmV3IFRhc2tTY2hlZHVsZXIoKTtcblxuICAgIHRoaXMuX2FjdGl2ZSA9IHRydWU7XG4gIH1cblxuICAvKipcbiAgKiBEZWFjdGl2YXRlIHRoZSBDaGFubmVsLCBkaXNhYmxpbmcgYW55IGZ1cnRoZXIgY29tbXVuaWNhdGlvblxuICAqL1xuICBwdWJsaWMgZGVhY3RpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gdW5kZWZpbmVkO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgKiBSZWdpc3RlciBhbiBFbmRQb2ludCB0byBzZW5kIGFuZCByZWNlaXZlIG1lc3NhZ2VzIHZpYSB0aGlzIENoYW5uZWwuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gcmVnaXN0ZXJcbiAgKi9cbiAgcHVibGljIGFkZEVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgdGhpcy5fZW5kUG9pbnRzLnB1c2goIGVuZFBvaW50ICk7XG4gIH1cblxuICAvKipcbiAgKiBVbnJlZ2lzdGVyIGFuIEVuZFBvaW50LlxuICAqXG4gICogQHBhcmFtIGVuZFBvaW50IC0gdGhlIEVuZFBvaW50IHRvIHVucmVnaXN0ZXJcbiAgKi9cbiAgcHVibGljIHJlbW92ZUVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgbGV0IGlkeCA9IHRoaXMuX2VuZFBvaW50cy5pbmRleE9mKCBlbmRQb2ludCApO1xuXG4gICAgaWYgKCBpZHggPj0gMCApXG4gICAge1xuICAgICAgdGhpcy5fZW5kUG9pbnRzLnNwbGljZSggaWR4LCAxICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogR2V0IEVuZFBvaW50cyByZWdpc3RlcmVkIHdpdGggdGhpcyBDaGFubmVsXG4gICpcbiAgKiBAcmV0dXJuIEFycmF5IG9mIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgZ2V0IGVuZFBvaW50cygpOiBFbmRQb2ludFtdXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnRzO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIG1lc3NhZ2UgdG8gYWxsIGxpc3RlbmVycyAoZXhjZXB0IG9yaWdpbilcbiAgKlxuICAqIEBwYXJhbSBvcmlnaW4gLSBFbmRQb2ludCB0aGF0IGlzIHNlbmRpbmcgdGhlIG1lc3NhZ2VcbiAgKiBAcGFyYW0gbWVzc2FnZSAtIE1lc3NhZ2UgdG8gYmUgc2VudFxuICAqL1xuICBwdWJsaWMgc2VuZE1lc3NhZ2UoIG9yaWdpbjogRW5kUG9pbnQsIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiApXG4gIHtcbiAgICBsZXQgaXNSZXNwb25zZSA9ICggbWVzc2FnZS5oZWFkZXIgJiYgbWVzc2FnZS5oZWFkZXIuaXNSZXNwb25zZSApO1xuXG4gICAgaWYgKCAhdGhpcy5fYWN0aXZlIClcbiAgICAgIHJldHVybjtcblxuICAgIGlmICggb3JpZ2luLmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uSU4gJiYgIWlzUmVzcG9uc2UgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnVW5hYmxlIHRvIHNlbmQgb24gSU4gcG9ydCcpO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzLmZvckVhY2goIGVuZFBvaW50ID0+IHtcbiAgICAgIC8vIFNlbmQgdG8gYWxsIGxpc3RlbmVycywgZXhjZXB0IGZvciBvcmlnaW5hdG9yIC4uLlxuICAgICAgaWYgKCBvcmlnaW4gIT0gZW5kUG9pbnQgKVxuICAgICAge1xuICAgICAgICAvLyBPbmx5IHNlbmQgdG8gSU4gb3IgSU5PVVQgbGlzdGVuZXJzLCBVTkxFU1MgbWVzc2FnZSBpcyBhXG4gICAgICAgIC8vIHJlcGx5IChpbiBhIGNsaWVudC1zZXJ2ZXIpIGNvbmZpZ3VyYXRpb25cbiAgICAgICAgaWYgKCBlbmRQb2ludC5kaXJlY3Rpb24gIT0gRGlyZWN0aW9uLk9VVCB8fCBpc1Jlc3BvbnNlIClcbiAgICAgICAge1xuICAgICAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIucXVldWVUYXNrKCAoKSA9PiB7XG4gICAgICAgICAgICBlbmRQb2ludC5oYW5kbGVNZXNzYWdlKCBtZXNzYWdlLCBvcmlnaW4sIHRoaXMgKTtcbiAgICAgICAgICB9ICk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi9jaGFubmVsJztcblxuZXhwb3J0IGVudW0gRGlyZWN0aW9uIHtcbiAgSU4gPSAxLFxuICBPVVQgPSAyLFxuICBJTk9VVCA9IDNcbn07XG5cbmV4cG9ydCB0eXBlIEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZSA9ICggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCByZWNlaXZpbmdFbmRQb2ludD86IEVuZFBvaW50LCByZWNlaXZpbmdDaGFubmVsPzogQ2hhbm5lbCApID0+IHZvaWQ7XG5cbi8qKlxuKiBBbiBFbmRQb2ludCBpcyBhIHNlbmRlci9yZWNlaXZlciBmb3IgbWVzc2FnZS1wYXNzaW5nLiBJdCBoYXMgYW4gaWRlbnRpZmllclxuKiBhbmQgYW4gb3B0aW9uYWwgZGlyZWN0aW9uLCB3aGljaCBtYXkgYmUgSU4sIE9VVCBvciBJTi9PVVQgKGRlZmF1bHQpLlxuKlxuKiBFbmRQb2ludHMgbWF5IGhhdmUgbXVsdGlwbGUgY2hhbm5lbHMgYXR0YWNoZWQsIGFuZCB3aWxsIGZvcndhcmQgbWVzc2FnZXNcbiogdG8gYWxsIG9mIHRoZW0uXG4qL1xuZXhwb3J0IGNsYXNzIEVuZFBvaW50XG57XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICAvKipcbiAgKiBBIGxpc3Qgb2YgYXR0YWNoZWQgQ2hhbm5lbHNcbiAgKi9cbiAgcHJvdGVjdGVkIF9jaGFubmVsczogQ2hhbm5lbFtdO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX21lc3NhZ2VMaXN0ZW5lcnM6IEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZVtdO1xuXG4gIHByaXZhdGUgX2RpcmVjdGlvbjogRGlyZWN0aW9uO1xuXG4gIGNvbnN0cnVjdG9yKCBpZDogc3RyaW5nLCBkaXJlY3Rpb246IERpcmVjdGlvbiA9IERpcmVjdGlvbi5JTk9VVCApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fZGlyZWN0aW9uID0gZGlyZWN0aW9uO1xuXG4gICAgdGhpcy5fY2hhbm5lbHMgPSBbXTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIENsZWFudXAgdGhlIEVuZFBvaW50LCBkZXRhY2hpbmcgYW55IGF0dGFjaGVkIENoYW5uZWxzIGFuZCByZW1vdmluZyBhbnlcbiAgKiBtZXNzYWdlLWxpc3RlbmVycy4gQ2FsbGluZyBzaHV0ZG93bigpIGlzIG1hbmRhdG9yeSB0byBhdm9pZCBtZW1vcnktbGVha3NcbiAgKiBkdWUgdG8gdGhlIGNpcmN1bGFyIHJlZmVyZW5jZXMgdGhhdCBleGlzdCBiZXR3ZWVuIENoYW5uZWxzIGFuZCBFbmRQb2ludHNcbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuZGV0YWNoQWxsKCk7XG5cbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzID0gW107XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBFbmRQb2ludCdzIGlkXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cblxuICAvKipcbiAgKiBBdHRhY2ggYSBDaGFubmVsIHRvIHRoaXMgRW5kUG9pbnQuIE9uY2UgYXR0YWNoZWQsIHRoZSBDaGFubmVsIHdpbGwgZm9yd2FyZFxuICAqIG1lc3NhZ2VzIHRvIHRoaXMgRW5kUG9pbnQsIGFuZCB3aWxsIGFjY2VwdCBtZXNzYWdlcyBvcmlnaW5hdGVkIGhlcmUuXG4gICogQW4gRW5kUG9pbnQgY2FuIGhhdmUgbXVsdGlwbGUgQ2hhbm5lbHMgYXR0YWNoZWQsIGluIHdoaWNoIGNhc2UgaXQgd2lsbFxuICAqIGJyb2FkY2FzdCB0byB0aGVtIGFsbCB3aGVuIHNlbmRpbmcsIGFuZCB3aWxsIHJlY2VpdmUgbWVzc2FnZXMgaW5cbiAgKiBhcnJpdmFsLW9yZGVyLlxuICAqL1xuICBwdWJsaWMgYXR0YWNoKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLnB1c2goIGNoYW5uZWwgKTtcblxuICAgIGNoYW5uZWwuYWRkRW5kUG9pbnQoIHRoaXMgKTtcbiAgfVxuXG4gIC8qKlxuICAqIERldGFjaCBhIHNwZWNpZmljIENoYW5uZWwgZnJvbSB0aGlzIEVuZFBvaW50LlxuICAqL1xuICBwdWJsaWMgZGV0YWNoKCBjaGFubmVsVG9EZXRhY2g6IENoYW5uZWwgKVxuICB7XG4gICAgbGV0IGlkeCA9IHRoaXMuX2NoYW5uZWxzLmluZGV4T2YoIGNoYW5uZWxUb0RldGFjaCApO1xuXG4gICAgaWYgKCBpZHggPj0gMCApXG4gICAge1xuICAgICAgY2hhbm5lbFRvRGV0YWNoLnJlbW92ZUVuZFBvaW50KCB0aGlzICk7XG5cbiAgICAgIHRoaXMuX2NoYW5uZWxzLnNwbGljZSggaWR4LCAxICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGFsbCBDaGFubmVscyBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2hBbGwoKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMuZm9yRWFjaCggY2hhbm5lbCA9PiB7XG4gICAgICBjaGFubmVsLnJlbW92ZUVuZFBvaW50KCB0aGlzICk7XG4gICAgfSApO1xuXG4gICAgdGhpcy5fY2hhbm5lbHMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIEFyZSBhbnkgY2hhbm5lbHMgYXR0YWNoZWQgdG8gdGhpcyBFbmRQb2ludD9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgRW5kcG9pbnQgaXMgYXR0YWNoZWQgdG8gYXQtbGVhc3Qtb25lIENoYW5uZWxcbiAgKi9cbiAgZ2V0IGF0dGFjaGVkKClcbiAge1xuICAgIHJldHVybiAoIHRoaXMuX2NoYW5uZWxzLmxlbmd0aCA+IDAgKTtcbiAgfVxuXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZGlyZWN0aW9uO1xuICB9XG5cbiAgLyoqXG4gICogSGFuZGxlIGFuIGluY29taW5nIE1lc3NhZ2UsIG1ldGhvZCBjYWxsZWQgYnkgQ2hhbm5lbC5cbiAgKi9cbiAgcHVibGljIGhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiwgZnJvbUVuZFBvaW50OiBFbmRQb2ludCwgZnJvbUNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5mb3JFYWNoKCBtZXNzYWdlTGlzdGVuZXIgPT4ge1xuICAgICAgbWVzc2FnZUxpc3RlbmVyKCBtZXNzYWdlLCB0aGlzLCBmcm9tQ2hhbm5lbCApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFNlbmQgYSBNZXNzYWdlLlxuICAqL1xuICBwdWJsaWMgc2VuZE1lc3NhZ2UoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiApXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwuc2VuZE1lc3NhZ2UoIHRoaXMsIG1lc3NhZ2UgKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgKiBSZWdpc3RlciBhIGRlbGVnYXRlIHRvIHJlY2VpdmUgaW5jb21pbmcgTWVzc2FnZXNcbiAgKlxuICAqIEBwYXJhbSBtZXNzYWdlTGlzdGVuZXIgLSBkZWxlZ2F0ZSB0byBiZSBjYWxsZWQgd2l0aCByZWNlaXZlZCBNZXNzYWdlXG4gICovXG4gIHB1YmxpYyBvbk1lc3NhZ2UoIG1lc3NhZ2VMaXN0ZW5lcjogSGFuZGxlTWVzc2FnZURlbGVnYXRlIClcbiAge1xuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMucHVzaCggbWVzc2FnZUxpc3RlbmVyICk7XG4gIH1cbn1cblxuLyoqXG4qIEFuIGluZGV4ZWQgY29sbGVjdGlvbiBvZiBFbmRQb2ludCBvYmplY3RzLCBub3JtYWxseSBpbmRleGVkIHZpYSBFbmRQb2ludCdzXG4qIHVuaXF1ZSBpZGVudGlmaWVyXG4qL1xuZXhwb3J0IHR5cGUgRW5kUG9pbnRDb2xsZWN0aW9uID0geyBbaWQ6IHN0cmluZ106IEVuZFBvaW50OyB9O1xuIiwiaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5pbXBvcnQgeyBLaW5kLCBLaW5kSW5mbyB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5cbmV4cG9ydCBlbnVtIFByb3RvY29sVHlwZUJpdHNcbntcbiAgUEFDS0VUID0gMCwgICAgICAgICAvKiogRGF0YWdyYW0tb3JpZW50ZWQgKGFsd2F5cyBjb25uZWN0ZWQuLi4pICovXG4gIFNUUkVBTSA9IDEsICAgICAgICAgLyoqIENvbm5lY3Rpb24tb3JpZW50ZWQgKi9cblxuICBPTkVXQVkgPSAwLCAgICAgICAgIC8qKiBVbmlkaXJlY3Rpb25hbCBPVVQgKHNvdXJjZSkgLT4gSU4gKHNpbmspICovXG4gIENMSUVOVFNFUlZFUiA9IDQsICAgLyoqIENvbW1hbmQgT1VULT5JTiwgUmVzcG9uc2UgSU4tPk9VVCAqL1xuICBQRUVSMlBFRVIgPSA2LCAgICAgIC8qKiBCaWRpcmVjdGlvbmFsOiBJTk9VVCA8LT4gSU5PVVQgKi9cblxuICBVTlRZUEVEID0gMCwgICAgICAgIC8qKiBVbnR5cGVkIGRhdGEgKi9cbiAgVFlQRUQgPSA4LCAgICAgICAgICAvKiogVHlwZWQgZGF0YSAqKi9cbn1cblxuZXhwb3J0IHR5cGUgUHJvdG9jb2xUeXBlID0gbnVtYmVyO1xuXG5leHBvcnQgY2xhc3MgUHJvdG9jb2w8VD5cbntcbiAgc3RhdGljIHByb3RvY29sVHlwZTogUHJvdG9jb2xUeXBlID0gMDtcbn1cblxuLyoqXG4qIEEgQ2xpZW50LVNlcnZlciBQcm90b2NvbCwgdG8gYmUgdXNlZCBiZXR3ZWVuXG4qL1xuY2xhc3MgQ2xpZW50U2VydmVyUHJvdG9jb2w8VD4gZXh0ZW5kcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSBQcm90b2NvbFR5cGVCaXRzLkNMSUVOVFNFUlZFUiB8IFByb3RvY29sVHlwZUJpdHMuVFlQRUQ7XG59XG5cbmNsYXNzIEFQRFUgaW1wbGVtZW50cyBLaW5kIHtcbiAga2luZEluZm86IEtpbmRJbmZvO1xuICBwcm9wZXJ0aWVzO1xufVxuXG5jbGFzcyBBUERVTWVzc2FnZSBleHRlbmRzIE1lc3NhZ2U8QVBEVT5cbntcbn1cblxuY2xhc3MgQVBEVVByb3RvY29sIGV4dGVuZHMgQ2xpZW50U2VydmVyUHJvdG9jb2w8QVBEVU1lc3NhZ2U+XG57XG5cbn1cbiIsImltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5cbi8qKlxuKiBAY2xhc3MgUG9ydEluZm9cbipcbiogTWV0YWRhdGEgYWJvdXQgYSBjb21wb25lbnQncyBQb3J0XG4qL1xuZXhwb3J0IGNsYXNzIFBvcnRJbmZvXG57XG4gIC8qKlxuICAqIEJyaWVmIGRlc2NyaXB0aW9uIGZvciB0aGUgcG9ydCwgdG8gYXBwZWFyIGluICdoaW50J1xuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIERpcmVjdGlvbjogSU4sIE9VVCwgb3IgSU5PVVRcbiAgKiAgIGZvciBjbGllbnQtc2VydmVyLCBPVVQ9Q2xpZW50LCBJTj1TZXJ2ZXJcbiAgKi9cbiAgZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgLyoqXG4gICogUHJvdG9jb2wgaW1wbGVtZW50ZWQgYnkgdGhlIHBvcnRcbiAgKi9cbiAgcHJvdG9jb2w6IFByb3RvY29sPGFueT47XG5cbiAgLyoqXG4gICogUkZVIC0gaW5kZXhhYmxlIHBvcnRzXG4gICovXG4gIGNvdW50OiBudW1iZXIgPSAwO1xuXG4gIC8qKlxuICAqIHRydWUgaXMgcG9ydCBtdXN0IGJlIGNvbm5lY3RlZCBmb3IgY29tcG9uZW50IHRvIGV4ZWN1dGVcbiAgKi9cbiAgcmVxdWlyZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbn1cbiIsImltcG9ydCB7IEtpbmQsIEtpbmRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24sIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuXG5pbXBvcnQgeyBQb3J0SW5mbyB9IGZyb20gJy4vcG9ydC1pbmZvJztcblxuLyoqXG4qIEBjbGFzcyBDb21wb25lbnRJbmZvXG4qXG4qIE1ldGFkYXRhIGFib3V0IGEgQ29tcG9uZW50XG4qL1xuZXhwb3J0IGNsYXNzIENvbXBvbmVudEluZm9cbntcbiAgLyoqXG4gICogQ29tcG9uZW50IE5hbWVcbiAgKi9cbiAgbmFtZTogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEJyaWVmIGRlc2NyaXB0aW9uIGZvciB0aGUgY29tcG9uZW50LCB0byBhcHBlYXIgaW4gJ2hpbnQnXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogTGluayB0byBkZXRhaWxlZCBpbmZvcm1hdGlvbiBmb3IgdGhlIGNvbXBvbmVudFxuICAqL1xuICBkZXRhaWxMaW5rOiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBDYXRlZ29yeSBuYW1lIGZvciB0aGUgY29tcG9uZW50LCBncm91cHMgc2FtZSBjYXRlZ29yaWVzIHRvZ2V0aGVyXG4gICovXG4gIGNhdGVnb3J5OiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBBdXRob3IncyBuYW1lXG4gICovXG4gIGF1dGhvcjogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQXJyYXkgb2YgUG9ydCBkZXNjcmlwdG9ycy4gV2hlbiBhY3RpdmUsIHRoZSBjb21wb25lbnQgd2lsbCBjb21tdW5pY2F0ZVxuICAqIHRocm91Z2ggY29ycmVzcG9uZGluZyBFbmRQb2ludHNcbiAgKi9cbiAgcG9ydHM6IHsgW2lkOiBzdHJpbmddOiBQb3J0SW5mbyB9ID0ge307XG4gIHN0b3JlczogeyBbaWQ6IHN0cmluZ106IFBvcnRJbmZvIH0gPSB7fTtcblxuICAvKipcbiAgKlxuICAqL1xuICBjb25maWdLaW5kOiBLaW5kQ29uc3RydWN0b3I7XG4gIGRlZmF1bHRDb25maWc6IEtpbmQ7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cbn1cbiIsIlxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgY29tcG9uZW50J3MgU3RvcmVcbiogVE9ETzogXG4qL1xuZXhwb3J0IGNsYXNzIFN0b3JlSW5mb1xue1xufVxuIiwiaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5pbXBvcnQgeyBTdG9yZUluZm8gfSBmcm9tICcuL3N0b3JlLWluZm8nO1xuaW1wb3J0IHsgQ29tcG9uZW50SW5mbyB9IGZyb20gJy4vY29tcG9uZW50LWluZm8nO1xuaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuaW1wb3J0IHsgS2luZCwgS2luZENvbnN0cnVjdG9yIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdDb21wb25lbnQnIG1ldGFkYXRhIChzdGF0aWMgY29tcG9uZW50SW5mbylcbiovXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50QnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApIHtcblxuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmNvbXBvbmVudEluZm8gPSB7XG4gICAgICBuYW1lOiBuYW1lIHx8IGN0b3IubmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIGRldGFpbExpbms6ICcnLFxuICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5LFxuICAgICAgYXV0aG9yOiAnJyxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIHN0b3Jlczoge30sXG4gICAgICBjb25maWdLaW5kOiBLaW5kLFxuICAgICAgZGVmYXVsdENvbmZpZzoge31cbiAgICB9O1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApOiBDb21wb25lbnRCdWlsZGVyXG4gIHtcbiAgICBsZXQgYnVpbGRlciA9IG5ldyBDb21wb25lbnRCdWlsZGVyKCBjdG9yLCBuYW1lLCBkZXNjcmlwdGlvbiwgY2F0ZWdvcnkgKTtcblxuICAgIHJldHVybiBidWlsZGVyO1xuICB9XG5cbiAgcHVibGljIGNvbmZpZyggY29uZmlnS2luZDogS2luZENvbnN0cnVjdG9yLCBkZWZhdWx0Q29uZmlnPzogS2luZCApOiB0aGlzIHtcblxuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLmNvbmZpZ0tpbmQgPSBjb25maWdLaW5kO1xuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLmRlZmF1bHRDb25maWcgPSBkZWZhdWx0Q29uZmlnO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgcG9ydCggaWQ6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZGlyZWN0aW9uOiBEaXJlY3Rpb24sIG9wdHM/OiB7IHByb3RvY29sPzogUHJvdG9jb2w8YW55PjsgY291bnQ/OiBudW1iZXI7IHJlcXVpcmVkPzogYm9vbGVhbiB9ICk6IHRoaXNcbiAge1xuICAgIG9wdHMgPSBvcHRzIHx8IHt9O1xuXG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8ucG9ydHNbIGlkIF0gPSB7XG4gICAgICBkaXJlY3Rpb246IGRpcmVjdGlvbixcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIHByb3RvY29sOiBvcHRzLnByb3RvY29sLFxuICAgICAgY291bnQ6IG9wdHMuY291bnQsXG4gICAgICByZXF1aXJlZDogb3B0cy5yZXF1aXJlZFxuICAgIH07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG4vKipcbiogQ29tcG9uZW50cyBhcmUgcnVudGltZSBvYmplY3RzIHRoYXQgZXhlY3V0ZSB3aXRoaW4gYSBHcmFwaC5cbipcbiogQSBncmFwaCBOb2RlIGlzIGEgcGxhY2Vob2xkZXIgZm9yIHRoZSBhY3R1YWwgQ29tcG9uZW50IHRoYXRcbiogd2lsbCBleGVjdXRlLlxuKlxuKiBUaGlzIGludGVyZmFjZSBkZWZpbmVzIHRoZSBzdGFuZGFyZCBtZXRob2RzIGFuZCBwcm9wZXJ0aWVzIHRoYXQgYSBDb21wb25lbnRcbiogY2FuIG9wdGlvbmFsbHkgaW1wbGVtZW50LlxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ29tcG9uZW50XG57XG4gIC8vIEluaXRpYWxpemF0aW9uIGFuZCBzaHV0ZG93blxuICBpbml0aWFsaXplPyggY29uZmlnPzogS2luZCApOiBFbmRQb2ludFtdO1xuICB0ZWFyZG93bj8oKTtcblxuICAvLyBSdW5uaW5nXG4gIHN0YXJ0PygpO1xuICBzdG9wPygpO1xuXG4gIC8vIFBhdXNpbmcgYW5kIGNvbnRpbnVpbmcgZXhlY3V0aW9uICh3aXRob3V0IHJlc2V0dGluZyAuLilcbiAgcGF1c2U/KCk7XG4gIHJlc3VtZT8oKTtcblxuICBiaW5kVmlldz8oIHZpZXc6IGFueSApO1xuICB1bmJpbmRWaWV3PygpO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENvbXBvbmVudENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIC4uLmFyZ3MgKTogQ29tcG9uZW50O1xuXG4gIGNvbXBvbmVudEluZm8/OiBDb21wb25lbnRJbmZvO1xufVxuIiwiaW1wb3J0IHsgRXZlbnRBZ2dyZWdhdG9yLCBTdWJzY3JpcHRpb24sIEhhbmRsZXIgYXMgRXZlbnRIYW5kbGVyIH0gZnJvbSAnYXVyZWxpYS1ldmVudC1hZ2dyZWdhdG9yJztcblxuLy9leHBvcnQgeyBFdmVudEhhbmRsZXIgfTtcblxuZXhwb3J0IGNsYXNzIEV2ZW50SHViXG57XG4gIF9ldmVudEFnZ3JlZ2F0b3I6IEV2ZW50QWdncmVnYXRvcjtcblxuICBjb25zdHJ1Y3RvciggKVxuICB7XG4gICAgdGhpcy5fZXZlbnRBZ2dyZWdhdG9yID0gbmV3IEV2ZW50QWdncmVnYXRvcigpO1xuICB9XG5cbiAgcHVibGljIHB1Ymxpc2goIGV2ZW50OiBzdHJpbmcsIGRhdGE/OiBhbnkgKVxuICB7XG4gICAgdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnB1Ymxpc2goIGV2ZW50LCBkYXRhICk7XG4gIH1cblxuICBwdWJsaWMgc3Vic2NyaWJlKCBldmVudDogc3RyaW5nLCBoYW5kbGVyOiBGdW5jdGlvbiApOiBTdWJzY3JpcHRpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9ldmVudEFnZ3JlZ2F0b3Iuc3Vic2NyaWJlKCBldmVudCwgaGFuZGxlciApO1xuICB9XG5cbiAgcHVibGljIHN1YnNjcmliZU9uY2UoIGV2ZW50OiBzdHJpbmcsIGhhbmRsZXI6IEZ1bmN0aW9uICk6IFN1YnNjcmlwdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2V2ZW50QWdncmVnYXRvci5zdWJzY3JpYmVPbmNlKCBldmVudCwgaGFuZGxlciApO1xuICB9XG59XG5cbi8qZnVuY3Rpb24gZXZlbnRIdWIoKTogYW55IHtcbiAgcmV0dXJuIGZ1bmN0aW9uIGV2ZW50SHViPFRGdW5jdGlvbiBleHRlbmRzIEZ1bmN0aW9uLCBFdmVudEh1Yj4odGFyZ2V0OiBURnVuY3Rpb24pOiBURnVuY3Rpb24ge1xuXG4gICAgdGFyZ2V0LnByb3RvdHlwZS5zdWJzY3JpYmUgPSBuZXdDb25zdHJ1Y3Rvci5wcm90b3R5cGUgPSBPYmplY3QuY3JlYXRlKHRhcmdldC5wcm90b3R5cGUpO1xuICAgIG5ld0NvbnN0cnVjdG9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IHRhcmdldDtcblxuICAgIHJldHVybiA8YW55PiBuZXdDb25zdHJ1Y3RvcjtcbiAgfVxufVxuXG5AZXZlbnRIdWIoKVxuY2xhc3MgTXlDbGFzcyB7fTtcbiovXG4iLCJpbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5cbi8qKlxuKiBBIFBvcnQgaXMgYSBwbGFjZWhvbGRlciBmb3IgYW4gRW5kUG9pbnQgcHVibGlzaGVkIGJ5IHRoZSB1bmRlcmx5aW5nXG4qIGNvbXBvbmVudCBvZiBhIE5vZGUuXG4qL1xuZXhwb3J0IGNsYXNzIFBvcnRcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogTm9kZTtcbiAgcHJvdGVjdGVkIF9wcm90b2NvbElEOiBzdHJpbmc7XG5cbiAgcHJvdGVjdGVkIF9lbmRQb2ludDogRW5kUG9pbnQ7XG5cbiAgcHVibGljIG1ldGFkYXRhOiBhbnk7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBOb2RlLCBlbmRQb2ludDogRW5kUG9pbnQsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIC8vIFdhcyBhbiBFbmRQb2ludCBzdXBwbGllZD9cbiAgICBpZiAoICFlbmRQb2ludCApXG4gICAge1xuICAgICAgbGV0IGRpcmVjdGlvbiA9IGF0dHJpYnV0ZXMuZGlyZWN0aW9uIHx8IERpcmVjdGlvbi5JTk9VVDtcblxuICAgICAgaWYgKCB0eXBlb2YgYXR0cmlidXRlcy5kaXJlY3Rpb24gPT0gXCJzdHJpbmdcIiApXG4gICAgICAgIGRpcmVjdGlvbiA9IERpcmVjdGlvblsgZGlyZWN0aW9uLnRvVXBwZXJDYXNlKCkgXTtcblxuICAgICAgLy8gQ3JlYXRlIGEgXCJkdW1teVwiIGVuZFBvaW50IHdpdGggY29ycmVjdCBpZCArIGRpcmVjdGlvblxuICAgICAgZW5kUG9pbnQgPSBuZXcgRW5kUG9pbnQoIGF0dHJpYnV0ZXMuaWQsIGRpcmVjdGlvbiApO1xuICAgIH1cblxuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5fZW5kUG9pbnQgPSBlbmRQb2ludDtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBhdHRyaWJ1dGVzWyAncHJvdG9jb2wnIF0gfHwgJ2FueSc7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IHg6IDEwMCwgeTogMTAwIH07XG4gIH1cblxuICBwdWJsaWMgZ2V0IGVuZFBvaW50KCkge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludDtcbiAgfVxuICBwdWJsaWMgc2V0IGVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKSB7XG4gICAgdGhpcy5fZW5kUG9pbnQgPSBlbmRQb2ludDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm4gUE9KTyBmb3Igc2VyaWFsaXphdGlvblxuICAgKi9cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgcG9ydCA9IHtcbiAgICAgIGlkOiB0aGlzLl9lbmRQb2ludC5pZCxcbiAgICAgIGRpcmVjdGlvbjogdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uLFxuICAgICAgcHJvdG9jb2w6ICggdGhpcy5fcHJvdG9jb2xJRCAhPSAnYW55JyApID8gdGhpcy5fcHJvdG9jb2xJRCA6IHVuZGVmaW5lZCxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhLFxuICAgIH07XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBvd25lclxuICAgKi9cbiAgZ2V0IG93bmVyKCk6IE5vZGUge1xuICAgIHJldHVybiB0aGlzLl9vd25lclxuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIHByb3RvY29sIElEXG4gICAqL1xuICBnZXQgcHJvdG9jb2xJRCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9wcm90b2NvbElEO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIEVuZFBvaW50IElEXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQuaWQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgRW5kUG9pbnQgRGlyZWN0aW9uXG4gICAqL1xuICBnZXQgZGlyZWN0aW9uKCk6IERpcmVjdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbjtcbiAgfVxuXG59XG5cbmV4cG9ydCBjbGFzcyBQdWJsaWNQb3J0IGV4dGVuZHMgUG9ydFxue1xuICBwcm94eUVuZFBvaW50OiBFbmRQb2ludDtcbiAgcHJveHlDaGFubmVsOiBDaGFubmVsO1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGVuZFBvaW50OiBFbmRQb2ludCwgYXR0cmlidXRlczoge30gKVxuICB7XG4gICAgc3VwZXIoIG93bmVyLCBlbmRQb2ludCwgYXR0cmlidXRlcyApO1xuXG4gICAgbGV0IHByb3h5RGlyZWN0aW9uID1cbiAgICAgICggdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uID09IERpcmVjdGlvbi5JTiApXG4gICAgICAgID8gRGlyZWN0aW9uLk9VVFxuICAgICAgICA6ICggdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uID09IERpcmVjdGlvbi5PVVQgKVxuICAgICAgICAgID8gRGlyZWN0aW9uLklOXG4gICAgICAgICAgOiBEaXJlY3Rpb24uSU5PVVQ7XG5cbiAgICAvLyBDcmVhdGUgYW4gRW5kUG9pbnQgdG8gcHJveHkgYmV0d2VlbiB0aGUgUHVibGljIGFuZCBQcml2YXRlIChpbnRlcm5hbClcbiAgICAvLyBzaWRlcyBvZiB0aGUgUG9ydC5cbiAgICB0aGlzLnByb3h5RW5kUG9pbnQgPSBuZXcgRW5kUG9pbnQoIHRoaXMuX2VuZFBvaW50LmlkLCBwcm94eURpcmVjdGlvbiApO1xuXG4gICAgLy8gV2lyZS11cCBwcm94eSAtXG5cbiAgICAvLyBGb3J3YXJkIGluY29taW5nIHBhY2tldHMgKGZyb20gcHVibGljIGludGVyZmFjZSkgdG8gcHJpdmF0ZVxuICAgIHRoaXMucHJveHlFbmRQb2ludC5vbk1lc3NhZ2UoICggbWVzc2FnZSApID0+IHtcbiAgICAgIHRoaXMuX2VuZFBvaW50LmhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2UsIHRoaXMucHJveHlFbmRQb2ludCwgdGhpcy5wcm94eUNoYW5uZWwgKTtcbiAgICB9KTtcblxuICAgIC8vIEZvcndhcmQgb3V0Z29pbmcgcGFja2V0cyAoZnJvbSBwcml2YXRlIGludGVyZmFjZSkgdG8gcHVibGljXG4gICAgdGhpcy5fZW5kUG9pbnQub25NZXNzYWdlKCAoIG1lc3NhZ2UgKSA9PiB7XG4gICAgICB0aGlzLnByb3h5RW5kUG9pbnQuc2VuZE1lc3NhZ2UoIG1lc3NhZ2UgKTtcbiAgICB9KTtcblxuICAgIC8vIG5vdCB5ZXQgY29ubmVjdGVkXG4gICAgdGhpcy5wcm94eUNoYW5uZWwgPSBudWxsO1xuICB9XG5cbiAgLy8gQ29ubmVjdCB0byBQcml2YXRlIChpbnRlcm5hbCkgRW5kUG9pbnQuIFRvIGJlIGNhbGxlZCBkdXJpbmcgZ3JhcGhcbiAgLy8gd2lyZVVwIHBoYXNlXG4gIHB1YmxpYyBjb25uZWN0UHJpdmF0ZSggY2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICB0aGlzLnByb3h5Q2hhbm5lbCA9IGNoYW5uZWw7XG5cbiAgICB0aGlzLnByb3h5RW5kUG9pbnQuYXR0YWNoKCBjaGFubmVsICk7XG4gIH1cblxuICBwdWJsaWMgZGlzY29ubmVjdFByaXZhdGUoKVxuICB7XG4gICAgdGhpcy5wcm94eUVuZFBvaW50LmRldGFjaCggdGhpcy5wcm94eUNoYW5uZWwgKTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIHBvcnQgPSBzdXBlci50b09iamVjdCggb3B0cyApO1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IFJ1bnRpbWVDb250ZXh0IH0gZnJvbSAnLi4vcnVudGltZS9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeX0gZnJvbSAnLi4vcnVudGltZS9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5pbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuXG5leHBvcnQgY2xhc3MgTm9kZSBleHRlbmRzIEV2ZW50SHViXG57XG4gIHByb3RlY3RlZCBfb3duZXI6IEdyYXBoO1xuICBwcm90ZWN0ZWQgX2lkOiBzdHJpbmc7XG5cbiAgcHJvdGVjdGVkIF9jb21wb25lbnQ6IHN0cmluZztcbiAgcHJvdGVjdGVkIF9pbml0aWFsRGF0YTogT2JqZWN0O1xuXG4gIHByb3RlY3RlZCBfcG9ydHM6IE1hcDxzdHJpbmcsIFBvcnQ+O1xuXG4gIHB1YmxpYyBtZXRhZGF0YTogYW55O1xuXG4gIC8qKlxuICAgKiBSdW50aW1lIGFuZCBjb21wb25lbnQgaW5zdGFuY2UgdGhhdCB0aGlzIG5vZGUgcmVwcmVzZW50c1xuICAgKi9cbiAgcHJvdGVjdGVkIF9jb250ZXh0OiBSdW50aW1lQ29udGV4dDtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9pZCA9IGF0dHJpYnV0ZXMuaWQgfHwgJyc7XG4gICAgdGhpcy5fY29tcG9uZW50ID0gYXR0cmlidXRlcy5jb21wb25lbnQ7XG4gICAgdGhpcy5faW5pdGlhbERhdGEgPSBhdHRyaWJ1dGVzLmluaXRpYWxEYXRhIHx8IHt9O1xuXG4gICAgdGhpcy5fcG9ydHMgPSBuZXcgTWFwPHN0cmluZywgUG9ydD4oKTtcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgfTtcblxuICAgIC8vIEluaXRpYWxseSBjcmVhdGUgJ3BsYWNlaG9sZGVyJyBwb3J0cy4gT25jZSBjb21wb25lbnQgaGFzIGJlZW5cbiAgICAvLyBsb2FkZWQgYW5kIGluc3RhbnRpYXRlZCwgdGhleSB3aWxsIGJlIGNvbm5lY3RlZCBjb25uZWN0ZWQgdG9cbiAgICAvLyB0aGUgY29tcG9uZW50J3MgY29tbXVuaWNhdGlvbiBlbmQtcG9pbnRzXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMucG9ydHMgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkUGxhY2Vob2xkZXJQb3J0KCBpZCwgYXR0cmlidXRlcy5wb3J0c1sgaWQgXSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm4gUE9KTyBmb3Igc2VyaWFsaXphdGlvblxuICAgKi9cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgbm9kZSA9IHtcbiAgICAgIGlkOiB0aGlzLmlkLFxuICAgICAgY29tcG9uZW50OiB0aGlzLl9jb21wb25lbnQsXG4gICAgICBpbml0aWFsRGF0YTogdGhpcy5faW5pdGlhbERhdGEsXG4gICAgICBwb3J0czoge30sXG4gICAgICBtZXRhZGF0YTogdGhpcy5tZXRhZGF0YVxuICAgIH07XG5cbiAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHBvcnQsIGlkICkgPT4ge1xuICAgICAgbm9kZS5wb3J0c1sgaWQgXSA9IHBvcnQudG9PYmplY3QoKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbm9kZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIE5vZGUncyBvd25lclxuICAgKi9cbiAgcHVibGljIGdldCBvd25lcigpOiBHcmFwaCB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyXG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBOb2RlJ3MgaWRcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9pZDtcbiAgfVxuICAvKipcbiAgICogU2V0IHRoZSBOb2RlJ3MgaWRcbiAgICogQHBhcmFtIGlkIC0gbmV3IGlkZW50aWZpZXJcbiAgICovXG4gIHNldCBpZCggaWQ6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuICB9XG5cbiAgcHVibGljIHVwZGF0ZVBvcnRzKCBlbmRQb2ludHM6IEVuZFBvaW50W10gKSB7XG4gICAgbGV0IGN1cnJlbnRQb3J0cyA9IHRoaXMuX3BvcnRzO1xuICAgIGxldCBuZXdQb3J0czogTWFwPHN0cmluZyxQb3J0PiA9IG5ldyBNYXA8c3RyaW5nLCBQb3J0PigpO1xuXG4gICAgLy8gUGFyYW0gZW5kUG9pbnRzIGlzIGFuIGFycmF5IG9mIEVuZFBvaW50cyBleHBvcnRlZCBieSBhIGNvbXBvbmVudFxuICAgIC8vIHVwZGF0ZSBvdXIgbWFwIG9mIFBvcnRzIHRvIHJlZmxlY3QgdGhpcyBhcnJheVxuICAgIC8vIFRoaXMgbWF5IG1lYW4gaW5jbHVkaW5nIGEgbmV3IFBvcnQsIHVwZGF0aW5nIGFuIGV4aXN0aW5nIFBvcnQgdG9cbiAgICAvLyB1c2UgdGhpcyBzdXBwbGllZCBFbmRQb2ludCwgb3IgZXZlbiBkZWxldGluZyBhICduby1sb25nZXInIHZhbGlkIFBvcnRcbiAgICBlbmRQb2ludHMuZm9yRWFjaCggKGVwOiBFbmRQb2ludCApID0+IHtcbiAgICAgIGxldCBpZCA9IGVwLmlkO1xuXG4gICAgICBpZiAoIGN1cnJlbnRQb3J0cy5oYXMoIGlkICkgKSB7XG4gICAgICAgIGxldCBwb3J0ID0gY3VycmVudFBvcnRzLmdldCggaWQgKTtcblxuICAgICAgICBwb3J0LmVuZFBvaW50ID0gZXA7XG5cbiAgICAgICAgbmV3UG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuXG4gICAgICAgIGN1cnJlbnRQb3J0cy5kZWxldGUoIGlkICk7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgLy8gZW5kUG9pbnQgbm90IGZvdW5kLCBjcmVhdGUgYSBwb3J0IGZvciBpdFxuICAgICAgICBsZXQgcG9ydCA9IG5ldyBQb3J0KCB0aGlzLCBlcCwgeyBpZDogaWQsIGRpcmVjdGlvbjogZXAuZGlyZWN0aW9uIH0gKTtcblxuICAgICAgICBuZXdQb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICB0aGlzLl9wb3J0cyA9IG5ld1BvcnRzO1xuICB9XG5cblxuICAvKipcbiAgICogQWRkIGEgcGxhY2Vob2xkZXIgUG9ydFxuICAgKi9cbiAgcHJvdGVjdGVkIGFkZFBsYWNlaG9sZGVyUG9ydCggaWQ6IHN0cmluZywgYXR0cmlidXRlczoge30gKTogUG9ydFxuICB7XG4gICAgYXR0cmlidXRlc1tcImlkXCJdID0gaWQ7XG5cbiAgICBsZXQgcG9ydCA9IG5ldyBQb3J0KCB0aGlzLCBudWxsLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLl9wb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm4gcG9ydHMgYXMgYW4gYXJyYXkgb2YgUG9ydHNcbiAgICpcbiAgICogQHJldHVybiBQb3J0W11cbiAgICovXG4gIGdldCBwb3J0cygpOiBNYXA8c3RyaW5nLCBQb3J0PlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BvcnRzO1xuICB9XG5cbiAgZ2V0UG9ydEFycmF5KCk6IFBvcnRbXSB7XG4gICAgbGV0IHhwb3J0czogUG9ydFtdID0gW107XG5cbiAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHBvcnQsIGlkICkgPT4ge1xuICAgICAgeHBvcnRzLnB1c2goIHBvcnQgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4geHBvcnRzO1xuICB9XG5cbiAgLyoqXG4gICAqIExvb2t1cCBhIFBvcnQgYnkgaXQncyBJRFxuICAgKiBAcGFyYW0gaWQgLSBwb3J0IGlkZW50aWZpZXJcbiAgICpcbiAgICogQHJldHVybiBQb3J0IG9yIHVuZGVmaW5lZFxuICAgKi9cbiAgZ2V0UG9ydEJ5SUQoIGlkOiBzdHJpbmcgKTogUG9ydFxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BvcnRzLmdldCggaWQgKTtcbiAgfVxuXG4gIGlkZW50aWZ5UG9ydCggaWQ6IHN0cmluZywgcHJvdG9jb2xJRD86IHN0cmluZyApOiBQb3J0XG4gIHtcbiAgICB2YXIgcG9ydDogUG9ydDtcblxuICAgIGlmICggaWQgKVxuICAgICAgcG9ydCA9IHRoaXMuX3BvcnRzLmdldCggaWQgKTtcbiAgICBlbHNlIGlmICggcHJvdG9jb2xJRCApXG4gICAge1xuICAgICAgdGhpcy5fcG9ydHMuZm9yRWFjaCggKCBwLCBpZCApID0+IHtcbiAgICAgICAgaWYgKCBwLnByb3RvY29sSUQgPT0gcHJvdG9jb2xJRCApXG4gICAgICAgICAgcG9ydCA9IHA7XG4gICAgICB9LCB0aGlzICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlIGEgUG9ydCBmcm9tIHRoaXMgTm9kZVxuICAgKiBAcGFyYW0gaWQgLSBpZGVudGlmaWVyIG9mIFBvcnQgdG8gYmUgcmVtb3ZlZFxuICAgKiBAcmV0dXJuIHRydWUgLSBwb3J0IHJlbW92ZWRcbiAgICogICAgICAgICBmYWxzZSAtIHBvcnQgaW5leGlzdGVudFxuICAgKi9cbiAgcmVtb3ZlUG9ydCggaWQ6IHN0cmluZyApOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHMuZGVsZXRlKCBpZCApO1xuICB9XG5cbiAgbG9hZENvbXBvbmVudCggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSApOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0aGlzLnVubG9hZENvbXBvbmVudCgpO1xuXG4gICAgLy8gR2V0IGEgQ29tcG9uZW50Q29udGV4dCByZXNwb25zYWJsZSBmb3IgQ29tcG9uZW50J3MgbGlmZS1jeWNsZSBjb250cm9sXG4gICAgbGV0IGN0eCA9IHRoaXMuX2NvbnRleHQgPSBmYWN0b3J5LmNyZWF0ZUNvbnRleHQoIHRoaXMuX2NvbXBvbmVudCwgdGhpcy5faW5pdGlhbERhdGEgKTtcblxuICAgIC8vIE1ha2Ugb3Vyc2VsdmVzIHZpc2libGUgdG8gY29udGV4dCAoYW5kIGluc3RhbmNlKVxuICAgIGN0eC5ub2RlID0gdGhpcztcblxuICAgIC8vbGV0IG1lID0gdGhpcztcblxuICAgIC8vIExvYWQgY29tcG9uZW50XG4gICAgcmV0dXJuIGN0eC5sb2FkKCk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGNvbnRleHQoKTogUnVudGltZUNvbnRleHQge1xuICAgIHJldHVybiB0aGlzLl9jb250ZXh0O1xuICB9XG5cbiAgdW5sb2FkQ29tcG9uZW50KClcbiAge1xuICAgIGlmICggdGhpcy5fY29udGV4dCApXG4gICAge1xuICAgICAgdGhpcy5fY29udGV4dC5yZWxlYXNlKCk7XG5cbiAgICAgIHRoaXMuX2NvbnRleHQgPSBudWxsO1xuICAgIH1cbiAgfVxuXG59XG4iLCJpbXBvcnQgeyBLaW5kIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50LCBFbmRQb2ludENvbGxlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuLi9ncmFwaC9ub2RlJztcbmltcG9ydCB7IFBvcnQgfSBmcm9tICcuLi9ncmFwaC9wb3J0JztcbmltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4vY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgQ29tcG9uZW50IH0gZnJvbSAnLi4vY29tcG9uZW50L2NvbXBvbmVudCc7XG5cbmltcG9ydCB7IENvbnRhaW5lciwgSW5qZWN0YWJsZSB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5cbmV4cG9ydCBlbnVtIFJ1blN0YXRlIHtcbiAgTkVXQk9STiwgICAgICAvLyBOb3QgeWV0IGxvYWRlZFxuICBMT0FESU5HLCAgICAgIC8vIFdhaXRpbmcgZm9yIGFzeW5jIGxvYWQgdG8gY29tcGxldGVcbiAgTE9BREVELCAgICAgICAvLyBDb21wb25lbnQgbG9hZGVkLCBub3QgeWV0IGV4ZWN1dGFibGVcbiAgUkVBRFksICAgICAgICAvLyBSZWFkeSBmb3IgRXhlY3V0aW9uXG4gIFJVTk5JTkcsICAgICAgLy8gTmV0d29yayBhY3RpdmUsIGFuZCBydW5uaW5nXG4gIFBBVVNFRCAgICAgICAgLy8gTmV0d29yayB0ZW1wb3JhcmlseSBwYXVzZWRcbn1cblxuLyoqXG4qIFRoZSBydW50aW1lIGNvbnRleHQgaW5mb3JtYXRpb24gZm9yIGEgQ29tcG9uZW50IGluc3RhbmNlXG4qL1xuZXhwb3J0IGNsYXNzIFJ1bnRpbWVDb250ZXh0XG57XG4gIC8qKlxuICAqIFRoZSBjb21wb25lbnQgaWQgLyBhZGRyZXNzXG4gICovXG4gIHByaXZhdGUgX2lkOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogVGhlIHJ1bnRpbWUgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgKi9cbiAgcHJpdmF0ZSBfaW5zdGFuY2U6IENvbXBvbmVudDtcblxuICAvKipcbiAgKiBJbml0aWFsIERhdGEgZm9yIHRoZSBjb21wb25lbnQgaW5zdGFuY2VcbiAgKi9cbiAgcHJpdmF0ZSBfY29uZmlnOiB7fTtcblxuICAvKipcbiAgKiBUaGUgcnVudGltZSBjb21wb25lbnQgaW5zdGFuY2UgdGhhdCB0aGlzIG5vZGUgcmVwcmVzZW50c1xuICAqL1xuICBwcml2YXRlIF9jb250YWluZXI6IENvbnRhaW5lcjtcblxuICAvKipcbiAgKiBUaGUgY29tcG9uZW50IGZhY3RvcnkgdGhhdCBjcmVhdGVkIHVzXG4gICovXG4gIHByaXZhdGUgX2ZhY3Rvcnk6IENvbXBvbmVudEZhY3Rvcnk7XG5cbiAgLyoqXG4gICogVGhlIG5vZGVcbiAgKi9cbiAgcHJpdmF0ZSBfbm9kZTogTm9kZTtcblxuICAvKipcbiAgKlxuICAqXG4gICovXG4gIGNvbnN0cnVjdG9yKCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5LCBjb250YWluZXI6IENvbnRhaW5lciwgaWQ6IHN0cmluZywgY29uZmlnOiB7fSwgZGVwczogSW5qZWN0YWJsZVtdID0gW10gKSB7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gZmFjdG9yeTtcblxuICAgIHRoaXMuX2lkID0gaWQ7XG5cbiAgICB0aGlzLl9jb25maWcgPSBjb25maWc7XG5cbiAgICB0aGlzLl9jb250YWluZXIgPSBjb250YWluZXI7XG5cbiAgICAvLyBSZWdpc3RlciBhbnkgY29udGV4dCBkZXBlbmRlbmNpZXNcbiAgICBmb3IoIGxldCBpIGluIGRlcHMgKVxuICAgIHtcbiAgICAgIGlmICggIXRoaXMuX2NvbnRhaW5lci5oYXNSZXNvbHZlciggZGVwc1tpXSApIClcbiAgICAgICAgdGhpcy5fY29udGFpbmVyLnJlZ2lzdGVyU2luZ2xldG9uKCBkZXBzW2ldLCBkZXBzW2ldICk7XG4gICAgfVxuICB9XG5cbiAgZ2V0IG5vZGUoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX25vZGU7XG4gIH1cbiAgc2V0IG5vZGUoIG5vZGU6IE5vZGUgKSB7XG4gICAgdGhpcy5fbm9kZSA9IG5vZGU7XG5cbiAgICAvLyBtYWtlIG5vZGUgJ2luamVjdGFibGUnIGluIGNvbnRhaW5lclxuICAgIHRoaXMuX2NvbnRhaW5lci5yZWdpc3Rlckluc3RhbmNlKCBOb2RlLCB0aGlzICk7XG4gIH1cblxuICBnZXQgaW5zdGFuY2UoKTogQ29tcG9uZW50IHtcbiAgICByZXR1cm4gdGhpcy5faW5zdGFuY2U7XG4gIH1cblxuICBnZXQgY29udGFpbmVyKCk6IENvbnRhaW5lciB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbnRhaW5lcjtcbiAgfVxuXG4gIGxvYWQoICk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIGdldCBhbiBpbnN0YW5jZSBmcm9tIHRoZSBmYWN0b3J5XG4gICAgICBtZS5fcnVuU3RhdGUgPSBSdW5TdGF0ZS5MT0FESU5HO1xuICAgICAgdGhpcy5fZmFjdG9yeS5sb2FkQ29tcG9uZW50KCB0aGlzLCB0aGlzLl9pZCApXG4gICAgICAgIC50aGVuKCAoaW5zdGFuY2UpID0+IHtcbiAgICAgICAgICAvLyBDb21wb25lbnQgKGFuZCBhbnkgZGVwZW5kZW5jaWVzKSBoYXZlIGJlZW4gbG9hZGVkXG4gICAgICAgICAgbWUuX2luc3RhbmNlID0gaW5zdGFuY2U7XG4gICAgICAgICAgbWUuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLkxPQURFRCApO1xuXG4gICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goIChlcnIpID0+IHtcbiAgICAgICAgICAvLyBVbmFibGUgdG8gbG9hZFxuICAgICAgICAgIG1lLl9ydW5TdGF0ZSA9IFJ1blN0YXRlLk5FV0JPUk47XG5cbiAgICAgICAgICByZWplY3QoIGVyciApO1xuICAgICAgICB9KTtcbiAgICB9ICk7XG4gIH1cblxuICBfcnVuU3RhdGU6IFJ1blN0YXRlID0gUnVuU3RhdGUuTkVXQk9STjtcbiAgZ2V0IHJ1blN0YXRlKCkge1xuICAgIHJldHVybiB0aGlzLl9ydW5TdGF0ZTtcbiAgfVxuXG4gIHByaXZhdGUgaW5TdGF0ZSggc3RhdGVzOiBSdW5TdGF0ZVtdICk6IGJvb2xlYW4ge1xuICAgIHJldHVybiBuZXcgU2V0PFJ1blN0YXRlPiggc3RhdGVzICkuaGFzKCB0aGlzLl9ydW5TdGF0ZSApO1xuICB9XG5cbiAgLyoqXG4gICogVHJhbnNpdGlvbiBjb21wb25lbnQgdG8gbmV3IHN0YXRlXG4gICogU3RhbmRhcmQgdHJhbnNpdGlvbnMsIGFuZCByZXNwZWN0aXZlIGFjdGlvbnMsIGFyZTpcbiAgKiAgIExPQURFRCAtPiBSRUFEWSAgICAgIGluc3RhbnRpYXRlIGFuZCBpbml0aWFsaXplIGNvbXBvbmVudFxuICAqICAgUkVBRFkgLT4gTE9BREVEICAgICAgdGVhcmRvd24gYW5kIGRlc3Ryb3kgY29tcG9uZW50XG4gICpcbiAgKiAgIFJFQURZIC0+IFJVTk5JTkcgICAgIHN0YXJ0IGNvbXBvbmVudCBleGVjdXRpb25cbiAgKiAgIFJVTk5JTkcgLT4gUkVBRFkgICAgIHN0b3AgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqXG4gICogICBSVU5OSU5HIC0+IFBBVVNFRCAgICBwYXVzZSBjb21wb25lbnQgZXhlY3V0aW9uXG4gICogICBQQVVTRUQgLT4gUlVOTklORyAgICByZXN1bWUgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqXG4gICovXG4gIHNldFJ1blN0YXRlKCBydW5TdGF0ZTogUnVuU3RhdGUgKSB7XG4gICAgbGV0IGluc3QgPSB0aGlzLmluc3RhbmNlO1xuXG4gICAgc3dpdGNoKCBydW5TdGF0ZSApIC8vIHRhcmdldCBzdGF0ZSAuLlxuICAgIHtcbiAgICAgIGNhc2UgUnVuU3RhdGUuTE9BREVEOiAvLyBqdXN0IGxvYWRlZCwgb3IgdGVhcmRvd25cbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUkVBRFksIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gdGVhcmRvd24gYW5kIGRlc3Ryb3kgY29tcG9uZW50XG4gICAgICAgICAgaWYgKCBpbnN0LnRlYXJkb3duIClcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpbnN0LnRlYXJkb3duKCk7XG5cbiAgICAgICAgICAgIC8vIGFuZCBkZXN0cm95IGluc3RhbmNlXG4gICAgICAgICAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlJFQURZOiAgLy8gaW5pdGlhbGl6ZSBvciBzdG9wIG5vZGVcbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuTE9BREVEIF0gKSApIHtcbiAgICAgICAgICAvLyBpbml0aWFsaXplIGNvbXBvbmVudFxuXG4gICAgICAgICAgbGV0IGVuZFBvaW50czogRW5kUG9pbnRbXSA9IFtdO1xuXG4gICAgICAgICAgaWYgKCBpbnN0LmluaXRpYWxpemUgKVxuICAgICAgICAgICAgZW5kUG9pbnRzID0gdGhpcy5pbnN0YW5jZS5pbml0aWFsaXplKCA8S2luZD50aGlzLl9jb25maWcgKTtcblxuICAgICAgICAgIGlmICggdGhpcy5fbm9kZSApXG4gICAgICAgICAgICB0aGlzLl9ub2RlLnVwZGF0ZVBvcnRzKCBlbmRQb2ludHMgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gc3RvcCBjb21wb25lbnRcbiAgICAgICAgICBpZiAoIGluc3Quc3RvcCApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnN0b3AoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBpbml0aWFsaXplZCwgbm90IGxvYWRlZCcgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUlVOTklORzogIC8vIHN0YXJ0L3Jlc3VtZSBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJFQURZLCBSdW5TdGF0ZS5SVU5OSU5HIF0gKSApIHtcbiAgICAgICAgICAvLyBzdGFydCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICAgICAgICAgaWYgKCBpbnN0LnN0YXJ0IClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2Uuc3RhcnQoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gcmVzdW1lIGNvbXBvbmVudCBleGVjdXRpb24gYWZ0ZXIgcGF1c2VcbiAgICAgICAgICBpZiAoIGluc3QucmVzdW1lIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UucmVzdW1lKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgc3RhcnRlZCwgbm90IHJlYWR5JyApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5QQVVTRUQ6ICAvLyBwYXVzZSBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkddICkgKSB7XG4gICAgICAgICAgaWYgKCBpbnN0LnBhdXNlIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UucGF1c2UoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gYWxyZWFkeSBwYXVzZWRcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBwYXVzZWQnICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHRoaXMuX3J1blN0YXRlID0gcnVuU3RhdGU7XG4gIH1cblxuICByZWxlYXNlKCkge1xuICAgIC8vIHJlbGVhc2UgaW5zdGFuY2UsIHRvIGF2b2lkIG1lbW9yeSBsZWFrc1xuICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBudWxsXG4gIH1cbn1cbiIsImV4cG9ydCBpbnRlcmZhY2UgTW9kdWxlTG9hZGVyIHtcbiAgaGFzTW9kdWxlPyggaWQ6IHN0cmluZyApOiBib29sZWFuO1xuXG4gIGxvYWRNb2R1bGUoIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxhbnk+O1xufVxuXG5kZWNsYXJlIGludGVyZmFjZSBTeXN0ZW0ge1xuICBub3JtYWxpemVTeW5jKCBpZCApO1xuICBpbXBvcnQoIGlkICk7XG59O1xuZGVjbGFyZSB2YXIgU3lzdGVtOiBTeXN0ZW07XG5cbmNsYXNzIE1vZHVsZVJlZ2lzdHJ5RW50cnkge1xuICBjb25zdHJ1Y3RvciggYWRkcmVzczogc3RyaW5nICkge1xuXG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFN5c3RlbU1vZHVsZUxvYWRlciBpbXBsZW1lbnRzIE1vZHVsZUxvYWRlciB7XG5cbiAgcHJpdmF0ZSBtb2R1bGVSZWdpc3RyeTogTWFwPHN0cmluZywgTW9kdWxlUmVnaXN0cnlFbnRyeT47XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5tb2R1bGVSZWdpc3RyeSA9IG5ldyBNYXA8c3RyaW5nLCBNb2R1bGVSZWdpc3RyeUVudHJ5PigpO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRPckNyZWF0ZU1vZHVsZVJlZ2lzdHJ5RW50cnkoYWRkcmVzczogc3RyaW5nKTogTW9kdWxlUmVnaXN0cnlFbnRyeSB7XG4gICAgcmV0dXJuIHRoaXMubW9kdWxlUmVnaXN0cnlbYWRkcmVzc10gfHwgKHRoaXMubW9kdWxlUmVnaXN0cnlbYWRkcmVzc10gPSBuZXcgTW9kdWxlUmVnaXN0cnlFbnRyeShhZGRyZXNzKSk7XG4gIH1cblxuICBsb2FkTW9kdWxlKCBpZDogc3RyaW5nICk6IFByb21pc2U8YW55PiB7XG4gICAgbGV0IG5ld0lkID0gU3lzdGVtLm5vcm1hbGl6ZVN5bmMoaWQpO1xuICAgIGxldCBleGlzdGluZyA9IHRoaXMubW9kdWxlUmVnaXN0cnlbbmV3SWRdO1xuXG4gICAgaWYgKGV4aXN0aW5nKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGV4aXN0aW5nKTtcbiAgICB9XG5cbiAgICByZXR1cm4gU3lzdGVtLmltcG9ydChuZXdJZCkudGhlbihtID0+IHtcbiAgICAgIHRoaXMubW9kdWxlUmVnaXN0cnlbbmV3SWRdID0gbTtcbiAgICAgIHJldHVybiBtOyAvL2Vuc3VyZU9yaWdpbk9uRXhwb3J0cyhtLCBuZXdJZCk7XG4gICAgfSk7XG4gIH1cblxufVxuIiwiaW1wb3J0IHsgQ29tcG9uZW50LCBDb21wb25lbnRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2NvbXBvbmVudC9jb21wb25lbnQnO1xuaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBNb2R1bGVMb2FkZXIgfSBmcm9tICcuL21vZHVsZS1sb2FkZXInO1xuXG5pbXBvcnQgeyBDb250YWluZXIsIEluamVjdGFibGUgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRGYWN0b3J5IHtcbiAgcHJpdmF0ZSBfbG9hZGVyOiBNb2R1bGVMb2FkZXI7XG4gIHByaXZhdGUgX2NvbnRhaW5lcjogQ29udGFpbmVyO1xuICBwcml2YXRlIF9jb21wb25lbnRzOiBNYXA8c3RyaW5nLCBDb21wb25lbnRDb25zdHJ1Y3Rvcj47XG5cbiAgY29uc3RydWN0b3IoIGNvbnRhaW5lcj86IENvbnRhaW5lciwgbG9hZGVyPzogTW9kdWxlTG9hZGVyICkge1xuICAgIHRoaXMuX2xvYWRlciA9IGxvYWRlcjtcbiAgICB0aGlzLl9jb250YWluZXIgPSBjb250YWluZXIgfHwgbmV3IENvbnRhaW5lcigpO1xuICAgIHRoaXMuX2NvbXBvbmVudHMgPSBuZXcgTWFwPHN0cmluZywgQ29tcG9uZW50Q29uc3RydWN0b3I+KCk7XG5cbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggdW5kZWZpbmVkLCBPYmplY3QgKTtcbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggXCJcIiwgT2JqZWN0ICk7XG4gIH1cblxuICBjcmVhdGVDb250ZXh0KCBpZDogc3RyaW5nLCBjb25maWc6IHt9LCBkZXBzOiBJbmplY3RhYmxlW10gPSBbXSApOiBSdW50aW1lQ29udGV4dFxuICB7XG4gICAgbGV0IGNoaWxkQ29udGFpbmVyOiBDb250YWluZXIgPSB0aGlzLl9jb250YWluZXIuY3JlYXRlQ2hpbGQoKTtcblxuICAgIHJldHVybiBuZXcgUnVudGltZUNvbnRleHQoIHRoaXMsIGNoaWxkQ29udGFpbmVyLCBpZCwgY29uZmlnLCBkZXBzICk7XG4gIH1cblxuICBnZXRDaGlsZENvbnRhaW5lcigpOiBDb250YWluZXIge1xuICAgIHJldHVybiA7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBjdHg6IFJ1bnRpbWVDb250ZXh0LCBpZDogc3RyaW5nICk6IFByb21pc2U8Q29tcG9uZW50PlxuICB7XG4gICAgbGV0IGNyZWF0ZUNvbXBvbmVudCA9IGZ1bmN0aW9uKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApOiBDb21wb25lbnRcbiAgICB7XG4gICAgICBsZXQgbmV3SW5zdGFuY2U6IENvbXBvbmVudCA9IGN0eC5jb250YWluZXIuaW52b2tlKCBjdG9yICk7XG5cbiAgICAgIHJldHVybiBuZXdJbnN0YW5jZTtcbiAgICB9XG5cbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENvbXBvbmVudD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIENoZWNrIGNhY2hlXG4gICAgICBsZXQgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgPSB0aGlzLmdldCggaWQgKTtcblxuICAgICAgaWYgKCBjdG9yICkge1xuICAgICAgICAvLyB1c2UgY2FjaGVkIGNvbnN0cnVjdG9yXG4gICAgICAgIHJlc29sdmUoIGNyZWF0ZUNvbXBvbmVudCggY3RvciApICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggdGhpcy5fbG9hZGVyICkge1xuICAgICAgICAvLyBnb3QgYSBsb2FkZWQsIHNvIHRyeSB0byBsb2FkIHRoZSBtb2R1bGUgLi4uXG4gICAgICAgIHRoaXMuX2xvYWRlci5sb2FkTW9kdWxlKCBpZCApXG4gICAgICAgICAgLnRoZW4oICggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKSA9PiB7XG5cbiAgICAgICAgICAgIC8vIHJlZ2lzdGVyIGxvYWRlZCBjb21wb25lbnRcbiAgICAgICAgICAgIG1lLl9jb21wb25lbnRzLnNldCggaWQsIGN0b3IgKTtcblxuICAgICAgICAgICAgLy8gaW5zdGFudGlhdGUgYW5kIHJlc29sdmVcbiAgICAgICAgICAgIHJlc29sdmUoIGNyZWF0ZUNvbXBvbmVudCggY3RvciApICk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAuY2F0Y2goICggZSApID0+IHtcbiAgICAgICAgICAgIHJlamVjdCggJ0NvbXBvbmVudEZhY3Rvcnk6IFVuYWJsZSB0byBsb2FkIGNvbXBvbmVudCBcIicgKyBpZCArICdcIiAtICcgKyBlICk7XG4gICAgICAgICAgfSApO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIC8vIG9vcHMuIG5vIGxvYWRlciAuLiBubyBjb21wb25lbnRcbiAgICAgICAgcmVqZWN0KCAnQ29tcG9uZW50RmFjdG9yeTogQ29tcG9uZW50IFwiJyArIGlkICsgJ1wiIG5vdCByZWdpc3RlcmVkLCBhbmQgTG9hZGVyIG5vdCBhdmFpbGFibGUnICk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICBnZXQoIGlkOiBzdHJpbmcgKTogQ29tcG9uZW50Q29uc3RydWN0b3Ige1xuICAgIHJldHVybiB0aGlzLl9jb21wb25lbnRzLmdldCggaWQgKTtcbiAgfVxuICByZWdpc3RlciggaWQ6IHN0cmluZywgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKSB7XG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIGlkLCBjdG9yICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuZXhwb3J0IHR5cGUgRW5kUG9pbnRSZWYgPSB7IG5vZGVJRDogc3RyaW5nLCBwb3J0SUQ6IHN0cmluZyB9O1xuXG5leHBvcnQgY2xhc3MgTGlua1xue1xuICBwcm90ZWN0ZWQgX293bmVyOiBHcmFwaDtcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfY2hhbm5lbDogQ2hhbm5lbDtcbiAgcHJvdGVjdGVkIF9mcm9tOiBFbmRQb2ludFJlZjtcbiAgcHJvdGVjdGVkIF90bzogRW5kUG9pbnRSZWY7XG5cbiAgcHJvdGVjdGVkIF9wcm90b2NvbElEOiBzdHJpbmc7XG4gIHByb3RlY3RlZCBtZXRhZGF0YTogYW55O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5faWQgPSBhdHRyaWJ1dGVzLmlkIHx8IFwiXCI7XG4gICAgLy90aGlzLl9jaGFubmVsID0gbnVsbDtcbiAgICB0aGlzLl9mcm9tID0gYXR0cmlidXRlc1sgJ2Zyb20nIF07XG4gICAgdGhpcy5fdG8gPSBhdHRyaWJ1dGVzWyAndG8nIF07XG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgbGV0IGxpbmsgPSB7XG4gICAgICBpZDogdGhpcy5faWQsXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgICBmcm9tOiB0aGlzLl9mcm9tLFxuICAgICAgdG86IHRoaXMuX3RvXG4gICAgfTtcblxuICAgIHJldHVybiBsaW5rO1xuICB9XG5cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBjb25uZWN0KCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIC8vIGlkZW50aWZ5IGZyb21Qb3J0IGluIGZyb21Ob2RlXG4gICAgbGV0IGZyb21Qb3J0OiBQb3J0ID0gdGhpcy5mcm9tTm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX2Zyb20ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICk7XG5cbiAgICAvLyBpZGVudGlmeSB0b1BvcnQgaW4gdG9Ob2RlXG4gICAgbGV0IHRvUG9ydDogUG9ydCA9IHRoaXMudG9Ob2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fdG8ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICk7XG5cbiAgICB0aGlzLl9jaGFubmVsID0gY2hhbm5lbDtcblxuICAgIGZyb21Qb3J0LmVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICAgIHRvUG9ydC5lbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogQ2hhbm5lbFxuICB7XG4gICAgbGV0IGNoYW4gPSB0aGlzLl9jaGFubmVsO1xuXG4gICAgaWYgKCBjaGFuIClcbiAgICB7XG4gICAgICB0aGlzLl9jaGFubmVsLmVuZFBvaW50cy5mb3JFYWNoKCAoIGVuZFBvaW50ICkgPT4ge1xuICAgICAgICBlbmRQb2ludC5kZXRhY2goIHRoaXMuX2NoYW5uZWwgKTtcbiAgICAgIH0gKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbCA9IHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICByZXR1cm4gY2hhbjtcbiAgfVxuXG4gIGdldCBmcm9tTm9kZSgpOiBOb2RlXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXIuZ2V0Tm9kZUJ5SUQoIHRoaXMuX2Zyb20ubm9kZUlEICk7XG4gIH1cblxuICBnZXQgZnJvbVBvcnQoKTogUG9ydFxuICB7XG4gICAgbGV0IG5vZGUgPSB0aGlzLmZyb21Ob2RlO1xuXG4gICAgcmV0dXJuIChub2RlKSA/IG5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl9mcm9tLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApIDogdW5kZWZpbmVkO1xuICB9XG5cbiAgc2V0IGZyb21Qb3J0KCBwb3J0OiBQb3J0IClcbiAge1xuICAgIHRoaXMuX2Zyb20gPSB7XG4gICAgICBub2RlSUQ6IHBvcnQub3duZXIuaWQsXG4gICAgICBwb3J0SUQ6IHBvcnQuaWRcbiAgICB9O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IHBvcnQucHJvdG9jb2xJRDtcbiAgfVxuXG4gIGdldCB0b05vZGUoKTogTm9kZVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyLmdldE5vZGVCeUlEKCB0aGlzLl90by5ub2RlSUQgKTtcbiAgfVxuXG4gIGdldCB0b1BvcnQoKTogUG9ydFxuICB7XG4gICAgbGV0IG5vZGUgPSB0aGlzLnRvTm9kZTtcblxuICAgIHJldHVybiAobm9kZSkgPyBub2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fdG8ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICkgOiB1bmRlZmluZWQ7XG4gIH1cblxuICBzZXQgdG9Qb3J0KCBwb3J0OiBQb3J0IClcbiAge1xuICAgIHRoaXMuX3RvID0ge1xuICAgICAgbm9kZUlEOiBwb3J0Lm93bmVyLmlkLFxuICAgICAgcG9ydElEOiBwb3J0LmlkXG4gICAgfTtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBwb3J0LnByb3RvY29sSUQ7XG4gIH1cblxuICBnZXQgcHJvdG9jb2xJRCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9wcm90b2NvbElEO1xuICB9XG59XG4iLCJpbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeSB9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgUnVudGltZUNvbnRleHQsIFJ1blN0YXRlIH0gZnJvbSAnLi4vcnVudGltZS9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IExpbmsgfSBmcm9tICcuL2xpbmsnO1xuaW1wb3J0IHsgUG9ydCwgUHVibGljUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbmV4cG9ydCBjbGFzcyBOZXR3b3JrIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgc3RhdGljIEVWRU5UX1NUQVRFX0NIQU5HRSA9ICduZXR3b3JrOnN0YXRlLWNoYW5nZSc7XG4gIHN0YXRpYyBFVkVOVF9HUkFQSF9DSEFOR0UgPSAnbmV0d29yazpncmFwaC1jaGFuZ2UnO1xuXG4gIHByaXZhdGUgX2dyYXBoOiBHcmFwaDtcblxuICBwcml2YXRlIF9mYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5O1xuXG4gIGNvbnN0cnVjdG9yKCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5LCBncmFwaD86IEdyYXBoIClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gZmFjdG9yeTtcbiAgICB0aGlzLl9ncmFwaCA9IGdyYXBoIHx8IG5ldyBHcmFwaCggbnVsbCwge30gKTtcblxuICAgIGxldCBtZSA9IHRoaXM7XG4gICAgdGhpcy5fZ3JhcGguc3Vic2NyaWJlKCBHcmFwaC5FVkVOVF9BRERfTk9ERSwgKCBkYXRhOiB7IG5vZGU6IE5vZGUgfSApPT4ge1xuICAgICAgbGV0IHJ1blN0YXRlOiBSdW5TdGF0ZSA9IG1lLl9ncmFwaC5jb250ZXh0LnJ1blN0YXRlO1xuXG4gICAgICBpZiAoIHJ1blN0YXRlICE9IFJ1blN0YXRlLk5FV0JPUk4gKVxuICAgICAge1xuICAgICAgICBsZXQgeyBub2RlIH0gPSBkYXRhO1xuXG4gICAgICAgIG5vZGUubG9hZENvbXBvbmVudCggbWUuX2ZhY3RvcnkgKVxuICAgICAgICAgIC50aGVuKCAoKT0+IHtcbiAgICAgICAgICAgIGlmICggTmV0d29yay5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCwgUnVuU3RhdGUuUkVBRFkgXSwgcnVuU3RhdGUgKSApXG4gICAgICAgICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIG5vZGUsIFJ1blN0YXRlLlJFQURZICk7XG5cbiAgICAgICAgICAgIGlmICggTmV0d29yay5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdLCBydW5TdGF0ZSApIClcbiAgICAgICAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggbm9kZSwgcnVuU3RhdGUgKTtcblxuICAgICAgICAgICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX0dSQVBIX0NIQU5HRSwgeyBub2RlOiBub2RlIH0gKTtcbiAgICAgICAgICB9KVxuICAgICAgfVxuICAgIH0gKTtcbiAgfVxuXG4gIGdldCBncmFwaCgpOiBHcmFwaCB7XG4gICAgcmV0dXJuIHRoaXMuX2dyYXBoO1xuICB9XG5cbiAgLyoqXG4gICogTG9hZCBhbGwgY29tcG9uZW50c1xuICAqL1xuICBsb2FkQ29tcG9uZW50cygpOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogUnVuU3RhdGUuTE9BRElORyB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fZ3JhcGgubG9hZENvbXBvbmVudCggdGhpcy5fZmFjdG9yeSApLnRoZW4oICgpPT4ge1xuICAgICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogUnVuU3RhdGUuTE9BREVEIH0gKTtcbiAgICB9KTtcbiAgfVxuXG4gIGluaXRpYWxpemUoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUkVBRFkgKTtcbiAgfVxuXG4gIHRlYXJkb3duKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLkxPQURFRCApO1xuICB9XG5cbiAgc3RhdGljIGluU3RhdGUoIHN0YXRlczogUnVuU3RhdGVbXSwgcnVuU3RhdGU6IFJ1blN0YXRlICk6IGJvb2xlYW4ge1xuICAgIHJldHVybiBuZXcgU2V0PFJ1blN0YXRlPiggc3RhdGVzICkuaGFzKCBydW5TdGF0ZSApO1xuICB9XG5cbiAgLyoqXG4gICogQWx0ZXIgcnVuLXN0YXRlIG9mIGEgTm9kZSAtIExPQURFRCwgUkVBRFksIFJVTk5JTkcgb3IgUEFVU0VELlxuICAqIFRyaWdnZXJzIFNldHVwIG9yIFRlYXJkb3duIGlmIHRyYW5zaXRpb25pbmcgYmV0d2VlbiBSRUFEWSBhbmQgTE9BREVEXG4gICogV2lyZXVwIGEgZ3JhcGgsIGNyZWF0aW5nIENoYW5uZWwgYmV0d2VlbiBsaW5rZWQgTm9kZXNcbiAgKiBBY3RzIHJlY3Vyc2l2ZWx5LCB3aXJpbmcgdXAgYW55IHN1Yi1ncmFwaHNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgc2V0UnVuU3RhdGUoIG5vZGU6IE5vZGUsIHJ1blN0YXRlOiBSdW5TdGF0ZSApXG4gIHtcbiAgICBsZXQgY3R4ID0gbm9kZS5jb250ZXh0O1xuICAgIGxldCBjdXJyZW50U3RhdGUgPSBjdHgucnVuU3RhdGU7XG5cbiAgICBpZiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApXG4gICAge1xuICAgICAgLy8gMS4gUHJlcHJvY2Vzc1xuICAgICAgLy8gICAgYS4gSGFuZGxlIHRlYXJkb3duXG4gICAgICAvLyAgICBiLiBQcm9wYWdhdGUgc3RhdGUgY2hhbmdlIHRvIHN1Ym5ldHNcbiAgICAgIGxldCBub2RlczogTWFwPHN0cmluZywgTm9kZT4gPSBub2RlLm5vZGVzO1xuXG4gICAgICBpZiAoICggcnVuU3RhdGUgPT0gUnVuU3RhdGUuTE9BREVEICkgJiYgKCBjdXJyZW50U3RhdGUgPj0gUnVuU3RhdGUuUkVBRFkgKSApIHtcbiAgICAgICAgLy8gdGVhcmluZyBkb3duIC4uIHVubGluayBncmFwaCBmaXJzdFxuICAgICAgICBsZXQgbGlua3M6IE1hcDxzdHJpbmcsIExpbms+ID0gbm9kZS5saW5rcztcblxuICAgICAgICAvLyB1bndpcmUgKGRlYWN0aXZhdGUgYW5kIGRlc3Ryb3kgKSBDaGFubmVscyBiZXR3ZWVuIGxpbmtlZCBub2Rlc1xuICAgICAgICBsaW5rcy5mb3JFYWNoKCAoIGxpbmsgKSA9PlxuICAgICAgICB7XG4gICAgICAgICAgTmV0d29yay51bndpcmVMaW5rKCBsaW5rICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH1cblxuICAgICAgLy8gUHJvcGFnYXRlIHN0YXRlIGNoYW5nZSB0byBzdWItbmV0cyBmaXJzdFxuICAgICAgbm9kZXMuZm9yRWFjaCggZnVuY3Rpb24oIHN1Yk5vZGUgKVxuICAgICAge1xuICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBzdWJOb2RlLCBydW5TdGF0ZSApO1xuICAgICAgfSApO1xuXG4gICAgICAvLyAyLiBDaGFuZ2Ugc3RhdGUgLi4uXG4gICAgICBjdHguc2V0UnVuU3RhdGUoIHJ1blN0YXRlICk7XG5cbiAgICAgIC8vIDMuIFBvc3Rwcm9jZXNzXG4gICAgICAvLyAgICBhLiBIYW5kbGUgc2V0dXBcbiAgICAgIGlmICggKCBydW5TdGF0ZSA9PSBSdW5TdGF0ZS5SRUFEWSApICYmICggY3VycmVudFN0YXRlID49IFJ1blN0YXRlLkxPQURFRCApICkge1xuXG4gICAgICAgIC8vIHNldHRpbmcgdXAgLi4gbGlua3VwIGdyYXBoIGZpcnN0XG4gICAgICAgIGxldCBsaW5rczogTWFwPHN0cmluZywgTGluaz4gPSBub2RlLmxpbmtzO1xuICAgICAgICAvLyB0cmVhdCBncmFwaCByZWN1cnNpdmVseVxuXG4gICAgICAgIC8vIDIuIHdpcmV1cCAoY3JlYXRlIGFuZCBhY3RpdmF0ZSkgYSBDaGFubmVsIGJldHdlZW4gbGlua2VkIG5vZGVzXG4gICAgICAgIGxpbmtzLmZvckVhY2goICggbGluayApID0+XG4gICAgICAgIHtcbiAgICAgICAgICBOZXR3b3JrLndpcmVMaW5rKCBsaW5rICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgLy8gQ2hhbmdlIHN0YXRlIC4uLlxuICAgICAgY3R4LnNldFJ1blN0YXRlKCBydW5TdGF0ZSApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIFVud2lyZSBhIGxpbmssIHJlbW92aW5nIHRoZSBDaGFubmVsIGJldHdlZW4gdGhlIGxpbmtlZCBOb2Rlc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyB1bndpcmVMaW5rKCBsaW5rOiBMaW5rIClcbiAge1xuICAgIC8vIGdldCBsaW5rZWQgbm9kZXMgKExpbmsgZmluZHMgTm9kZXMgaW4gcGFyZW50IEdyYXBoKVxuICAgIGxldCBmcm9tTm9kZSA9IGxpbmsuZnJvbU5vZGU7XG4gICAgbGV0IHRvTm9kZSA9IGxpbmsudG9Ob2RlO1xuXG4gICAgbGV0IGNoYW46IENoYW5uZWwgPSBsaW5rLmRpc2Nvbm5lY3QoKTtcblxuICAgIGlmICggY2hhbiApXG4gICAgICBjaGFuLmRlYWN0aXZhdGUoKTtcbiAgfVxuXG4gIC8qKlxuICAqIFdpcmV1cCBhIGxpbmssIGNyZWF0aW5nIENoYW5uZWwgYmV0d2VlbiB0aGUgbGlua2VkIE5vZGVzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHdpcmVMaW5rKCBsaW5rOiBMaW5rIClcbiAge1xuICAgIC8vIGdldCBsaW5rZWQgbm9kZXMgKExpbmsgZmluZHMgTm9kZXMgaW4gcGFyZW50IEdyYXBoKVxuICAgIGxldCBmcm9tTm9kZSA9IGxpbmsuZnJvbU5vZGU7XG4gICAgbGV0IHRvTm9kZSA9IGxpbmsudG9Ob2RlO1xuXG4gICAgLy9kZWJ1Z01lc3NhZ2UoIFwiTGluayhcIitsaW5rLmlkK1wiKTogXCIgKyBsaW5rLmZyb20gKyBcIiAtPiBcIiArIGxpbmsudG8gKyBcIiBwcm90bz1cIitsaW5rLnByb3RvY29sICk7XG5cbiAgICBsZXQgY2hhbm5lbCA9IG5ldyBDaGFubmVsKCk7XG5cbiAgICBsaW5rLmNvbm5lY3QoIGNoYW5uZWwgKTtcblxuICAgIGNoYW5uZWwuYWN0aXZhdGUoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXRSdW5TdGF0ZSggcnVuU3RhdGU6IFJ1blN0YXRlIClcbiAge1xuICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIHRoaXMuX2dyYXBoLCBydW5TdGF0ZSApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogcnVuU3RhdGUgfSApO1xuICB9XG5cbiAgc3RhcnQoIGluaXRpYWxseVBhdXNlZDogYm9vbGVhbiA9IGZhbHNlICkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIGluaXRpYWxseVBhdXNlZCA/IFJ1blN0YXRlLlBBVVNFRCA6IFJ1blN0YXRlLlJVTk5JTkcgKTtcbiAgfVxuXG4gIHN0ZXAoKSB7XG4gICAgLy8gVE9ETzogU2luZ2xlLXN0ZXBcbiAgfVxuXG4gIHN0b3AoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUkVBRFkgKTtcbiAgfVxuXG4gIHBhdXNlKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlBBVVNFRCApO1xuICB9XG5cbiAgcmVzdW1lKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJVTk5JTkcgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeX0gZnJvbSAnLi4vcnVudGltZS9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuXG5pbXBvcnQgeyBOZXR3b3JrIH0gZnJvbSAnLi9uZXR3b3JrJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgTGluayB9IGZyb20gJy4vbGluayc7XG5pbXBvcnQgeyBQb3J0LCBQdWJsaWNQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuLyoqXG4gKiBBIEdyYXBoIGlzIGEgY29sbGVjdGlvbiBvZiBOb2RlcyBpbnRlcmNvbm5lY3RlZCB2aWEgTGlua3MuXG4gKiBBIEdyYXBoIGlzIGl0c2VsZiBhIE5vZGUsIHdob3NlIFBvcnRzIGFjdCBhcyBwdWJsaXNoZWQgRW5kUG9pbnRzLCB0byB0aGUgR3JhcGguXG4gKi9cbmV4cG9ydCBjbGFzcyBHcmFwaCBleHRlbmRzIE5vZGVcbntcbiAgc3RhdGljIEVWRU5UX0FERF9OT0RFID0gJ2dyYXBoOmFkZC1ub2RlJztcbiAgc3RhdGljIEVWRU5UX1VQRF9OT0RFID0gJ2dyYXBoOnVwZC1ub2RlJztcbiAgc3RhdGljIEVWRU5UX0RFTF9OT0RFID0gJ2dyYXBoOmRlbC1ub2RlJztcblxuICBzdGF0aWMgRVZFTlRfQUREX0xJTksgPSAnZ3JhcGg6YWRkLWxpbmsnO1xuICBzdGF0aWMgRVZFTlRfVVBEX0xJTksgPSAnZ3JhcGg6dXBkLWxpbmsnO1xuICBzdGF0aWMgRVZFTlRfREVMX0xJTksgPSAnZ3JhcGg6ZGVsLWxpbmsnO1xuXG4gIC8qKlxuICAqIE5vZGVzIGluIHRoaXMgZ3JhcGguIEVhY2ggbm9kZSBtYXkgYmU6XG4gICogICAxLiBBIENvbXBvbmVudFxuICAqICAgMi4gQSBzdWItZ3JhcGhcbiAgKi9cbiAgcHJvdGVjdGVkIF9ub2RlczogTWFwPHN0cmluZywgTm9kZT47XG5cbiAgLy8gTGlua3MgaW4gdGhpcyBncmFwaC4gRWFjaCBub2RlIG1heSBiZTpcbiAgcHJvdGVjdGVkIF9saW5rczogTWFwPHN0cmluZywgTGluaz47XG5cbiAgLy8gUHVibGljIFBvcnRzIGluIHRoaXMgZ3JhcGguIEluaGVyaXRlZCBmcm9tIE5vZGVcbiAgLy8gcHJpdmF0ZSBQb3J0cztcbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgc3VwZXIoIG93bmVyLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLmluaXRGcm9tT2JqZWN0KCBhdHRyaWJ1dGVzICk7XG4gIH1cblxuICBpbml0RnJvbVN0cmluZygganNvblN0cmluZzogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuaW5pdEZyb21PYmplY3QoIEpTT04ucGFyc2UoIGpzb25TdHJpbmcgKSApO1xuICB9XG5cbiAgaW5pdEZyb21PYmplY3QoIGF0dHJpYnV0ZXM6IGFueSApIHtcblxuICAgIHRoaXMuaWQgPSBhdHRyaWJ1dGVzLmlkIHx8IFwiJGdyYXBoXCI7XG5cbiAgICB0aGlzLl9ub2RlcyA9IG5ldyBNYXA8c3RyaW5nLCBOb2RlPigpO1xuICAgIHRoaXMuX2xpbmtzID0gbmV3IE1hcDxzdHJpbmcsIExpbms+KCk7XG5cbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5ub2RlcyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGROb2RlKCBpZCwgYXR0cmlidXRlcy5ub2Rlc1sgaWQgXSApO1xuICAgIH0pO1xuXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMubGlua3MgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkTGluayggaWQsIGF0dHJpYnV0ZXMubGlua3NbIGlkIF0gKTtcbiAgICB9KTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzOiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgZ3JhcGggPSBzdXBlci50b09iamVjdCgpO1xuXG4gICAgbGV0IG5vZGVzID0gZ3JhcGhbIFwibm9kZXNcIiBdID0ge307XG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbi8vICAgICAgaWYgKCBub2RlICE9IHRoaXMgKVxuICAgICAgICBub2Rlc1sgaWQgXSA9IG5vZGUudG9PYmplY3QoKTtcbiAgICB9KTtcblxuICAgIGxldCBsaW5rcyA9IGdyYXBoWyBcImxpbmtzXCIgXSA9IHt9O1xuICAgIHRoaXMuX2xpbmtzLmZvckVhY2goICggbGluaywgaWQgKSA9PiB7XG4gICAgICBsaW5rc1sgaWQgXSA9IGxpbmsudG9PYmplY3QoKTtcbiAgICB9KTtcblxuICAgIHJldHVybiBncmFwaDtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnkgKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgcGVuZGluZ0NvdW50ID0gMDtcblxuICAgICAgbGV0IG5vZGVzID0gbmV3IE1hcDxzdHJpbmcsIE5vZGU+KCB0aGlzLl9ub2RlcyApO1xuICAgICAgbm9kZXMuc2V0KCAnJGdyYXBoJywgdGhpcyApO1xuXG4gICAgICBub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgICBsZXQgZG9uZTogUHJvbWlzZTx2b2lkPjtcblxuICAgICAgICBwZW5kaW5nQ291bnQrKztcblxuICAgICAgICBpZiAoIG5vZGUgPT0gdGhpcyApIHtcbiAgICAgICAgICBkb25lID0gc3VwZXIubG9hZENvbXBvbmVudCggZmFjdG9yeSApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIGRvbmUgPSBub2RlLmxvYWRDb21wb25lbnQoIGZhY3RvcnkgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGRvbmUudGhlbiggKCkgPT4ge1xuICAgICAgICAgIC0tcGVuZGluZ0NvdW50O1xuICAgICAgICAgIGlmICggcGVuZGluZ0NvdW50ID09IDAgKVxuICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goICggcmVhc29uICkgPT4ge1xuICAgICAgICAgIHJlamVjdCggcmVhc29uICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH0gKTtcbiAgICB9ICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IG5vZGVzKCk6IE1hcDxzdHJpbmcsIE5vZGU+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fbm9kZXM7XG4gIH1cblxuLyogIHB1YmxpYyBnZXRBbGxOb2RlcygpOiBOb2RlW11cbiAge1xuICAgIGxldCBub2RlczogTm9kZVtdID0gW107XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgLy8gRG9uJ3QgcmVjdXJzZSBvbiBncmFwaCdzIHBzZXVkby1ub2RlXG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIG5vZGVzID0gbm9kZXMuY29uY2F0KCBub2RlLmdldEFsbE5vZGVzKCkgKTtcblxuICAgICAgbm9kZXMucHVzaCggbm9kZSApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlcztcbiAgfSovXG5cbiAgcHVibGljIGdldCBsaW5rcygpOiBNYXA8c3RyaW5nLCBMaW5rPlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzO1xuICB9XG5cbi8qICBwdWJsaWMgZ2V0QWxsTGlua3MoKTogTGlua1tdXG4gIHtcbiAgICBsZXQgbGlua3M6IExpbmtbXSA9IFtdO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgbGlua3MgPSBsaW5rcy5jb25jYXQoIG5vZGUuZ2V0QWxsTGlua3MoKSApO1xuICAgIH0gKVxuXG4gICAgdGhpcy5fbGlua3MuZm9yRWFjaCggKCBsaW5rLCBpZCApID0+IHtcbiAgICAgIGxpbmtzLnB1c2goIGxpbmsgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbGlua3M7XG4gIH0qL1xuXG4vKiAgcHVibGljIGdldEFsbFBvcnRzKCk6IFBvcnRbXVxuICB7XG4gICAgbGV0IHBvcnRzOiBQb3J0W10gPSBzdXBlci5nZXRQb3J0QXJyYXkoKTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIHBvcnRzID0gcG9ydHMuY29uY2F0KCBub2RlLmdldEFsbFBvcnRzKCkgKTtcbiAgICAgIGVsc2VcbiAgICAgICAgcG9ydHMgPSBwb3J0cy5jb25jYXQoIG5vZGUuZ2V0UG9ydEFycmF5KCkgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gcG9ydHM7XG4gIH0qL1xuXG4gIHB1YmxpYyBnZXROb2RlQnlJRCggaWQ6IHN0cmluZyApOiBOb2RlXG4gIHtcbiAgICBpZiAoIGlkID09ICckZ3JhcGgnIClcbiAgICAgIHJldHVybiB0aGlzO1xuXG4gICAgcmV0dXJuIHRoaXMuX25vZGVzLmdldCggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBhZGROb2RlKCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzPzoge30gKTogTm9kZSB7XG5cbiAgICBsZXQgbm9kZSA9IG5ldyBOb2RlKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG5cbiAgICBub2RlLmlkID0gaWQ7XG5cbiAgICB0aGlzLl9ub2Rlcy5zZXQoIGlkLCBub2RlICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0FERF9OT0RFLCB7IG5vZGU6IG5vZGUgfSApO1xuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICBwdWJsaWMgcmVuYW1lTm9kZSggaWQ6IHN0cmluZywgbmV3SUQ6IHN0cmluZyApIHtcblxuICAgIGxldCBub2RlID0gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuXG4gICAgaWYgKCBpZCAhPSBuZXdJRCApXG4gICAge1xuICAgICAgbGV0IGV2ZW50RGF0YSA9IHsgbm9kZTogbm9kZSwgYXR0cnM6IHsgaWQ6IG5vZGUuaWQgfSB9O1xuXG4gICAgICB0aGlzLl9ub2Rlcy5kZWxldGUoIGlkICk7XG5cbiAgICAgIG5vZGUuaWQgPSBuZXdJRDtcblxuICAgICAgdGhpcy5fbm9kZXMuc2V0KCBuZXdJRCwgbm9kZSApO1xuXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX1VQRF9OT0RFLCBldmVudERhdGEgKTtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgcmVtb3ZlTm9kZSggaWQ6IHN0cmluZyApOiBib29sZWFuIHtcblxuICAgIGxldCBub2RlID0gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuICAgIGlmICggbm9kZSApXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0RFTF9OT0RFLCB7IG5vZGU6IG5vZGUgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX25vZGVzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXRMaW5rQnlJRCggaWQ6IHN0cmluZyApOiBMaW5rIHtcblxuICAgIHJldHVybiB0aGlzLl9saW5rc1sgaWQgXTtcbiAgfVxuXG4gIHB1YmxpYyBhZGRMaW5rKCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzPzoge30gKTogTGluayB7XG5cbiAgICBsZXQgbGluayA9IG5ldyBMaW5rKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsaW5rLmlkID0gaWQ7XG5cbiAgICB0aGlzLl9saW5rcy5zZXQoIGlkLCBsaW5rICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0FERF9MSU5LLCB7IGxpbms6IGxpbmsgfSApO1xuXG4gICAgcmV0dXJuIGxpbms7XG4gIH1cblxuICBwdWJsaWMgcmVuYW1lTGluayggaWQ6IHN0cmluZywgbmV3SUQ6IHN0cmluZyApIHtcblxuICAgIGxldCBsaW5rID0gdGhpcy5fbGlua3MuZ2V0KCBpZCApO1xuXG4gICAgdGhpcy5fbGlua3MuZGVsZXRlKCBpZCApO1xuXG4gICAgbGV0IGV2ZW50RGF0YSA9IHsgbGluazogbGluaywgYXR0cnM6IHsgaWQ6IGxpbmsuaWQgfSB9O1xuXG4gICAgbGluay5pZCA9IG5ld0lEO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9VUERfTk9ERSwgZXZlbnREYXRhICk7XG5cbiAgICB0aGlzLl9saW5rcy5zZXQoIG5ld0lELCBsaW5rICk7XG4gIH1cblxuICBwdWJsaWMgcmVtb3ZlTGluayggaWQ6IHN0cmluZyApOiBib29sZWFuIHtcblxuICAgIGxldCBsaW5rID0gdGhpcy5fbGlua3MuZ2V0KCBpZCApO1xuICAgIGlmICggbGluayApXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0RFTF9MSU5LLCB7IGxpbms6IGxpbmsgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBhZGRQdWJsaWNQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQdWJsaWNQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFB1YmxpY1BvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG59XG4iLCJpbXBvcnQgeyBNb2R1bGVMb2FkZXIgfSBmcm9tICcuL21vZHVsZS1sb2FkZXInO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeSB9IGZyb20gJy4vY29tcG9uZW50LWZhY3RvcnknO1xuXG5pbXBvcnQgeyBDb250YWluZXIgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuXG5cbmV4cG9ydCBjbGFzcyBTaW11bGF0aW9uRW5naW5lXG57XG4gIGxvYWRlcjogTW9kdWxlTG9hZGVyO1xuICBjb250YWluZXI6IENvbnRhaW5lcjtcblxuICAvKipcbiAgKiBDcmVhdGVzIGFuIGluc3RhbmNlIG9mIFNpbXVsYXRpb25FbmdpbmUuXG4gICogQHBhcmFtIGxvYWRlciBUaGUgbW9kdWxlIGxvYWRlci5cbiAgKiBAcGFyYW0gY29udGFpbmVyIFRoZSByb290IERJIGNvbnRhaW5lciBmb3IgdGhlIHNpbXVsYXRpb24uXG4gICovXG4gIGNvbnN0cnVjdG9yKCBsb2FkZXI6IE1vZHVsZUxvYWRlciwgY29udGFpbmVyOiBDb250YWluZXIgKSB7XG4gICAgdGhpcy5sb2FkZXIgPSBsb2FkZXI7XG4gICAgdGhpcy5jb250YWluZXIgPSBjb250YWluZXI7XG4gIH1cblxuXG4gIC8qKlxuICAqIFJldHVybiBhIENvbXBvbmVudEZhY3RvcnkgZmFjYWRlXG4gICovXG4gIGdldENvbXBvbmVudEZhY3RvcnkoKTogQ29tcG9uZW50RmFjdG9yeSB7XG4gICAgcmV0dXJuIG5ldyBDb21wb25lbnRGYWN0b3J5KCB0aGlzLmNvbnRhaW5lciwgdGhpcy5sb2FkZXIgKTtcbiAgfVxuXG59XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
