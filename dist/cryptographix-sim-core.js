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
    toString(format, opt) {
        let s = "";
        for (var i = 0; i < this.length; ++i)
            s += ("0" + this.byteArray[i].toString(16)).slice(-2);
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
            || (window && window.crypto.subtle)
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

export { Container, inject };

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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeS50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvd2ViY3J5cHRvLnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9kZXMudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS5qcyIsImtpbmQva2luZC50cyIsIm1lc3NhZ2luZy9tZXNzYWdlLnRzIiwicnVudGltZS90YXNrLXNjaGVkdWxlci50cyIsIm1lc3NhZ2luZy9jaGFubmVsLnRzIiwibWVzc2FnaW5nL2VuZC1wb2ludC50cyIsIm1lc3NhZ2luZy9wcm90b2NvbC50cyIsImNvbXBvbmVudC9wb3J0LWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LWluZm8udHMiLCJjb21wb25lbnQvc3RvcmUtaW5mby50cyIsImNvbXBvbmVudC9jb21wb25lbnQudHMiLCJkZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXIudHMiLCJldmVudC1odWIvZXZlbnQtaHViLnRzIiwiZ3JhcGgvcG9ydC50cyIsImdyYXBoL25vZGUudHMiLCJydW50aW1lL3J1bnRpbWUtY29udGV4dC50cyIsInJ1bnRpbWUvbW9kdWxlLWxvYWRlci50cyIsInJ1bnRpbWUvY29tcG9uZW50LWZhY3RvcnkudHMiLCJncmFwaC9saW5rLnRzIiwiZ3JhcGgvbmV0d29yay50cyIsImdyYXBoL2dyYXBoLnRzIiwicnVudGltZS9zaW11bGF0aW9uLWVuZ2luZS50cyJdLCJuYW1lcyI6WyJIZXhDb2RlYyIsIkhleENvZGVjLmRlY29kZSIsIkJBU0U2NFNQRUNJQUxTIiwiQmFzZTY0Q29kZWMiLCJCYXNlNjRDb2RlYy5kZWNvZGUiLCJCYXNlNjRDb2RlYy5kZWNvZGUuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLnB1c2giLCJCYXNlNjRDb2RlYy5lbmNvZGUiLCJCYXNlNjRDb2RlYy5lbmNvZGUuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLnRyaXBsZXRUb0Jhc2U2NCIsIkJ5dGVFbmNvZGluZyIsIkJ5dGVBcnJheSIsIkJ5dGVBcnJheS5jb25zdHJ1Y3RvciIsIkJ5dGVBcnJheS5lbmNvZGluZ1RvU3RyaW5nIiwiQnl0ZUFycmF5LnN0cmluZ1RvRW5jb2RpbmciLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJDcnlwdG9ncmFwaGljT3BlcmF0aW9uIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkuY29uc3RydWN0b3IiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0cnkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmVuY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRpZ2VzdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuc2lnbiIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudmVyaWZ5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5leHBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmdlbmVyYXRlS2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5pbXBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlcml2ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuZGVyaXZlQml0cyIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIud3JhcEtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudW53cmFwS2V5IiwiV2ViQ3J5cHRvU2VydmljZSIsIldlYkNyeXB0b1NlcnZpY2UuY29uc3RydWN0b3IiLCJXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSIsIldlYkNyeXB0b1NlcnZpY2UuZW5jcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGVjcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGlnZXN0IiwiV2ViQ3J5cHRvU2VydmljZS5leHBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLmdlbmVyYXRlS2V5IiwiV2ViQ3J5cHRvU2VydmljZS5pbXBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLnNpZ24iLCJXZWJDcnlwdG9TZXJ2aWNlLnZlcmlmeSIsIkRFU1NlY3JldEtleSIsIkRFU1NlY3JldEtleS5jb25zdHJ1Y3RvciIsIkRFU1NlY3JldEtleS5hbGdvcml0aG0iLCJERVNTZWNyZXRLZXkuZXh0cmFjdGFibGUiLCJERVNTZWNyZXRLZXkudHlwZSIsIkRFU1NlY3JldEtleS51c2FnZXMiLCJERVNTZWNyZXRLZXkua2V5TWF0ZXJpYWwiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZSIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmNvbnN0cnVjdG9yIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZW5jcnlwdCIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlY3J5cHQiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5pbXBvcnRLZXkiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5zaWduIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzLmRlc19jcmVhdGVLZXlzIiwiRW51bSIsIkludGVnZXIiLCJGaWVsZEFycmF5IiwiS2luZEluZm8iLCJLaW5kSW5mby5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyIiwiS2luZEJ1aWxkZXIuY29uc3RydWN0b3IiLCJLaW5kQnVpbGRlci5pbml0IiwiS2luZEJ1aWxkZXIuZmllbGQiLCJLaW5kQnVpbGRlci5ib29sRmllbGQiLCJLaW5kQnVpbGRlci5udW1iZXJGaWVsZCIsIktpbmRCdWlsZGVyLmludGVnZXJGaWVsZCIsIktpbmRCdWlsZGVyLnVpbnQzMkZpZWxkIiwiS2luZEJ1aWxkZXIuYnl0ZUZpZWxkIiwiS2luZEJ1aWxkZXIuc3RyaW5nRmllbGQiLCJLaW5kQnVpbGRlci5raW5kRmllbGQiLCJLaW5kQnVpbGRlci5lbnVtRmllbGQiLCJLaW5kIiwiS2luZC5nZXRLaW5kSW5mbyIsIktpbmQuaW5pdEZpZWxkcyIsIk1lc3NhZ2UiLCJNZXNzYWdlLmNvbnN0cnVjdG9yIiwiTWVzc2FnZS5oZWFkZXIiLCJNZXNzYWdlLnBheWxvYWQiLCJLaW5kTWVzc2FnZSIsIlRhc2tTY2hlZHVsZXIiLCJUYXNrU2NoZWR1bGVyLmNvbnN0cnVjdG9yIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyLnJlcXVlc3RGbHVzaC5oYW5kbGVGbHVzaFRpbWVyIiwiVGFza1NjaGVkdWxlci5zaHV0ZG93biIsIlRhc2tTY2hlZHVsZXIucXVldWVUYXNrIiwiVGFza1NjaGVkdWxlci5mbHVzaFRhc2tRdWV1ZSIsIlRhc2tTY2hlZHVsZXIub25FcnJvciIsIkNoYW5uZWwiLCJDaGFubmVsLmNvbnN0cnVjdG9yIiwiQ2hhbm5lbC5zaHV0ZG93biIsIkNoYW5uZWwuYWN0aXZlIiwiQ2hhbm5lbC5hY3RpdmF0ZSIsIkNoYW5uZWwuZGVhY3RpdmF0ZSIsIkNoYW5uZWwuYWRkRW5kUG9pbnQiLCJDaGFubmVsLnJlbW92ZUVuZFBvaW50IiwiQ2hhbm5lbC5lbmRQb2ludHMiLCJDaGFubmVsLnNlbmRNZXNzYWdlIiwiRGlyZWN0aW9uIiwiRW5kUG9pbnQiLCJFbmRQb2ludC5jb25zdHJ1Y3RvciIsIkVuZFBvaW50LnNodXRkb3duIiwiRW5kUG9pbnQuaWQiLCJFbmRQb2ludC5hdHRhY2giLCJFbmRQb2ludC5kZXRhY2giLCJFbmRQb2ludC5kZXRhY2hBbGwiLCJFbmRQb2ludC5hdHRhY2hlZCIsIkVuZFBvaW50LmRpcmVjdGlvbiIsIkVuZFBvaW50LmhhbmRsZU1lc3NhZ2UiLCJFbmRQb2ludC5zZW5kTWVzc2FnZSIsIkVuZFBvaW50Lm9uTWVzc2FnZSIsIlByb3RvY29sVHlwZUJpdHMiLCJQcm90b2NvbCIsIkNsaWVudFNlcnZlclByb3RvY29sIiwiQVBEVSIsIkFQRFVNZXNzYWdlIiwiQVBEVVByb3RvY29sIiwiUG9ydEluZm8iLCJQb3J0SW5mby5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEluZm8iLCJDb21wb25lbnRJbmZvLmNvbnN0cnVjdG9yIiwiU3RvcmVJbmZvIiwiQ29tcG9uZW50QnVpbGRlciIsIkNvbXBvbmVudEJ1aWxkZXIuY29uc3RydWN0b3IiLCJDb21wb25lbnRCdWlsZGVyLmluaXQiLCJDb21wb25lbnRCdWlsZGVyLmNvbmZpZyIsIkNvbXBvbmVudEJ1aWxkZXIucG9ydCIsIkV2ZW50SHViIiwiRXZlbnRIdWIuY29uc3RydWN0b3IiLCJFdmVudEh1Yi5wdWJsaXNoIiwiRXZlbnRIdWIuc3Vic2NyaWJlIiwiRXZlbnRIdWIuc3Vic2NyaWJlT25jZSIsIlBvcnQiLCJQb3J0LmNvbnN0cnVjdG9yIiwiUG9ydC5lbmRQb2ludCIsIlBvcnQudG9PYmplY3QiLCJQb3J0Lm93bmVyIiwiUG9ydC5wcm90b2NvbElEIiwiUG9ydC5pZCIsIlBvcnQuZGlyZWN0aW9uIiwiUHVibGljUG9ydCIsIlB1YmxpY1BvcnQuY29uc3RydWN0b3IiLCJQdWJsaWNQb3J0LmNvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC5kaXNjb25uZWN0UHJpdmF0ZSIsIlB1YmxpY1BvcnQudG9PYmplY3QiLCJOb2RlIiwiTm9kZS5jb25zdHJ1Y3RvciIsIk5vZGUudG9PYmplY3QiLCJOb2RlLm93bmVyIiwiTm9kZS5pZCIsIk5vZGUudXBkYXRlUG9ydHMiLCJOb2RlLmFkZFBsYWNlaG9sZGVyUG9ydCIsIk5vZGUucG9ydHMiLCJOb2RlLmdldFBvcnRBcnJheSIsIk5vZGUuZ2V0UG9ydEJ5SUQiLCJOb2RlLmlkZW50aWZ5UG9ydCIsIk5vZGUucmVtb3ZlUG9ydCIsIk5vZGUubG9hZENvbXBvbmVudCIsIk5vZGUuY29udGV4dCIsIk5vZGUudW5sb2FkQ29tcG9uZW50IiwiUnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dCIsIlJ1bnRpbWVDb250ZXh0LmNvbnN0cnVjdG9yIiwiUnVudGltZUNvbnRleHQubm9kZSIsIlJ1bnRpbWVDb250ZXh0Lmluc3RhbmNlIiwiUnVudGltZUNvbnRleHQuY29udGFpbmVyIiwiUnVudGltZUNvbnRleHQubG9hZCIsIlJ1bnRpbWVDb250ZXh0LnJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQuaW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnNldFJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQucmVsZWFzZSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkiLCJNb2R1bGVSZWdpc3RyeUVudHJ5LmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeSIsIlN5c3RlbU1vZHVsZUxvYWRlci5sb2FkTW9kdWxlIiwiQ29tcG9uZW50RmFjdG9yeSIsIkNvbXBvbmVudEZhY3RvcnkuY29uc3RydWN0b3IiLCJDb21wb25lbnRGYWN0b3J5LmNyZWF0ZUNvbnRleHQiLCJDb21wb25lbnRGYWN0b3J5LmdldENoaWxkQ29udGFpbmVyIiwiQ29tcG9uZW50RmFjdG9yeS5sb2FkQ29tcG9uZW50IiwiQ29tcG9uZW50RmFjdG9yeS5nZXQiLCJDb21wb25lbnRGYWN0b3J5LnJlZ2lzdGVyIiwiTGluayIsIkxpbmsuY29uc3RydWN0b3IiLCJMaW5rLnRvT2JqZWN0IiwiTGluay5pZCIsIkxpbmsuY29ubmVjdCIsIkxpbmsuZGlzY29ubmVjdCIsIkxpbmsuZnJvbU5vZGUiLCJMaW5rLmZyb21Qb3J0IiwiTGluay50b05vZGUiLCJMaW5rLnRvUG9ydCIsIkxpbmsucHJvdG9jb2xJRCIsIk5ldHdvcmsiLCJOZXR3b3JrLmNvbnN0cnVjdG9yIiwiTmV0d29yay5ncmFwaCIsIk5ldHdvcmsubG9hZENvbXBvbmVudHMiLCJOZXR3b3JrLmluaXRpYWxpemUiLCJOZXR3b3JrLnRlYXJkb3duIiwiTmV0d29yay5pblN0YXRlIiwiTmV0d29yay5zZXRSdW5TdGF0ZSIsIk5ldHdvcmsudW53aXJlTGluayIsIk5ldHdvcmsud2lyZUxpbmsiLCJOZXR3b3JrLnN0YXJ0IiwiTmV0d29yay5zdGVwIiwiTmV0d29yay5zdG9wIiwiTmV0d29yay5wYXVzZSIsIk5ldHdvcmsucmVzdW1lIiwiR3JhcGgiLCJHcmFwaC5jb25zdHJ1Y3RvciIsIkdyYXBoLmluaXRGcm9tU3RyaW5nIiwiR3JhcGguaW5pdEZyb21PYmplY3QiLCJHcmFwaC50b09iamVjdCIsIkdyYXBoLmxvYWRDb21wb25lbnQiLCJHcmFwaC5ub2RlcyIsIkdyYXBoLmxpbmtzIiwiR3JhcGguZ2V0Tm9kZUJ5SUQiLCJHcmFwaC5hZGROb2RlIiwiR3JhcGgucmVuYW1lTm9kZSIsIkdyYXBoLnJlbW92ZU5vZGUiLCJHcmFwaC5nZXRMaW5rQnlJRCIsIkdyYXBoLmFkZExpbmsiLCJHcmFwaC5yZW5hbWVMaW5rIiwiR3JhcGgucmVtb3ZlTGluayIsIkdyYXBoLmFkZFB1YmxpY1BvcnQiLCJTaW11bGF0aW9uRW5naW5lIiwiU2ltdWxhdGlvbkVuZ2luZS5jb25zdHJ1Y3RvciIsIlNpbXVsYXRpb25FbmdpbmUuZ2V0Q29tcG9uZW50RmFjdG9yeSJdLCJtYXBwaW5ncyI6IkFBQUE7SUFJRUEsT0FBT0EsTUFBTUEsQ0FBRUEsQ0FBU0E7UUFFdEJDLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pDQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFHQSxHQUFHQSxrQkFBa0JBLENBQUNBO1lBQzdCQSxJQUFJQSxLQUFLQSxHQUFHQSw2QkFBNkJBLENBQUNBO1lBQzFDQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtZQUN2QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3ZCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsR0FBR0EsR0FBR0EsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7WUFDeEJBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO2dCQUN4QkEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDM0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO2dCQUNqQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLFFBQVFBLENBQUNBLFlBQVlBLEdBQUdBLEdBQUdBLENBQUNBO1FBQzlCQSxDQUFDQTtRQUVEQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtRQUN2QkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDN0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBLEVBQ2pDQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNwQkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsR0FBR0EsQ0FBQ0E7Z0JBQ1RBLEtBQUtBLENBQUNBO1lBQ1ZBLElBQUlBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLFlBQVlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQ2pDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDUkEsUUFBUUEsQ0FBQ0E7WUFDYkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0E7Z0JBQ2ZBLE1BQU1BLDhCQUE4QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDN0NBLElBQUlBLElBQUlBLENBQUNBLENBQUNBO1lBQ1ZBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLFVBQVVBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUNwQkEsR0FBR0EsQ0FBQ0EsSUFBSUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2pCQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQTtnQkFDVEEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDbkJBLENBQUNBO1lBQUNBLElBQUlBLENBQUNBLENBQUNBO2dCQUNKQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQTtZQUNmQSxDQUFDQTtRQUNIQSxDQUFDQTtRQUVEQSxFQUFFQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQTtZQUNiQSxNQUFNQSx5Q0FBeUNBLENBQUNBO1FBRWxEQSxNQUFNQSxDQUFDQSxVQUFVQSxDQUFDQSxJQUFJQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtJQUNoQ0EsQ0FBQ0E7QUFDSEQsQ0FBQ0E7QUFBQTtBQzlDRCxJQUFLLGNBUUo7QUFSRCxXQUFLLGNBQWM7SUFDakJFLHdDQUFPQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQSxVQUFBQSxDQUFBQTtJQUN4QkEseUNBQVFBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLFdBQUFBLENBQUFBO0lBQ3pCQSwwQ0FBU0EsR0FBR0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsWUFBQUEsQ0FBQUE7SUFDMUJBLHlDQUFRQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQSxXQUFBQSxDQUFBQTtJQUN6QkEseUNBQVFBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLFdBQUFBLENBQUFBO0lBQ3pCQSxpREFBZ0JBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLG1CQUFBQSxDQUFBQTtJQUNqQ0Esa0RBQWlCQSxHQUFHQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQSxvQkFBQUEsQ0FBQUE7QUFDcENBLENBQUNBLEVBUkksY0FBYyxLQUFkLGNBQWMsUUFRbEI7QUFFRDtJQUVFQyxPQUFPQSxNQUFNQSxDQUFFQSxHQUFXQTtRQUV4QkMsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLE1BQU1BLElBQUlBLEtBQUtBLENBQUNBLHVEQUF1REEsQ0FBQ0EsQ0FBQ0E7UUFDM0VBLENBQUNBO1FBRURBLGdCQUFpQkEsR0FBV0E7WUFFMUJDLElBQUlBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBRTdCQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxjQUFjQSxDQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxLQUFLQSxjQUFjQSxDQUFDQSxhQUFhQSxDQUFDQTtnQkFDeEVBLE1BQU1BLENBQUNBLEVBQUVBLENBQUNBO1lBRVpBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLGNBQWNBLENBQUNBLEtBQUtBLElBQUlBLElBQUlBLEtBQUtBLGNBQWNBLENBQUNBLGNBQWNBLENBQUNBO2dCQUMxRUEsTUFBTUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7WUFFWkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsY0FBY0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FDbENBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFDQSxNQUFNQSxHQUFHQSxFQUFFQSxDQUFDQTtvQkFDcENBLE1BQU1BLENBQUNBLElBQUlBLEdBQUdBLGNBQWNBLENBQUNBLE1BQU1BLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO2dCQUVoREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsR0FBR0EsY0FBY0EsQ0FBQ0EsS0FBS0EsR0FBR0EsRUFBRUEsQ0FBQ0E7b0JBQ25DQSxNQUFNQSxDQUFDQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFDQSxLQUFLQSxDQUFDQTtnQkFFckNBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLEdBQUdBLGNBQWNBLENBQUNBLEtBQUtBLEdBQUdBLEVBQUVBLENBQUNBO29CQUNuQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsR0FBR0EsY0FBY0EsQ0FBQ0EsS0FBS0EsR0FBR0EsRUFBRUEsQ0FBQ0E7WUFDNUNBLENBQUNBO1lBRURBLE1BQU1BLElBQUlBLEtBQUtBLENBQUNBLDRDQUE0Q0EsQ0FBQ0EsQ0FBQ0E7UUFDaEVBLENBQUNBO1FBT0RELElBQUlBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBQ3JCQSxJQUFJQSxZQUFZQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUd6RkEsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsWUFBWUEsQ0FBRUEsQ0FBQ0E7UUFHOURBLElBQUlBLENBQUNBLEdBQUdBLFlBQVlBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZEQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVWQSxjQUFlQSxDQUFPQTtZQUNwQkUsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDZkEsQ0FBQ0E7UUFFREYsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFakJBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQzdCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMzSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDN0JBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFFQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzlHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUN4QkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRURELE9BQU9BLE1BQU1BLENBQUVBLEtBQWlCQTtRQUU5QkksSUFBSUEsQ0FBU0EsQ0FBQ0E7UUFDZEEsSUFBSUEsVUFBVUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDbENBLElBQUlBLE1BQU1BLEdBQUdBLEVBQUVBLENBQUNBO1FBRWhCQSxNQUFNQSxNQUFNQSxHQUFHQSxrRUFBa0VBLENBQUNBO1FBQ2xGQSxnQkFBaUJBLEdBQVNBO1lBQ3hCQyxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM1QkEsQ0FBQ0E7UUFFREQseUJBQTBCQSxHQUFXQTtZQUNuQ0UsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDNUdBLENBQUNBO1FBR0RGLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLFVBQVVBLENBQUNBO1FBQ3ZDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQTtZQUMvQkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbkVBLE1BQU1BLElBQUlBLGVBQWVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBO1FBQ2xDQSxDQUFDQTtRQUdEQSxNQUFNQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuQkEsS0FBS0EsQ0FBQ0E7Z0JBQ0pBLElBQUlBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO2dCQUNuQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzVCQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDckNBLE1BQU1BLElBQUlBLElBQUlBLENBQUNBO2dCQUNmQSxLQUFLQSxDQUFBQTtZQUNQQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2xFQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDN0JBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQTtnQkFDZEEsS0FBS0EsQ0FBQUE7WUFDUEE7Z0JBQ0VBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO0lBQ2hCQSxDQUFDQTtBQUNISixDQUFDQTtBQUFBO09DaklNLEVBQUUsUUFBUSxFQUFFLE1BQU0sYUFBYTtPQUMvQixFQUFFLFdBQVcsRUFBRSxNQUFNLGdCQUFnQjtBQUU1QyxXQUFZLFlBS1g7QUFMRCxXQUFZLFlBQVk7SUFDdEJPLDZDQUFHQSxDQUFBQTtJQUNIQSw2Q0FBR0EsQ0FBQUE7SUFDSEEsbURBQU1BLENBQUFBO0lBQ05BLCtDQUFJQSxDQUFBQTtBQUNOQSxDQUFDQSxFQUxXLFlBQVksS0FBWixZQUFZLFFBS3ZCO0FBRUQ7SUEyQ0VDLFlBQWFBLEtBQXFFQSxFQUFFQSxRQUFpQkEsRUFBRUEsR0FBU0E7UUFFOUdDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO1lBRUNBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3ZDQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxRQUFRQSxJQUFJQSxRQUFRQSxJQUFJQSxZQUFZQSxDQUFDQSxHQUFJQSxDQUFDQSxDQUNyREEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsV0FBWUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFlQSxLQUFLQSxDQUFFQSxDQUFDQTtZQUN4REEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsVUFBV0EsQ0FBQ0E7Z0JBQ3JDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUN6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsU0FBVUEsQ0FBQ0E7Z0JBQ3BDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUNuQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsS0FBTUEsQ0FBQ0E7Z0JBQ2hDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtRQUs3Q0EsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsS0FBS0EsSUFBSUEsUUFBU0EsQ0FBQ0EsQ0FDcENBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLE1BQU9BLENBQUNBLENBQ3RDQSxDQUFDQTtnQkFDR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDekRBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQ3hDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLElBQUtBLENBQUNBLENBQ3pDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtnQkFDN0JBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBO29CQUN4QkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBRTVDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxFQUFFQSxDQUFDQTtZQUN0QkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBVUEsQ0FBQ0EsQ0FDdEJBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGdDQUFnQ0EsQ0FBQ0EsQ0FBQUE7UUFDcERBLENBQUNBO0lBQ0hBLENBQUNBO0lBcEZERCxPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQXNCQTtRQUM3Q0UsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLE1BQU1BO2dCQUN0QkEsTUFBTUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLElBQUlBO2dCQUNwQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7WUFDaEJBLEtBQUtBLFlBQVlBLENBQUNBLEdBQUdBO2dCQUNuQkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFDZkE7Z0JBQ0VBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBO1FBQ2pCQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVERixPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQWdCQTtRQUN2Q0csRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsV0FBV0EsRUFBRUEsSUFBSUEsUUFBU0EsQ0FBQ0E7WUFDdkNBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLE1BQU1BLENBQUNBO1FBQzdCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxRQUFRQSxDQUFDQSxXQUFXQSxFQUFFQSxJQUFJQSxNQUFPQSxDQUFDQTtZQUMxQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFDM0JBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFdBQVdBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBO1lBQ3pDQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQSxHQUFHQSxDQUFDQTtRQUMxQkEsSUFBSUE7WUFDRkEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBZ0VESCxJQUFJQSxNQUFNQTtRQUVSSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUMvQkEsQ0FBQ0E7SUFFREosSUFBSUEsTUFBTUEsQ0FBRUEsR0FBV0E7UUFFckJJLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLElBQUlBLEdBQUlBLENBQUNBLENBQ25DQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUNsREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDekJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQ3ZDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFREosSUFBSUEsWUFBWUE7UUFFZEssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURMLE1BQU1BLENBQUVBLEtBQWdCQTtRQUV0Qk0sSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFDeEJBLElBQUlBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBO1FBQzFCQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFDQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUVyQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsRUFBR0EsQ0FBQ0EsQ0FDVEEsQ0FBQ0E7WUFDQ0EsR0FBR0EsQ0FBQUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ2hDQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNuQ0EsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7SUFDWkEsQ0FBQ0E7SUFLRE4sTUFBTUEsQ0FBRUEsTUFBY0E7UUFFcEJPLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLENBQUVBLENBQUNBO0lBQ2xDQSxDQUFDQTtJQUVEUCxNQUFNQSxDQUFFQSxNQUFjQTtRQUVwQlEsTUFBTUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsTUFBTUEsQ0FBTUEsSUFBS0EsQ0FBQ0EsQ0FBRUE7Y0FDdENBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLEdBQUdBLENBQUNBLENBQUVBLENBQVFBLENBQUNBO0lBQ2hEQSxDQUFDQTtJQUVEUixrQkFBa0JBLENBQUVBLE1BQU1BO1FBRXhCUyxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxNQUFNQSxDQUFNQSxDQUFFQTtjQUNoQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBRUEsSUFBS0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7SUFDaERBLENBQUNBO0lBRURULE9BQU9BLENBQUVBLE1BQWNBO1FBRXJCVSxNQUFNQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxNQUFNQSxDQUFNQSxJQUFJQSxFQUFFQSxDQUFFQTtjQUN0Q0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBRUEsSUFBSUEsRUFBRUEsQ0FBRUE7Y0FDdENBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLEdBQUdBLENBQUNBLENBQUVBLElBQUtBLENBQUNBLENBQUVBO2NBQ3RDQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFFQSxDQUFRQSxDQUFDQTtJQUNoREEsQ0FBQ0E7SUFNRFYsU0FBU0EsQ0FBRUEsTUFBY0EsRUFBRUEsS0FBYUE7UUFFdENXLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLE1BQU1BLENBQUVBLEdBQUdBLEtBQUtBLENBQUNBO1FBRWpDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVEWCxVQUFVQSxDQUFFQSxNQUFjQSxFQUFFQSxLQUFnQkE7UUFFMUNZLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLEdBQUdBLENBQUVBLEtBQUtBLENBQUNBLFNBQVNBLEVBQUVBLE1BQU1BLENBQUVBLENBQUNBO1FBRTlDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVEWixLQUFLQTtRQUVIYSxNQUFNQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUNqREEsQ0FBQ0E7SUFPRGIsT0FBT0EsQ0FBRUEsTUFBY0EsRUFBRUEsS0FBY0E7UUFFckNjLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLE1BQU1BLENBQUNBLFNBQVNBLENBQUVBLEtBQUtBLENBQUdBLENBQUNBO1lBQy9CQSxLQUFLQSxHQUFHQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUVuQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsQ0FBRUEsTUFBTUEsRUFBRUEsTUFBTUEsR0FBR0EsS0FBS0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDekVBLENBQUNBO0lBT0RkLE1BQU1BLENBQUVBLE1BQWNBLEVBQUVBLEtBQWNBO1FBRXBDZSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxNQUFNQSxDQUFDQSxTQUFTQSxDQUFFQSxLQUFLQSxDQUFHQSxDQUFDQTtZQUMvQkEsS0FBS0EsR0FBR0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFFbkNBLE1BQU1BLENBQUNBLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLFFBQVFBLENBQUVBLE1BQU1BLEVBQUVBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUVBLENBQUVBLENBQUNBO0lBQzVFQSxDQUFDQTtJQU1EZixPQUFPQSxDQUFFQSxLQUFhQTtRQUVwQmdCLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLENBQUVBLEdBQUdBLEtBQUtBLENBQUNBO1FBRWhEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVEaEIsU0FBU0EsQ0FBRUEsR0FBV0E7UUFFcEJpQixJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxHQUFHQSxDQUFDQTtRQUVsQkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFRGpCLE1BQU1BLENBQUVBLEtBQWdCQTtRQUV0QmtCLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1FBRXhCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxFQUFFQSxDQUFDQSxNQUFNQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUU1REEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDekJBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLEdBQUdBLENBQUVBLEtBQUtBLENBQUNBLFNBQVNBLEVBQUVBLEVBQUVBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBO1FBRWpEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVEbEIsR0FBR0E7UUFFRG1CLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1FBRXhCQSxHQUFHQSxDQUFBQSxDQUFFQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtZQUNoQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBRUEsSUFBSUEsQ0FBQ0E7UUFFdEJBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRURuQixHQUFHQSxDQUFFQSxLQUFnQkE7UUFFbkJvQixJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQTtRQUN4QkEsSUFBSUEsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFFMUJBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO1lBQ2hDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUUzQkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFRHBCLEVBQUVBLENBQUVBLEtBQWdCQTtRQUVsQnFCLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1FBQ3hCQSxJQUFJQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtRQUUxQkEsR0FBR0EsQ0FBQUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0E7WUFDaENBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBRTNCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVEckIsR0FBR0EsQ0FBRUEsS0FBZ0JBO1FBRW5Cc0IsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7UUFDeEJBLElBQUlBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBO1FBRTFCQSxHQUFHQSxDQUFBQSxDQUFFQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtZQUNoQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFFM0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRUR0QixRQUFRQSxDQUFFQSxNQUFlQSxFQUFFQSxHQUFTQTtRQUVsQ3VCLElBQUlBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBO1FBQ1hBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENB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Q0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFL0RBLE1BQU1BLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBO2NBQ25DQSxRQUFRQSxDQUFDQSxPQUFPQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxDQUFFQTtjQUNuQ0EsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBYUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lBRURMLE1BQU1BLENBQUNBLFNBQTZCQSxFQUFFQSxJQUFlQTtRQUNuRE0sSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsUUFBUUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFL0RBLE1BQU1BLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBO2NBQ2xDQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQTtjQUM3QkEsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBYUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lBRUROLElBQUlBLENBQUVBLFNBQTZCQSxFQUFFQSxHQUFjQSxFQUFFQSxJQUFlQTtRQUNsRU8sSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsUUFBUUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFL0RBLE1BQU1BLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFFBQVFBLENBQUNBLElBQUlBLENBQUVBO2NBQ2hDQSxRQUFRQSxDQUFDQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxHQUFHQSxFQUFFQSxJQUFJQSxDQUFFQTtjQUNoQ0EsT0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBYUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lB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QTtZQUVqQ0EsT0FBT0EsQ0FBRUEsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7UUFFbkdBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBS09MLEdBQUdBLENBQUVBLEdBQWVBLEVBQUVBLE9BQW1CQSxFQUFFQSxPQUFlQSxFQUFFQSxJQUFZQSxFQUFFQSxFQUFlQSxFQUFFQSxPQUFnQkE7UUFLakhNLHdCQUF5QkEsR0FBR0E7WUFFMUJDLElBQUlBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFFMUNBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO2dCQUVDQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLEdBQUdBO29CQUN0Q0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBRUEsQ0FBRUE7b0JBQzVLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNySkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzlLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxJQUFJQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxDQUFDQSxDQUFFQTtvQkFDM0lBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLElBQUlBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQ3JLQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDakxBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUM3SkEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsR0FBR0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxDQUFDQSxFQUFDQSxJQUFJQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtvQkFDbkpBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUNuTEEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3RLQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxHQUFHQSxFQUFDQSxHQUFHQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxDQUFDQSxDQUFFQTtpQkFDOUdBLENBQUNBO1lBQ0pBLENBQUNBO1lBR0RBLElBQUlBLFVBQVVBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRXhDQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxXQUFXQSxDQUFDQSxFQUFFQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtZQUU1Q0EsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFaEVBLElBQUlBLFFBQVFBLEVBQUVBLFNBQVNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLElBQUlBLENBQUNBO1lBRXhDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUMvQkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLEdBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUN6RUEsS0FBS0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBRXpFQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDbkZBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUcvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0EsQ0FBQ0E7Z0JBRW5EQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDdEdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBO2dCQUdiQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUNwQ0EsQ0FBQ0E7b0JBRUNBLEVBQUVBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO3dCQUNDQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTt3QkFBQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7b0JBQzVFQSxDQUFDQTtvQkFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7b0JBTTVCQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDbkVBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUMzRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzFFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQTtvQkFDL0NBLFNBQVNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNyRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzlFQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDOUVBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUNsREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsU0FBU0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7b0JBQ3BEQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsU0FBU0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3BFQSxDQUFDQTtZQUNIQSxDQUFDQTtZQUVEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtRQUNkQSxDQUFDQTtRQUdERCxJQUFJQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLENBQUNBO1FBRTFDQSxFQUFFQSxDQUFDQSxDQUFFQSxLQUFLQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUN6QkEsQ0FBQ0E7WUFDQ0EsS0FBS0EsR0FBR0EsdUJBQXVCQSxDQUFDQSxLQUFLQSxHQUFHQTtnQkFDdENBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLENBQUNBLFVBQVVBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNyb0JBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLENBQUNBLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEdBQUdBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLEVBQUNBLEdBQUdBLEVBQUNBLFNBQVNBLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO2dCQUN6aUJBLFdBQVdBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLENBQUNBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLEdBQUdBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO2dCQUNqZkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsU0FBU0EsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JtQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3pqQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsVUFBVUEsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsT0FBT0EsRUFBQ0EsVUFBVUEsRUFBQ0EsVUFBVUEsQ0FBQ0EsQ0FBRUE7YUFDdGxCQSxDQUFDQTtRQUNKQSxDQUFDQTtRQUdEQSxJQUFJQSxJQUFJQSxHQUFHQSxjQUFjQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVqQ0EsSUFBSUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsRUFBRUEsT0FBT0EsQ0FBQ0E7UUFDMUNBLElBQUlBLE9BQU9BLEVBQUVBLFFBQVFBLEVBQUVBLFFBQVFBLEVBQUVBLFNBQVNBLENBQUFBO1FBQzFDQSxJQUFJQSxHQUFHQSxHQUFHQSxPQUFPQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUd6QkEsSUFBSUEsVUFBVUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFM0NBLEVBQUVBLENBQUNBLENBQUNBLFVBQVVBLElBQUlBLENBQUNBLENBQUNBLENBQ3BCQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNwREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsT0FBT0EsR0FBR0EsT0FBT0EsR0FBR0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbEdBLENBQUNBO1FBR0RBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLE9BQU9BLElBQUlBLFNBQVNBLENBQUVBLElBQUlBLENBQUVBLE9BQU9BLElBQUlBLENBQUNBLENBQUdBLENBQUNBLENBQ25EQSxDQUFDQTtZQUNDQSxJQUFJQSxlQUFlQSxHQUFHQSxPQUFPQSxDQUFDQTtZQUM5QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFFcEJBLE9BQU9BLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO1lBQ3BDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxlQUFlQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVsQ0EsTUFBTUEsQ0FBQUEsQ0FBRUEsT0FBUUEsQ0FBQ0EsQ0FDakJBLENBQUNBO2dCQUNDQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7b0JBQ3pGQSxLQUFLQSxDQUFDQTtnQkFFUkEsS0FBS0EsQ0FBQ0E7b0JBQ05BLENBQUNBO3dCQUNDQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTt3QkFFOUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUVBLENBQUVBLENBQUNBOzRCQUNYQSxHQUFHQSxJQUFFQSxDQUFDQSxDQUFDQTt3QkFFVEEsS0FBS0EsQ0FBQ0E7b0JBQ1JBLENBQUNBO2dCQUVEQSxLQUFLQSxDQUFDQTtvQkFDSkEsT0FBT0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7b0JBQ3ZGQSxLQUFLQSxDQUFDQTtZQUVWQSxDQUFDQTtZQUVEQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFBQTtRQUNsQkEsQ0FBQ0E7UUFHREEsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFFbkNBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBRVZBLE9BQU9BLEdBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBQ3hFQSxRQUFRQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtRQUMxRUEsQ0FBQ0E7UUFFREEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFHWEEsT0FBT0EsQ0FBQ0EsR0FBR0EsR0FBR0EsRUFDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDekZBLEtBQUtBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO1lBR3pGQSxFQUFFQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUNkQSxDQUFDQTtnQkFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FDWkEsQ0FBQ0E7b0JBQ0NBLElBQUlBLElBQUlBLE9BQU9BLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxRQUFRQSxDQUFDQTtnQkFDckNBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtvQkFDQ0EsUUFBUUEsR0FBR0EsT0FBT0EsQ0FBQ0E7b0JBQ25CQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtvQkFDckJBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBO29CQUNmQSxRQUFRQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDbkJBLENBQUNBO1lBQ0hBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUUvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFDQSxVQUFVQSxFQUFFQSxDQUFDQSxJQUFFQSxDQUFDQSxFQUM1QkEsQ0FBQ0E7Z0JBQ0NBLElBQUlBLE9BQU9BLEdBQUdBLE9BQU9BLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLENBQUNBLENBQUNBO2dCQUMzQkEsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRzNCQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUFFQSxDQUFDQSxJQUFFQSxPQUFPQSxFQUN6Q0EsQ0FBQ0E7b0JBQ0NBLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO29CQUM3QkEsSUFBSUEsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBR3pEQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQTtvQkFDWkEsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0E7b0JBQ2JBLEtBQUtBLEdBQUdBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNyRkEsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQzVFQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDckZBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQU1BLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUNoR0EsQ0FBQ0E7Z0JBRURBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFBQ0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7WUFDMUNBLENBQUNBO1lBR0RBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBQ3JDQSxLQUFLQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUd4Q0EsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFD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QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsS0FBS0EsRUFBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRTVFQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFTQSxDQUFDQSxDQUNwQkEsQ0FBQ0E7d0JBQ0NBLElBQUlBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO3dCQUdoQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ3hCQSxDQUFDQTtnQkFDSEEsQ0FBQ0E7Z0JBQ0RBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLFFBQVFBLENBQUNBLEtBQUtBO2dCQUNqQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRzFDQSxJQUFJQSxTQUFTQSxHQUFlQSxFQUFFQSxDQUFDQTtvQkFFL0JBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFVBQVdBLENBQUNBO3dCQUNwQkEsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsVUFBVUEsQ0FBUUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0E7b0JBRTdEQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFNQSxDQUFDQTt3QkFDZkEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7Z0JBQ3hDQSxDQUFDQTtnQkFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBRWpFQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxJQUFLQSxDQUFDQTt3QkFDZEEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0E7Z0JBQ3pCQSxDQUFDQTtnQkFDREEsSUFBSUE7b0JBQ0ZBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLDZDQUE2Q0EsQ0FBRUEsQ0FBQ0E7Z0JBQ25FQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxRQUFRQSxDQUFDQSxPQUFPQTtnQkFDbkJBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUUzREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBTUEsQ0FBQ0E7d0JBQ2ZBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLENBQUNBO2dCQUMxQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUUvQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0E7d0JBQ2hCQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQTtnQkFDM0JBLENBQUNBO2dCQUNEQSxJQUFJQTtvQkFDRkEsTUFBTUEsSUFBSUEsS0FBS0EsQ0FBRUEsd0NBQXdDQSxDQUFFQSxDQUFDQTtnQkFDOURBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLFFBQVFBLENBQUNBLE1BQU1BO2dCQUNsQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBQ0Es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QSxNQUFNQSxDQUFFQSxDQUFDQTtRQUNsQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFDOUJBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFVBQVVBLENBQUVBLFVBQVVBLENBQUVBLElBQUlBLEtBQUtBLENBQUNBO1FBRXJEQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxVQUFVQSxDQUFDQSxRQUFRQSxJQUFJQSxFQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtJQUM1REEsQ0FBQ0E7SUFFREQsUUFBUUEsQ0FBRUEsSUFBVUE7UUFFbEJFLElBQUlBLElBQUlBLEdBQUdBO1lBQ1RBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1lBQ1pBLFFBQVFBLEVBQUVBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLElBQUlBLEtBQUtBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFNBQVNBO1lBQ3RFQSxRQUFRQSxFQUFFQSxJQUFJQSxDQUFDQSxRQUFRQTtZQUN2QkEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsS0FBS0E7WUFDaEJBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEdBQUdBO1NBQ2JBLENBQUNBO1FBRUZBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRURGLElBQUlBLEVBQUVBLENBQUVBLEVBQVVBO1FBRWhCRyxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUFFQSxDQUFDQTtJQUNoQkEsQ0FBQ0E7SUFFREgsT0FBT0EsQ0FBRUEsT0FBZ0JBO1FBR3ZCSSxJQUFJQSxRQUFRQSxHQUFTQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxDQUFDQTtRQUd2RkEsSUFBSUEsTUFBTUEsR0FBU0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0E7UUFFakZBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLE9BQU9BLENBQUNBO1FBRXhCQSxRQUFRQSxDQUFDQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxPQUFPQSxDQUFFQSxDQUFDQTtRQUNwQ0EsTUFBTUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsT0FBT0EsQ0FBRUEsQ0FBQ0E7SUFDcENBLENBQUNBO0lBRURKLFVBQVVBO1FBRVJLLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBO1FBRXpCQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQSxDQUNYQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxTQUFTQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxRQUFRQTtnQkFDekNBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUNBLFFBQVFBLENBQUVBLENBQUNBO1lBQ25DQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVKQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxTQUFTQSxDQUFDQTtRQUM1QkEsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFREwsSUFBSUEsUUFBUUE7UUFFVk0sTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDdERBLENBQUNBO0lBRUROLElBQUlBLFFBQVFBO1FBRVZPLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBO1FBRXpCQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUN2RkEsQ0FBQ0E7SUFFRFAsSUFBSUEsUUFBUUEsQ0FBRUEsSUFBVUE7UUFFdEJPLElBQUlBLENBQUNBLEtBQUtBLEdBQUdBO1lBQ1hBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLEVBQUVBO1lBQ3JCQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQTtTQUNoQkEsQ0FBQ0E7UUFFRkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0E7SUFDckNBLENBQUNBO0lBRURQLElBQUlBLE1BQU1BO1FBRVJRLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLFdBQVdBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBO0lBQ3BEQSxDQUFDQTtJQUVEUixJQUFJQSxNQUFNQTtRQUVSUyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUV2QkEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsR0FBR0EsU0FBU0EsQ0FBQ0E7SUFDckZBLENBQUNBO0lBRURULElBQUlBLE1BQU1BLENBQUVBLElBQVVBO1FBRXBCUyxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQTtZQUNUQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxFQUFFQTtZQUNyQkEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUE7U0FDaEJBLENBQUNBO1FBRUZBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO0lBQ3JDQSxDQUFDQTtJQUVEVCxJQUFJQSxVQUFV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Q0EsTUFBTUEsQ0FBQ0E7SUFDckJBLENBQUNBO0lBZ0NNUCxXQUFXQSxDQUFFQSxFQUFVQTtRQUU1QlEsRUFBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsSUFBSUEsUUFBU0EsQ0FBQ0E7WUFDbkJBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBRWRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQy9CQSxDQUFDQTtJQUVNUixPQUFPQSxDQUFFQSxFQUFVQSxFQUFFQSxVQUFlQTtRQUV6Q1MsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsSUFBSUEsQ0FBRUEsSUFBSUEsRUFBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7UUFFeENBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO1FBRWJBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO1FBRTVCQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUVyREEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFTVQsVUFBVUEsQ0FBRUEsRUFBVUEsRUFBRUEsS0FBYUE7UUFFMUNVLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBRWpDQSxFQUFFQSxDQUFDQSxDQUFFQSxFQUFFQSxJQUFJQSxLQUFNQSxDQUFDQSxDQUNsQkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsU0FBU0EsR0FBR0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7WUFFdkRBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1lBRXpCQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUVoQkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsS0FBS0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7WUFFL0JBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBQ2xEQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVNVixVQUFVQSxDQUFFQSxFQUFVQTtRQUUzQlcsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDakNBLEVBQUVBLENBQUNBLENBQUVBLElBQUtBLENBQUNBO1lBQ1RBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXZEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUNsQ0EsQ0FBQ0E7SUFFTVgsV0FBV0EsQ0FBRUEsRUFBVUE7UUFFNUJZLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQzNCQSxDQUFDQTtJQUVNWixPQUFPQSxDQUFFQSxFQUFVQSxFQUFFQSxVQUFlQTtRQUV6Q2EsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsSUFBSUEsQ0FBRUEsSUFBSUEsRUFBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7UUFFeENBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO1FBRWJBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO1FBRTVCQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUVyREEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFTWIsVUFBVUEsQ0FBRUEsRUFBVUEsRUFBRUEsS0FBYUE7UUFFMUNjLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV6QkEsSUFBSUEsU0FBU0EsR0FBR0EsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsS0FBS0EsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7UUFFdkRBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEtBQUtBLENBQUNBO1FBRWhCQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUVoREEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsS0FBS0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDakNBLENBQUNBO0lBRU1kLFVBQVVBLENBQUVBLEVBQVVBO1FBRTNCZSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBS0EsQ0FBQ0E7WUFDVEEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFdkRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQ2xDQSxDQUFDQTtJQUVNZixhQUFhQSxDQUFFQSxFQUFVQSxFQUFFQSxVQUFjQTtRQUU5Q2dCLFVBQVVBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBO1FBRXRCQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUVwREEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0FBQ0hoQixDQUFDQTtBQTdQUSxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBQ2xDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUVsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBQ2xDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0F1UHpDOztPQzFRTSxFQUFFLGdCQUFnQixFQUFFLE1BQU0scUJBQXFCO0FBS3REO0lBVUVpQixZQUFhQSxNQUFvQkEsRUFBRUEsU0FBb0JBO1FBQ3JEQyxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxNQUFNQSxDQUFDQTtRQUNyQkEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsU0FBU0EsQ0FBQ0E7SUFDN0JBLENBQUNBO0lBTURELG1CQUFtQkE7UUFDakJFLE1BQU1BLENBQUNBLElBQUlBLGdCQUFnQkEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDN0RBLENBQUNBO0FBRUhGLENBQUNBO0FBQUEiLCJmaWxlIjoiY3J5cHRvZ3JhcGhpeC1zaW0tY29yZS5qcyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBjbGFzcyBIZXhDb2RlY1xue1xuICBwcml2YXRlIHN0YXRpYyBoZXhEZWNvZGVNYXA6IG51bWJlcltdO1xuXG4gIHN0YXRpYyBkZWNvZGUoIGE6IHN0cmluZyApOiBVaW50OEFycmF5XG4gIHtcbiAgICBpZiAoIEhleENvZGVjLmhleERlY29kZU1hcCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIHZhciBoZXggPSBcIjAxMjM0NTY3ODlBQkNERUZcIjtcbiAgICAgIHZhciBhbGxvdyA9IFwiIFxcZlxcblxcclxcdFxcdTAwQTBcXHUyMDI4XFx1MjAyOVwiO1xuICAgICAgdmFyIGRlYzogbnVtYmVyW10gPSBbXTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMTY7ICsraSlcbiAgICAgICAgICBkZWNbaGV4LmNoYXJBdChpKV0gPSBpO1xuICAgICAgaGV4ID0gaGV4LnRvTG93ZXJDYXNlKCk7XG4gICAgICBmb3IgKHZhciBpID0gMTA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFsbG93Lmxlbmd0aDsgKytpKVxuICAgICAgICAgIGRlY1thbGxvdy5jaGFyQXQoaSldID0gLTE7XG4gICAgICBIZXhDb2RlYy5oZXhEZWNvZGVNYXAgPSBkZWM7XG4gICAgfVxuXG4gICAgdmFyIG91dDogbnVtYmVyW10gPSBbXTtcbiAgICB2YXIgYml0cyA9IDAsIGNoYXJfY291bnQgPSAwO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYS5sZW5ndGg7ICsraSlcbiAgICB7XG4gICAgICB2YXIgYyA9IGEuY2hhckF0KGkpO1xuICAgICAgaWYgKGMgPT0gJz0nKVxuICAgICAgICAgIGJyZWFrO1xuICAgICAgdmFyIGIgPSBIZXhDb2RlYy5oZXhEZWNvZGVNYXBbY107XG4gICAgICBpZiAoYiA9PSAtMSlcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgIGlmIChiID09IHVuZGVmaW5lZClcbiAgICAgICAgICB0aHJvdyAnSWxsZWdhbCBjaGFyYWN0ZXIgYXQgb2Zmc2V0ICcgKyBpO1xuICAgICAgYml0cyB8PSBiO1xuICAgICAgaWYgKCsrY2hhcl9jb3VudCA+PSAyKSB7XG4gICAgICAgICAgb3V0LnB1c2goIGJpdHMgKTtcbiAgICAgICAgICBiaXRzID0gMDtcbiAgICAgICAgICBjaGFyX2NvdW50ID0gMDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYml0cyA8PD0gNDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoY2hhcl9jb3VudClcbiAgICAgIHRocm93IFwiSGV4IGVuY29kaW5nIGluY29tcGxldGU6IDQgYml0cyBtaXNzaW5nXCI7XG5cbiAgICByZXR1cm4gVWludDhBcnJheS5mcm9tKCBvdXQgKTtcbiAgfVxufVxuIiwidHlwZSBieXRlID0gbnVtYmVyO1xuXG5lbnVtIEJBU0U2NFNQRUNJQUxTIHtcbiAgUExVUyA9ICcrJy5jaGFyQ29kZUF0KDApLFxuICBTTEFTSCA9ICcvJy5jaGFyQ29kZUF0KDApLFxuICBOVU1CRVIgPSAnMCcuY2hhckNvZGVBdCgwKSxcbiAgTE9XRVIgPSAnYScuY2hhckNvZGVBdCgwKSxcbiAgVVBQRVIgPSAnQScuY2hhckNvZGVBdCgwKSxcbiAgUExVU19VUkxfU0FGRSA9ICctJy5jaGFyQ29kZUF0KDApLFxuICBTTEFTSF9VUkxfU0FGRSA9ICdfJy5jaGFyQ29kZUF0KDApXG59XG5cbmV4cG9ydCBjbGFzcyBCYXNlNjRDb2RlY1xue1xuICBzdGF0aWMgZGVjb2RlKCBiNjQ6IHN0cmluZyApOiBVaW50OEFycmF5XG4gIHtcbiAgICBpZiAoYjY0Lmxlbmd0aCAlIDQgPiAwKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gTGVuZ3RoIG11c3QgYmUgYSBtdWx0aXBsZSBvZiA0Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZGVjb2RlKCBlbHQ6IFN0cmluZyApOiBudW1iZXJcbiAgICB7XG4gICAgICB2YXIgY29kZSA9IGVsdC5jaGFyQ29kZUF0KDApO1xuXG4gICAgICBpZiAoY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuUExVUyB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTX1VSTF9TQUZFKVxuICAgICAgICByZXR1cm4gNjI7IC8vICcrJ1xuXG4gICAgICBpZiAoY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuU0xBU0ggfHwgY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuU0xBU0hfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MzsgLy8gJy8nXG5cbiAgICAgIGlmIChjb2RlID49IEJBU0U2NFNQRUNJQUxTLk5VTUJFUilcbiAgICAgIHtcbiAgICAgICAgaWYgKGNvZGUgPCBCQVNFNjRTUEVDSUFMUy5OVU1CRVIgKyAxMClcbiAgICAgICAgICByZXR1cm4gY29kZSAtIEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDI2ICsgMjY7XG5cbiAgICAgICAgaWYgKGNvZGUgPCBCQVNFNjRTUEVDSUFMUy5VUFBFUiArIDI2KVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuVVBQRVI7XG5cbiAgICAgICAgaWYgKGNvZGUgPCBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2KVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTE9XRVIgKyAyNjtcbiAgICAgIH1cblxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGJhc2U2NCBzdHJpbmcuIENoYXJhY3RlciBub3QgdmFsaWQnKTtcbiAgICB9XG5cbiAgICAvLyB0aGUgbnVtYmVyIG9mIGVxdWFsIHNpZ25zIChwbGFjZSBob2xkZXJzKVxuICAgIC8vIGlmIHRoZXJlIGFyZSB0d28gcGxhY2Vob2xkZXJzLCB0aGFuIHRoZSB0d28gY2hhcmFjdGVycyBiZWZvcmUgaXRcbiAgICAvLyByZXByZXNlbnQgb25lIGJ5dGVcbiAgICAvLyBpZiB0aGVyZSBpcyBvbmx5IG9uZSwgdGhlbiB0aGUgdGhyZWUgY2hhcmFjdGVycyBiZWZvcmUgaXQgcmVwcmVzZW50IDIgYnl0ZXNcbiAgICAvLyB0aGlzIGlzIGp1c3QgYSBjaGVhcCBoYWNrIHRvIG5vdCBkbyBpbmRleE9mIHR3aWNlXG4gICAgbGV0IGxlbiA9IGI2NC5sZW5ndGg7XG4gICAgbGV0IHBsYWNlSG9sZGVycyA9IGI2NC5jaGFyQXQobGVuIC0gMikgPT09ICc9JyA/IDIgOiBiNjQuY2hhckF0KGxlbiAtIDEpID09PSAnPScgPyAxIDogMDtcblxuICAgIC8vIGJhc2U2NCBpcyA0LzMgKyB1cCB0byB0d28gY2hhcmFjdGVycyBvZiB0aGUgb3JpZ2luYWwgZGF0YVxuICAgIGxldCBhcnIgPSBuZXcgVWludDhBcnJheSggYjY0Lmxlbmd0aCAqIDMgLyA0IC0gcGxhY2VIb2xkZXJzICk7XG5cbiAgICAvLyBpZiB0aGVyZSBhcmUgcGxhY2Vob2xkZXJzLCBvbmx5IGdldCB1cCB0byB0aGUgbGFzdCBjb21wbGV0ZSA0IGNoYXJzXG4gICAgbGV0IGwgPSBwbGFjZUhvbGRlcnMgPiAwID8gYjY0Lmxlbmd0aCAtIDQgOiBiNjQubGVuZ3RoO1xuXG4gICAgdmFyIEwgPSAwO1xuXG4gICAgZnVuY3Rpb24gcHVzaCAodjogYnl0ZSkge1xuICAgICAgYXJyW0wrK10gPSB2O1xuICAgIH1cblxuICAgIGxldCBpID0gMCwgaiA9IDA7XG5cbiAgICBmb3IgKDsgaSA8IGw7IGkgKz0gNCwgaiArPSAzKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAxOCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDEpKSA8PCAxMikgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA8PCA2KSB8IGRlY29kZShiNjQuY2hhckF0KGkgKyAzKSk7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDAwMCkgPj4gMTYpO1xuICAgICAgcHVzaCgodG1wICYgMHhGRjAwKSA+PiA4KTtcbiAgICAgIHB1c2godG1wICYgMHhGRik7XG4gICAgfVxuXG4gICAgaWYgKHBsYWNlSG9sZGVycyA9PT0gMikge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMikgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDEpKSA+PiA0KTtcbiAgICAgIHB1c2godG1wICYgMHhGRik7XG4gICAgfSBlbHNlIGlmIChwbGFjZUhvbGRlcnMgPT09IDEpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDEwKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDQpIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAyKSkgPj4gMik7XG4gICAgICBwdXNoKCh0bXAgPj4gOCkgJiAweEZGKTtcbiAgICAgIHB1c2godG1wICYgMHhGRik7XG4gICAgfVxuXG4gICAgcmV0dXJuIGFycjtcbiAgfVxuXG4gIHN0YXRpYyBlbmNvZGUoIHVpbnQ4OiBVaW50OEFycmF5ICk6IHN0cmluZ1xuICB7XG4gICAgdmFyIGk6IG51bWJlcjtcbiAgICB2YXIgZXh0cmFCeXRlcyA9IHVpbnQ4Lmxlbmd0aCAlIDM7IC8vIGlmIHdlIGhhdmUgMSBieXRlIGxlZnQsIHBhZCAyIGJ5dGVzXG4gICAgdmFyIG91dHB1dCA9ICcnO1xuXG4gICAgY29uc3QgbG9va3VwID0gJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nO1xuICAgIGZ1bmN0aW9uIGVuY29kZSggbnVtOiBieXRlICkge1xuICAgICAgcmV0dXJuIGxvb2t1cC5jaGFyQXQobnVtKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB0cmlwbGV0VG9CYXNlNjQoIG51bTogbnVtYmVyICkge1xuICAgICAgcmV0dXJuIGVuY29kZShudW0gPj4gMTggJiAweDNGKSArIGVuY29kZShudW0gPj4gMTIgJiAweDNGKSArIGVuY29kZShudW0gPj4gNiAmIDB4M0YpICsgZW5jb2RlKG51bSAmIDB4M0YpO1xuICAgIH1cblxuICAgIC8vIGdvIHRocm91Z2ggdGhlIGFycmF5IGV2ZXJ5IHRocmVlIGJ5dGVzLCB3ZSdsbCBkZWFsIHdpdGggdHJhaWxpbmcgc3R1ZmYgbGF0ZXJcbiAgICBsZXQgbGVuZ3RoID0gdWludDgubGVuZ3RoIC0gZXh0cmFCeXRlcztcbiAgICBmb3IgKGkgPSAwOyBpIDwgbGVuZ3RoOyBpICs9IDMpIHtcbiAgICAgIGxldCB0ZW1wID0gKHVpbnQ4W2ldIDw8IDE2KSArICh1aW50OFtpICsgMV0gPDwgOCkgKyAodWludDhbaSArIDJdKTtcbiAgICAgIG91dHB1dCArPSB0cmlwbGV0VG9CYXNlNjQodGVtcCk7XG4gICAgfVxuXG4gICAgLy8gcGFkIHRoZSBlbmQgd2l0aCB6ZXJvcywgYnV0IG1ha2Ugc3VyZSB0byBub3QgZm9yZ2V0IHRoZSBleHRyYSBieXRlc1xuICAgIHN3aXRjaCAoZXh0cmFCeXRlcykge1xuICAgICAgY2FzZSAxOlxuICAgICAgICBsZXQgdGVtcCA9IHVpbnQ4W3VpbnQ4Lmxlbmd0aCAtIDFdO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKHRlbXAgPj4gMik7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPDwgNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9ICc9PSc7XG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlIDI6XG4gICAgICAgIHRlbXAgPSAodWludDhbdWludDgubGVuZ3RoIC0gMl0gPDwgOCkgKyAodWludDhbdWludDgubGVuZ3RoIC0gMV0pO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKHRlbXAgPj4gMTApO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKCh0ZW1wID4+IDQpICYgMHgzRik7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPDwgMikgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9ICc9JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHJldHVybiBvdXRwdXQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IEhleENvZGVjIH0gZnJvbSAnLi9oZXgtY29kZWMnO1xuaW1wb3J0IHsgQmFzZTY0Q29kZWMgfSBmcm9tICcuL2Jhc2U2NC1jb2RlYyc7XG5cbmV4cG9ydCBlbnVtIEJ5dGVFbmNvZGluZyB7XG4gIFJBVyxcbiAgSEVYLFxuICBCQVNFNjQsXG4gIFVURjhcbn1cblxuZXhwb3J0IGNsYXNzIEJ5dGVBcnJheSAvL2V4dGVuZHMgVWludDhBcnJheVxue1xuICBwdWJsaWMgc3RhdGljIFJBVyA9IEJ5dGVFbmNvZGluZy5SQVc7XG4gIHB1YmxpYyBzdGF0aWMgSEVYID0gQnl0ZUVuY29kaW5nLkhFWDtcbiAgcHVibGljIHN0YXRpYyBCQVNFNjQgPSBCeXRlRW5jb2RpbmcuQkFTRTY0O1xuICBwdWJsaWMgc3RhdGljIFVURjggPSBCeXRlRW5jb2RpbmcuVVRGODtcblxuICBzdGF0aWMgZW5jb2RpbmdUb1N0cmluZyggZW5jb2Rpbmc6IEJ5dGVFbmNvZGluZyApOiBzdHJpbmcge1xuICAgIHN3aXRjaCggZW5jb2RpbmcgKSB7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5CQVNFNjQ6XG4gICAgICAgIHJldHVybiAnQkFTRTY0JztcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLlVURjg6XG4gICAgICAgIHJldHVybiAnVVRGOCc7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5IRVg6XG4gICAgICAgIHJldHVybiAnSEVYJztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiAnUkFXJztcbiAgICB9XG4gIH1cblxuICBzdGF0aWMgc3RyaW5nVG9FbmNvZGluZyggZW5jb2Rpbmc6IHN0cmluZyApOiBCeXRlRW5jb2Rpbmcge1xuICAgIGlmICggZW5jb2RpbmcudG9VcHBlckNhc2UoKSA9PSAnQkFTRTY0JyApXG4gICAgICByZXR1cm4gQnl0ZUVuY29kaW5nLkJBU0U2NDtcbiAgICBlbHNlIGlmICggZW5jb2RpbmcudG9VcHBlckNhc2UoKSA9PSAnVVRGOCcgKVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5VVEY4O1xuICAgIGVsc2UgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdIRVgnIClcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuSEVYO1xuICAgIGVsc2VcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuUkFXO1xuICB9XG5cblxuICBwcml2YXRlIGJ5dGVBcnJheTogVWludDhBcnJheTtcbiAgLyoqXG4gICAqIENyZWF0ZSBhIEJ5dGVBcnJheVxuICAgKiBAcGFyYW0gYnl0ZXMgLSBpbml0aWFsIGNvbnRlbnRzLCBvcHRpb25hbFxuICAgKiAgIG1heSBiZTpcbiAgICogICAgIGFuIGV4aXN0aW5nIEJ5dGVBcnJheVxuICAgKiAgICAgYW4gQXJyYXkgb2YgbnVtYmVycyAoMC4uMjU1KVxuICAgKiAgICAgYSBzdHJpbmcsIHRvIGJlIGNvbnZlcnRlZFxuICAgKiAgICAgYW4gQXJyYXlCdWZmZXJcbiAgICogICAgIGEgVWludDhBcnJheVxuICAgKi9cbiAgY29uc3RydWN0b3IoIGJ5dGVzPzogQnl0ZUFycmF5IHwgQXJyYXk8bnVtYmVyPiB8IFN0cmluZyB8IEFycmF5QnVmZmVyIHwgVWludDhBcnJheSwgZW5jb2Rpbmc/OiBudW1iZXIsIG9wdD86IGFueSApXG4gIHtcbiAgICBpZiAoICFieXRlcyApXG4gICAge1xuICAgICAgLy8gemVyby1sZW5ndGggYXJyYXlcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDAgKTtcbiAgICB9XG4gICAgZWxzZSBpZiAoICFlbmNvZGluZyB8fCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuUkFXIClcbiAgICB7XG4gICAgICBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCA8QXJyYXlCdWZmZXI+Ynl0ZXMgKTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBieXRlcy5ieXRlQXJyYXk7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJ5dGVzICk7XG4gICAgICAvL2Vsc2UgaWYgKCB0eXBlb2YgYnl0ZXMgPT0gXCJzdHJpbmdcIiApXG4gICAgICAvL3tcbi8vICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICAvL31cbiAgICB9XG4gICAgZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICB7XG4gICAgICBpZiAoIGVuY29kaW5nID09IEJ5dGVFbmNvZGluZy5CQVNFNjQgKVxuICAgICAge1xuICAgICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gQmFzZTY0Q29kZWMuZGVjb2RlKCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLkhFWCApXG4gICAgICB7XG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gSGV4Q29kZWMuZGVjb2RlKCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLlVURjggKVxuICAgICAge1xuICAgICAgICBsZXQgbCA9ICggPHN0cmluZz5ieXRlcyApLmxlbmd0aDtcbiAgICAgICAgbGV0IGJhID0gbmV3IFVpbnQ4QXJyYXkoIGwgKTtcbiAgICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBsOyArK2kgKVxuICAgICAgICAgIGJhW2ldID0gKCA8c3RyaW5nPmJ5dGVzICkuY2hhckNvZGVBdCggaSApO1xuXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYmE7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gTXVzdCBoYXZlIGV4ZWMgb25lIG9mIGFib3ZlIGFsbG9jYXRvcnNcbiAgICBpZiAoICF0aGlzLmJ5dGVBcnJheSApXG4gICAge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIkludmFsaWQgUGFyYW1zIGZvciBCeXRlQXJyYXkoKVwiKVxuICAgIH1cbiAgfVxuXG4gIGdldCBsZW5ndGgoKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xuICB9XG5cbiAgc2V0IGxlbmd0aCggbGVuOiBudW1iZXIgKVxuICB7XG4gICAgaWYgKCB0aGlzLmJ5dGVBcnJheS5sZW5ndGggPj0gbGVuIClcbiAgICB7XG4gICAgICB0aGlzLmJ5dGVBcnJheSA9IHRoaXMuYnl0ZUFycmF5LnNsaWNlKCAwLCBsZW4gKTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxldCBvbGQgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiApO1xuICAgICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBvbGQsIDAgKTtcbiAgICB9XG4gIH1cblxuICBnZXQgYmFja2luZ0FycmF5KCk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheTtcbiAgfVxuXG4gIGVxdWFscyggdmFsdWU6IEJ5dGVBcnJheSApOiBib29sZWFuXG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuICAgIHZhciBvayA9ICggYmEubGVuZ3RoID09IHZiYS5sZW5ndGggKTtcblxuICAgIGlmICggb2sgKVxuICAgIHtcbiAgICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgICBvayA9IG9rICYmICggYmFbaV0gPT0gdmJhW2ldICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG9rO1xuICB9XG5cbiAgLyoqXG4gICAgKiBnZXQgYnl0ZSBhdCBvZmZzZXRcbiAgICAqL1xuICBieXRlQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgXTtcbiAgfVxuXG4gIHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdICAgICAgICk7XG4gIH1cblxuICBsaXR0bGVFbmRpYW5Xb3JkQXQoIG9mZnNldCApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gPDwgIDggKTtcbiAgfVxuXG4gIGR3b3JkQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSA8PCAyNCApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAxNiApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDIgXSA8PCAgOCApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDMgXSAgICAgICApO1xuICB9XG5cbiAgLyoqXG4gICAgKiBzZXQgYnl0ZSBhdCBvZmZzZXRcbiAgICAqIEBmbHVlbnRcbiAgICAqL1xuICBzZXRCeXRlQXQoIG9mZnNldDogbnVtYmVyLCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldEJ5dGVzQXQoIG9mZnNldDogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCB2YWx1ZS5ieXRlQXJyYXksIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjbG9uZSgpOiBCeXRlQXJyYXlcbiAge1xuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSgpICk7XG4gIH1cblxuICAvKipcbiAgKiBFeHRyYWN0IGEgc2VjdGlvbiAob2Zmc2V0LCBjb3VudCkgZnJvbSB0aGUgQnl0ZUFycmF5XG4gICogQGZsdWVudFxuICAqIEByZXR1cm5zIGEgbmV3IEJ5dGVBcnJheSBjb250YWluaW5nIGEgc2VjdGlvbi5cbiAgKi9cbiAgYnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIGNvdW50PzogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgaWYgKCAhTnVtYmVyLmlzSW50ZWdlciggY291bnQgKSApXG4gICAgICBjb3VudCA9ICggdGhpcy5sZW5ndGggLSBvZmZzZXQgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSggb2Zmc2V0LCBvZmZzZXQgKyBjb3VudCApICk7XG4gIH1cblxuICAvKipcbiAgKiBDcmVhdGUgYSB2aWV3IGludG8gdGhlIEJ5dGVBcnJheVxuICAqXG4gICogQHJldHVybnMgYSBCeXRlQXJyYXkgcmVmZXJlbmNpbmcgYSBzZWN0aW9uIG9mIG9yaWdpbmFsIEJ5dGVBcnJheS5cbiAgKi9cbiAgdmlld0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnN1YmFycmF5KCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFwcGVuZCBieXRlXG4gICogQGZsdWVudFxuICAqL1xuICBhZGRCeXRlKCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXlbIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldExlbmd0aCggbGVuOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmxlbmd0aCA9IGxlbjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgY29uY2F0KCBieXRlczogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG5cbiAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCBiYS5sZW5ndGggKyBieXRlcy5sZW5ndGggKTtcblxuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYmEgKTtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIGJ5dGVzLmJ5dGVBcnJheSwgYmEubGVuZ3RoICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG5vdCggKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeMHhGRjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgYW5kKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSAmIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBvciggdmFsdWU6IEJ5dGVBcnJheSApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG5cbiAgICBmb3IoIGxldCBpID0gMDsgaSA8IGJhLmxlbmd0aDsgKytpIClcbiAgICAgIGJhW2ldID0gYmFbaV0gfCB2YmFbIGkgXTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgeG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB0b1N0cmluZyggZm9ybWF0PzogbnVtYmVyLCBvcHQ/OiBhbnkgKVxuICB7XG4gICAgbGV0IHMgPSBcIlwiO1xuICAgIGZvciggdmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICBzICs9ICggXCIwXCIgKyB0aGlzLmJ5dGVBcnJheVsgaSBdLnRvU3RyaW5nKCAxNiApKS5zbGljZSggLTIgKTtcblxuICAgIHJldHVybiBzO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgZW51bSBDcnlwdG9ncmFwaGljT3BlcmF0aW9uIHtcbiAgRU5DUllQVCxcbiAgREVDUllQVCxcbiAgRElHRVNULFxuICBTSUdOLFxuICBWRVJJRlksXG4gIERFUklWRV9CSVRTLFxuXG4gIERFUklWRV9LRVksXG4gIElNUE9SVF9LRVksXG4gIEVYUE9SVF9LRVksXG4gIEdFTkVSQVRFX0tFWSxcbiAgV1JBUF9LRVksXG4gIFVOV1JBUF9LRVksXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBlbmNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuICBkZWNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIGRpZ2VzdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIHNpZ24/KCBhbGdvcml0aG06IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG4gIHZlcmlmeT8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG5cbiAgZGVyaXZlQml0cz8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGxlbmd0aDogbnVtYmVyICk6IFByb21pc2U8Qnl0ZUFycmF5Pjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yIHtcbiAgbmV3KCk6IENyeXB0b2dyYXBoaWNTZXJ2aWNlO1xuXG4gIHN1cHBvcnRlZE9wZXJhdGlvbnM/OiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBkZXJpdmVLZXk/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG5cbiAgd3JhcEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSwgd3JhcHBpbmdLZXk6IENyeXB0b0tleSwgd3JhcEFsZ29yaXRobTogQWxnb3JpdGhtICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcbiAgdW53cmFwS2V5PyggZm9ybWF0OiBzdHJpbmcsIHdyYXBwZWRLZXk6IEJ5dGVBcnJheSwgdW53cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB1bndyYXBBbGdvcml0aG06IEFsZ29yaXRobSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuXG4gIGltcG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG4gIGdlbmVyYXRlS2V5PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj47XG4gIGV4cG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3RvciB7XG4gIG5ldygpOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZTtcblxuICBzdXBwb3J0ZWRPcGVyYXRpb25zPzogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdO1xufVxuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSB7XG4gIHByaXZhdGUgX3NlcnZpY2VNYXA6IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3I+O1xuICBwcml2YXRlIF9rZXlTZXJ2aWNlTWFwOiBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPjtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLl9zZXJ2aWNlTWFwID0gbmV3IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNTZXJ2aWNlQ29uc3RydWN0b3I+KCk7XG4gICAgdGhpcy5fa2V5U2VydmljZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPigpO1xuICB9XG5cbiAgZ2V0U2VydmljZSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0gKTogeyBuYW1lOiBzdHJpbmcsIGluc3RhbmNlOiBDcnlwdG9ncmFwaGljU2VydmljZSB9IHtcbiAgICBsZXQgYWxnbyA9ICggYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0ICkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICBsZXQgc2VydmljZSA9IHRoaXMuX3NlcnZpY2VNYXAuZ2V0KCBhbGdvICk7XG5cbiAgICByZXR1cm4geyBuYW1lOiBhbGdvLCBpbnN0YW5jZTogc2VydmljZSA/IG5ldyBzZXJ2aWNlKCkgOiBudWxsIH07XG4gIH1cblxuICBnZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSApOiB7IG5hbWU6IHN0cmluZywgaW5zdGFuY2U6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0ge1xuICAgIGxldCBhbGdvID0gKCBhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QgKSA/ICg8QWxnb3JpdGhtPmFsZ29yaXRobSkubmFtZSA6IDxzdHJpbmc+YWxnb3JpdGhtO1xuICAgIGxldCBzZXJ2aWNlID0gdGhpcy5fa2V5U2VydmljZU1hcC5nZXQoIGFsZ28gKTtcblxuICAgIHJldHVybiB7IG5hbWU6IGFsZ28sIGluc3RhbmNlOiBzZXJ2aWNlID8gbmV3IHNlcnZpY2UoKSA6IG51bGwgfTtcbiAgfVxuXG4gIHNldFNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fc2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG4gIHNldEtleVNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fa2V5U2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgLy8gc2luZ2xldG9uIHJlZ2lzdHJ5XG4gIHByaXZhdGUgc3RhdGljIF9yZWdpc3RyeTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSA9IG5ldyBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5KCk7XG5cbiAgcHVibGljIHN0YXRpYyByZWdpc3RlclNlcnZpY2UoIG5hbWU6IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLl9yZWdpc3RyeS5zZXRTZXJ2aWNlKCBuYW1lLCBjdG9yLCBvcGVycyApO1xuICB9XG4gIHB1YmxpYyBzdGF0aWMgcmVnaXN0ZXJLZXlTZXJ2aWNlKCBuYW1lOiBzdHJpbmcsIGN0b3I6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3IsIG9wZXJzOiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW10gKSB7XG4gICAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnkuc2V0S2V5U2VydmljZSggbmFtZSwgY3Rvciwgb3BlcnMgKTtcbiAgfVxuXG4gIGdldCByZWdpc3RyeSgpOiBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5IHtcbiAgICByZXR1cm4gQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnk7XG4gIH1cblxuICBlbmNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmVuY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5lbmNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5kZWNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kaWdlc3QgKVxuICAgICAgPyBpbnN0YW5jZS5kaWdlc3QoIG5hbWUsIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBzaWduKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2Uuc2lnbiApXG4gICAgICA/IGluc3RhbmNlLnNpZ24oIG5hbWUsIGtleSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIHZlcmlmeShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UudmVyaWZ5IClcbiAgICAgID8gaW5zdGFuY2UudmVyaWZ5KCBuYW1lLCBrZXksIHNpZ25hdHVyZSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSgga2V5LmFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZXhwb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuZXhwb3J0S2V5KCBmb3JtYXQsIGtleSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGdlbmVyYXRlS2V5KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5nZW5lcmF0ZUtleSApXG4gICAgICA/IGluc3RhbmNlLmdlbmVyYXRlS2V5KCBuYW1lLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oIFwiXCIgKTtcbiAgfVxuXG4gIGltcG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSAsIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuaW1wb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuaW1wb3J0S2V5KCBmb3JtYXQsIGtleURhdGEsIG5hbWUsIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxDcnlwdG9LZXk+KCBcIlwiICk7XG4gIH1cblxuICBkZXJpdmVLZXkoIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGRlcml2ZWRLZXlUeXBlOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZXJpdmVLZXkgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVLZXkoIG5hbWUsIGJhc2VLZXksIGRlcml2ZWRLZXlUeXBlLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG5cbiAgZGVyaXZlQml0cyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgbGVuZ3RoOiBudW1iZXIgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlcml2ZUJpdHMgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVCaXRzKCBuYW1lLCBiYXNlS2V5LCBsZW5ndGggKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB3cmFwS2V5KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IEFsZ29yaXRobSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGtleS5hbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS53cmFwS2V5KCBmb3JtYXQsIGtleSwgd3JhcHBpbmdLZXksIHdyYXBBbGdvcml0aG0gKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB1bndyYXBLZXkoIGZvcm1hdDogc3RyaW5nLCB3cmFwcGVkS2V5OiBCeXRlQXJyYXksIHVud3JhcHBpbmdLZXk6IENyeXB0b0tleSwgdW53cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0sIHVud3JhcHBlZEtleUFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggdW53cmFwQWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS51bndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS51bndyYXBLZXkoIGZvcm1hdCwgd3JhcHBlZEtleSwgdW53cmFwcGluZ0tleSwgbmFtZSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiwgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0gZnJvbSAnLi9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnknO1xuXG5kZWNsYXJlIHZhciBtc3JjcnlwdG87XG5cbmV4cG9ydCBjbGFzcyBXZWJDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgcHJvdGVjdGVkIGNyeXB0bzogU3VidGxlQ3J5cHRvO1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICB9XG5cbiAgc3RhdGljIF9zdWJ0bGU6IFN1YnRsZUNyeXB0bztcbiAgc3RhdGljIGdldCBzdWJ0bGUoKTogU3VidGxlQ3J5cHRvIHtcbiAgICBsZXQgc3VidGxlID0gV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlXG4gICAgICB8fCAoIHdpbmRvdyAmJiB3aW5kb3cuY3J5cHRvLnN1YnRsZSApXG4gICAgICB8fCBtc3JjcnlwdG87XG5cbiAgICBpZiAoICFXZWJDcnlwdG9TZXJ2aWNlLl9zdWJ0bGUgKVxuICAgICAgIFdlYkNyeXB0b1NlcnZpY2UuX3N1YnRsZSA9IHN1YnRsZTtcblxuICAgIHJldHVybiBzdWJ0bGU7XG4gIH1cblxuICBlbmNyeXB0KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmVuY3J5cHQoYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZGVjcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZGVjcnlwdChhbGdvcml0aG0sIGtleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IGFueSB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZGlnZXN0KGFsZ29yaXRobSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZXhwb3J0S2V5KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5leHBvcnRLZXkoZm9ybWF0LCBrZXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBnZW5lcmF0ZUtleSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG5cbiAgIH0pO1xuICB9XG5cbiAgaW1wb3J0S2V5KGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENyeXB0b0tleT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuaW1wb3J0S2V5KGZvcm1hdCwga2V5RGF0YS5iYWNraW5nQXJyYXksIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcylcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKHJlcyk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgIH0pO1xuICB9XG5cbiAgc2lnbihhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuc2lnbihhbGdvcml0aG0sIGtleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICB2ZXJpZnkoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBzaWduYXR1cmU6IEJ5dGVBcnJheSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS52ZXJpZnkoYWxnb3JpdGhtLCBrZXksIHNpZ25hdHVyZS5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG59XG5cbi8qY2xhc3MgU0hBMUNyeXB0b1NlcnZpY2UgaW1wbGVtZW50cyBDcnlwdG9ncmFwaGljU2VydmljZSB7XG4gIGRpZ2VzdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIFRPRE86IEltcGxlbWVudCBTSEEtMVxuICAgICAgbXNyY3J5cHRvLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxufVxuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS0xJywgU0hBMUNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ESUdFU1QgXSApO1xuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS0yNTYnLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnU0hBLTUxMicsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ESUdFU1QgXSApO1xuKi9cblxuaWYgKCBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSApIHtcbiAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdBRVMtQ0JDJywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkVOQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uREVDUllQVCBdICk7XG4gIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnQUVTLUdDTScsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQgXSApO1xuICAvL0NyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnUlNBU1NBLVhZWicsIFdlYkNyeXB0b1NlcnZpY2UgKTtcblxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi4va2luZC9ieXRlLWFycmF5JztcbmltcG9ydCB7IENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24sIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB9IGZyb20gJy4vY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlLXJlZ2lzdHJ5JztcblxuY2xhc3MgREVTU2VjcmV0S2V5IGltcGxlbWVudHMgQ3J5cHRvS2V5IHtcbiAgcHJpdmF0ZSBfa2V5TWF0ZXJpYWw6IEJ5dGVBcnJheTtcbiAgcHJpdmF0ZSBfZXh0cmFjdGFibGU6IGJvb2xlYW47XG4gIHByaXZhdGUgX2FsZ29yaXRobTogS2V5QWxnb3JpdGhtO1xuICBwcml2YXRlIF90eXBlOiBzdHJpbmc7XG4gIHByaXZhdGUgX3VzYWdlczogc3RyaW5nW107XG5cbiAgY29uc3RydWN0b3IoIGtleU1hdGVyaWFsOiBCeXRlQXJyYXksIGFsZ29yaXRobTogS2V5QWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwgdXNhZ2VzOiBzdHJpbmdbXSApIHtcblxuICAgIHRoaXMuX2tleU1hdGVyaWFsID0ga2V5TWF0ZXJpYWw7XG5cbiAgICB0aGlzLl9hbGdvcml0aG0gPSBhbGdvcml0aG07XG5cbiAgICB0aGlzLl9leHRyYWN0YWJsZSA9IGV4dHJhY3RhYmxlO1xuXG4gICAgdGhpcy5fdHlwZSA9ICdzZWNyZXQnO1xuXG4gICAgdGhpcy5fdXNhZ2VzID0gdXNhZ2VzO1xuICAgIE9iamVjdC5mcmVlemUoIHRoaXMuX3VzYWdlcyApO1xuICB9XG5cbiAgZ2V0IGFsZ29yaXRobSgpIHsgcmV0dXJuIHRoaXMuX2FsZ29yaXRobTsgfVxuICBnZXQgZXh0cmFjdGFibGUoKTogYm9vbGVhbiB7IHJldHVybiB0aGlzLl9leHRyYWN0YWJsZTsgfVxuICBnZXQgdHlwZSgpIHsgcmV0dXJuIHRoaXMuX3R5cGU7IH1cbiAgZ2V0IHVzYWdlcygpOiBzdHJpbmdbXSB7IHJldHVybiBBcnJheS5mcm9tKCB0aGlzLl91c2FnZXMgKTsgfVxuXG4gIGdldCBrZXlNYXRlcmlhbCgpIHsgcmV0dXJuIHRoaXMuX2tleU1hdGVyaWFsIH07XG59XG5cbmV4cG9ydCBjbGFzcyBERVNDcnlwdG9ncmFwaGljU2VydmljZSBpbXBsZW1lbnRzIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKCkge1xuICB9XG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcblxuICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAxLCAwICkgKSApO1xuICAgIH0pO1xuICB9XG5cbiAgZGVjcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcblxuICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAwLCAwICkgKSApO1xuICAgICAgLy9jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGltcG9ydEtleShmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5LCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBuZXcgREVTU2VjcmV0S2V5KCBrZXlEYXRhLCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKTtcblxuICAgICAgcmVzb2x2ZSggZGVzS2V5ICk7XG4gICB9KTtcbiAgfVxuXG4gIHNpZ24oIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcblxuICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAwLCAwICkgKSApO1xuICAgICAgLy9jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHN0YXRpYyBkZXNQQztcbiAgc3RhdGljIGRlc1NQO1xuXG4gIHByaXZhdGUgZGVzKCBrZXk6IFVpbnQ4QXJyYXksIG1lc3NhZ2U6IFVpbnQ4QXJyYXksIGVuY3J5cHQ6IG51bWJlciwgbW9kZTogbnVtYmVyLCBpdj86IFVpbnQ4QXJyYXksIHBhZGRpbmc/OiBudW1iZXIgKTogVWludDhBcnJheVxuICB7XG4gICAgLy9kZXNfY3JlYXRlS2V5c1xuICAgIC8vdGhpcyB0YWtlcyBhcyBpbnB1dCBhIDY0IGJpdCBrZXkgKGV2ZW4gdGhvdWdoIG9ubHkgNTYgYml0cyBhcmUgdXNlZClcbiAgICAvL2FzIGFuIGFycmF5IG9mIDIgaW50ZWdlcnMsIGFuZCByZXR1cm5zIDE2IDQ4IGJpdCBrZXlzXG4gICAgZnVuY3Rpb24gZGVzX2NyZWF0ZUtleXMgKGtleSlcbiAgICB7XG4gICAgICBsZXQgZGVzUEMgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNQQztcblxuICAgICAgaWYgKCAhZGVzUEMgKVxuICAgICAge1xuICAgICAgICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICAgICAgICBkZXNQQyA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1BDID0ge1xuICAgICAgICAgIHBjMmJ5dGVzMCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NCwweDIwMDAwMDAwLDB4MjAwMDAwMDQsMHgxMDAwMCwweDEwMDA0LDB4MjAwMTAwMDAsMHgyMDAxMDAwNCwweDIwMCwweDIwNCwweDIwMDAwMjAwLDB4MjAwMDAyMDQsMHgxMDIwMCwweDEwMjA0LDB4MjAwMTAyMDAsMHgyMDAxMDIwNCBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxLDB4MTAwMDAwLDB4MTAwMDAxLDB4NDAwMDAwMCwweDQwMDAwMDEsMHg0MTAwMDAwLDB4NDEwMDAwMSwweDEwMCwweDEwMSwweDEwMDEwMCwweDEwMDEwMSwweDQwMDAxMDAsMHg0MDAwMTAxLDB4NDEwMDEwMCwweDQxMDAxMDFdICksXG4gICAgICAgICAgcGMyYnl0ZXMyIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOCwwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMzIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMDAwMDAsMHg4MDAwMDAwLDB4ODIwMDAwMCwweDIwMDAsMHgyMDIwMDAsMHg4MDAyMDAwLDB4ODIwMjAwMCwweDIwMDAwLDB4MjIwMDAwLDB4ODAyMDAwMCwweDgyMjAwMDAsMHgyMjAwMCwweDIyMjAwMCwweDgwMjIwMDAsMHg4MjIyMDAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMHgxMDAwLDB4NDEwMDAsMHgxMDEwLDB4NDEwMTAsMHgxMDAwLDB4NDEwMDAsMHgxMDEwLDB4NDEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXM1IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAsMHgyMCwweDQyMCwwLDB4NDAwLDB4MjAsMHg0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMF0gKSxcbiAgICAgICAgICBwYzJieXRlczYgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDIsMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDJdICksXG4gICAgICAgICAgcGMyYnl0ZXM3IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMCwweDgwMCwweDEwODAwLDB4MjAwMDAwMDAsMHgyMDAxMDAwMCwweDIwMDAwODAwLDB4MjAwMTA4MDAsMHgyMDAwMCwweDMwMDAwLDB4MjA4MDAsMHgzMDgwMCwweDIwMDIwMDAwLDB4MjAwMzAwMDAsMHgyMDAyMDgwMCwweDIwMDMwODAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwMDAsMCwweDQwMDAwLDB4MiwweDQwMDAyLDB4MiwweDQwMDAyLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDIsMHgyMDQwMDAyLDB4MjAwMDAwMiwweDIwNDAwMDJdICksXG4gICAgICAgICAgcGMyYnl0ZXM5IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOF0gKSxcbiAgICAgICAgICBwYzJieXRlczEwOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDIwLDAsMHgyMCwweDEwMDAwMCwweDEwMDAyMCwweDEwMDAwMCwweDEwMDAyMCwweDIwMDAsMHgyMDIwLDB4MjAwMCwweDIwMjAsMHgxMDIwMDAsMHgxMDIwMjAsMHgxMDIwMDAsMHgxMDIwMjBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMTogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwLDB4MjAwLDB4MTAwMDIwMCwweDIwMDAwMCwweDEyMDAwMDAsMHgyMDAyMDAsMHgxMjAwMjAwLDB4NDAwMDAwMCwweDUwMDAwMDAsMHg0MDAwMjAwLDB4NTAwMDIwMCwweDQyMDAwMDAsMHg1MjAwMDAwLDB4NDIwMDIwMCwweDUyMDAyMDBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMjogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwLDB4ODAwMDAwMCwweDgwMDEwMDAsMHg4MDAwMCwweDgxMDAwLDB4ODA4MDAwMCwweDgwODEwMDAsMHgxMCwweDEwMTAsMHg4MDAwMDEwLDB4ODAwMTAxMCwweDgwMDEwLDB4ODEwMTAsMHg4MDgwMDEwLDB4ODA4MTAxMF0gKSxcbiAgICAgICAgICBwYzJieXRlczEzOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgxMDAsMHgxMDQsMCwweDQsMHgxMDAsMHgxMDQsMHgxLDB4NSwweDEwMSwweDEwNSwweDEsMHg1LDB4MTAxLDB4MTA1XSApXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIC8vaG93IG1hbnkgaXRlcmF0aW9ucyAoMSBmb3IgZGVzLCAzIGZvciB0cmlwbGUgZGVzKVxuICAgICAgdmFyIGl0ZXJhdGlvbnMgPSBrZXkubGVuZ3RoID4gOCA/IDMgOiAxOyAvL2NoYW5nZWQgYnkgUGF1bCAxNi82LzIwMDcgdG8gdXNlIFRyaXBsZSBERVMgZm9yIDkrIGJ5dGUga2V5c1xuICAgICAgLy9zdG9yZXMgdGhlIHJldHVybiBrZXlzXG4gICAgICB2YXIga2V5cyA9IG5ldyBVaW50MzJBcnJheSgzMiAqIGl0ZXJhdGlvbnMpO1xuICAgICAgLy9ub3cgZGVmaW5lIHRoZSBsZWZ0IHNoaWZ0cyB3aGljaCBuZWVkIHRvIGJlIGRvbmVcbiAgICAgIHZhciBzaGlmdHMgPSBbIDAsIDAsIDEsIDEsIDEsIDEsIDEsIDEsIDAsIDEsIDEsIDEsIDEsIDEsIDEsIDAgXTtcbiAgICAgIC8vb3RoZXIgdmFyaWFibGVzXG4gICAgICB2YXIgbGVmdHRlbXAsIHJpZ2h0dGVtcCwgbT0wLCBuPTAsIHRlbXA7XG5cbiAgICAgIGZvciAodmFyIGo9MDsgajxpdGVyYXRpb25zOyBqKyspXG4gICAgICB7IC8vZWl0aGVyIDEgb3IgMyBpdGVyYXRpb25zXG4gICAgICAgIGxlZnQgPSAgKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcbiAgICAgICAgcmlnaHQgPSAoa2V5W20rK10gPDwgMjQpIHwgKGtleVttKytdIDw8IDE2KSB8IChrZXlbbSsrXSA8PCA4KSB8IGtleVttKytdO1xuXG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMikgXiByaWdodCkgJiAweDMzMzMzMzMzOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICAgIC8vdGhlIHJpZ2h0IHNpZGUgbmVlZHMgdG8gYmUgc2hpZnRlZCBhbmQgdG8gZ2V0IHRoZSBsYXN0IGZvdXIgYml0cyBvZiB0aGUgbGVmdCBzaWRlXG4gICAgICAgIHRlbXAgPSAobGVmdCA8PCA4KSB8ICgocmlnaHQgPj4+IDIwKSAmIDB4MDAwMDAwZjApO1xuICAgICAgICAvL2xlZnQgbmVlZHMgdG8gYmUgcHV0IHVwc2lkZSBkb3duXG4gICAgICAgIGxlZnQgPSAocmlnaHQgPDwgMjQpIHwgKChyaWdodCA8PCA4KSAmIDB4ZmYwMDAwKSB8ICgocmlnaHQgPj4+IDgpICYgMHhmZjAwKSB8ICgocmlnaHQgPj4+IDI0KSAmIDB4ZjApO1xuICAgICAgICByaWdodCA9IHRlbXA7XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGVzZSBzaGlmdHMgb24gdGhlIGxlZnQgYW5kIHJpZ2h0IGtleXNcbiAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgc2hpZnRzLmxlbmd0aDsgaSsrKVxuICAgICAgICB7XG4gICAgICAgICAgLy9zaGlmdCB0aGUga2V5cyBlaXRoZXIgb25lIG9yIHR3byBiaXRzIHRvIHRoZSBsZWZ0XG4gICAgICAgICAgaWYgKHNoaWZ0c1tpXSlcbiAgICAgICAgICB7XG4gICAgICAgICAgICBsZWZ0ID0gKGxlZnQgPDwgMikgfCAobGVmdCA+Pj4gMjYpOyByaWdodCA9IChyaWdodCA8PCAyKSB8IChyaWdodCA+Pj4gMjYpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBlbHNlXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDI3KTsgcmlnaHQgPSAocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDI3KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgbGVmdCAmPSAtMHhmOyByaWdodCAmPSAtMHhmO1xuXG4gICAgICAgICAgLy9ub3cgYXBwbHkgUEMtMiwgaW4gc3VjaCBhIHdheSB0aGF0IEUgaXMgZWFzaWVyIHdoZW4gZW5jcnlwdGluZyBvciBkZWNyeXB0aW5nXG4gICAgICAgICAgLy90aGlzIGNvbnZlcnNpb24gd2lsbCBsb29rIGxpa2UgUEMtMiBleGNlcHQgb25seSB0aGUgbGFzdCA2IGJpdHMgb2YgZWFjaCBieXRlIGFyZSB1c2VkXG4gICAgICAgICAgLy9yYXRoZXIgdGhhbiA0OCBjb25zZWN1dGl2ZSBiaXRzIGFuZCB0aGUgb3JkZXIgb2YgbGluZXMgd2lsbCBiZSBhY2NvcmRpbmcgdG9cbiAgICAgICAgICAvL2hvdyB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zIHdpbGwgYmUgYXBwbGllZDogUzIsIFM0LCBTNiwgUzgsIFMxLCBTMywgUzUsIFM3XG4gICAgICAgICAgbGVmdHRlbXAgPSBkZXNQQy5wYzJieXRlczBbbGVmdCA+Pj4gMjhdIHwgZGVzUEMucGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczJbKGxlZnQgPj4+IDIwKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczNbKGxlZnQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzNFsobGVmdCA+Pj4gMTIpICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzNVsobGVmdCA+Pj4gOCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczZbKGxlZnQgPj4+IDQpICYgMHhmXTtcbiAgICAgICAgICByaWdodHRlbXAgPSBkZXNQQy5wYzJieXRlczdbcmlnaHQgPj4+IDI4XSB8IGRlc1BDLnBjMmJ5dGVzOFsocmlnaHQgPj4+IDI0KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczlbKHJpZ2h0ID4+PiAyMCkgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczExWyhyaWdodCA+Pj4gMTIpICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzMTJbKHJpZ2h0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczEzWyhyaWdodCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjtcbiAgICAgICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICAgICAgfVxuICAgICAgfSAvL2ZvciBlYWNoIGl0ZXJhdGlvbnNcblxuICAgICAgcmV0dXJuIGtleXM7XG4gICAgfSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG4gICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICBsZXQgZGVzU1AgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNTUDtcblxuICAgIGlmICggZGVzU1AgPT0gdW5kZWZpbmVkIClcbiAgICB7XG4gICAgICBkZXNTUCA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1NQID0ge1xuICAgICAgICBzcGZ1bmN0aW9uMTogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDEwNDAwLDAsMHgxMDAwMCwweDEwMTA0MDQsMHgxMDEwMDA0LDB4MTA0MDQsMHg0LDB4MTAwMDAsMHg0MDAsMHgxMDEwNDAwLDB4MTAxMDQwNCwweDQwMCwweDEwMDA0MDQsMHgxMDEwMDA0LDB4MTAwMDAwMCwweDQsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwweDEwNDAwLDB4MTA0MDAsMHgxMDEwMDAwLDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwNCwweDEwMDAwMDQsMHgxMDAwMDA0LDB4MTAwMDQsMCwweDQwNCwweDEwNDA0LDB4MTAwMDAwMCwweDEwMDAwLDB4MTAxMDQwNCwweDQsMHgxMDEwMDAwLDB4MTAxMDQwMCwweDEwMDAwMDAsMHgxMDAwMDAwLDB4NDAwLDB4MTAxMDAwNCwweDEwMDAwLDB4MTA0MDAsMHgxMDAwMDA0LDB4NDAwLDB4NCwweDEwMDA0MDQsMHgxMDQwNCwweDEwMTA0MDQsMHgxMDAwNCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDAwNCwweDQwNCwweDEwNDA0LDB4MTAxMDQwMCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDAsMHgxMDAwNCwweDEwNDAwLDAsMHgxMDEwMDA0XSApLFxuICAgICAgICBzcGZ1bmN0aW9uMjogbmV3IFVpbnQzMkFycmF5KCBbLTB4N2ZlZjdmZTAsLTB4N2ZmZjgwMDAsMHg4MDAwLDB4MTA4MDIwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsLTB4N2ZlZjdmZTAsLTB4N2ZlZjgwMDAsLTB4ODAwMDAwMDAsLTB4N2ZmZjgwMDAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwweDEwODAwMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwwLC0weDgwMDAwMDAwLDB4ODAwMCwweDEwODAyMCwtMHg3ZmYwMDAwMCwweDEwMDAyMCwtMHg3ZmZmZmZlMCwwLDB4MTA4MDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwtMHg3ZmYwMDAwMCwweDgwMjAsMCwweDEwODAyMCwtMHg3ZmVmZmZlMCwweDEwMDAwMCwtMHg3ZmZmN2ZlMCwtMHg3ZmYwMDAwMCwtMHg3ZmVmODAwMCwweDgwMDAsLTB4N2ZmMDAwMDAsLTB4N2ZmZjgwMDAsMHgyMCwtMHg3ZmVmN2ZlMCwweDEwODAyMCwweDIwLDB4ODAwMCwtMHg4MDAwMDAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsMHgxMDAwMDAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsMHgxMDgwMDAsMCwtMHg3ZmZmODAwMCwweDgwMjAsLTB4ODAwMDAwMDAsLTB4N2ZlZmZmZTAsLTB4N2ZlZjdmZTAsMHgxMDgwMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb24zOiBuZXcgVWludDMyQXJyYXkoIFsweDIwOCwweDgwMjAyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjAwLDAsMHgyMDIwOCwweDgwMDAyMDAsMHgyMDAwOCwweDgwMDAwMDgsMHg4MDAwMDA4LDB4MjAwMDAsMHg4MDIwMjA4LDB4MjAwMDgsMHg4MDIwMDAwLDB4MjA4LDB4ODAwMDAwMCwweDgsMHg4MDIwMjAwLDB4MjAwLDB4MjAyMDAsMHg4MDIwMDAwLDB4ODAyMDAwOCwweDIwMjA4LDB4ODAwMDIwOCwweDIwMjAwLDB4MjAwMDAsMHg4MDAwMjA4LDB4OCwweDgwMjAyMDgsMHgyMDAsMHg4MDAwMDAwLDB4ODAyMDIwMCwweDgwMDAwMDAsMHgyMDAwOCwweDIwOCwweDIwMDAwLDB4ODAyMDIwMCwweDgwMDAyMDAsMCwweDIwMCwweDIwMDA4LDB4ODAyMDIwOCwweDgwMDAyMDAsMHg4MDAwMDA4LDB4MjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwOCwweDIwMDAwLDB4ODAwMDAwMCwweDgwMjAyMDgsMHg4LDB4MjAyMDgsMHgyMDIwMCwweDgwMDAwMDgsMHg4MDIwMDAwLDB4ODAwMDIwOCwweDIwOCwweDgwMjAwMDAsMHgyMDIwOCwweDgsMHg4MDIwMDA4LDB4MjAyMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb240OiBuZXcgVWludDMyQXJyYXkoIFsweDgwMjAwMSwweDIwODEsMHgyMDgxLDB4ODAsMHg4MDIwODAsMHg4MDAwODEsMHg4MDAwMDEsMHgyMDAxLDAsMHg4MDIwMDAsMHg4MDIwMDAsMHg4MDIwODEsMHg4MSwwLDB4ODAwMDgwLDB4ODAwMDAxLDB4MSwweDIwMDAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDEsMHgyMDgwLDB4ODAwMDgxLDB4MSwweDIwODAsMHg4MDAwODAsMHgyMDAwLDB4ODAyMDgwLDB4ODAyMDgxLDB4ODEsMHg4MDAwODAsMHg4MDAwMDEsMHg4MDIwMDAsMHg4MDIwODEsMHg4MSwwLDAsMHg4MDIwMDAsMHgyMDgwLDB4ODAwMDgwLDB4ODAwMDgxLDB4MSwweDgwMjAwMSwweDIwODEsMHgyMDgxLDB4ODAsMHg4MDIwODEsMHg4MSwweDEsMHgyMDAwLDB4ODAwMDAxLDB4MjAwMSwweDgwMjA4MCwweDgwMDA4MSwweDIwMDEsMHgyMDgwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAwLDB4ODAyMDgwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNTogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAsMHgyMDgwMTAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4ODAwMDAsMHgxMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MDA4MDEwMCwweDgwMDAwLDB4MjAwMDEwMCwweDQwMDgwMTAwLDB4NDIwMDAxMDAsMHg0MjA4MDAwMCwweDgwMTAwLDB4NDAwMDAwMDAsMHgyMDAwMDAwLDB4NDAwODAwMDAsMHg0MDA4MDAwMCwwLDB4NDAwMDAxMDAsMHg0MjA4MDEwMCwweDQyMDgwMTAwLDB4MjAwMDEwMCwweDQyMDgwMDAwLDB4NDAwMDAxMDAsMCwweDQyMDAwMDAwLDB4MjA4MDEwMCwweDIwMDAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4ODAwMDAsMHg0MjAwMDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDQwMDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMDAwLDB4NDIwODAwMDAsMHgyMDgwMTAwLDB4NDAwODAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDIwODAwMDAsMHg0MjA4MDEwMCwweDgwMTAwLDB4NDIwMDAwMDAsMHg0MjA4MDEwMCwweDIwODAwMDAsMCwweDQwMDgwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDEwMCwweDgwMDAwLDAsMHg0MDA4MDAwMCwweDIwODAxMDAsMHg0MDAwMDEwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjY6IG5ldyBVaW50MzJBcnJheSggWzB4MjAwMDAwMTAsMHgyMDQwMDAwMCwweDQwMDAsMHgyMDQwNDAxMCwweDIwNDAwMDAwLDB4MTAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4NDA0MDEwLDB4NDAwMDAwLDB4MjAwMDAwMTAsMHg0MDAwMTAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMHg0MDAwLDB4NDA0MDAwLDB4MjAwMDQwMTAsMHgxMCwweDIwNDAwMDEwLDB4MjA0MDAwMTAsMCwweDQwNDAxMCwweDIwNDA0MDAwLDB4NDAxMCwweDQwNDAwMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHgyMDAwNDAwMCwweDEwLDB4MjA0MDAwMTAsMHg0MDQwMDAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHgyMDQwNDAxMCwweDQwNDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMCwweDIwNDAwMDEwLDB4MTAsMHg0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHg0MDAwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjc6IG5ldyBVaW50MzJBcnJheSggWzB4MjAwMDAwLDB4NDIwMDAwMiwweDQwMDA4MDIsMCwweDgwMCwweDQwMDA4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4NDIwMDgwMiwweDIwMDAwMCwwLDB4NDAwMDAwMiwweDIsMHg0MDAwMDAwLDB4NDIwMDAwMiwweDgwMiwweDQwMDA4MDAsMHgyMDA4MDIsMHgyMDAwMDIsMHg0MDAwODAwLDB4NDAwMDAwMiwweDQyMDAwMDAsMHg0MjAwODAwLDB4MjAwMDAyLDB4NDIwMDAwMCwweDgwMCwweDgwMiwweDQyMDA4MDIsMHgyMDA4MDAsMHgyLDB4NDAwMDAwMCwweDIwMDgwMCwweDQwMDAwMDAsMHgyMDA4MDAsMHgyMDAwMDAsMHg0MDAwODAyLDB4NDAwMDgwMiwweDQyMDAwMDIsMHg0MjAwMDAyLDB4MiwweDIwMDAwMiwweDQwMDAwMDAsMHg0MDAwODAwLDB4MjAwMDAwLDB4NDIwMDgwMCwweDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg4MDIsMHg0MDAwMDAyLDB4NDIwMDgwMiwweDQyMDAwMDAsMHgyMDA4MDAsMCwweDIsMHg0MjAwODAyLDAsMHgyMDA4MDIsMHg0MjAwMDAwLDB4ODAwLDB4NDAwMDAwMiwweDQwMDA4MDAsMHg4MDAsMHgyMDAwMDJdICksXG4gICAgICAgIHNwZnVuY3Rpb244OiBuZXcgVWludDMyQXJyYXkoIFsweDEwMDAxMDQwLDB4MTAwMCwweDQwMDAwLDB4MTAwNDEwNDAsMHgxMDAwMDAwMCwweDEwMDAxMDQwLDB4NDAsMHgxMDAwMDAwMCwweDQwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4MTAwNDEwMDAsMHg0MTA0MCwweDEwMDAsMHg0MCwweDEwMDQwMDAwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDEwNDAsMHg0MTAwMCwweDQwMDQwLDB4MTAwNDAwNDAsMHgxMDA0MTAwMCwweDEwNDAsMCwwLDB4MTAwNDAwNDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4NDEwNDAsMHg0MDAwMCwweDQxMDQwLDB4NDAwMDAsMHgxMDA0MTAwMCwweDEwMDAsMHg0MCwweDEwMDQwMDQwLDB4MTAwMCwweDQxMDQwLDB4MTAwMDEwMDAsMHg0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MDA0MCwweDEwMDAwMDAwLDB4NDAwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MDA0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDAwMTAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4NDEwMDAsMHgxMDQwLDB4MTA0MCwweDQwMDQwLDB4MTAwMDAwMDAsMHgxMDA0MTAwMF0gKSxcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy9jcmVhdGUgdGhlIDE2IG9yIDQ4IHN1YmtleXMgd2Ugd2lsbCBuZWVkXG4gICAgdmFyIGtleXMgPSBkZXNfY3JlYXRlS2V5cygga2V5ICk7XG5cbiAgICB2YXIgbT0wLCBpLCBqLCB0ZW1wLCBsZWZ0LCByaWdodCwgbG9vcGluZztcbiAgICB2YXIgY2JjbGVmdCwgY2JjbGVmdDIsIGNiY3JpZ2h0LCBjYmNyaWdodDJcbiAgICB2YXIgbGVuID0gbWVzc2FnZS5sZW5ndGg7XG5cbiAgICAvL3NldCB1cCB0aGUgbG9vcHMgZm9yIHNpbmdsZSBhbmQgdHJpcGxlIGRlc1xuICAgIHZhciBpdGVyYXRpb25zID0ga2V5cy5sZW5ndGggPT0gMzIgPyAzIDogOTsgLy9zaW5nbGUgb3IgdHJpcGxlIGRlc1xuXG4gICAgaWYgKGl0ZXJhdGlvbnMgPT0gMylcbiAgICB7XG4gICAgICBsb29waW5nID0gZW5jcnlwdCA/IFsgMCwgMzIsIDIgXSA6IFsgMzAsIC0yLCAtMiBdO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyLCA2MiwgMzAsIC0yLCA2NCwgOTYsIDIgXSA6IFsgOTQsIDYyLCAtMiwgMzIsIDY0LCAyLCAzMCwgLTIsIC0yIF07XG4gICAgfVxuXG4gICAgLy8gcGFkIHRoZSBtZXNzYWdlIGRlcGVuZGluZyBvbiB0aGUgcGFkZGluZyBwYXJhbWV0ZXJcbiAgICBpZiAoICggcGFkZGluZyAhPSB1bmRlZmluZWQgKSAmJiAoIHBhZGRpbmcgIT0gNCApIClcbiAgICB7XG4gICAgICB2YXIgdW5wYWRkZWRNZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgIHZhciBwYWQgPSA4LShsZW4lOCk7XG5cbiAgICAgIG1lc3NhZ2UgPSBuZXcgVWludDhBcnJheSggbGVuICsgOCApO1xuICAgICAgbWVzc2FnZS5zZXQoIHVucGFkZGVkTWVzc2FnZSwgMCApO1xuXG4gICAgICBzd2l0Y2goIHBhZGRpbmcgKVxuICAgICAge1xuICAgICAgICBjYXNlIDA6IC8vIHplcm8tcGFkXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAgXSApLCBsZW4gKTtcbiAgICAgICAgICBicmVhaztcblxuICAgICAgICBjYXNlIDE6IC8vIFBLQ1M3IHBhZGRpbmdcbiAgICAgICAge1xuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZF0gKSwgOCApO1xuXG4gICAgICAgICAgaWYgKCBwYWQ9PTggKVxuICAgICAgICAgICAgbGVuKz04O1xuXG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cblxuICAgICAgICBjYXNlIDI6ICAvLyBwYWQgdGhlIG1lc3NhZ2Ugd2l0aCBzcGFjZXNcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCBdICksIDggKTtcbiAgICAgICAgICBicmVhaztcblxuICAgICAgfVxuXG4gICAgICBsZW4gKz0gOC0obGVuJTgpXG4gICAgfVxuXG4gICAgLy8gc3RvcmUgdGhlIHJlc3VsdCBoZXJlXG4gICAgdmFyIHJlc3VsdCA9IG5ldyBVaW50OEFycmF5KCBsZW4gKTtcblxuICAgIGlmIChtb2RlID09IDEpXG4gICAgeyAvL0NCQyBtb2RlXG4gICAgICB2YXIgbSA9IDA7XG5cbiAgICAgIGNiY2xlZnQgPSAgKGl2W20rK10gPDwgMjQpIHwgKGl2W20rK10gPDwgMTYpIHwgKGl2W20rK10gPDwgOCkgfCBpdlttKytdO1xuICAgICAgY2JjcmlnaHQgPSAoaXZbbSsrXSA8PCAyNCkgfCAoaXZbbSsrXSA8PCAxNikgfCAoaXZbbSsrXSA8PCA4KSB8IGl2W20rK107XG4gICAgfVxuXG4gICAgdmFyIHJtID0gMDtcblxuICAgIC8vbG9vcCB0aHJvdWdoIGVhY2ggNjQgYml0IGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgd2hpbGUgKG0gPCBsZW4pXG4gICAge1xuICAgICAgbGVmdCA9ICAobWVzc2FnZVttKytdIDw8IDI0KSB8IChtZXNzYWdlW20rK10gPDwgMTYpIHwgKG1lc3NhZ2VbbSsrXSA8PCA4KSB8IG1lc3NhZ2VbbSsrXTtcbiAgICAgIHJpZ2h0ID0gKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG5cbiAgICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgICBpZiAobW9kZSA9PSAxKVxuICAgICAge1xuICAgICAgICBpZiAoZW5jcnlwdClcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDsgcmlnaHQgXj0gY2JjcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICB7XG4gICAgICAgICAgY2JjbGVmdDIgPSBjYmNsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0MiA9IGNiY3JpZ2h0O1xuICAgICAgICAgIGNiY2xlZnQgPSBsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0ID0gcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy9maXJzdCBlYWNoIDY0IGJ1dCBjaHVuayBvZiB0aGUgbWVzc2FnZSBtdXN0IGJlIHBlcm11dGVkIGFjY29yZGluZyB0byBJUFxuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMTYpIF4gcmlnaHQpICYgMHgwMDAwZmZmZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxNik7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gMikgXiBsZWZ0KSAmIDB4MzMzMzMzMzM7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgMik7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAgIGxlZnQgPSAoKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMzEpKTtcbiAgICAgIHJpZ2h0ID0gKChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMzEpKTtcblxuICAgICAgLy9kbyB0aGlzIGVpdGhlciAxIG9yIDMgdGltZXMgZm9yIGVhY2ggY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICAgIGZvciAoaj0wOyBqPGl0ZXJhdGlvbnM7IGorPTMpXG4gICAgICB7XG4gICAgICAgIHZhciBlbmRsb29wID0gbG9vcGluZ1tqKzFdO1xuICAgICAgICB2YXIgbG9vcGluYyA9IGxvb3BpbmdbaisyXTtcblxuICAgICAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZSBlbmNyeXB0aW9uIG9yIGRlY3J5cHRpb25cbiAgICAgICAgZm9yIChpPWxvb3Bpbmdbal07IGkhPWVuZGxvb3A7IGkrPWxvb3BpbmMpXG4gICAgICAgIHsgLy9mb3IgZWZmaWNpZW5jeVxuICAgICAgICAgIHZhciByaWdodDEgPSByaWdodCBeIGtleXNbaV07XG4gICAgICAgICAgdmFyIHJpZ2h0MiA9ICgocmlnaHQgPj4+IDQpIHwgKHJpZ2h0IDw8IDI4KSkgXiBrZXlzW2krMV07XG5cbiAgICAgICAgICAvL3RoZSByZXN1bHQgaXMgYXR0YWluZWQgYnkgcGFzc2luZyB0aGVzZSBieXRlcyB0aHJvdWdoIHRoZSBTIHNlbGVjdGlvbiBmdW5jdGlvbnNcbiAgICAgICAgICB0ZW1wID0gbGVmdDtcbiAgICAgICAgICBsZWZ0ID0gcmlnaHQ7XG4gICAgICAgICAgcmlnaHQgPSB0ZW1wIF4gKGRlc1NQLnNwZnVuY3Rpb24yWyhyaWdodDEgPj4+IDI0KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjRbKHJpZ2h0MSA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgZGVzU1Auc3BmdW5jdGlvbjZbKHJpZ2h0MSA+Pj4gIDgpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uOFtyaWdodDEgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBkZXNTUC5zcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb24zWyhyaWdodDIgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IGRlc1NQLnNwZnVuY3Rpb241WyhyaWdodDIgPj4+ICA4KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjdbcmlnaHQyICYgMHgzZl0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdGVtcCA9IGxlZnQ7IGxlZnQgPSByaWdodDsgcmlnaHQgPSB0ZW1wOyAvL3VucmV2ZXJzZSBsZWZ0IGFuZCByaWdodFxuICAgICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgICAgbGVmdCA9ICgobGVmdCA+Pj4gMSkgfCAobGVmdCA8PCAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpO1xuXG4gICAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDI7XG4gICAgICAgICAgcmlnaHQgXj0gY2JjcmlnaHQyO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc3VsdC5zZXQoIG5ldyBVaW50OEFycmF5ICggWyAobGVmdD4+PjI0KSAmIDB4ZmYsIChsZWZ0Pj4+MTYpICYgMHhmZiwgKGxlZnQ+Pj44KSAmIDB4ZmYsIChsZWZ0KSAmIDB4ZmYsIChyaWdodD4+PjI0KSAmIDB4ZmYsIChyaWdodD4+PjE2KSAmIDB4ZmYsIChyaWdodD4+PjgpICYgMHhmZiwgKHJpZ2h0KSAmIDB4ZmYgXSApLCBybSApO1xuXG4gICAgICBybSArPSA4O1xuICAgIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9IC8vZW5kIG9mIGRlc1xuXG59XG5cbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnREVTLUVDQicsXG4gIERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLFxuICBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uSU1QT1JUX0tFWSwgXSApO1xuIixudWxsLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgY2xhc3MgRW51bSB7XG59XG5cbmV4cG9ydCBjbGFzcyBJbnRlZ2VyIGV4dGVuZHMgTnVtYmVyIHtcbn1cblxuLyoqXG4gKiBTZXQgb2YgZGF0YSB0eXBlcyB0aGF0IGFyZSB2YWxpZCBhcyBLaW5kIGZpZWxkc1xuICogaW5jbHVkZXMgRmllbGRUeXBlQXJyYXkga2x1ZGdlIHJlcXVpcmVkIGZvciBUUyB0byBwYXJzZSByZWN1cnNpdmVcbiAqIHR5cGUgZGVmaW5pdGlvbnNcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkQXJyYXkgZXh0ZW5kcyBBcnJheTxGaWVsZFR5cGU+IHt9XG5leHBvcnQgdHlwZSBGaWVsZFR5cGUgPSBTdHJpbmcgfCBOdW1iZXIgfCBJbnRlZ2VyIHwgRW51bSB8IEJ5dGVBcnJheSB8IEtpbmQgfCBGaWVsZEFycmF5O1xuXG5leHBvcnQgY2xhc3MgRmllbGRBcnJheSBpbXBsZW1lbnRzIEZpZWxkQXJyYXkge31cblxuZXhwb3J0IHZhciBGaWVsZFR5cGVzID0ge1xuICBCb29sZWFuOiBCb29sZWFuLFxuXG4gIE51bWJlcjogTnVtYmVyLFxuXG4gIEludGVnZXI6IEludGVnZXIsXG5cbiAgQnl0ZUFycmF5OiBCeXRlQXJyYXksXG5cbiAgRW51bTogRW51bSxcblxuICBBcnJheTogRmllbGRBcnJheSxcblxuICBTdHJpbmc6IFN0cmluZyxcblxuICBLaW5kOiBLaW5kXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRPcHRpb25zIHtcbiAgLyoqXG4gICogbWluaW11bSBsZW5ndGggZm9yIFN0cmluZywgbWluaW11bSB2YWx1ZSBmb3IgTnVtYmVyL0ludGVnZXJcbiAgKi9cbiAgbWluaW11bT86IG51bWJlcjtcblxuICAvKipcbiAgKiBtYXhpbXVtIGxlbmd0aCBmb3IgU3RyaW5nLCBtYXhpbXVtIHZhbHVlIGZvciBOdW1iZXIvSW50ZWdlclxuICAqL1xuICBtYXhpbXVtPzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIGRlZmF1bHQgdmFsdWUgZHVyaW5nIGluaXRpYWxpemF0aW9uXG4gICovXG4gIFwiZGVmYXVsdFwiPzogYW55O1xuXG4gIC8qKlxuICAqIGRvZXMgbm90IGV4aXN0IGFzIGFuIG93blByb3BlcnR5XG4gICovXG4gIGNhbGN1bGF0ZWQ/OiBib29sZWFuO1xuXG4gIC8qKlxuICAqIHN1Yi1raW5kLCB3aGVuIGZpZWxkIGlzIHR5cGUgS2luZFxuICAqL1xuICBraW5kPzogS2luZDtcblxuICAvKipcbiAgKiBzdWItZmllbGQgaW5mbywgd2hlbiBmaWVsZCBpcyB0eXBlIEZpZWxkQXJyYXlcbiAgKi9cbiAgYXJyYXlJbmZvPzogRmllbGRJbmZvO1xuXG4gIC8qKlxuICAqIGluZGV4L3ZhbHVlIG1hcCwgd2hlbiBmaWVsZCBpZiB0eXBlIEVudW1cbiAgKi9cbiAgZW51bU1hcD86IE1hcDxudW1iZXIsIHN0cmluZz47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRJbmZvIGV4dGVuZHMgRmllbGRPcHRpb25zIHtcbiAgLyoqXG4gICogRGVzY3JpcHRpb24gZm9yIGZpZWxkXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogVHlwZSBvZiBmaWVsZCwgb25lIG9mIEZpZWxkVHlwZXNcbiAgKi9cbiAgZmllbGRUeXBlOiBGaWVsZFR5cGU7XG59XG5cblxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgS2luZC4gQ29udGFpbnMgbmFtZSwgZGVzY3JpcHRpb24gYW5kIGEgbWFwIG9mXG4qIHByb3BlcnR5LWRlc2NyaXB0b3JzIHRoYXQgZGVzY3JpYmUgdGhlIHNlcmlhbGl6YWJsZSBmaWVsZHMgb2ZcbiogYW4gb2JqZWN0IG9mIHRoYXQgS2luZC5cbiovXG5leHBvcnQgY2xhc3MgS2luZEluZm9cbntcbiAgbmFtZTogc3RyaW5nO1xuXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgZmllbGRzOiB7IFtpZDogc3RyaW5nXTogRmllbGRJbmZvIH0gPSB7fTtcbn1cblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdLaW5kJyBtZXRhZGF0YVxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kQnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IEtpbmRDb25zdHJ1Y3RvcjtcblxuICBjb25zdHJ1Y3RvciggY3RvcjogS2luZENvbnN0cnVjdG9yLCBkZXNjcmlwdGlvbjogc3RyaW5nICkge1xuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmtpbmRJbmZvID0ge1xuICAgICAgbmFtZTogY3Rvci5uYW1lLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZmllbGRzOiB7fVxuICAgIH1cbiAgfVxuXG5cbiAgcHJpdmF0ZSBraW5kSW5mbzogS2luZEluZm87XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IEtpbmRCdWlsZGVyKCBjdG9yLCBkZXNjcmlwdGlvbiApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgZmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZmllbGRUeXBlOiBGaWVsZFR5cGUsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyXG4gIHtcbiAgICBsZXQgZmllbGQ6IEZpZWxkSW5mbyA9IDxGaWVsZEluZm8+b3B0cztcblxuICAgIGZpZWxkLmRlc2NyaXB0aW9uID0gZGVzY3JpcHRpb247XG4gICAgZmllbGQuZmllbGRUeXBlID0gZmllbGRUeXBlO1xuXG4gICAgdGhpcy5jdG9yLmtpbmRJbmZvLmZpZWxkc1sgbmFtZSBdID0gZmllbGQ7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBib29sRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgQm9vbGVhbiwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIG51bWJlckZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIE51bWJlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGludGVnZXJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgdWludDMyRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMubWluaW11bSA9IG9wdHMubWluaW11bSB8fCAwO1xuICAgIG9wdHMubWF4aW11bSA9IG9wdHMubWF4aW11bSB8fCAweEZGRkZGRkZGO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgYnl0ZUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLm1pbmltdW0gPSBvcHRzLm1pbmltdW0gfHwgMDtcbiAgICBvcHRzLm1heGltdW0gPSBvcHRzLm1heGltdW0gfHwgMjU1O1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgc3RyaW5nRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgU3RyaW5nLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMga2luZEZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGtpbmQ6IEtpbmQsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLmtpbmQgPSBraW5kO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBLaW5kLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgZW51bUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGVudW1tOiB7IFsgaWR4OiBudW1iZXIgXTogc3RyaW5nIH0sIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcblxuICAgIG9wdHMuZW51bU1hcCA9IG5ldyBNYXA8bnVtYmVyLHN0cmluZz4oICk7XG5cbiAgICBmb3IoIGxldCBpZHggaW4gZW51bW0gKSB7XG4gICAgICBpZiAoIDEgKiBpZHggPT0gaWR4IClcbiAgICAgICAgb3B0cy5lbnVtTWFwLnNldCggaWR4LCBlbnVtbVsgaWR4IF0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEVudW0sIG9wdHMgKTtcbiAgfVxufVxuXG4vKiAgbWFrZUtpbmQoIGtpbmRDb25zdHJ1Y3Rvciwga2luZE9wdGlvbnMgKVxuICB7XG4gICAgdmFyICRraW5kSW5mbyA9IGtpbmRPcHRpb25zLmtpbmRJbmZvO1xuXG4gICAga2luZENvbnN0cnVjdG9yLiRraW5kTmFtZSA9ICRraW5kSW5mby50aXRsZTtcblxuICAgIHZhciBrZXlzID0gT2JqZWN0LmtleXMoIGtpbmRPcHRpb25zLmtpbmRNZXRob2RzICk7XG5cbiAgICBmb3IgKCB2YXIgaiA9IDAsIGpqID0ga2V5cy5sZW5ndGg7IGogPCBqajsgaisrICkge1xuICAgICAgdmFyIGtleSA9IGtleXNbal07XG4gICAgICBraW5kQ29uc3RydWN0b3Jba2V5XSA9IGtpbmRPcHRpb25zLmtpbmRNZXRob2RzW2tleV07XG4gICAgfVxuXG4gICAga2luZENvbnN0cnVjdG9yLmdldEtpbmRJbmZvID0ga2luZENvbnN0cnVjdG9yLnByb3RvdHlwZS5nZXRLaW5kSW5mbyA9IGZ1bmN0aW9uIGdldEtpbmRJbmZvKCkge1xuICAgICAgcmV0dXJuICRraW5kSW5mbztcbiAgICB9XG5cbiAgICByZXR1cm4ga2luZENvbnN0cnVjdG9yO1xuICB9XG4qL1xuXG4vKipcbiogUmVwcmVzZW50cyBhIHNlcmlhbGl6YWJsZSBhbmQgaW5zcGVjdGFibGUgZGF0YS10eXBlXG4qIGltcGxlbWVudGVkIGFzIGEgaGFzaC1tYXAgY29udGFpbmluZyBrZXktdmFsdWUgcGFpcnMsXG4qIGFsb25nIHdpdGggbWV0YWRhdGEgdGhhdCBkZXNjcmliZXMgZWFjaCBmaWVsZCB1c2luZyBhIGpzb24tc2NoZW1lIGxpa2VcbiovXG5leHBvcnQgaW50ZXJmYWNlIEtpbmRcbntcbn1cblxuZXhwb3J0IGNsYXNzIEtpbmQgaW1wbGVtZW50cyBLaW5kIHtcbiAgc3RhdGljIGdldEtpbmRJbmZvKCBraW5kOiBLaW5kICk6IEtpbmRJbmZvIHtcbiAgICByZXR1cm4gKDxLaW5kQ29uc3RydWN0b3I+KGtpbmQuY29uc3RydWN0b3IpKS5raW5kSW5mbztcbiAgfVxuXG4gIHN0YXRpYyBpbml0RmllbGRzKCBraW5kOiBLaW5kLCBhdHRyaWJ1dGVzOiB7fSA9IHt9ICApIHtcbiAgICBsZXQga2luZEluZm8gPSBLaW5kLmdldEtpbmRJbmZvKCBraW5kICk7XG5cbiAgICBmb3IoIGxldCBpZCBpbiBraW5kSW5mby5maWVsZHMgKSB7XG4gICAgICBsZXQgZmllbGQgPSBraW5kSW5mby5maWVsZHNbIGlkIF07XG4gICAgICBsZXQgZmllbGRUeXBlID0gZmllbGQuZmllbGRUeXBlO1xuXG4vLyAgICAgIGNvbnNvbGUubG9nKCBpZCArICc6JyArIGZpZWxkVHlwZSApO1xuLy8gICAgICBjb25zb2xlLmxvZygga2luZC5oYXNPd25Qcm9wZXJ0eShpZCkgICk7XG5cbiAgICAgIGxldCB2YWw6IGFueTtcblxuICAgICAgaWYgKCAhZmllbGQuY2FsY3VsYXRlZCApIHtcbiAgICAgICAgLy8gd2Ugb25seSBzZXQgJ25vbictY2FsY3VsYXRlZCBmaWVsZCwgc2luY2UgY2FsY3VsYXRlZCBmaWVsZCBoYXZlXG4gICAgICAgIC8vIG5vIHNldHRlclxuXG4gICAgICAgIC8vIGdvdCBhIHZhbHVlIGZvciB0aGlzIGZpZWxkID9cbiAgICAgICAgaWYgKCBhdHRyaWJ1dGVzWyBpZCBdIClcbiAgICAgICAgICB2YWwgPSBhdHRyaWJ1dGVzWyBpZCBdO1xuICAgICAgICBlbHNlIGlmICggZmllbGQuZGVmYXVsdCAhPSB1bmRlZmluZWQgKVxuICAgICAgICAgIHZhbCA9IGZpZWxkLmRlZmF1bHQ7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gU3RyaW5nIClcbiAgICAgICAgICB2YWwgPSAnJztcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBOdW1iZXIgKVxuICAgICAgICAgIHZhbCA9IDA7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gSW50ZWdlciApXG4gICAgICAgICAgdmFsID0gZmllbGQubWluaW11bSB8fCAwO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEJvb2xlYW4gKVxuICAgICAgICAgIHZhbCA9IGZhbHNlO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEJ5dGVBcnJheSApXG4gICAgICAgICAgdmFsID0gbmV3IEJ5dGVBcnJheSgpO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEVudW0gKVxuICAgICAgICAgIHZhbCA9IGZpZWxkLmVudW1NYXAua2V5c1swXTtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBLaW5kICkge1xuICAgICAgICAgIGxldCB4eCA9ICg8S2luZD5maWVsZFR5cGUpLmNvbnN0cnVjdG9yO1xuICAgICAgICAgIHZhbCA9IE9iamVjdC5jcmVhdGUoIHh4ICk7XG4gICAgICAgIH1cblxuICAgICAgICBraW5kWyBpZCBdID0gdmFsO1xuXG4vLyAgICAgICAgY29uc29sZS5sb2coIGtpbmRbaWRdICk7XG4gICAgICB9XG4gICAgfVxuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2luZENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIC4uLmFyZ3MgKTogS2luZDtcblxuICBraW5kSW5mbz86IEtpbmRJbmZvO1xufVxuIiwiaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4vZW5kLXBvaW50JztcblxuLypcbiogTWVzc2FnZSBIZWFkZXJcbiovXG5leHBvcnQgaW50ZXJmYWNlIE1lc3NhZ2VIZWFkZXJcbntcbiAgLypcbiAgKiBNZXNzYWdlIE5hbWUsIGluZGljYXRlcyBhIGNvbW1hbmQgLyBtZXRob2QgLyByZXNwb25zZSB0byBleGVjdXRlXG4gICovXG4gIG1ldGhvZD86IHN0cmluZztcblxuICAvKlxuICAqIE1lc3NhZ2UgSWRlbnRpZmllciAodW5pcXVlKSBmb3IgZWFjaCBzZW50IG1lc3NhZ2UgKG9yIENNRC1SRVNQIHBhaXIpXG4gICovXG4gIGlkPzogbnVtYmVyO1xuXG5cbiAgLypcbiAgKiBEZXNjcmlwdGlvbiwgdXNlZnVsIGZvciB0cmFjaW5nIGFuZCBsb2dnaW5nXG4gICovXG4gIGRlc2NyaXB0aW9uPzogc3RyaW5nO1xuXG4gIC8qXG4gICogRm9yIENNRC9SRVNQIHN0eWxlIHByb3RvY29scywgaW5kaWNhdGVzIHRoYXQgbWVzc2FnZSBkaXNwYXRjaGVkXG4gICogaW4gcmVzcG9uc2UgdG8gYSBwcmV2aW91cyBjb21tYW5kXG4gICovXG4gIGlzUmVzcG9uc2U/OiBib29sZWFuO1xuXG4gIC8qXG4gICogRW5kUG9pbnQgdGhhdCBvcmlnaW5hdGVkIHRoZSBtZXNzYWdlXG4gICovXG4gIG9yaWdpbj86IEVuZFBvaW50O1xuXG5cbiAgLypcbiAgKiBJbmRpY2F0ZXMgdGhlIEtpbmQgb2YgZGF0YSAod2hlbiBzZXJpYWxpemVkKVxuICAqL1xuICBraW5kTmFtZT86IHN0cmluZztcbn1cblxuLypcbiogQSBUeXBlZCBNZXNzYWdlLCB3aXRoIGhlYWRlciBhbmQgcGF5bG9hZFxuKi9cbmV4cG9ydCBjbGFzcyBNZXNzYWdlPFQ+XG57XG4gIHByaXZhdGUgX2hlYWRlcjogTWVzc2FnZUhlYWRlcjtcbiAgcHJpdmF0ZSBfcGF5bG9hZDogVDtcblxuICBjb25zdHJ1Y3RvciggaGVhZGVyOiBNZXNzYWdlSGVhZGVyLCBwYXlsb2FkOiBUIClcbiAge1xuICAgIHRoaXMuX2hlYWRlciA9IGhlYWRlciB8fCB7fTtcbiAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgfVxuXG4gIGdldCBoZWFkZXIoKTogTWVzc2FnZUhlYWRlclxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2hlYWRlcjtcbiAgfVxuXG4gIGdldCBwYXlsb2FkKCk6IFRcbiAge1xuICAgIHJldHVybiB0aGlzLl9wYXlsb2FkO1xuICB9XG59XG5cbi8qXG4qIEEgdHlwZWQgTWVzc2FnZSB3aG9zZSBwYXlsb2FkIGlzIGEgS2luZFxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kTWVzc2FnZTxLIGV4dGVuZHMgS2luZD4gZXh0ZW5kcyBNZXNzYWdlPEs+XG57XG59XG4iLCJleHBvcnQgdHlwZSBUYXNrID0gKCkgPT4gdm9pZDtcbmV4cG9ydCB0eXBlIEZsdXNoRnVuYyA9ICgpID0+IHZvaWQ7XG52YXIgd2luZG93ID0gd2luZG93IHx8IHt9O1xuXG5leHBvcnQgY2xhc3MgVGFza1NjaGVkdWxlclxue1xuICBzdGF0aWMgbWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyKGZsdXNoKTogRmx1c2hGdW5jXG4gIHtcbiAgICB2YXIgdG9nZ2xlID0gMTtcblxuICAgIHZhciBvYnNlcnZlciA9IG5ldyBUYXNrU2NoZWR1bGVyLkJyb3dzZXJNdXRhdGlvbk9ic2VydmVyKGZsdXNoKTtcblxuICAgIHZhciBub2RlOiBPYmplY3QgPSBkb2N1bWVudC5jcmVhdGVUZXh0Tm9kZSgnJyk7XG5cbiAgICBvYnNlcnZlci5vYnNlcnZlKG5vZGUsIHsgY2hhcmFjdGVyRGF0YTogdHJ1ZSB9KTtcblxuICAgIHJldHVybiBmdW5jdGlvbiByZXF1ZXN0Rmx1c2goKVxuICAgIHtcbiAgICAgIHRvZ2dsZSA9IC10b2dnbGU7XG4gICAgICBub2RlW1wiZGF0YVwiXSA9IHRvZ2dsZTtcbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIG1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIoZmx1c2gpOiBGbHVzaEZ1bmNcbiAge1xuICAgIHJldHVybiBmdW5jdGlvbiByZXF1ZXN0Rmx1c2goKSB7XG4gICAgICB2YXIgdGltZW91dEhhbmRsZSA9IHNldFRpbWVvdXQoaGFuZGxlRmx1c2hUaW1lciwgMCk7XG5cbiAgICAgIHZhciBpbnRlcnZhbEhhbmRsZSA9IHNldEludGVydmFsKGhhbmRsZUZsdXNoVGltZXIsIDUwKTtcbiAgICAgIGZ1bmN0aW9uIGhhbmRsZUZsdXNoVGltZXIoKVxuICAgICAge1xuICAgICAgICBjbGVhclRpbWVvdXQodGltZW91dEhhbmRsZSk7XG4gICAgICAgIGNsZWFySW50ZXJ2YWwoaW50ZXJ2YWxIYW5kbGUpO1xuICAgICAgICBmbHVzaCgpO1xuICAgICAgfVxuICAgIH07XG4gIH1cblxuICBzdGF0aWMgQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIgPSB3aW5kb3dbIFwiTXV0YXRpb25PYnNlcnZlclwiIF0gfHwgd2luZG93WyBcIldlYktpdE11dGF0aW9uT2JzZXJ2ZXJcIl07XG4gIHN0YXRpYyBoYXNTZXRJbW1lZGlhdGUgPSB0eXBlb2Ygc2V0SW1tZWRpYXRlID09PSAnZnVuY3Rpb24nO1xuXG4gIHN0YXRpYyB0YXNrUXVldWVDYXBhY2l0eSA9IDEwMjQ7XG4gIHRhc2tRdWV1ZTogVGFza1tdO1xuXG4gIHJlcXVlc3RGbHVzaFRhc2tRdWV1ZTogRmx1c2hGdW5jO1xuXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMudGFza1F1ZXVlID0gW107XG5cbiAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICBpZiAodHlwZW9mIFRhc2tTY2hlZHVsZXIuQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIgPT09ICdmdW5jdGlvbicpXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUgPSBUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlcihmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBzZWxmLmZsdXNoVGFza1F1ZXVlKCk7XG4gICAgICB9KTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlID0gVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHNlbGYuZmx1c2hUYXNrUXVldWUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIENsZWFudXAgdGhlIFRhc2tTY2hlZHVsZXIsIGNhbmNlbGxpbmcgYW55IHBlbmRpbmcgY29tbXVuaWNhdGlvbnMuXG4gICovXG4gIHNodXRkb3duKClcbiAge1xuICB9XG5cbiAgcXVldWVUYXNrKCB0YXNrKVxuICB7XG4gICAgaWYgKCB0aGlzLnRhc2tRdWV1ZS5sZW5ndGggPCAxIClcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSgpO1xuICAgIH1cblxuICAgIHRoaXMudGFza1F1ZXVlLnB1c2godGFzayk7XG4gIH1cblxuICBmbHVzaFRhc2tRdWV1ZSgpXG4gIHtcbiAgICB2YXIgcXVldWUgPSB0aGlzLnRhc2tRdWV1ZSxcbiAgICAgICAgY2FwYWNpdHkgPSBUYXNrU2NoZWR1bGVyLnRhc2tRdWV1ZUNhcGFjaXR5LFxuICAgICAgICBpbmRleCA9IDAsXG4gICAgICAgIHRhc2s7XG5cbiAgICB3aGlsZSAoaW5kZXggPCBxdWV1ZS5sZW5ndGgpXG4gICAge1xuICAgICAgdGFzayA9IHF1ZXVlW2luZGV4XTtcblxuICAgICAgdHJ5XG4gICAgICB7XG4gICAgICAgIHRhc2suY2FsbCgpO1xuICAgICAgfVxuICAgICAgY2F0Y2ggKGVycm9yKVxuICAgICAge1xuICAgICAgICB0aGlzLm9uRXJyb3IoZXJyb3IsIHRhc2spO1xuICAgICAgfVxuXG4gICAgICBpbmRleCsrO1xuXG4gICAgICBpZiAoaW5kZXggPiBjYXBhY2l0eSlcbiAgICAgIHtcbiAgICAgICAgZm9yICh2YXIgc2NhbiA9IDA7IHNjYW4gPCBpbmRleDsgc2NhbisrKVxuICAgICAgICB7XG4gICAgICAgICAgcXVldWVbc2Nhbl0gPSBxdWV1ZVtzY2FuICsgaW5kZXhdO1xuICAgICAgICB9XG5cbiAgICAgICAgcXVldWUubGVuZ3RoIC09IGluZGV4O1xuICAgICAgICBpbmRleCA9IDA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcXVldWUubGVuZ3RoID0gMDtcbiAgfVxuXG4gIG9uRXJyb3IoZXJyb3IsIHRhc2spXG4gIHtcbiAgICBpZiAoJ29uRXJyb3InIGluIHRhc2spIHtcbiAgICAgIHRhc2sub25FcnJvcihlcnJvcik7XG4gICAgfVxuICAgIGVsc2UgaWYgKCBUYXNrU2NoZWR1bGVyLmhhc1NldEltbWVkaWF0ZSApXG4gICAge1xuICAgICAgc2V0SW1tZWRpYXRlKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9KTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIHNldFRpbWVvdXQoZnVuY3Rpb24gKCkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0sIDApO1xuICAgIH1cbiAgfVxufVxuIiwiaW1wb3J0IHsgVGFza1NjaGVkdWxlciB9IGZyb20gJy4uL3J1bnRpbWUvdGFzay1zY2hlZHVsZXInO1xuaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4vZW5kLXBvaW50JztcbmltcG9ydCB7IE1lc3NhZ2UgfSBmcm9tICcuL21lc3NhZ2UnO1xuXG4vKipcbiogQSBtZXNzYWdlLXBhc3NpbmcgY2hhbm5lbCBiZXR3ZWVuIG11bHRpcGxlIEVuZFBvaW50c1xuKlxuKiBFbmRQb2ludHMgbXVzdCBmaXJzdCByZWdpc3RlciB3aXRoIHRoZSBDaGFubmVsLiBXaGVuZXZlciB0aGUgQ2hhbm5lbCBpcyBpblxuKiBhbiBhY3RpdmUgc3RhdGUsIGNhbGxzIHRvIHNlbmRNZXNzYWdlIHdpbGwgZm9yd2FyZCB0aGUgbWVzc2FnZSB0byBhbGxcbiogcmVnaXN0ZXJlZCBFbmRQb2ludHMgKGV4Y2VwdCB0aGUgb3JpZ2luYXRvciBFbmRQb2ludCkuXG4qL1xuZXhwb3J0IGNsYXNzIENoYW5uZWxcbntcbiAgLyoqXG4gICogVHJ1ZSBpZiBDaGFubmVsIGlzIGFjdGl2ZVxuICAqL1xuICBwcml2YXRlIF9hY3RpdmU6IGJvb2xlYW47XG5cbiAgLyoqXG4gICogQXJyYXkgb2YgRW5kUG9pbnRzIGF0dGFjaGVkIHRvIHRoaXMgQ2hhbm5lbFxuICAqL1xuICBwcml2YXRlIF9lbmRQb2ludHM6IEVuZFBvaW50W107XG5cbiAgLyoqXG4gICogUHJpdmF0ZSBUYXNrU2NoZWR1bGVyIHVzZWQgdG8gbWFrZSBtZXNzYWdlLXNlbmRzIGFzeW5jaHJvbm91cy5cbiAgKi9cbiAgcHJpdmF0ZSBfdGFza1NjaGVkdWxlcjogVGFza1NjaGVkdWxlcjtcblxuICAvKipcbiAgKiBDcmVhdGUgYSBuZXcgQ2hhbm5lbCwgaW5pdGlhbGx5IGluYWN0aXZlXG4gICovXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuICAgIHRoaXMuX2VuZFBvaW50cyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgQ2hhbm5lbCwgZGVhY3RpdmF0ZSwgcmVtb3ZlIGFsbCBFbmRQb2ludHMgYW5kXG4gICogYWJvcnQgYW55IHBlbmRpbmcgY29tbXVuaWNhdGlvbnMuXG4gICovXG4gIHB1YmxpYyBzaHV0ZG93bigpXG4gIHtcbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcblxuICAgIHRoaXMuX2VuZFBvaW50cyA9IFtdO1xuXG4gICAgaWYgKCB0aGlzLl90YXNrU2NoZWR1bGVyIClcbiAgICB7XG4gICAgICB0aGlzLl90YXNrU2NoZWR1bGVyLnNodXRkb3duKCk7XG5cbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogSXMgQ2hhbm5lbCBhY3RpdmU/XG4gICpcbiAgKiBAcmV0dXJucyB0cnVlIGlmIGNoYW5uZWwgaXMgYWN0aXZlLCBmYWxzZSBvdGhlcndpc2VcbiAgKi9cbiAgcHVibGljIGdldCBhY3RpdmUoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2FjdGl2ZTtcbiAgfVxuXG4gIC8qKlxuICAqIEFjdGl2YXRlIHRoZSBDaGFubmVsLCBlbmFibGluZyBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBhY3RpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gbmV3IFRhc2tTY2hlZHVsZXIoKTtcblxuICAgIHRoaXMuX2FjdGl2ZSA9IHRydWU7XG4gIH1cblxuICAvKipcbiAgKiBEZWFjdGl2YXRlIHRoZSBDaGFubmVsLCBkaXNhYmxpbmcgYW55IGZ1cnRoZXIgY29tbXVuaWNhdGlvblxuICAqL1xuICBwdWJsaWMgZGVhY3RpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gdW5kZWZpbmVkO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgKiBSZWdpc3RlciBhbiBFbmRQb2ludCB0byBzZW5kIGFuZCByZWNlaXZlIG1lc3NhZ2VzIHZpYSB0aGlzIENoYW5uZWwuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gcmVnaXN0ZXJcbiAgKi9cbiAgcHVibGljIGFkZEVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgdGhpcy5fZW5kUG9pbnRzLnB1c2goIGVuZFBvaW50ICk7XG4gIH1cblxuICAvKipcbiAgKiBVbnJlZ2lzdGVyIGFuIEVuZFBvaW50LlxuICAqXG4gICogQHBhcmFtIGVuZFBvaW50IC0gdGhlIEVuZFBvaW50IHRvIHVucmVnaXN0ZXJcbiAgKi9cbiAgcHVibGljIHJlbW92ZUVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgbGV0IGlkeCA9IHRoaXMuX2VuZFBvaW50cy5pbmRleE9mKCBlbmRQb2ludCApO1xuXG4gICAgaWYgKCBpZHggPj0gMCApXG4gICAge1xuICAgICAgdGhpcy5fZW5kUG9pbnRzLnNwbGljZSggaWR4LCAxICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogR2V0IEVuZFBvaW50cyByZWdpc3RlcmVkIHdpdGggdGhpcyBDaGFubmVsXG4gICpcbiAgKiBAcmV0dXJuIEFycmF5IG9mIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgZ2V0IGVuZFBvaW50cygpOiBFbmRQb2ludFtdXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnRzO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIG1lc3NhZ2UgdG8gYWxsIGxpc3RlbmVycyAoZXhjZXB0IG9yaWdpbilcbiAgKlxuICAqIEBwYXJhbSBvcmlnaW4gLSBFbmRQb2ludCB0aGF0IGlzIHNlbmRpbmcgdGhlIG1lc3NhZ2VcbiAgKiBAcGFyYW0gbWVzc2FnZSAtIE1lc3NhZ2UgdG8gYmUgc2VudFxuICAqL1xuICBwdWJsaWMgc2VuZE1lc3NhZ2UoIG9yaWdpbjogRW5kUG9pbnQsIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiApXG4gIHtcbiAgICBsZXQgaXNSZXNwb25zZSA9ICggbWVzc2FnZS5oZWFkZXIgJiYgbWVzc2FnZS5oZWFkZXIuaXNSZXNwb25zZSApO1xuXG4gICAgaWYgKCAhdGhpcy5fYWN0aXZlIClcbiAgICAgIHJldHVybjtcblxuICAgIGlmICggb3JpZ2luLmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uSU4gJiYgIWlzUmVzcG9uc2UgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnVW5hYmxlIHRvIHNlbmQgb24gSU4gcG9ydCcpO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzLmZvckVhY2goIGVuZFBvaW50ID0+IHtcbiAgICAgIC8vIFNlbmQgdG8gYWxsIGxpc3RlbmVycywgZXhjZXB0IGZvciBvcmlnaW5hdG9yIC4uLlxuICAgICAgaWYgKCBvcmlnaW4gIT0gZW5kUG9pbnQgKVxuICAgICAge1xuICAgICAgICAvLyBPbmx5IHNlbmQgdG8gSU4gb3IgSU5PVVQgbGlzdGVuZXJzLCBVTkxFU1MgbWVzc2FnZSBpcyBhXG4gICAgICAgIC8vIHJlcGx5IChpbiBhIGNsaWVudC1zZXJ2ZXIpIGNvbmZpZ3VyYXRpb25cbiAgICAgICAgaWYgKCBlbmRQb2ludC5kaXJlY3Rpb24gIT0gRGlyZWN0aW9uLk9VVCB8fCBpc1Jlc3BvbnNlIClcbiAgICAgICAge1xuICAgICAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIucXVldWVUYXNrKCAoKSA9PiB7XG4gICAgICAgICAgICBlbmRQb2ludC5oYW5kbGVNZXNzYWdlKCBtZXNzYWdlLCBvcmlnaW4sIHRoaXMgKTtcbiAgICAgICAgICB9ICk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi9jaGFubmVsJztcblxuZXhwb3J0IGVudW0gRGlyZWN0aW9uIHtcbiAgSU4gPSAxLFxuICBPVVQgPSAyLFxuICBJTk9VVCA9IDNcbn07XG5cbmV4cG9ydCB0eXBlIEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZSA9ICggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCByZWNlaXZpbmdFbmRQb2ludD86IEVuZFBvaW50LCByZWNlaXZpbmdDaGFubmVsPzogQ2hhbm5lbCApID0+IHZvaWQ7XG5cbi8qKlxuKiBBbiBFbmRQb2ludCBpcyBhIHNlbmRlci9yZWNlaXZlciBmb3IgbWVzc2FnZS1wYXNzaW5nLiBJdCBoYXMgYW4gaWRlbnRpZmllclxuKiBhbmQgYW4gb3B0aW9uYWwgZGlyZWN0aW9uLCB3aGljaCBtYXkgYmUgSU4sIE9VVCBvciBJTi9PVVQgKGRlZmF1bHQpLlxuKlxuKiBFbmRQb2ludHMgbWF5IGhhdmUgbXVsdGlwbGUgY2hhbm5lbHMgYXR0YWNoZWQsIGFuZCB3aWxsIGZvcndhcmQgbWVzc2FnZXNcbiogdG8gYWxsIG9mIHRoZW0uXG4qL1xuZXhwb3J0IGNsYXNzIEVuZFBvaW50XG57XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICAvKipcbiAgKiBBIGxpc3Qgb2YgYXR0YWNoZWQgQ2hhbm5lbHNcbiAgKi9cbiAgcHJvdGVjdGVkIF9jaGFubmVsczogQ2hhbm5lbFtdO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX21lc3NhZ2VMaXN0ZW5lcnM6IEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZVtdO1xuXG4gIHByaXZhdGUgX2RpcmVjdGlvbjogRGlyZWN0aW9uO1xuXG4gIGNvbnN0cnVjdG9yKCBpZDogc3RyaW5nLCBkaXJlY3Rpb246IERpcmVjdGlvbiA9IERpcmVjdGlvbi5JTk9VVCApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fZGlyZWN0aW9uID0gZGlyZWN0aW9uO1xuXG4gICAgdGhpcy5fY2hhbm5lbHMgPSBbXTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIENsZWFudXAgdGhlIEVuZFBvaW50LCBkZXRhY2hpbmcgYW55IGF0dGFjaGVkIENoYW5uZWxzIGFuZCByZW1vdmluZyBhbnlcbiAgKiBtZXNzYWdlLWxpc3RlbmVycy4gQ2FsbGluZyBzaHV0ZG93bigpIGlzIG1hbmRhdG9yeSB0byBhdm9pZCBtZW1vcnktbGVha3NcbiAgKiBkdWUgdG8gdGhlIGNpcmN1bGFyIHJlZmVyZW5jZXMgdGhhdCBleGlzdCBiZXR3ZWVuIENoYW5uZWxzIGFuZCBFbmRQb2ludHNcbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuZGV0YWNoQWxsKCk7XG5cbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzID0gW107XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBFbmRQb2ludCdzIGlkXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cblxuICAvKipcbiAgKiBBdHRhY2ggYSBDaGFubmVsIHRvIHRoaXMgRW5kUG9pbnQuIE9uY2UgYXR0YWNoZWQsIHRoZSBDaGFubmVsIHdpbGwgZm9yd2FyZFxuICAqIG1lc3NhZ2VzIHRvIHRoaXMgRW5kUG9pbnQsIGFuZCB3aWxsIGFjY2VwdCBtZXNzYWdlcyBvcmlnaW5hdGVkIGhlcmUuXG4gICogQW4gRW5kUG9pbnQgY2FuIGhhdmUgbXVsdGlwbGUgQ2hhbm5lbHMgYXR0YWNoZWQsIGluIHdoaWNoIGNhc2UgaXQgd2lsbFxuICAqIGJyb2FkY2FzdCB0byB0aGVtIGFsbCB3aGVuIHNlbmRpbmcsIGFuZCB3aWxsIHJlY2VpdmUgbWVzc2FnZXMgaW5cbiAgKiBhcnJpdmFsLW9yZGVyLlxuICAqL1xuICBwdWJsaWMgYXR0YWNoKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLnB1c2goIGNoYW5uZWwgKTtcblxuICAgIGNoYW5uZWwuYWRkRW5kUG9pbnQoIHRoaXMgKTtcbiAgfVxuXG4gIC8qKlxuICAqIERldGFjaCBhIHNwZWNpZmljIENoYW5uZWwgZnJvbSB0aGlzIEVuZFBvaW50LlxuICAqL1xuICBwdWJsaWMgZGV0YWNoKCBjaGFubmVsVG9EZXRhY2g6IENoYW5uZWwgKVxuICB7XG4gICAgbGV0IGlkeCA9IHRoaXMuX2NoYW5uZWxzLmluZGV4T2YoIGNoYW5uZWxUb0RldGFjaCApO1xuXG4gICAgaWYgKCBpZHggPj0gMCApXG4gICAge1xuICAgICAgY2hhbm5lbFRvRGV0YWNoLnJlbW92ZUVuZFBvaW50KCB0aGlzICk7XG5cbiAgICAgIHRoaXMuX2NoYW5uZWxzLnNwbGljZSggaWR4LCAxICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGFsbCBDaGFubmVscyBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2hBbGwoKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMuZm9yRWFjaCggY2hhbm5lbCA9PiB7XG4gICAgICBjaGFubmVsLnJlbW92ZUVuZFBvaW50KCB0aGlzICk7XG4gICAgfSApO1xuXG4gICAgdGhpcy5fY2hhbm5lbHMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIEFyZSBhbnkgY2hhbm5lbHMgYXR0YWNoZWQgdG8gdGhpcyBFbmRQb2ludD9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgRW5kcG9pbnQgaXMgYXR0YWNoZWQgdG8gYXQtbGVhc3Qtb25lIENoYW5uZWxcbiAgKi9cbiAgZ2V0IGF0dGFjaGVkKClcbiAge1xuICAgIHJldHVybiAoIHRoaXMuX2NoYW5uZWxzLmxlbmd0aCA+IDAgKTtcbiAgfVxuXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZGlyZWN0aW9uO1xuICB9XG5cbiAgLyoqXG4gICogSGFuZGxlIGFuIGluY29taW5nIE1lc3NhZ2UsIG1ldGhvZCBjYWxsZWQgYnkgQ2hhbm5lbC5cbiAgKi9cbiAgcHVibGljIGhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiwgZnJvbUVuZFBvaW50OiBFbmRQb2ludCwgZnJvbUNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5mb3JFYWNoKCBtZXNzYWdlTGlzdGVuZXIgPT4ge1xuICAgICAgbWVzc2FnZUxpc3RlbmVyKCBtZXNzYWdlLCB0aGlzLCBmcm9tQ2hhbm5lbCApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFNlbmQgYSBNZXNzYWdlLlxuICAqL1xuICBwdWJsaWMgc2VuZE1lc3NhZ2UoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiApXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwuc2VuZE1lc3NhZ2UoIHRoaXMsIG1lc3NhZ2UgKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgKiBSZWdpc3RlciBhIGRlbGVnYXRlIHRvIHJlY2VpdmUgaW5jb21pbmcgTWVzc2FnZXNcbiAgKlxuICAqIEBwYXJhbSBtZXNzYWdlTGlzdGVuZXIgLSBkZWxlZ2F0ZSB0byBiZSBjYWxsZWQgd2l0aCByZWNlaXZlZCBNZXNzYWdlXG4gICovXG4gIHB1YmxpYyBvbk1lc3NhZ2UoIG1lc3NhZ2VMaXN0ZW5lcjogSGFuZGxlTWVzc2FnZURlbGVnYXRlIClcbiAge1xuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMucHVzaCggbWVzc2FnZUxpc3RlbmVyICk7XG4gIH1cbn1cblxuLyoqXG4qIEFuIGluZGV4ZWQgY29sbGVjdGlvbiBvZiBFbmRQb2ludCBvYmplY3RzLCBub3JtYWxseSBpbmRleGVkIHZpYSBFbmRQb2ludCdzXG4qIHVuaXF1ZSBpZGVudGlmaWVyXG4qL1xuZXhwb3J0IHR5cGUgRW5kUG9pbnRDb2xsZWN0aW9uID0geyBbaWQ6IHN0cmluZ106IEVuZFBvaW50OyB9O1xuIiwiaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5pbXBvcnQgeyBLaW5kLCBLaW5kSW5mbyB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5cbmV4cG9ydCBlbnVtIFByb3RvY29sVHlwZUJpdHNcbntcbiAgUEFDS0VUID0gMCwgICAgICAgICAvKiogRGF0YWdyYW0tb3JpZW50ZWQgKGFsd2F5cyBjb25uZWN0ZWQuLi4pICovXG4gIFNUUkVBTSA9IDEsICAgICAgICAgLyoqIENvbm5lY3Rpb24tb3JpZW50ZWQgKi9cblxuICBPTkVXQVkgPSAwLCAgICAgICAgIC8qKiBVbmlkaXJlY3Rpb25hbCBPVVQgKHNvdXJjZSkgLT4gSU4gKHNpbmspICovXG4gIENMSUVOVFNFUlZFUiA9IDQsICAgLyoqIENvbW1hbmQgT1VULT5JTiwgUmVzcG9uc2UgSU4tPk9VVCAqL1xuICBQRUVSMlBFRVIgPSA2LCAgICAgIC8qKiBCaWRpcmVjdGlvbmFsOiBJTk9VVCA8LT4gSU5PVVQgKi9cblxuICBVTlRZUEVEID0gMCwgICAgICAgIC8qKiBVbnR5cGVkIGRhdGEgKi9cbiAgVFlQRUQgPSA4LCAgICAgICAgICAvKiogVHlwZWQgZGF0YSAqKi9cbn1cblxuZXhwb3J0IHR5cGUgUHJvdG9jb2xUeXBlID0gbnVtYmVyO1xuXG5leHBvcnQgY2xhc3MgUHJvdG9jb2w8VD5cbntcbiAgc3RhdGljIHByb3RvY29sVHlwZTogUHJvdG9jb2xUeXBlID0gMDtcbn1cblxuLyoqXG4qIEEgQ2xpZW50LVNlcnZlciBQcm90b2NvbCwgdG8gYmUgdXNlZCBiZXR3ZWVuXG4qL1xuY2xhc3MgQ2xpZW50U2VydmVyUHJvdG9jb2w8VD4gZXh0ZW5kcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSBQcm90b2NvbFR5cGVCaXRzLkNMSUVOVFNFUlZFUiB8IFByb3RvY29sVHlwZUJpdHMuVFlQRUQ7XG59XG5cbmNsYXNzIEFQRFUgaW1wbGVtZW50cyBLaW5kIHtcbiAga2luZEluZm86IEtpbmRJbmZvO1xuICBwcm9wZXJ0aWVzO1xufVxuXG5jbGFzcyBBUERVTWVzc2FnZSBleHRlbmRzIE1lc3NhZ2U8QVBEVT5cbntcbn1cblxuY2xhc3MgQVBEVVByb3RvY29sIGV4dGVuZHMgQ2xpZW50U2VydmVyUHJvdG9jb2w8QVBEVU1lc3NhZ2U+XG57XG5cbn1cbiIsImltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5cbi8qKlxuKiBAY2xhc3MgUG9ydEluZm9cbipcbiogTWV0YWRhdGEgYWJvdXQgYSBjb21wb25lbnQncyBQb3J0XG4qL1xuZXhwb3J0IGNsYXNzIFBvcnRJbmZvXG57XG4gIC8qKlxuICAqIEJyaWVmIGRlc2NyaXB0aW9uIGZvciB0aGUgcG9ydCwgdG8gYXBwZWFyIGluICdoaW50J1xuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIERpcmVjdGlvbjogSU4sIE9VVCwgb3IgSU5PVVRcbiAgKiAgIGZvciBjbGllbnQtc2VydmVyLCBPVVQ9Q2xpZW50LCBJTj1TZXJ2ZXJcbiAgKi9cbiAgZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgLyoqXG4gICogUHJvdG9jb2wgaW1wbGVtZW50ZWQgYnkgdGhlIHBvcnRcbiAgKi9cbiAgcHJvdG9jb2w6IFByb3RvY29sPGFueT47XG5cbiAgLyoqXG4gICogUkZVIC0gaW5kZXhhYmxlIHBvcnRzXG4gICovXG4gIGNvdW50OiBudW1iZXIgPSAwO1xuXG4gIC8qKlxuICAqIHRydWUgaXMgcG9ydCBtdXN0IGJlIGNvbm5lY3RlZCBmb3IgY29tcG9uZW50IHRvIGV4ZWN1dGVcbiAgKi9cbiAgcmVxdWlyZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbn1cbiIsImltcG9ydCB7IEtpbmQsIEtpbmRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24sIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuXG5pbXBvcnQgeyBQb3J0SW5mbyB9IGZyb20gJy4vcG9ydC1pbmZvJztcblxuLyoqXG4qIEBjbGFzcyBDb21wb25lbnRJbmZvXG4qXG4qIE1ldGFkYXRhIGFib3V0IGEgQ29tcG9uZW50XG4qL1xuZXhwb3J0IGNsYXNzIENvbXBvbmVudEluZm9cbntcbiAgLyoqXG4gICogQ29tcG9uZW50IE5hbWVcbiAgKi9cbiAgbmFtZTogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEJyaWVmIGRlc2NyaXB0aW9uIGZvciB0aGUgY29tcG9uZW50LCB0byBhcHBlYXIgaW4gJ2hpbnQnXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogTGluayB0byBkZXRhaWxlZCBpbmZvcm1hdGlvbiBmb3IgdGhlIGNvbXBvbmVudFxuICAqL1xuICBkZXRhaWxMaW5rOiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBDYXRlZ29yeSBuYW1lIGZvciB0aGUgY29tcG9uZW50LCBncm91cHMgc2FtZSBjYXRlZ29yaWVzIHRvZ2V0aGVyXG4gICovXG4gIGNhdGVnb3J5OiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBBdXRob3IncyBuYW1lXG4gICovXG4gIGF1dGhvcjogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQXJyYXkgb2YgUG9ydCBkZXNjcmlwdG9ycy4gV2hlbiBhY3RpdmUsIHRoZSBjb21wb25lbnQgd2lsbCBjb21tdW5pY2F0ZVxuICAqIHRocm91Z2ggY29ycmVzcG9uZGluZyBFbmRQb2ludHNcbiAgKi9cbiAgcG9ydHM6IHsgW2lkOiBzdHJpbmddOiBQb3J0SW5mbyB9ID0ge307XG4gIHN0b3JlczogeyBbaWQ6IHN0cmluZ106IFBvcnRJbmZvIH0gPSB7fTtcblxuICAvKipcbiAgKlxuICAqL1xuICBjb25maWdLaW5kOiBLaW5kQ29uc3RydWN0b3I7XG4gIGRlZmF1bHRDb25maWc6IEtpbmQ7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cbn1cbiIsIlxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgY29tcG9uZW50J3MgU3RvcmVcbiogVE9ETzogXG4qL1xuZXhwb3J0IGNsYXNzIFN0b3JlSW5mb1xue1xufVxuIiwiaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5pbXBvcnQgeyBTdG9yZUluZm8gfSBmcm9tICcuL3N0b3JlLWluZm8nO1xuaW1wb3J0IHsgQ29tcG9uZW50SW5mbyB9IGZyb20gJy4vY29tcG9uZW50LWluZm8nO1xuaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuaW1wb3J0IHsgS2luZCwgS2luZENvbnN0cnVjdG9yIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdDb21wb25lbnQnIG1ldGFkYXRhIChzdGF0aWMgY29tcG9uZW50SW5mbylcbiovXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50QnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApIHtcblxuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmNvbXBvbmVudEluZm8gPSB7XG4gICAgICBuYW1lOiBuYW1lIHx8IGN0b3IubmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIGRldGFpbExpbms6ICcnLFxuICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5LFxuICAgICAgYXV0aG9yOiAnJyxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIHN0b3Jlczoge30sXG4gICAgICBjb25maWdLaW5kOiBLaW5kLFxuICAgICAgZGVmYXVsdENvbmZpZzoge31cbiAgICB9O1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApOiBDb21wb25lbnRCdWlsZGVyXG4gIHtcbiAgICBsZXQgYnVpbGRlciA9IG5ldyBDb21wb25lbnRCdWlsZGVyKCBjdG9yLCBuYW1lLCBkZXNjcmlwdGlvbiwgY2F0ZWdvcnkgKTtcblxuICAgIHJldHVybiBidWlsZGVyO1xuICB9XG5cbiAgcHVibGljIGNvbmZpZyggY29uZmlnS2luZDogS2luZENvbnN0cnVjdG9yLCBkZWZhdWx0Q29uZmlnPzogS2luZCApOiB0aGlzIHtcblxuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLmNvbmZpZ0tpbmQgPSBjb25maWdLaW5kO1xuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLmRlZmF1bHRDb25maWcgPSBkZWZhdWx0Q29uZmlnO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgcG9ydCggaWQ6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZGlyZWN0aW9uOiBEaXJlY3Rpb24sIG9wdHM/OiB7IHByb3RvY29sPzogUHJvdG9jb2w8YW55PjsgY291bnQ/OiBudW1iZXI7IHJlcXVpcmVkPzogYm9vbGVhbiB9ICk6IHRoaXNcbiAge1xuICAgIG9wdHMgPSBvcHRzIHx8IHt9O1xuXG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8ucG9ydHNbIGlkIF0gPSB7XG4gICAgICBkaXJlY3Rpb246IGRpcmVjdGlvbixcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIHByb3RvY29sOiBvcHRzLnByb3RvY29sLFxuICAgICAgY291bnQ6IG9wdHMuY291bnQsXG4gICAgICByZXF1aXJlZDogb3B0cy5yZXF1aXJlZFxuICAgIH07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG4vKipcbiogQ29tcG9uZW50cyBhcmUgcnVudGltZSBvYmplY3RzIHRoYXQgZXhlY3V0ZSB3aXRoaW4gYSBHcmFwaC5cbipcbiogQSBncmFwaCBOb2RlIGlzIGEgcGxhY2Vob2xkZXIgZm9yIHRoZSBhY3R1YWwgQ29tcG9uZW50IHRoYXRcbiogd2lsbCBleGVjdXRlLlxuKlxuKiBUaGlzIGludGVyZmFjZSBkZWZpbmVzIHRoZSBzdGFuZGFyZCBtZXRob2RzIGFuZCBwcm9wZXJ0aWVzIHRoYXQgYSBDb21wb25lbnRcbiogY2FuIG9wdGlvbmFsbHkgaW1wbGVtZW50LlxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ29tcG9uZW50XG57XG4gIC8vIEluaXRpYWxpemF0aW9uIGFuZCBzaHV0ZG93blxuICBpbml0aWFsaXplPyggY29uZmlnPzogS2luZCApOiBFbmRQb2ludFtdO1xuICB0ZWFyZG93bj8oKTtcblxuICAvLyBSdW5uaW5nXG4gIHN0YXJ0PygpO1xuICBzdG9wPygpO1xuXG4gIC8vIFBhdXNpbmcgYW5kIGNvbnRpbnVpbmcgZXhlY3V0aW9uICh3aXRob3V0IHJlc2V0dGluZyAuLilcbiAgcGF1c2U/KCk7XG4gIHJlc3VtZT8oKTtcblxuICBiaW5kVmlldz8oIHZpZXc6IGFueSApO1xuICB1bmJpbmRWaWV3PygpO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENvbXBvbmVudENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIC4uLmFyZ3MgKTogQ29tcG9uZW50O1xuXG4gIGNvbXBvbmVudEluZm8/OiBDb21wb25lbnRJbmZvO1xufVxuIiwiaW1wb3J0IHsgQ29udGFpbmVyLCBhdXRvaW5qZWN0IGFzIGluamVjdCB9IGZyb20gJ2F1cmVsaWEtZGVwZW5kZW5jeS1pbmplY3Rpb24nO1xuaW1wb3J0IHsgbWV0YWRhdGEgfSBmcm9tICdhdXJlbGlhLW1ldGFkYXRhJztcblxuZXhwb3J0IHsgQ29udGFpbmVyLCBpbmplY3QgfTtcbmV4cG9ydCBpbnRlcmZhY2UgSW5qZWN0YWJsZSB7XG4gIG5ldyggLi4uYXJncyApOiBPYmplY3Q7XG59XG4iLCJpbXBvcnQgeyBFdmVudEFnZ3JlZ2F0b3IsIFN1YnNjcmlwdGlvbiwgSGFuZGxlciBhcyBFdmVudEhhbmRsZXIgfSBmcm9tICdhdXJlbGlhLWV2ZW50LWFnZ3JlZ2F0b3InO1xuXG4vL2V4cG9ydCB7IEV2ZW50SGFuZGxlciB9O1xuXG5leHBvcnQgY2xhc3MgRXZlbnRIdWJcbntcbiAgX2V2ZW50QWdncmVnYXRvcjogRXZlbnRBZ2dyZWdhdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IgPSBuZXcgRXZlbnRBZ2dyZWdhdG9yKCk7XG4gIH1cblxuICBwdWJsaWMgcHVibGlzaCggZXZlbnQ6IHN0cmluZywgZGF0YT86IGFueSApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IucHVibGlzaCggZXZlbnQsIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmUoIGV2ZW50OiBzdHJpbmcsIGhhbmRsZXI6IEZ1bmN0aW9uICk6IFN1YnNjcmlwdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2V2ZW50QWdncmVnYXRvci5zdWJzY3JpYmUoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cblxuICBwdWJsaWMgc3Vic2NyaWJlT25jZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZU9uY2UoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cbn1cblxuLypmdW5jdGlvbiBldmVudEh1YigpOiBhbnkge1xuICByZXR1cm4gZnVuY3Rpb24gZXZlbnRIdWI8VEZ1bmN0aW9uIGV4dGVuZHMgRnVuY3Rpb24sIEV2ZW50SHViPih0YXJnZXQ6IFRGdW5jdGlvbik6IFRGdW5jdGlvbiB7XG5cbiAgICB0YXJnZXQucHJvdG90eXBlLnN1YnNjcmliZSA9IG5ld0NvbnN0cnVjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUodGFyZ2V0LnByb3RvdHlwZSk7XG4gICAgbmV3Q29uc3RydWN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gdGFyZ2V0O1xuXG4gICAgcmV0dXJuIDxhbnk+IG5ld0NvbnN0cnVjdG9yO1xuICB9XG59XG5cbkBldmVudEh1YigpXG5jbGFzcyBNeUNsYXNzIHt9O1xuKi9cbiIsImltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcblxuLyoqXG4qIEEgUG9ydCBpcyBhIHBsYWNlaG9sZGVyIGZvciBhbiBFbmRQb2ludCBwdWJsaXNoZWQgYnkgdGhlIHVuZGVybHlpbmdcbiogY29tcG9uZW50IG9mIGEgTm9kZS5cbiovXG5leHBvcnQgY2xhc3MgUG9ydFxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBOb2RlO1xuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2VuZFBvaW50OiBFbmRQb2ludDtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IE5vZGUsIGVuZFBvaW50OiBFbmRQb2ludCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgLy8gV2FzIGFuIEVuZFBvaW50IHN1cHBsaWVkP1xuICAgIGlmICggIWVuZFBvaW50IClcbiAgICB7XG4gICAgICBsZXQgZGlyZWN0aW9uID0gYXR0cmlidXRlcy5kaXJlY3Rpb24gfHwgRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgICBpZiAoIHR5cGVvZiBhdHRyaWJ1dGVzLmRpcmVjdGlvbiA9PSBcInN0cmluZ1wiIClcbiAgICAgICAgZGlyZWN0aW9uID0gRGlyZWN0aW9uWyBkaXJlY3Rpb24udG9VcHBlckNhc2UoKSBdO1xuXG4gICAgICAvLyBDcmVhdGUgYSBcImR1bW15XCIgZW5kUG9pbnQgd2l0aCBjb3JyZWN0IGlkICsgZGlyZWN0aW9uXG4gICAgICBlbmRQb2ludCA9IG5ldyBFbmRQb2ludCggYXR0cmlidXRlcy5pZCwgZGlyZWN0aW9uICk7XG4gICAgfVxuXG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnQoKSB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50O1xuICB9XG4gIHB1YmxpYyBzZXQgZW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApIHtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0ge1xuICAgICAgaWQ6IHRoaXMuX2VuZFBvaW50LmlkLFxuICAgICAgZGlyZWN0aW9uOiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24sXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgfTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIG93bmVyXG4gICAqL1xuICBnZXQgb3duZXIoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyXG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgcHJvdG9jb2wgSURcbiAgICovXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgRW5kUG9pbnQgSURcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5pZDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBEaXJlY3Rpb25cbiAgICovXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uO1xuICB9XG5cbn1cblxuZXhwb3J0IGNsYXNzIFB1YmxpY1BvcnQgZXh0ZW5kcyBQb3J0XG57XG4gIHByb3h5RW5kUG9pbnQ6IEVuZFBvaW50O1xuICBwcm94eUNoYW5uZWw6IENoYW5uZWw7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGVuZFBvaW50LCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsZXQgcHJveHlEaXJlY3Rpb24gPVxuICAgICAgKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLklOIClcbiAgICAgICAgPyBEaXJlY3Rpb24uT1VUXG4gICAgICAgIDogKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLk9VVCApXG4gICAgICAgICAgPyBEaXJlY3Rpb24uSU5cbiAgICAgICAgICA6IERpcmVjdGlvbi5JTk9VVDtcblxuICAgIC8vIENyZWF0ZSBhbiBFbmRQb2ludCB0byBwcm94eSBiZXR3ZWVuIHRoZSBQdWJsaWMgYW5kIFByaXZhdGUgKGludGVybmFsKVxuICAgIC8vIHNpZGVzIG9mIHRoZSBQb3J0LlxuICAgIHRoaXMucHJveHlFbmRQb2ludCA9IG5ldyBFbmRQb2ludCggdGhpcy5fZW5kUG9pbnQuaWQsIHByb3h5RGlyZWN0aW9uICk7XG5cbiAgICAvLyBXaXJlLXVwIHByb3h5IC1cblxuICAgIC8vIEZvcndhcmQgaW5jb21pbmcgcGFja2V0cyAoZnJvbSBwdWJsaWMgaW50ZXJmYWNlKSB0byBwcml2YXRlXG4gICAgdGhpcy5wcm94eUVuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5fZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgdGhpcy5wcm94eUVuZFBvaW50LCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICAgIH0pO1xuXG4gICAgLy8gRm9yd2FyZCBvdXRnb2luZyBwYWNrZXRzIChmcm9tIHByaXZhdGUgaW50ZXJmYWNlKSB0byBwdWJsaWNcbiAgICB0aGlzLl9lbmRQb2ludC5vbk1lc3NhZ2UoICggbWVzc2FnZSApID0+IHtcbiAgICAgIHRoaXMucHJveHlFbmRQb2ludC5zZW5kTWVzc2FnZSggbWVzc2FnZSApO1xuICAgIH0pO1xuXG4gICAgLy8gbm90IHlldCBjb25uZWN0ZWRcbiAgICB0aGlzLnByb3h5Q2hhbm5lbCA9IG51bGw7XG4gIH1cblxuICAvLyBDb25uZWN0IHRvIFByaXZhdGUgKGludGVybmFsKSBFbmRQb2ludC4gVG8gYmUgY2FsbGVkIGR1cmluZyBncmFwaFxuICAvLyB3aXJlVXAgcGhhc2VcbiAgcHVibGljIGNvbm5lY3RQcml2YXRlKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMucHJveHlDaGFubmVsID0gY2hhbm5lbDtcblxuICAgIHRoaXMucHJveHlFbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIHB1YmxpYyBkaXNjb25uZWN0UHJpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQuZGV0YWNoKCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgcG9ydCA9IHN1cGVyLnRvT2JqZWN0KCBvcHRzICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBOb2RlIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NvbXBvbmVudDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgX2luaXRpYWxEYXRhOiBPYmplY3Q7XG5cbiAgcHJvdGVjdGVkIF9wb3J0czogTWFwPHN0cmluZywgUG9ydD47XG5cbiAgcHVibGljIG1ldGFkYXRhOiBhbnk7XG5cbiAgLyoqXG4gICAqIFJ1bnRpbWUgYW5kIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICAqL1xuICBwcm90ZWN0ZWQgX2NvbnRleHQ6IFJ1bnRpbWVDb250ZXh0O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCAnJztcbiAgICB0aGlzLl9jb21wb25lbnQgPSBhdHRyaWJ1dGVzLmNvbXBvbmVudDtcbiAgICB0aGlzLl9pbml0aWFsRGF0YSA9IGF0dHJpYnV0ZXMuaW5pdGlhbERhdGEgfHwge307XG5cbiAgICB0aGlzLl9wb3J0cyA9IG5ldyBNYXA8c3RyaW5nLCBQb3J0PigpO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB9O1xuXG4gICAgLy8gSW5pdGlhbGx5IGNyZWF0ZSAncGxhY2Vob2xkZXInIHBvcnRzLiBPbmNlIGNvbXBvbmVudCBoYXMgYmVlblxuICAgIC8vIGxvYWRlZCBhbmQgaW5zdGFudGlhdGVkLCB0aGV5IHdpbGwgYmUgY29ubmVjdGVkIGNvbm5lY3RlZCB0b1xuICAgIC8vIHRoZSBjb21wb25lbnQncyBjb21tdW5pY2F0aW9uIGVuZC1wb2ludHNcbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5wb3J0cyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGRQbGFjZWhvbGRlclBvcnQoIGlkLCBhdHRyaWJ1dGVzLnBvcnRzWyBpZCBdICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBub2RlID0ge1xuICAgICAgaWQ6IHRoaXMuaWQsXG4gICAgICBjb21wb25lbnQ6IHRoaXMuX2NvbXBvbmVudCxcbiAgICAgIGluaXRpYWxEYXRhOiB0aGlzLl9pbml0aWFsRGF0YSxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhXG4gICAgfTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICBub2RlLnBvcnRzWyBpZCBdID0gcG9ydC50b09iamVjdCgpO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIG93bmVyXG4gICAqL1xuICBwdWJsaWMgZ2V0IG93bmVyKCk6IEdyYXBoIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXJcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIE5vZGUncyBpZFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2lkO1xuICB9XG4gIC8qKlxuICAgKiBTZXQgdGhlIE5vZGUncyBpZFxuICAgKiBAcGFyYW0gaWQgLSBuZXcgaWRlbnRpZmllclxuICAgKi9cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBwdWJsaWMgdXBkYXRlUG9ydHMoIGVuZFBvaW50czogRW5kUG9pbnRbXSApIHtcbiAgICBsZXQgY3VycmVudFBvcnRzID0gdGhpcy5fcG9ydHM7XG4gICAgbGV0IG5ld1BvcnRzOiBNYXA8c3RyaW5nLFBvcnQ+ID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICAvLyBQYXJhbSBlbmRQb2ludHMgaXMgYW4gYXJyYXkgb2YgRW5kUG9pbnRzIGV4cG9ydGVkIGJ5IGEgY29tcG9uZW50XG4gICAgLy8gdXBkYXRlIG91ciBtYXAgb2YgUG9ydHMgdG8gcmVmbGVjdCB0aGlzIGFycmF5XG4gICAgLy8gVGhpcyBtYXkgbWVhbiBpbmNsdWRpbmcgYSBuZXcgUG9ydCwgdXBkYXRpbmcgYW4gZXhpc3RpbmcgUG9ydCB0b1xuICAgIC8vIHVzZSB0aGlzIHN1cHBsaWVkIEVuZFBvaW50LCBvciBldmVuIGRlbGV0aW5nIGEgJ25vLWxvbmdlcicgdmFsaWQgUG9ydFxuICAgIGVuZFBvaW50cy5mb3JFYWNoKCAoZXA6IEVuZFBvaW50ICkgPT4ge1xuICAgICAgbGV0IGlkID0gZXAuaWQ7XG5cbiAgICAgIGlmICggY3VycmVudFBvcnRzLmhhcyggaWQgKSApIHtcbiAgICAgICAgbGV0IHBvcnQgPSBjdXJyZW50UG9ydHMuZ2V0KCBpZCApO1xuXG4gICAgICAgIHBvcnQuZW5kUG9pbnQgPSBlcDtcblxuICAgICAgICBuZXdQb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICAgICAgY3VycmVudFBvcnRzLmRlbGV0ZSggaWQgKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBlbmRQb2ludCBub3QgZm91bmQsIGNyZWF0ZSBhIHBvcnQgZm9yIGl0XG4gICAgICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIGVwLCB7IGlkOiBpZCwgZGlyZWN0aW9uOiBlcC5kaXJlY3Rpb24gfSApO1xuXG4gICAgICAgIG5ld1BvcnRzLnNldCggaWQsIHBvcnQgKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3UG9ydHM7XG4gIH1cblxuXG4gIC8qKlxuICAgKiBBZGQgYSBwbGFjZWhvbGRlciBQb3J0XG4gICAqL1xuICBwcm90ZWN0ZWQgYWRkUGxhY2Vob2xkZXJQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBwb3J0cyBhcyBhbiBhcnJheSBvZiBQb3J0c1xuICAgKlxuICAgKiBAcmV0dXJuIFBvcnRbXVxuICAgKi9cbiAgZ2V0IHBvcnRzKCk6IE1hcDxzdHJpbmcsIFBvcnQ+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHM7XG4gIH1cblxuICBnZXRQb3J0QXJyYXkoKTogUG9ydFtdIHtcbiAgICBsZXQgeHBvcnRzOiBQb3J0W10gPSBbXTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICB4cG9ydHMucHVzaCggcG9ydCApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiB4cG9ydHM7XG4gIH1cblxuICAvKipcbiAgICogTG9va3VwIGEgUG9ydCBieSBpdCdzIElEXG4gICAqIEBwYXJhbSBpZCAtIHBvcnQgaWRlbnRpZmllclxuICAgKlxuICAgKiBAcmV0dXJuIFBvcnQgb3IgdW5kZWZpbmVkXG4gICAqL1xuICBnZXRQb3J0QnlJRCggaWQ6IHN0cmluZyApOiBQb3J0XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICB9XG5cbiAgaWRlbnRpZnlQb3J0KCBpZDogc3RyaW5nLCBwcm90b2NvbElEPzogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHZhciBwb3J0OiBQb3J0O1xuXG4gICAgaWYgKCBpZCApXG4gICAgICBwb3J0ID0gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICAgIGVsc2UgaWYgKCBwcm90b2NvbElEIClcbiAgICB7XG4gICAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHAsIGlkICkgPT4ge1xuICAgICAgICBpZiAoIHAucHJvdG9jb2xJRCA9PSBwcm90b2NvbElEIClcbiAgICAgICAgICBwb3J0ID0gcDtcbiAgICAgIH0sIHRoaXMgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmUgYSBQb3J0IGZyb20gdGhpcyBOb2RlXG4gICAqIEBwYXJhbSBpZCAtIGlkZW50aWZpZXIgb2YgUG9ydCB0byBiZSByZW1vdmVkXG4gICAqIEByZXR1cm4gdHJ1ZSAtIHBvcnQgcmVtb3ZlZFxuICAgKiAgICAgICAgIGZhbHNlIC0gcG9ydCBpbmV4aXN0ZW50XG4gICAqL1xuICByZW1vdmVQb3J0KCBpZDogc3RyaW5nICk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMudW5sb2FkQ29tcG9uZW50KCk7XG5cbiAgICAvLyBHZXQgYSBDb21wb25lbnRDb250ZXh0IHJlc3BvbnNhYmxlIGZvciBDb21wb25lbnQncyBsaWZlLWN5Y2xlIGNvbnRyb2xcbiAgICBsZXQgY3R4ID0gdGhpcy5fY29udGV4dCA9IGZhY3RvcnkuY3JlYXRlQ29udGV4dCggdGhpcy5fY29tcG9uZW50LCB0aGlzLl9pbml0aWFsRGF0YSApO1xuXG4gICAgLy8gTWFrZSBvdXJzZWx2ZXMgdmlzaWJsZSB0byBjb250ZXh0IChhbmQgaW5zdGFuY2UpXG4gICAgY3R4Lm5vZGUgPSB0aGlzO1xuXG4gICAgLy9sZXQgbWUgPSB0aGlzO1xuXG4gICAgLy8gTG9hZCBjb21wb25lbnRcbiAgICByZXR1cm4gY3R4LmxvYWQoKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgY29udGV4dCgpOiBSdW50aW1lQ29udGV4dCB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbnRleHQ7XG4gIH1cblxuICB1bmxvYWRDb21wb25lbnQoKVxuICB7XG4gICAgaWYgKCB0aGlzLl9jb250ZXh0IClcbiAgICB7XG4gICAgICB0aGlzLl9jb250ZXh0LnJlbGVhc2UoKTtcblxuICAgICAgdGhpcy5fY29udGV4dCA9IG51bGw7XG4gICAgfVxuICB9XG5cbn1cbiIsImltcG9ydCB7IEtpbmQgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuaW1wb3J0IHsgRW5kUG9pbnQsIEVuZFBvaW50Q29sbGVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4uL2dyYXBoL25vZGUnO1xuaW1wb3J0IHsgUG9ydCB9IGZyb20gJy4uL2dyYXBoL3BvcnQnO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeX0gZnJvbSAnLi9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBDb21wb25lbnQgfSBmcm9tICcuLi9jb21wb25lbnQvY29tcG9uZW50JztcblxuaW1wb3J0IHsgQ29udGFpbmVyLCBJbmplY3RhYmxlIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcblxuZXhwb3J0IGVudW0gUnVuU3RhdGUge1xuICBORVdCT1JOLCAgICAgIC8vIE5vdCB5ZXQgbG9hZGVkXG4gIExPQURJTkcsICAgICAgLy8gV2FpdGluZyBmb3IgYXN5bmMgbG9hZCB0byBjb21wbGV0ZVxuICBMT0FERUQsICAgICAgIC8vIENvbXBvbmVudCBsb2FkZWQsIG5vdCB5ZXQgZXhlY3V0YWJsZVxuICBSRUFEWSwgICAgICAgIC8vIFJlYWR5IGZvciBFeGVjdXRpb25cbiAgUlVOTklORywgICAgICAvLyBOZXR3b3JrIGFjdGl2ZSwgYW5kIHJ1bm5pbmdcbiAgUEFVU0VEICAgICAgICAvLyBOZXR3b3JrIHRlbXBvcmFyaWx5IHBhdXNlZFxufVxuXG4vKipcbiogVGhlIHJ1bnRpbWUgY29udGV4dCBpbmZvcm1hdGlvbiBmb3IgYSBDb21wb25lbnQgaW5zdGFuY2VcbiovXG5leHBvcnQgY2xhc3MgUnVudGltZUNvbnRleHRcbntcbiAgLyoqXG4gICogVGhlIGNvbXBvbmVudCBpZCAvIGFkZHJlc3NcbiAgKi9cbiAgcHJpdmF0ZSBfaWQ6IHN0cmluZztcblxuICAvKipcbiAgKiBUaGUgcnVudGltZSBjb21wb25lbnQgaW5zdGFuY2UgdGhhdCB0aGlzIG5vZGUgcmVwcmVzZW50c1xuICAqL1xuICBwcml2YXRlIF9pbnN0YW5jZTogQ29tcG9uZW50O1xuXG4gIC8qKlxuICAqIEluaXRpYWwgRGF0YSBmb3IgdGhlIGNvbXBvbmVudCBpbnN0YW5jZVxuICAqL1xuICBwcml2YXRlIF9jb25maWc6IHt9O1xuXG4gIC8qKlxuICAqIFRoZSBydW50aW1lIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICovXG4gIHByaXZhdGUgX2NvbnRhaW5lcjogQ29udGFpbmVyO1xuXG4gIC8qKlxuICAqIFRoZSBjb21wb25lbnQgZmFjdG9yeSB0aGF0IGNyZWF0ZWQgdXNcbiAgKi9cbiAgcHJpdmF0ZSBfZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeTtcblxuICAvKipcbiAgKiBUaGUgbm9kZVxuICAqL1xuICBwcml2YXRlIF9ub2RlOiBOb2RlO1xuXG4gIC8qKlxuICAqXG4gICpcbiAgKi9cbiAgY29uc3RydWN0b3IoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnksIGNvbnRhaW5lcjogQ29udGFpbmVyLCBpZDogc3RyaW5nLCBjb25maWc6IHt9LCBkZXBzOiBJbmplY3RhYmxlW10gPSBbXSApIHtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBmYWN0b3J5O1xuXG4gICAgdGhpcy5faWQgPSBpZDtcblxuICAgIHRoaXMuX2NvbmZpZyA9IGNvbmZpZztcblxuICAgIHRoaXMuX2NvbnRhaW5lciA9IGNvbnRhaW5lcjtcblxuICAgIC8vIFJlZ2lzdGVyIGFueSBjb250ZXh0IGRlcGVuZGVuY2llc1xuICAgIGZvciggbGV0IGkgaW4gZGVwcyApXG4gICAge1xuICAgICAgaWYgKCAhdGhpcy5fY29udGFpbmVyLmhhc1Jlc29sdmVyKCBkZXBzW2ldICkgKVxuICAgICAgICB0aGlzLl9jb250YWluZXIucmVnaXN0ZXJTaW5nbGV0b24oIGRlcHNbaV0sIGRlcHNbaV0gKTtcbiAgICB9XG4gIH1cblxuICBnZXQgbm9kZSgpOiBOb2RlIHtcbiAgICByZXR1cm4gdGhpcy5fbm9kZTtcbiAgfVxuICBzZXQgbm9kZSggbm9kZTogTm9kZSApIHtcbiAgICB0aGlzLl9ub2RlID0gbm9kZTtcblxuICAgIC8vIG1ha2Ugbm9kZSAnaW5qZWN0YWJsZScgaW4gY29udGFpbmVyXG4gICAgdGhpcy5fY29udGFpbmVyLnJlZ2lzdGVySW5zdGFuY2UoIE5vZGUsIHRoaXMgKTtcbiAgfVxuXG4gIGdldCBpbnN0YW5jZSgpOiBDb21wb25lbnQge1xuICAgIHJldHVybiB0aGlzLl9pbnN0YW5jZTtcbiAgfVxuXG4gIGdldCBjb250YWluZXIoKTogQ29udGFpbmVyIHtcbiAgICByZXR1cm4gdGhpcy5fY29udGFpbmVyO1xuICB9XG5cbiAgbG9hZCggKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gZ2V0IGFuIGluc3RhbmNlIGZyb20gdGhlIGZhY3RvcnlcbiAgICAgIG1lLl9ydW5TdGF0ZSA9IFJ1blN0YXRlLkxPQURJTkc7XG4gICAgICB0aGlzLl9mYWN0b3J5LmxvYWRDb21wb25lbnQoIHRoaXMsIHRoaXMuX2lkIClcbiAgICAgICAgLnRoZW4oIChpbnN0YW5jZSkgPT4ge1xuICAgICAgICAgIC8vIENvbXBvbmVudCAoYW5kIGFueSBkZXBlbmRlbmNpZXMpIGhhdmUgYmVlbiBsb2FkZWRcbiAgICAgICAgICBtZS5faW5zdGFuY2UgPSBpbnN0YW5jZTtcbiAgICAgICAgICBtZS5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuTE9BREVEICk7XG5cbiAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaCggKGVycikgPT4ge1xuICAgICAgICAgIC8vIFVuYWJsZSB0byBsb2FkXG4gICAgICAgICAgbWUuX3J1blN0YXRlID0gUnVuU3RhdGUuTkVXQk9STjtcblxuICAgICAgICAgIHJlamVjdCggZXJyICk7XG4gICAgICAgIH0pO1xuICAgIH0gKTtcbiAgfVxuXG4gIF9ydW5TdGF0ZTogUnVuU3RhdGUgPSBSdW5TdGF0ZS5ORVdCT1JOO1xuICBnZXQgcnVuU3RhdGUoKSB7XG4gICAgcmV0dXJuIHRoaXMuX3J1blN0YXRlO1xuICB9XG5cbiAgcHJpdmF0ZSBpblN0YXRlKCBzdGF0ZXM6IFJ1blN0YXRlW10gKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIG5ldyBTZXQ8UnVuU3RhdGU+KCBzdGF0ZXMgKS5oYXMoIHRoaXMuX3J1blN0YXRlICk7XG4gIH1cblxuICAvKipcbiAgKiBUcmFuc2l0aW9uIGNvbXBvbmVudCB0byBuZXcgc3RhdGVcbiAgKiBTdGFuZGFyZCB0cmFuc2l0aW9ucywgYW5kIHJlc3BlY3RpdmUgYWN0aW9ucywgYXJlOlxuICAqICAgTE9BREVEIC0+IFJFQURZICAgICAgaW5zdGFudGlhdGUgYW5kIGluaXRpYWxpemUgY29tcG9uZW50XG4gICogICBSRUFEWSAtPiBMT0FERUQgICAgICB0ZWFyZG93biBhbmQgZGVzdHJveSBjb21wb25lbnRcbiAgKlxuICAqICAgUkVBRFkgLT4gUlVOTklORyAgICAgc3RhcnQgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqICAgUlVOTklORyAtPiBSRUFEWSAgICAgc3RvcCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICpcbiAgKiAgIFJVTk5JTkcgLT4gUEFVU0VEICAgIHBhdXNlIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKiAgIFBBVVNFRCAtPiBSVU5OSU5HICAgIHJlc3VtZSBjb21wb25lbnQgZXhlY3V0aW9uXG4gICpcbiAgKi9cbiAgc2V0UnVuU3RhdGUoIHJ1blN0YXRlOiBSdW5TdGF0ZSApIHtcbiAgICBsZXQgaW5zdCA9IHRoaXMuaW5zdGFuY2U7XG5cbiAgICBzd2l0Y2goIHJ1blN0YXRlICkgLy8gdGFyZ2V0IHN0YXRlIC4uXG4gICAge1xuICAgICAgY2FzZSBSdW5TdGF0ZS5MT0FERUQ6IC8vIGp1c3QgbG9hZGVkLCBvciB0ZWFyZG93blxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SRUFEWSwgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyB0ZWFyZG93biBhbmQgZGVzdHJveSBjb21wb25lbnRcbiAgICAgICAgICBpZiAoIGluc3QudGVhcmRvd24gKVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGluc3QudGVhcmRvd24oKTtcblxuICAgICAgICAgICAgLy8gYW5kIGRlc3Ryb3kgaW5zdGFuY2VcbiAgICAgICAgICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUkVBRFk6ICAvLyBpbml0aWFsaXplIG9yIHN0b3Agbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5MT0FERUQgXSApICkge1xuICAgICAgICAgIC8vIGluaXRpYWxpemUgY29tcG9uZW50XG5cbiAgICAgICAgICBsZXQgZW5kUG9pbnRzOiBFbmRQb2ludFtdID0gW107XG5cbiAgICAgICAgICBpZiAoIGluc3QuaW5pdGlhbGl6ZSApXG4gICAgICAgICAgICBlbmRQb2ludHMgPSB0aGlzLmluc3RhbmNlLmluaXRpYWxpemUoIDxLaW5kPnRoaXMuX2NvbmZpZyApO1xuXG4gICAgICAgICAgaWYgKCB0aGlzLl9ub2RlIClcbiAgICAgICAgICAgIHRoaXMuX25vZGUudXBkYXRlUG9ydHMoIGVuZFBvaW50cyApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyBzdG9wIGNvbXBvbmVudFxuICAgICAgICAgIGlmICggaW5zdC5zdG9wIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2Uuc3RvcCgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIGluaXRpYWxpemVkLCBub3QgbG9hZGVkJyApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5SVU5OSU5HOiAgLy8gc3RhcnQvcmVzdW1lIG5vZGVcbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUkVBRFksIFJ1blN0YXRlLlJVTk5JTkcgXSApICkge1xuICAgICAgICAgIC8vIHN0YXJ0IGNvbXBvbmVudCBleGVjdXRpb25cbiAgICAgICAgICBpZiAoIGluc3Quc3RhcnQgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5zdGFydCgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyByZXN1bWUgY29tcG9uZW50IGV4ZWN1dGlvbiBhZnRlciBwYXVzZVxuICAgICAgICAgIGlmICggaW5zdC5yZXN1bWUgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5yZXN1bWUoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBzdGFydGVkLCBub3QgcmVhZHknICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlBBVVNFRDogIC8vIHBhdXNlIG5vZGVcbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklOR10gKSApIHtcbiAgICAgICAgICBpZiAoIGluc3QucGF1c2UgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5wYXVzZSgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyBhbHJlYWR5IHBhdXNlZFxuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIHBhdXNlZCcgKTtcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgdGhpcy5fcnVuU3RhdGUgPSBydW5TdGF0ZTtcbiAgfVxuXG4gIHJlbGVhc2UoKSB7XG4gICAgLy8gcmVsZWFzZSBpbnN0YW5jZSwgdG8gYXZvaWQgbWVtb3J5IGxlYWtzXG4gICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IG51bGxcbiAgfVxufVxuIiwiZXhwb3J0IGludGVyZmFjZSBNb2R1bGVMb2FkZXIge1xuICBoYXNNb2R1bGU/KCBpZDogc3RyaW5nICk6IGJvb2xlYW47XG5cbiAgbG9hZE1vZHVsZSggaWQ6IHN0cmluZyApOiBQcm9taXNlPGFueT47XG59XG5cbmRlY2xhcmUgaW50ZXJmYWNlIFN5c3RlbSB7XG4gIG5vcm1hbGl6ZVN5bmMoIGlkICk7XG4gIGltcG9ydCggaWQgKTtcbn07XG5kZWNsYXJlIHZhciBTeXN0ZW06IFN5c3RlbTtcblxuY2xhc3MgTW9kdWxlUmVnaXN0cnlFbnRyeSB7XG4gIGNvbnN0cnVjdG9yKCBhZGRyZXNzOiBzdHJpbmcgKSB7XG5cbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU3lzdGVtTW9kdWxlTG9hZGVyIGltcGxlbWVudHMgTW9kdWxlTG9hZGVyIHtcblxuICBwcml2YXRlIG1vZHVsZVJlZ2lzdHJ5OiBNYXA8c3RyaW5nLCBNb2R1bGVSZWdpc3RyeUVudHJ5PjtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLm1vZHVsZVJlZ2lzdHJ5ID0gbmV3IE1hcDxzdHJpbmcsIE1vZHVsZVJlZ2lzdHJ5RW50cnk+KCk7XG4gIH1cblxuICBwcml2YXRlIGdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeShhZGRyZXNzOiBzdHJpbmcpOiBNb2R1bGVSZWdpc3RyeUVudHJ5IHtcbiAgICByZXR1cm4gdGhpcy5tb2R1bGVSZWdpc3RyeVthZGRyZXNzXSB8fCAodGhpcy5tb2R1bGVSZWdpc3RyeVthZGRyZXNzXSA9IG5ldyBNb2R1bGVSZWdpc3RyeUVudHJ5KGFkZHJlc3MpKTtcbiAgfVxuXG4gIGxvYWRNb2R1bGUoIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxhbnk+IHtcbiAgICBsZXQgbmV3SWQgPSBTeXN0ZW0ubm9ybWFsaXplU3luYyhpZCk7XG4gICAgbGV0IGV4aXN0aW5nID0gdGhpcy5tb2R1bGVSZWdpc3RyeVtuZXdJZF07XG5cbiAgICBpZiAoZXhpc3RpbmcpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZXhpc3RpbmcpO1xuICAgIH1cblxuICAgIHJldHVybiBTeXN0ZW0uaW1wb3J0KG5ld0lkKS50aGVuKG0gPT4ge1xuICAgICAgdGhpcy5tb2R1bGVSZWdpc3RyeVtuZXdJZF0gPSBtO1xuICAgICAgcmV0dXJuIG07IC8vZW5zdXJlT3JpZ2luT25FeHBvcnRzKG0sIG5ld0lkKTtcbiAgICB9KTtcbiAgfVxuXG59XG4iLCJpbXBvcnQgeyBDb21wb25lbnQsIENvbXBvbmVudENvbnN0cnVjdG9yIH0gZnJvbSAnLi4vY29tcG9uZW50L2NvbXBvbmVudCc7XG5pbXBvcnQgeyBSdW50aW1lQ29udGV4dCB9IGZyb20gJy4vcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IE1vZHVsZUxvYWRlciB9IGZyb20gJy4vbW9kdWxlLWxvYWRlcic7XG5cbmltcG9ydCB7IENvbnRhaW5lciwgSW5qZWN0YWJsZSB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5pbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcblxuZXhwb3J0IGNsYXNzIENvbXBvbmVudEZhY3Rvcnkge1xuICBwcml2YXRlIF9sb2FkZXI6IE1vZHVsZUxvYWRlcjtcbiAgcHJpdmF0ZSBfY29udGFpbmVyOiBDb250YWluZXI7XG4gIHByaXZhdGUgX2NvbXBvbmVudHM6IE1hcDxzdHJpbmcsIENvbXBvbmVudENvbnN0cnVjdG9yPjtcblxuICBjb25zdHJ1Y3RvciggY29udGFpbmVyPzogQ29udGFpbmVyLCBsb2FkZXI/OiBNb2R1bGVMb2FkZXIgKSB7XG4gICAgdGhpcy5fbG9hZGVyID0gbG9hZGVyO1xuICAgIHRoaXMuX2NvbnRhaW5lciA9IGNvbnRhaW5lciB8fCBuZXcgQ29udGFpbmVyKCk7XG4gICAgdGhpcy5fY29tcG9uZW50cyA9IG5ldyBNYXA8c3RyaW5nLCBDb21wb25lbnRDb25zdHJ1Y3Rvcj4oKTtcblxuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCB1bmRlZmluZWQsIE9iamVjdCApO1xuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCBcIlwiLCBPYmplY3QgKTtcbiAgfVxuXG4gIGNyZWF0ZUNvbnRleHQoIGlkOiBzdHJpbmcsIGNvbmZpZzoge30sIGRlcHM6IEluamVjdGFibGVbXSA9IFtdICk6IFJ1bnRpbWVDb250ZXh0XG4gIHtcbiAgICBsZXQgY2hpbGRDb250YWluZXI6IENvbnRhaW5lciA9IHRoaXMuX2NvbnRhaW5lci5jcmVhdGVDaGlsZCgpO1xuXG4gICAgcmV0dXJuIG5ldyBSdW50aW1lQ29udGV4dCggdGhpcywgY2hpbGRDb250YWluZXIsIGlkLCBjb25maWcsIGRlcHMgKTtcbiAgfVxuXG4gIGdldENoaWxkQ29udGFpbmVyKCk6IENvbnRhaW5lciB7XG4gICAgcmV0dXJuIDtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGN0eDogUnVudGltZUNvbnRleHQsIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxDb21wb25lbnQ+XG4gIHtcbiAgICBsZXQgY3JlYXRlQ29tcG9uZW50ID0gZnVuY3Rpb24oIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICk6IENvbXBvbmVudFxuICAgIHtcbiAgICAgIGxldCBuZXdJbnN0YW5jZTogQ29tcG9uZW50ID0gY3R4LmNvbnRhaW5lci5pbnZva2UoIGN0b3IgKTtcblxuICAgICAgcmV0dXJuIG5ld0luc3RhbmNlO1xuICAgIH1cblxuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q29tcG9uZW50PiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gQ2hlY2sgY2FjaGVcbiAgICAgIGxldCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciA9IHRoaXMuZ2V0KCBpZCApO1xuXG4gICAgICBpZiAoIGN0b3IgKSB7XG4gICAgICAgIC8vIHVzZSBjYWNoZWQgY29uc3RydWN0b3JcbiAgICAgICAgcmVzb2x2ZSggY3JlYXRlQ29tcG9uZW50KCBjdG9yICkgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCB0aGlzLl9sb2FkZXIgKSB7XG4gICAgICAgIC8vIGdvdCBhIGxvYWRlZCwgc28gdHJ5IHRvIGxvYWQgdGhlIG1vZHVsZSAuLi5cbiAgICAgICAgdGhpcy5fbG9hZGVyLmxvYWRNb2R1bGUoIGlkIClcbiAgICAgICAgICAudGhlbiggKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApID0+IHtcblxuICAgICAgICAgICAgLy8gcmVnaXN0ZXIgbG9hZGVkIGNvbXBvbmVudFxuICAgICAgICAgICAgbWUuX2NvbXBvbmVudHMuc2V0KCBpZCwgY3RvciApO1xuXG4gICAgICAgICAgICAvLyBpbnN0YW50aWF0ZSBhbmQgcmVzb2x2ZVxuICAgICAgICAgICAgcmVzb2x2ZSggY3JlYXRlQ29tcG9uZW50KCBjdG9yICkgKTtcbiAgICAgICAgICB9KVxuICAgICAgICAgIC5jYXRjaCggKCBlICkgPT4ge1xuICAgICAgICAgICAgcmVqZWN0KCAnQ29tcG9uZW50RmFjdG9yeTogVW5hYmxlIHRvIGxvYWQgY29tcG9uZW50IFwiJyArIGlkICsgJ1wiIC0gJyArIGUgKTtcbiAgICAgICAgICB9ICk7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgLy8gb29wcy4gbm8gbG9hZGVyIC4uIG5vIGNvbXBvbmVudFxuICAgICAgICByZWplY3QoICdDb21wb25lbnRGYWN0b3J5OiBDb21wb25lbnQgXCInICsgaWQgKyAnXCIgbm90IHJlZ2lzdGVyZWQsIGFuZCBMb2FkZXIgbm90IGF2YWlsYWJsZScgKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIGdldCggaWQ6IHN0cmluZyApOiBDb21wb25lbnRDb25zdHJ1Y3RvciB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbXBvbmVudHMuZ2V0KCBpZCApO1xuICB9XG4gIHJlZ2lzdGVyKCBpZDogc3RyaW5nLCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApIHtcbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggaWQsIGN0b3IgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IFBvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG5leHBvcnQgdHlwZSBFbmRQb2ludFJlZiA9IHsgbm9kZUlEOiBzdHJpbmcsIHBvcnRJRDogc3RyaW5nIH07XG5cbmV4cG9ydCBjbGFzcyBMaW5rXG57XG4gIHByb3RlY3RlZCBfb3duZXI6IEdyYXBoO1xuICBwcm90ZWN0ZWQgX2lkOiBzdHJpbmc7XG5cbiAgcHJvdGVjdGVkIF9jaGFubmVsOiBDaGFubmVsO1xuICBwcm90ZWN0ZWQgX2Zyb206IEVuZFBvaW50UmVmO1xuICBwcm90ZWN0ZWQgX3RvOiBFbmRQb2ludFJlZjtcblxuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcbiAgcHJvdGVjdGVkIG1ldGFkYXRhOiBhbnk7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9pZCA9IGF0dHJpYnV0ZXMuaWQgfHwgXCJcIjtcbiAgICAvL3RoaXMuX2NoYW5uZWwgPSBudWxsO1xuICAgIHRoaXMuX2Zyb20gPSBhdHRyaWJ1dGVzWyAnZnJvbScgXTtcbiAgICB0aGlzLl90byA9IGF0dHJpYnV0ZXNbICd0bycgXTtcbiAgICB0aGlzLl9wcm90b2NvbElEID0gYXR0cmlidXRlc1sgJ3Byb3RvY29sJyBdIHx8ICdhbnknO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB4OiAxMDAsIHk6IDEwMCB9O1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICBsZXQgbGluayA9IHtcbiAgICAgIGlkOiB0aGlzLl9pZCxcbiAgICAgIHByb3RvY29sOiAoIHRoaXMuX3Byb3RvY29sSUQgIT0gJ2FueScgKSA/IHRoaXMuX3Byb3RvY29sSUQgOiB1bmRlZmluZWQsXG4gICAgICBtZXRhZGF0YTogdGhpcy5tZXRhZGF0YSxcbiAgICAgIGZyb206IHRoaXMuX2Zyb20sXG4gICAgICB0bzogdGhpcy5fdG9cbiAgICB9O1xuXG4gICAgcmV0dXJuIGxpbms7XG4gIH1cblxuICBzZXQgaWQoIGlkOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIGNvbm5lY3QoIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgLy8gaWRlbnRpZnkgZnJvbVBvcnQgaW4gZnJvbU5vZGVcbiAgICBsZXQgZnJvbVBvcnQ6IFBvcnQgPSB0aGlzLmZyb21Ob2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fZnJvbS5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKTtcblxuICAgIC8vIGlkZW50aWZ5IHRvUG9ydCBpbiB0b05vZGVcbiAgICBsZXQgdG9Qb3J0OiBQb3J0ID0gdGhpcy50b05vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl90by5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKTtcblxuICAgIHRoaXMuX2NoYW5uZWwgPSBjaGFubmVsO1xuXG4gICAgZnJvbVBvcnQuZW5kUG9pbnQuYXR0YWNoKCBjaGFubmVsICk7XG4gICAgdG9Qb3J0LmVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiBDaGFubmVsXG4gIHtcbiAgICBsZXQgY2hhbiA9IHRoaXMuX2NoYW5uZWw7XG5cbiAgICBpZiAoIGNoYW4gKVxuICAgIHtcbiAgICAgIHRoaXMuX2NoYW5uZWwuZW5kUG9pbnRzLmZvckVhY2goICggZW5kUG9pbnQgKSA9PiB7XG4gICAgICAgIGVuZFBvaW50LmRldGFjaCggdGhpcy5fY2hhbm5lbCApO1xuICAgICAgfSApO1xuXG4gICAgICB0aGlzLl9jaGFubmVsID0gdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIHJldHVybiBjaGFuO1xuICB9XG5cbiAgZ2V0IGZyb21Ob2RlKCk6IE5vZGVcbiAge1xuICAgIHJldHVybiB0aGlzLl9vd25lci5nZXROb2RlQnlJRCggdGhpcy5fZnJvbS5ub2RlSUQgKTtcbiAgfVxuXG4gIGdldCBmcm9tUG9ydCgpOiBQb3J0XG4gIHtcbiAgICBsZXQgbm9kZSA9IHRoaXMuZnJvbU5vZGU7XG5cbiAgICByZXR1cm4gKG5vZGUpID8gbm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX2Zyb20ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICkgOiB1bmRlZmluZWQ7XG4gIH1cblxuICBzZXQgZnJvbVBvcnQoIHBvcnQ6IFBvcnQgKVxuICB7XG4gICAgdGhpcy5fZnJvbSA9IHtcbiAgICAgIG5vZGVJRDogcG9ydC5vd25lci5pZCxcbiAgICAgIHBvcnRJRDogcG9ydC5pZFxuICAgIH07XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gcG9ydC5wcm90b2NvbElEO1xuICB9XG5cbiAgZ2V0IHRvTm9kZSgpOiBOb2RlXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXIuZ2V0Tm9kZUJ5SUQoIHRoaXMuX3RvLm5vZGVJRCApO1xuICB9XG5cbiAgZ2V0IHRvUG9ydCgpOiBQb3J0XG4gIHtcbiAgICBsZXQgbm9kZSA9IHRoaXMudG9Ob2RlO1xuXG4gICAgcmV0dXJuIChub2RlKSA/IG5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl90by5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKSA6IHVuZGVmaW5lZDtcbiAgfVxuXG4gIHNldCB0b1BvcnQoIHBvcnQ6IFBvcnQgKVxuICB7XG4gICAgdGhpcy5fdG8gPSB7XG4gICAgICBub2RlSUQ6IHBvcnQub3duZXIuaWQsXG4gICAgICBwb3J0SUQ6IHBvcnQuaWRcbiAgICB9O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IHBvcnQucHJvdG9jb2xJRDtcbiAgfVxuXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5IH0gZnJvbSAnLi4vcnVudGltZS9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBSdW50aW1lQ29udGV4dCwgUnVuU3RhdGUgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgTGluayB9IGZyb20gJy4vbGluayc7XG5pbXBvcnQgeyBQb3J0LCBQdWJsaWNQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuZXhwb3J0IGNsYXNzIE5ldHdvcmsgZXh0ZW5kcyBFdmVudEh1Ylxue1xuICBzdGF0aWMgRVZFTlRfU1RBVEVfQ0hBTkdFID0gJ25ldHdvcms6c3RhdGUtY2hhbmdlJztcbiAgc3RhdGljIEVWRU5UX0dSQVBIX0NIQU5HRSA9ICduZXR3b3JrOmdyYXBoLWNoYW5nZSc7XG5cbiAgcHJpdmF0ZSBfZ3JhcGg6IEdyYXBoO1xuXG4gIHByaXZhdGUgX2ZhY3Rvcnk6IENvbXBvbmVudEZhY3Rvcnk7XG5cbiAgY29uc3RydWN0b3IoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnksIGdyYXBoPzogR3JhcGggKVxuICB7XG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBmYWN0b3J5O1xuICAgIHRoaXMuX2dyYXBoID0gZ3JhcGggfHwgbmV3IEdyYXBoKCBudWxsLCB7fSApO1xuXG4gICAgbGV0IG1lID0gdGhpcztcbiAgICB0aGlzLl9ncmFwaC5zdWJzY3JpYmUoIEdyYXBoLkVWRU5UX0FERF9OT0RFLCAoIGRhdGE6IHsgbm9kZTogTm9kZSB9ICk9PiB7XG4gICAgICBsZXQgcnVuU3RhdGU6IFJ1blN0YXRlID0gbWUuX2dyYXBoLmNvbnRleHQucnVuU3RhdGU7XG5cbiAgICAgIGlmICggcnVuU3RhdGUgIT0gUnVuU3RhdGUuTkVXQk9STiApXG4gICAgICB7XG4gICAgICAgIGxldCB7IG5vZGUgfSA9IGRhdGE7XG5cbiAgICAgICAgbm9kZS5sb2FkQ29tcG9uZW50KCBtZS5fZmFjdG9yeSApXG4gICAgICAgICAgLnRoZW4oICgpPT4ge1xuICAgICAgICAgICAgaWYgKCBOZXR3b3JrLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VELCBSdW5TdGF0ZS5SRUFEWSBdLCBydW5TdGF0ZSApIClcbiAgICAgICAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggbm9kZSwgUnVuU3RhdGUuUkVBRFkgKTtcblxuICAgICAgICAgICAgaWYgKCBOZXR3b3JrLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0sIHJ1blN0YXRlICkgKVxuICAgICAgICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBub2RlLCBydW5TdGF0ZSApO1xuXG4gICAgICAgICAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfR1JBUEhfQ0hBTkdFLCB7IG5vZGU6IG5vZGUgfSApO1xuICAgICAgICAgIH0pXG4gICAgICB9XG4gICAgfSApO1xuICB9XG5cbiAgZ2V0IGdyYXBoKCk6IEdyYXBoIHtcbiAgICByZXR1cm4gdGhpcy5fZ3JhcGg7XG4gIH1cblxuICAvKipcbiAgKiBMb2FkIGFsbCBjb21wb25lbnRzXG4gICovXG4gIGxvYWRDb21wb25lbnRzKCk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfU1RBVEVfQ0hBTkdFLCB7IHN0YXRlOiBSdW5TdGF0ZS5MT0FESU5HIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9ncmFwaC5sb2FkQ29tcG9uZW50KCB0aGlzLl9mYWN0b3J5ICkudGhlbiggKCk9PiB7XG4gICAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfU1RBVEVfQ0hBTkdFLCB7IHN0YXRlOiBSdW5TdGF0ZS5MT0FERUQgfSApO1xuICAgIH0pO1xuICB9XG5cbiAgaW5pdGlhbGl6ZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SRUFEWSApO1xuICB9XG5cbiAgdGVhcmRvd24oKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuTE9BREVEICk7XG4gIH1cblxuICBzdGF0aWMgaW5TdGF0ZSggc3RhdGVzOiBSdW5TdGF0ZVtdLCBydW5TdGF0ZTogUnVuU3RhdGUgKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIG5ldyBTZXQ8UnVuU3RhdGU+KCBzdGF0ZXMgKS5oYXMoIHJ1blN0YXRlICk7XG4gIH1cblxuICAvKipcbiAgKiBBbHRlciBydW4tc3RhdGUgb2YgYSBOb2RlIC0gTE9BREVELCBSRUFEWSwgUlVOTklORyBvciBQQVVTRUQuXG4gICogVHJpZ2dlcnMgU2V0dXAgb3IgVGVhcmRvd24gaWYgdHJhbnNpdGlvbmluZyBiZXR3ZWVuIFJFQURZIGFuZCBMT0FERURcbiAgKiBXaXJldXAgYSBncmFwaCwgY3JlYXRpbmcgQ2hhbm5lbCBiZXR3ZWVuIGxpbmtlZCBOb2Rlc1xuICAqIEFjdHMgcmVjdXJzaXZlbHksIHdpcmluZyB1cCBhbnkgc3ViLWdyYXBoc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyBzZXRSdW5TdGF0ZSggbm9kZTogTm9kZSwgcnVuU3RhdGU6IFJ1blN0YXRlIClcbiAge1xuICAgIGxldCBjdHggPSBub2RlLmNvbnRleHQ7XG4gICAgbGV0IGN1cnJlbnRTdGF0ZSA9IGN0eC5ydW5TdGF0ZTtcblxuICAgIGlmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoIClcbiAgICB7XG4gICAgICAvLyAxLiBQcmVwcm9jZXNzXG4gICAgICAvLyAgICBhLiBIYW5kbGUgdGVhcmRvd25cbiAgICAgIC8vICAgIGIuIFByb3BhZ2F0ZSBzdGF0ZSBjaGFuZ2UgdG8gc3VibmV0c1xuICAgICAgbGV0IG5vZGVzOiBNYXA8c3RyaW5nLCBOb2RlPiA9IG5vZGUubm9kZXM7XG5cbiAgICAgIGlmICggKCBydW5TdGF0ZSA9PSBSdW5TdGF0ZS5MT0FERUQgKSAmJiAoIGN1cnJlbnRTdGF0ZSA+PSBSdW5TdGF0ZS5SRUFEWSApICkge1xuICAgICAgICAvLyB0ZWFyaW5nIGRvd24gLi4gdW5saW5rIGdyYXBoIGZpcnN0XG4gICAgICAgIGxldCBsaW5rczogTWFwPHN0cmluZywgTGluaz4gPSBub2RlLmxpbmtzO1xuXG4gICAgICAgIC8vIHVud2lyZSAoZGVhY3RpdmF0ZSBhbmQgZGVzdHJveSApIENoYW5uZWxzIGJldHdlZW4gbGlua2VkIG5vZGVzXG4gICAgICAgIGxpbmtzLmZvckVhY2goICggbGluayApID0+XG4gICAgICAgIHtcbiAgICAgICAgICBOZXR3b3JrLnVud2lyZUxpbmsoIGxpbmsgKTtcbiAgICAgICAgfSApO1xuICAgICAgfVxuXG4gICAgICAvLyBQcm9wYWdhdGUgc3RhdGUgY2hhbmdlIHRvIHN1Yi1uZXRzIGZpcnN0XG4gICAgICBub2Rlcy5mb3JFYWNoKCBmdW5jdGlvbiggc3ViTm9kZSApXG4gICAgICB7XG4gICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIHN1Yk5vZGUsIHJ1blN0YXRlICk7XG4gICAgICB9ICk7XG5cbiAgICAgIC8vIDIuIENoYW5nZSBzdGF0ZSAuLi5cbiAgICAgIGN0eC5zZXRSdW5TdGF0ZSggcnVuU3RhdGUgKTtcblxuICAgICAgLy8gMy4gUG9zdHByb2Nlc3NcbiAgICAgIC8vICAgIGEuIEhhbmRsZSBzZXR1cFxuICAgICAgaWYgKCAoIHJ1blN0YXRlID09IFJ1blN0YXRlLlJFQURZICkgJiYgKCBjdXJyZW50U3RhdGUgPj0gUnVuU3RhdGUuTE9BREVEICkgKSB7XG5cbiAgICAgICAgLy8gc2V0dGluZyB1cCAuLiBsaW5rdXAgZ3JhcGggZmlyc3RcbiAgICAgICAgbGV0IGxpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPiA9IG5vZGUubGlua3M7XG4gICAgICAgIC8vIHRyZWF0IGdyYXBoIHJlY3Vyc2l2ZWx5XG5cbiAgICAgICAgLy8gMi4gd2lyZXVwIChjcmVhdGUgYW5kIGFjdGl2YXRlKSBhIENoYW5uZWwgYmV0d2VlbiBsaW5rZWQgbm9kZXNcbiAgICAgICAgbGlua3MuZm9yRWFjaCggKCBsaW5rICkgPT5cbiAgICAgICAge1xuICAgICAgICAgIE5ldHdvcmsud2lyZUxpbmsoIGxpbmsgKTtcbiAgICAgICAgfSApO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBDaGFuZ2Ugc3RhdGUgLi4uXG4gICAgICBjdHguc2V0UnVuU3RhdGUoIHJ1blN0YXRlICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogVW53aXJlIGEgbGluaywgcmVtb3ZpbmcgdGhlIENoYW5uZWwgYmV0d2VlbiB0aGUgbGlua2VkIE5vZGVzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHVud2lyZUxpbmsoIGxpbms6IExpbmsgKVxuICB7XG4gICAgLy8gZ2V0IGxpbmtlZCBub2RlcyAoTGluayBmaW5kcyBOb2RlcyBpbiBwYXJlbnQgR3JhcGgpXG4gICAgbGV0IGZyb21Ob2RlID0gbGluay5mcm9tTm9kZTtcbiAgICBsZXQgdG9Ob2RlID0gbGluay50b05vZGU7XG5cbiAgICBsZXQgY2hhbjogQ2hhbm5lbCA9IGxpbmsuZGlzY29ubmVjdCgpO1xuXG4gICAgaWYgKCBjaGFuIClcbiAgICAgIGNoYW4uZGVhY3RpdmF0ZSgpO1xuICB9XG5cbiAgLyoqXG4gICogV2lyZXVwIGEgbGluaywgY3JlYXRpbmcgQ2hhbm5lbCBiZXR3ZWVuIHRoZSBsaW5rZWQgTm9kZXNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgd2lyZUxpbmsoIGxpbms6IExpbmsgKVxuICB7XG4gICAgLy8gZ2V0IGxpbmtlZCBub2RlcyAoTGluayBmaW5kcyBOb2RlcyBpbiBwYXJlbnQgR3JhcGgpXG4gICAgbGV0IGZyb21Ob2RlID0gbGluay5mcm9tTm9kZTtcbiAgICBsZXQgdG9Ob2RlID0gbGluay50b05vZGU7XG5cbiAgICAvL2RlYnVnTWVzc2FnZSggXCJMaW5rKFwiK2xpbmsuaWQrXCIpOiBcIiArIGxpbmsuZnJvbSArIFwiIC0+IFwiICsgbGluay50byArIFwiIHByb3RvPVwiK2xpbmsucHJvdG9jb2wgKTtcblxuICAgIGxldCBjaGFubmVsID0gbmV3IENoYW5uZWwoKTtcblxuICAgIGxpbmsuY29ubmVjdCggY2hhbm5lbCApO1xuXG4gICAgY2hhbm5lbC5hY3RpdmF0ZSgpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHNldFJ1blN0YXRlKCBydW5TdGF0ZTogUnVuU3RhdGUgKVxuICB7XG4gICAgTmV0d29yay5zZXRSdW5TdGF0ZSggdGhpcy5fZ3JhcGgsIHJ1blN0YXRlICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfU1RBVEVfQ0hBTkdFLCB7IHN0YXRlOiBydW5TdGF0ZSB9ICk7XG4gIH1cblxuICBzdGFydCggaW5pdGlhbGx5UGF1c2VkOiBib29sZWFuID0gZmFsc2UgKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggaW5pdGlhbGx5UGF1c2VkID8gUnVuU3RhdGUuUEFVU0VEIDogUnVuU3RhdGUuUlVOTklORyApO1xuICB9XG5cbiAgc3RlcCgpIHtcbiAgICAvLyBUT0RPOiBTaW5nbGUtc3RlcFxuICB9XG5cbiAgc3RvcCgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SRUFEWSApO1xuICB9XG5cbiAgcGF1c2UoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUEFVU0VEICk7XG4gIH1cblxuICByZXN1bWUoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUlVOTklORyApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IE5ldHdvcmsgfSBmcm9tICcuL25ldHdvcmsnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBMaW5rIH0gZnJvbSAnLi9saW5rJztcbmltcG9ydCB7IFBvcnQsIFB1YmxpY1BvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG4vKipcbiAqIEEgR3JhcGggaXMgYSBjb2xsZWN0aW9uIG9mIE5vZGVzIGludGVyY29ubmVjdGVkIHZpYSBMaW5rcy5cbiAqIEEgR3JhcGggaXMgaXRzZWxmIGEgTm9kZSwgd2hvc2UgUG9ydHMgYWN0IGFzIHB1Ymxpc2hlZCBFbmRQb2ludHMsIHRvIHRoZSBHcmFwaC5cbiAqL1xuZXhwb3J0IGNsYXNzIEdyYXBoIGV4dGVuZHMgTm9kZVxue1xuICBzdGF0aWMgRVZFTlRfQUREX05PREUgPSAnZ3JhcGg6YWRkLW5vZGUnO1xuICBzdGF0aWMgRVZFTlRfVVBEX05PREUgPSAnZ3JhcGg6dXBkLW5vZGUnO1xuICBzdGF0aWMgRVZFTlRfREVMX05PREUgPSAnZ3JhcGg6ZGVsLW5vZGUnO1xuXG4gIHN0YXRpYyBFVkVOVF9BRERfTElOSyA9ICdncmFwaDphZGQtbGluayc7XG4gIHN0YXRpYyBFVkVOVF9VUERfTElOSyA9ICdncmFwaDp1cGQtbGluayc7XG4gIHN0YXRpYyBFVkVOVF9ERUxfTElOSyA9ICdncmFwaDpkZWwtbGluayc7XG5cbiAgLyoqXG4gICogTm9kZXMgaW4gdGhpcyBncmFwaC4gRWFjaCBub2RlIG1heSBiZTpcbiAgKiAgIDEuIEEgQ29tcG9uZW50XG4gICogICAyLiBBIHN1Yi1ncmFwaFxuICAqL1xuICBwcm90ZWN0ZWQgX25vZGVzOiBNYXA8c3RyaW5nLCBOb2RlPjtcblxuICAvLyBMaW5rcyBpbiB0aGlzIGdyYXBoLiBFYWNoIG5vZGUgbWF5IGJlOlxuICBwcm90ZWN0ZWQgX2xpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPjtcblxuICAvLyBQdWJsaWMgUG9ydHMgaW4gdGhpcyBncmFwaC4gSW5oZXJpdGVkIGZyb20gTm9kZVxuICAvLyBwcml2YXRlIFBvcnRzO1xuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuaW5pdEZyb21PYmplY3QoIGF0dHJpYnV0ZXMgKTtcbiAgfVxuXG4gIGluaXRGcm9tU3RyaW5nKCBqc29uU3RyaW5nOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5pbml0RnJvbU9iamVjdCggSlNPTi5wYXJzZSgganNvblN0cmluZyApICk7XG4gIH1cblxuICBpbml0RnJvbU9iamVjdCggYXR0cmlidXRlczogYW55ICkge1xuXG4gICAgdGhpcy5pZCA9IGF0dHJpYnV0ZXMuaWQgfHwgXCIkZ3JhcGhcIjtcblxuICAgIHRoaXMuX25vZGVzID0gbmV3IE1hcDxzdHJpbmcsIE5vZGU+KCk7XG4gICAgdGhpcy5fbGlua3MgPSBuZXcgTWFwPHN0cmluZywgTGluaz4oKTtcblxuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLm5vZGVzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZE5vZGUoIGlkLCBhdHRyaWJ1dGVzLm5vZGVzWyBpZCBdICk7XG4gICAgfSk7XG5cbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5saW5rcyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGRMaW5rKCBpZCwgYXR0cmlidXRlcy5saW5rc1sgaWQgXSApO1xuICAgIH0pO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM6IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBncmFwaCA9IHN1cGVyLnRvT2JqZWN0KCk7XG5cbiAgICBsZXQgbm9kZXMgPSBncmFwaFsgXCJub2Rlc1wiIF0gPSB7fTtcbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuLy8gICAgICBpZiAoIG5vZGUgIT0gdGhpcyApXG4gICAgICAgIG5vZGVzWyBpZCBdID0gbm9kZS50b09iamVjdCgpO1xuICAgIH0pO1xuXG4gICAgbGV0IGxpbmtzID0gZ3JhcGhbIFwibGlua3NcIiBdID0ge307XG4gICAgdGhpcy5fbGlua3MuZm9yRWFjaCggKCBsaW5rLCBpZCApID0+IHtcbiAgICAgIGxpbmtzWyBpZCBdID0gbGluay50b09iamVjdCgpO1xuICAgIH0pO1xuXG4gICAgcmV0dXJuIGdyYXBoO1xuICB9XG5cbiAgbG9hZENvbXBvbmVudCggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSApOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBwZW5kaW5nQ291bnQgPSAwO1xuXG4gICAgICBsZXQgbm9kZXMgPSBuZXcgTWFwPHN0cmluZywgTm9kZT4oIHRoaXMuX25vZGVzICk7XG4gICAgICBub2Rlcy5zZXQoICckZ3JhcGgnLCB0aGlzICk7XG5cbiAgICAgIG5vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICAgIGxldCBkb25lOiBQcm9taXNlPHZvaWQ+O1xuXG4gICAgICAgIHBlbmRpbmdDb3VudCsrO1xuXG4gICAgICAgIGlmICggbm9kZSA9PSB0aGlzICkge1xuICAgICAgICAgIGRvbmUgPSBzdXBlci5sb2FkQ29tcG9uZW50KCBmYWN0b3J5ICk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgZG9uZSA9IG5vZGUubG9hZENvbXBvbmVudCggZmFjdG9yeSApO1xuICAgICAgICB9XG5cbiAgICAgICAgZG9uZS50aGVuKCAoKSA9PiB7XG4gICAgICAgICAgLS1wZW5kaW5nQ291bnQ7XG4gICAgICAgICAgaWYgKCBwZW5kaW5nQ291bnQgPT0gMCApXG4gICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaCggKCByZWFzb24gKSA9PiB7XG4gICAgICAgICAgcmVqZWN0KCByZWFzb24gKTtcbiAgICAgICAgfSApO1xuICAgICAgfSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgbm9kZXMoKTogTWFwPHN0cmluZywgTm9kZT5cbiAge1xuICAgIHJldHVybiB0aGlzLl9ub2RlcztcbiAgfVxuXG4vKiAgcHVibGljIGdldEFsbE5vZGVzKCk6IE5vZGVbXVxuICB7XG4gICAgbGV0IG5vZGVzOiBOb2RlW10gPSBbXTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICAvLyBEb24ndCByZWN1cnNlIG9uIGdyYXBoJ3MgcHNldWRvLW5vZGVcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgbm9kZXMgPSBub2Rlcy5jb25jYXQoIG5vZGUuZ2V0QWxsTm9kZXMoKSApO1xuXG4gICAgICBub2Rlcy5wdXNoKCBub2RlICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIG5vZGVzO1xuICB9Ki9cblxuICBwdWJsaWMgZ2V0IGxpbmtzKCk6IE1hcDxzdHJpbmcsIExpbms+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fbGlua3M7XG4gIH1cblxuLyogIHB1YmxpYyBnZXRBbGxMaW5rcygpOiBMaW5rW11cbiAge1xuICAgIGxldCBsaW5rczogTGlua1tdID0gW107XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBsaW5rcyA9IGxpbmtzLmNvbmNhdCggbm9kZS5nZXRBbGxMaW5rcygpICk7XG4gICAgfSApXG5cbiAgICB0aGlzLl9saW5rcy5mb3JFYWNoKCAoIGxpbmssIGlkICkgPT4ge1xuICAgICAgbGlua3MucHVzaCggbGluayApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBsaW5rcztcbiAgfSovXG5cbi8qICBwdWJsaWMgZ2V0QWxsUG9ydHMoKTogUG9ydFtdXG4gIHtcbiAgICBsZXQgcG9ydHM6IFBvcnRbXSA9IHN1cGVyLmdldFBvcnRBcnJheSgpO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgcG9ydHMgPSBwb3J0cy5jb25jYXQoIG5vZGUuZ2V0QWxsUG9ydHMoKSApO1xuICAgICAgZWxzZVxuICAgICAgICBwb3J0cyA9IHBvcnRzLmNvbmNhdCggbm9kZS5nZXRQb3J0QXJyYXkoKSApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBwb3J0cztcbiAgfSovXG5cbiAgcHVibGljIGdldE5vZGVCeUlEKCBpZDogc3RyaW5nICk6IE5vZGVcbiAge1xuICAgIGlmICggaWQgPT0gJyRncmFwaCcgKVxuICAgICAgcmV0dXJuIHRoaXM7XG5cbiAgICByZXR1cm4gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuICB9XG5cbiAgcHVibGljIGFkZE5vZGUoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM/OiB7fSApOiBOb2RlIHtcblxuICAgIGxldCBub2RlID0gbmV3IE5vZGUoIHRoaXMsIGF0dHJpYnV0ZXMgKTtcblxuICAgIG5vZGUuaWQgPSBpZDtcblxuICAgIHRoaXMuX25vZGVzLnNldCggaWQsIG5vZGUgKTtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfQUREX05PREUsIHsgbm9kZTogbm9kZSB9ICk7XG5cbiAgICByZXR1cm4gbm9kZTtcbiAgfVxuXG4gIHB1YmxpYyByZW5hbWVOb2RlKCBpZDogc3RyaW5nLCBuZXdJRDogc3RyaW5nICkge1xuXG4gICAgbGV0IG5vZGUgPSB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG5cbiAgICBpZiAoIGlkICE9IG5ld0lEIClcbiAgICB7XG4gICAgICBsZXQgZXZlbnREYXRhID0geyBub2RlOiBub2RlLCBhdHRyczogeyBpZDogbm9kZS5pZCB9IH07XG5cbiAgICAgIHRoaXMuX25vZGVzLmRlbGV0ZSggaWQgKTtcblxuICAgICAgbm9kZS5pZCA9IG5ld0lEO1xuXG4gICAgICB0aGlzLl9ub2Rlcy5zZXQoIG5ld0lELCBub2RlICk7XG5cbiAgICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfVVBEX05PREUsIGV2ZW50RGF0YSApO1xuICAgIH1cbiAgfVxuXG4gIHB1YmxpYyByZW1vdmVOb2RlKCBpZDogc3RyaW5nICk6IGJvb2xlYW4ge1xuXG4gICAgbGV0IG5vZGUgPSB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG4gICAgaWYgKCBub2RlIClcbiAgICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfREVMX05PREUsIHsgbm9kZTogbm9kZSB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fbm9kZXMuZGVsZXRlKCBpZCApO1xuICB9XG5cbiAgcHVibGljIGdldExpbmtCeUlEKCBpZDogc3RyaW5nICk6IExpbmsge1xuXG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzWyBpZCBdO1xuICB9XG5cbiAgcHVibGljIGFkZExpbmsoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM/OiB7fSApOiBMaW5rIHtcblxuICAgIGxldCBsaW5rID0gbmV3IExpbmsoIHRoaXMsIGF0dHJpYnV0ZXMgKTtcblxuICAgIGxpbmsuaWQgPSBpZDtcblxuICAgIHRoaXMuX2xpbmtzLnNldCggaWQsIGxpbmsgKTtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfQUREX0xJTkssIHsgbGluazogbGluayB9ICk7XG5cbiAgICByZXR1cm4gbGluaztcbiAgfVxuXG4gIHB1YmxpYyByZW5hbWVMaW5rKCBpZDogc3RyaW5nLCBuZXdJRDogc3RyaW5nICkge1xuXG4gICAgbGV0IGxpbmsgPSB0aGlzLl9saW5rcy5nZXQoIGlkICk7XG5cbiAgICB0aGlzLl9saW5rcy5kZWxldGUoIGlkICk7XG5cbiAgICBsZXQgZXZlbnREYXRhID0geyBsaW5rOiBsaW5rLCBhdHRyczogeyBpZDogbGluay5pZCB9IH07XG5cbiAgICBsaW5rLmlkID0gbmV3SUQ7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX1VQRF9OT0RFLCBldmVudERhdGEgKTtcblxuICAgIHRoaXMuX2xpbmtzLnNldCggbmV3SUQsIGxpbmsgKTtcbiAgfVxuXG4gIHB1YmxpYyByZW1vdmVMaW5rKCBpZDogc3RyaW5nICk6IGJvb2xlYW4ge1xuXG4gICAgbGV0IGxpbmsgPSB0aGlzLl9saW5rcy5nZXQoIGlkICk7XG4gICAgaWYgKCBsaW5rIClcbiAgICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfREVMX0xJTkssIHsgbGluazogbGluayB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fbGlua3MuZGVsZXRlKCBpZCApO1xuICB9XG5cbiAgcHVibGljIGFkZFB1YmxpY1BvcnQoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IHt9ICk6IFB1YmxpY1BvcnRcbiAge1xuICAgIGF0dHJpYnV0ZXNbXCJpZFwiXSA9IGlkO1xuXG4gICAgbGV0IHBvcnQgPSBuZXcgUHVibGljUG9ydCggdGhpcywgbnVsbCwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5fcG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZUxvYWRlciB9IGZyb20gJy4vbW9kdWxlLWxvYWRlcic7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5IH0gZnJvbSAnLi9jb21wb25lbnQtZmFjdG9yeSc7XG5cbmltcG9ydCB7IENvbnRhaW5lciB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5cblxuZXhwb3J0IGNsYXNzIFNpbXVsYXRpb25FbmdpbmVcbntcbiAgbG9hZGVyOiBNb2R1bGVMb2FkZXI7XG4gIGNvbnRhaW5lcjogQ29udGFpbmVyO1xuXG4gIC8qKlxuICAqIENyZWF0ZXMgYW4gaW5zdGFuY2Ugb2YgU2ltdWxhdGlvbkVuZ2luZS5cbiAgKiBAcGFyYW0gbG9hZGVyIFRoZSBtb2R1bGUgbG9hZGVyLlxuICAqIEBwYXJhbSBjb250YWluZXIgVGhlIHJvb3QgREkgY29udGFpbmVyIGZvciB0aGUgc2ltdWxhdGlvbi5cbiAgKi9cbiAgY29uc3RydWN0b3IoIGxvYWRlcjogTW9kdWxlTG9hZGVyLCBjb250YWluZXI6IENvbnRhaW5lciApIHtcbiAgICB0aGlzLmxvYWRlciA9IGxvYWRlcjtcbiAgICB0aGlzLmNvbnRhaW5lciA9IGNvbnRhaW5lcjtcbiAgfVxuXG5cbiAgLyoqXG4gICogUmV0dXJuIGEgQ29tcG9uZW50RmFjdG9yeSBmYWNhZGVcbiAgKi9cbiAgZ2V0Q29tcG9uZW50RmFjdG9yeSgpOiBDb21wb25lbnRGYWN0b3J5IHtcbiAgICByZXR1cm4gbmV3IENvbXBvbmVudEZhY3RvcnkoIHRoaXMuY29udGFpbmVyLCB0aGlzLmxvYWRlciApO1xuICB9XG5cbn1cbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
