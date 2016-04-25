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
        let len = this.byteArray.length;
        this.length++;
        this.byteArray[len] = value;
        return this;
    }
    setLength(len) {
        this.length = len;
        return this;
    }
    concat(bytes) {
        let orig = this.byteArray;
        let len = this.length;
        this.length += bytes.length;
        this.byteArray.set(orig);
        this.byteArray.set(bytes.byteArray, len);
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
                    s += ("0" + this.byteArray[i].toString(16)).slice(-2).toUpperCase();
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



export class Enum {
}
export class Integer extends Number {
}
export class FieldArray {
}
export const FieldTypes = {
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
        return this.field(name, description, FieldTypes.Integer, opts);
    }
    uint32Field(name, description, opts = {}) {
        opts.minimum = opts.minimum || 0;
        opts.maximum = opts.maximum || 0xFFFFFFFF;
        return this.field(name, description, FieldTypes.Integer, opts);
    }
    byteField(name, description, opts = {}) {
        opts.minimum = opts.minimum || 0;
        opts.maximum = opts.maximum || 255;
        return this.field(name, description, FieldTypes.Integer, opts);
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
        return this.field(name, description, FieldTypes.Enum, opts);
    }
}
export class Kind {
    static isKind(kind) {
        return !!(kind && kind.constructor && (kind.constructor).kindInfo);
    }
    static getKindConstructor(kind) {
        return kind && kind.constructor && (kind.constructor);
    }
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
                else if (fieldType == FieldTypes.Integer)
                    val = field.minimum || 0;
                else if (fieldType == Boolean)
                    val = false;
                else if (fieldType == FieldTypes.ByteArray)
                    val = new ByteArray();
                else if (fieldType == FieldTypes.Enum)
                    val = field.enumMap.keys[0];
                else if (fieldType == Kind) {
                    let ctor = fieldType.constructor;
                    val = Object.create(ctor);
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
    static setDeliveryHook(deliveryHook) {
        Channel._deliveryHook = deliveryHook;
    }
    ;
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
                    let task = () => {
                        endPoint.handleMessage(message, origin, this);
                    };
                    let canSend = true;
                    if (Channel._deliveryHook) {
                        let scheduler = this._taskScheduler;
                        let messageHookInfo = {
                            message: message,
                            channel: this,
                            origin: origin,
                            destination: endPoint,
                            sendMessage: () => { scheduler.queueTask(task); }
                        };
                        canSend = !Channel._deliveryHook(messageHookInfo);
                    }
                    if (canSend)
                        this._taskScheduler.queueTask(task);
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
            || (window && window.crypto && window.crypto.subtle);
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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJraW5kL2ZpZWxkLWluZm8udHMiLCJraW5kL2tpbmQudHMiLCJtZXNzYWdpbmcvbWVzc2FnZS50cyIsInJ1bnRpbWUvdGFzay1zY2hlZHVsZXIudHMiLCJtZXNzYWdpbmcvY2hhbm5lbC50cyIsIm1lc3NhZ2luZy9lbmQtcG9pbnQudHMiLCJtZXNzYWdpbmcvcHJvdG9jb2wudHMiLCJjb21wb25lbnQvcG9ydC1pbmZvLnRzIiwiY29tcG9uZW50L2NvbXBvbmVudC1pbmZvLnRzIiwiY29tcG9uZW50L3N0b3JlLWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL3dlYmNyeXB0by50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvZGVzLnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9jcnlwdG9ncmFwaGljLXNlcnZpY2UuanMiLCJkZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXIudHMiLCJldmVudC1odWIvZXZlbnQtaHViLnRzIiwiZ3JhcGgvcG9ydC50cyIsImdyYXBoL25vZGUudHMiLCJydW50aW1lL3J1bnRpbWUtY29udGV4dC50cyIsInJ1bnRpbWUvbW9kdWxlLWxvYWRlci50cyIsInJ1bnRpbWUvY29tcG9uZW50LWZhY3RvcnkudHMiLCJncmFwaC9saW5rLnRzIiwiZ3JhcGgvbmV0d29yay50cyIsImdyYXBoL2dyYXBoLnRzIiwicnVudGltZS9zaW11bGF0aW9uLWVuZ2luZS50cyJdLCJuYW1lcyI6WyJIZXhDb2RlYyIsIkhleENvZGVjLmRlY29kZSIsIkJBU0U2NFNQRUNJQUxTIiwiQmFzZTY0Q29kZWMiLCJCYXNlNjRDb2RlYy5kZWNvZGUiLCJCYXNlNjRDb2RlYy5kZWNvZGUuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLnB1c2giLCJCYXNlNjRDb2RlYy5lbmNvZGUiLCJCYXNlNjRDb2RlYy5lbmNvZGUuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLnRyaXBsZXRUb0Jhc2U2NCIsIkJ5dGVFbmNvZGluZyIsIkJ5dGVBcnJheSIsIkJ5dGVBcnJheS5jb25zdHJ1Y3RvciIsIkJ5dGVBcnJheS5lbmNvZGluZ1RvU3RyaW5nIiwiQnl0ZUFycmF5LnN0cmluZ1RvRW5jb2RpbmciLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJFbnVtIiwiSW50ZWdlciIsIkZpZWxkQXJyYXkiLCJLaW5kSW5mbyIsIktpbmRJbmZvLmNvbnN0cnVjdG9yIiwiS2luZEJ1aWxkZXIiLCJLaW5kQnVpbGRlci5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyLmluaXQiLCJLaW5kQnVpbGRlci5maWVsZCIsIktpbmRCdWlsZGVyLmJvb2xGaWVsZCIsIktpbmRCdWlsZGVyLm51bWJlckZpZWxkIiwiS2luZEJ1aWxkZXIuaW50ZWdlckZpZWxkIiwiS2luZEJ1aWxkZXIudWludDMyRmllbGQiLCJLaW5kQnVpbGRlci5ieXRlRmllbGQiLCJLaW5kQnVpbGRlci5zdHJpbmdGaWVsZCIsIktpbmRCdWlsZGVyLmtpbmRGaWVsZCIsIktpbmRCdWlsZGVyLmVudW1GaWVsZCIsIktpbmQiLCJLaW5kLmlzS2luZCIsIktpbmQuZ2V0S2luZENvbnN0cnVjdG9yIiwiS2luZC5nZXRLaW5kSW5mbyIsIktpbmQuaW5pdEZpZWxkcyIsIk1lc3NhZ2UiLCJNZXNzYWdlLmNvbnN0cnVjdG9yIiwiTWVzc2FnZS5oZWFkZXIiLCJNZXNzYWdlLnBheWxvYWQiLCJLaW5kTWVzc2FnZSIsIlRhc2tTY2hlZHVsZXIiLCJUYXNrU2NoZWR1bGVyLmNvbnN0cnVjdG9yIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyLnJlcXVlc3RGbHVzaC5oYW5kbGVGbHVzaFRpbWVyIiwiVGFza1NjaGVkdWxlci5zaHV0ZG93biIsIlRhc2tTY2hlZHVsZXIucXVldWVUYXNrIiwiVGFza1NjaGVkdWxlci5mbHVzaFRhc2tRdWV1ZSIsIlRhc2tTY2hlZHVsZXIub25FcnJvciIsIkNoYW5uZWwiLCJDaGFubmVsLmNvbnN0cnVjdG9yIiwiQ2hhbm5lbC5zZXREZWxpdmVyeUhvb2siLCJDaGFubmVsLnNodXRkb3duIiwiQ2hhbm5lbC5hY3RpdmUiLCJDaGFubmVsLmFjdGl2YXRlIiwiQ2hhbm5lbC5kZWFjdGl2YXRlIiwiQ2hhbm5lbC5hZGRFbmRQb2ludCIsIkNoYW5uZWwucmVtb3ZlRW5kUG9pbnQiLCJDaGFubmVsLmVuZFBvaW50cyIsIkNoYW5uZWwuc2VuZE1lc3NhZ2UiLCJEaXJlY3Rpb24iLCJFbmRQb2ludCIsIkVuZFBvaW50LmNvbnN0cnVjdG9yIiwiRW5kUG9pbnQuc2h1dGRvd24iLCJFbmRQb2ludC5pZCIsIkVuZFBvaW50LmF0dGFjaCIsIkVuZFBvaW50LmRldGFjaCIsIkVuZFBvaW50LmRldGFjaEFsbCIsIkVuZFBvaW50LmF0dGFjaGVkIiwiRW5kUG9pbnQuZGlyZWN0aW9uIiwiRW5kUG9pbnQuaGFuZGxlTWVzc2FnZSIsIkVuZFBvaW50LnNlbmRNZXNzYWdlIiwiRW5kUG9pbnQub25NZXNzYWdlIiwiUHJvdG9jb2xUeXBlQml0cyIsIlByb3RvY29sIiwiQ2xpZW50U2VydmVyUHJvdG9jb2wiLCJBUERVIiwiQVBEVU1lc3NhZ2UiLCJBUERVUHJvdG9jb2wiLCJQb3J0SW5mbyIsIlBvcnRJbmZvLmNvbnN0cnVjdG9yIiwiQ29tcG9uZW50SW5mbyIsIkNvbXBvbmVudEluZm8uY29uc3RydWN0b3IiLCJTdG9yZUluZm8iLCJDb21wb25lbnRCdWlsZGVyIiwiQ29tcG9uZW50QnVpbGRlci5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEJ1aWxkZXIuaW5pdCIsIkNvbXBvbmVudEJ1aWxkZXIuY29uZmlnIiwiQ29tcG9uZW50QnVpbGRlci5wb3J0IiwiQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmNvbnN0cnVjdG9yIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeS5nZXRTZXJ2aWNlIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeS5nZXRLZXlTZXJ2aWNlIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeS5zZXRTZXJ2aWNlIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeS5zZXRLZXlTZXJ2aWNlIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlcktleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdHJ5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5lbmNyeXB0IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5kZWNyeXB0IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5kaWdlc3QiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnNpZ24iLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnZlcmlmeSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuZXhwb3J0S2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5nZW5lcmF0ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuaW1wb3J0S2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5kZXJpdmVLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlcml2ZUJpdHMiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLndyYXBLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnVud3JhcEtleSIsIldlYkNyeXB0b1NlcnZpY2UiLCJXZWJDcnlwdG9TZXJ2aWNlLmNvbnN0cnVjdG9yIiwiV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUiLCJXZWJDcnlwdG9TZXJ2aWNlLmVuY3J5cHQiLCJXZWJDcnlwdG9TZXJ2aWNlLmRlY3J5cHQiLCJXZWJDcnlwdG9TZXJ2aWNlLmRpZ2VzdCIsIldlYkNyeXB0b1NlcnZpY2UuZXhwb3J0S2V5IiwiV2ViQ3J5cHRvU2VydmljZS5nZW5lcmF0ZUtleSIsIldlYkNyeXB0b1NlcnZpY2UuaW1wb3J0S2V5IiwiV2ViQ3J5cHRvU2VydmljZS5zaWduIiwiV2ViQ3J5cHRvU2VydmljZS52ZXJpZnkiLCJERVNTZWNyZXRLZXkiLCJERVNTZWNyZXRLZXkuY29uc3RydWN0b3IiLCJERVNTZWNyZXRLZXkuYWxnb3JpdGhtIiwiREVTU2VjcmV0S2V5LmV4dHJhY3RhYmxlIiwiREVTU2VjcmV0S2V5LnR5cGUiLCJERVNTZWNyZXRLZXkudXNhZ2VzIiwiREVTU2VjcmV0S2V5LmtleU1hdGVyaWFsIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5jb25zdHJ1Y3RvciIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmVuY3J5cHQiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZWNyeXB0IiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuaW1wb3J0S2V5IiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uuc2lnbiIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlcyIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlcy5kZXNfY3JlYXRlS2V5cyIsIkV2ZW50SHViIiwiRXZlbnRIdWIuY29uc3RydWN0b3IiLCJFdmVudEh1Yi5wdWJsaXNoIiwiRXZlbnRIdWIuc3Vic2NyaWJlIiwiRXZlbnRIdWIuc3Vic2NyaWJlT25jZSIsIlBvcnQiLCJQb3J0LmNvbnN0cnVjdG9yIiwiUG9ydC5lbmRQb2ludCIsIlBvcnQudG9PYmplY3QiLCJQb3J0Lm93bmVyIiwiUG9ydC5wcm90b2NvbElEIiwiUG9ydC5pZCIsIlBvcnQuZGlyZWN0aW9uIiwiUHVibGljUG9ydCIsIlB1YmxpY1BvcnQuY29uc3RydWN0b3IiLCJQdWJsaWNQb3J0LmNvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC5kaXNjb25uZWN0UHJpdmF0ZSIsIlB1YmxpY1BvcnQudG9PYmplY3QiLCJOb2RlIiwiTm9kZS5jb25zdHJ1Y3RvciIsIk5vZGUudG9PYmplY3QiLCJOb2RlLm93bmVyIiwiTm9kZS5pZCIsIk5vZGUudXBkYXRlUG9ydHMiLCJOb2RlLmFkZFBsYWNlaG9sZGVyUG9ydCIsIk5vZGUucG9ydHMiLCJOb2RlLmdldFBvcnRBcnJheSIsIk5vZGUuZ2V0UG9ydEJ5SUQiLCJOb2RlLmlkZW50aWZ5UG9ydCIsIk5vZGUucmVtb3ZlUG9ydCIsIk5vZGUubG9hZENvbXBvbmVudCIsIk5vZGUuY29udGV4dCIsIk5vZGUudW5sb2FkQ29tcG9uZW50IiwiUnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dCIsIlJ1bnRpbWVDb250ZXh0LmNvbnN0cnVjdG9yIiwiUnVudGltZUNvbnRleHQubm9kZSIsIlJ1bnRpbWVDb250ZXh0Lmluc3RhbmNlIiwiUnVudGltZUNvbnRleHQuY29udGFpbmVyIiwiUnVudGltZUNvbnRleHQubG9hZCIsIlJ1bnRpbWVDb250ZXh0LnJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQuaW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnNldFJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQucmVsZWFzZSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkiLCJNb2R1bGVSZWdpc3RyeUVudHJ5LmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmNvbnN0cnVjdG9yIiwiU3lzdGVtTW9kdWxlTG9hZGVyLmdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeSIsIlN5c3RlbU1vZHVsZUxvYWRlci5sb2FkTW9kdWxlIiwiQ29tcG9uZW50RmFjdG9yeSIsIkNvbXBvbmVudEZhY3RvcnkuY29uc3RydWN0b3IiLCJDb21wb25lbnRGYWN0b3J5LmNyZWF0ZUNvbnRleHQiLCJDb21wb25lbnRGYWN0b3J5LmdldENoaWxkQ29udGFpbmVyIiwiQ29tcG9uZW50RmFjdG9yeS5sb2FkQ29tcG9uZW50IiwiQ29tcG9uZW50RmFjdG9yeS5nZXQiLCJDb21wb25lbnRGYWN0b3J5LnJlZ2lzdGVyIiwiTGluayIsIkxpbmsuY29uc3RydWN0b3IiLCJMaW5rLnRvT2JqZWN0IiwiTGluay5pZCIsIkxpbmsuY29ubmVjdCIsIkxpbmsuZGlzY29ubmVjdCIsIkxpbmsuZnJvbU5vZGUiLCJMaW5rLmZyb21Qb3J0IiwiTGluay50b05vZGUiLCJMaW5rLnRvUG9ydCIsIkxpbmsucHJvdG9jb2xJRCIsIk5ldHdvcmsiLCJOZXR3b3JrLmNvbnN0cnVjdG9yIiwiTmV0d29yay5ncmFwaCIsIk5ldHdvcmsubG9hZENvbXBvbmVudHMiLCJOZXR3b3JrLmluaXRpYWxpemUiLCJOZXR3b3JrLnRlYXJkb3duIiwiTmV0d29yay5pblN0YXRlIiwiTmV0d29yay5zZXRSdW5TdGF0ZSIsIk5ldHdvcmsudW53aXJlTGluayIsIk5ldHdvcmsud2lyZUxpbmsiLCJOZXR3b3JrLnN0YXJ0IiwiTmV0d29yay5zdGVwIiwiTmV0d29yay5zdG9wIiwiTmV0d29yay5wYXVzZSIsIk5ldHdvcmsucmVzdW1lIiwiR3JhcGgiLCJHcmFwaC5jb25zdHJ1Y3RvciIsIkdyYXBoLmluaXRGcm9tU3RyaW5nIiwiR3JhcGguaW5pdEZyb21PYmplY3QiLCJHcmFwaC50b09iamVjdCIsIkdyYXBoLmxvYWRDb21wb25lbnQiLCJHcmFwaC5ub2RlcyIsIkdyYXBoLmxpbmtzIiwiR3JhcGguZ2V0Tm9kZUJ5SUQiLCJHcmFwaC5hZGROb2RlIiwiR3JhcGgucmVuYW1lTm9kZSIsIkdyYXBoLnJlbW92ZU5vZGUiLCJHcmFwaC5nZXRMaW5rQnlJRCIsIkdyYXBoLmFkZExpbmsiLCJHcmFwaC5yZW5hbWVMaW5rIiwiR3JhcGgucmVtb3ZlTGluayIsIkdyYXBoLmFkZFB1YmxpY1BvcnQiLCJTaW11bGF0aW9uRW5naW5lIiwiU2ltdWxhdGlvbkVuZ2luZS5jb25zdHJ1Y3RvciIsIlNpbXVsYXRpb25FbmdpbmUuZ2V0Q29tcG9uZW50RmFjdG9yeSJdLCJtYXBwaW5ncyI6IkFBQUE7SUFJRUEsT0FBT0EsTUFBTUEsQ0FBRUEsQ0FBU0E7UUFFdEJDLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFlBQVlBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pDQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFHQSxHQUFHQSxrQkFBa0JBLENBQUNBO1lBQzdCQSxJQUFJQSxLQUFLQSxHQUFHQSw2QkFBNkJBLENBQUNBO1lBQzFDQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtZQUN2QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3ZCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsR0FBR0EsR0FBR0EsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7WUFDeEJBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO2dCQUN4QkEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDM0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO2dCQUNqQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLFFBQVFBLENBQUNBLFlBQVlBLEdBQUdBLEdBQUdBLENBQUNBO1FBQzlCQSxDQUFDQTtRQUVEQSxJQUFJQSxHQUFHQSxHQUFhQSxFQUFFQSxDQUFDQTtRQUN2QkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsVUFBVUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDN0JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBLEVBQ2pDQSxDQUFDQTtZ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VUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsWUFBWUEsQ0FBRUEsQ0FBQ0E7UUFHOURBLElBQUlBLENBQUNBLEdBQUdBLFlBQVlBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZEQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVWQSxjQUFlQSxDQUFPQTtZQUNwQkUsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDZkEsQ0FBQ0E7UUFFREYsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFFakJBLEdBQUdBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQzdCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMzSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsUUFBUUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDN0JBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDdkJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzFFQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsWUFBWUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUJBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQzlHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUN4QkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBO0lBQ2JBLENBQUNBO0lBRURELE9BQU9BLE1BQU1BLENBQUVBLEtBQWlCQTtRQUU5QkksSUFBSUEsQ0FBU0EsQ0FBQ0E7UUFDZEEsSUFBSUEsVUFBVUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDbENBLElBQUlBLE1BQU1BLEdBQUdBLEVBQUVBLENBQUNBO1FBRWhCQSxNQUFNQSxNQUFNQSxHQUFHQSxrRUFBa0VBLENBQUNBO1FBQ2xGQSxnQkFBaUJBLEdBQVNBO1lBQ3hCQyxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM1QkEsQ0FBQ0E7UUFFREQseUJBQTBCQSxHQUFXQTtZQUNuQ0UsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDNUdBLENBQUNBO1FBR0RGLElBQUlBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLFVBQVVBLENBQUNBO1FBQ3ZDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxNQUFNQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQTtZQUMvQkEsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbkVBLE1BQU1BLElBQUlBLGVBQWVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBO1FBQ2xDQSxDQUFDQTtRQUdEQSxNQUFNQSxDQUFDQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuQkEsS0FBS0EsQ0FBQ0E7Z0JBQ0pBLElBQUlBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO2dCQUNuQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzVCQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDckNBLE1BQU1BLElBQUlBLElBQUlBLENBQUNBO2dCQUNmQSxLQUFLQSxDQUFBQTtZQUNQQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2xFQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDN0JBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxHQUFHQSxDQUFDQTtnQkFDZEEsS0FBS0EsQ0FBQUE7WUFDUEE7Z0JBQ0VBLEtBQUtBLENBQUNBO1FBQ1ZBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO0lBQ2hCQSxDQUFDQTtBQUNISixDQUFDQTtBQUFBO09DaklNLEVBQUUsUUFBUSxFQUFFLE1BQU0sYUFBYTtPQUMvQixFQUFFLFdBQVcsRUFBRSxNQUFNLGdCQUFnQjtBQUU1QyxXQUFZLFlBS1g7QUFMRCxXQUFZLFlBQVk7SUFDdEJPLDZDQUFHQSxDQUFBQTtJQUNIQSw2Q0FBR0EsQ0FBQUE7SUFDSEEsbURBQU1BLENBQUFBO0lBQ05BLCtDQUFJQSxDQUFBQTtBQUNOQSxDQUFDQSxFQUxXLFlBQVksS0FBWixZQUFZLFFBS3ZCO0FBRUQ7SUEyQ0VDLFlBQWFBLEtBQXFFQSxFQUFFQSxRQUFpQkEsRUFBRUEsR0FBU0E7UUFFOUdDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO1lBRUNBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3ZDQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxRQUFRQSxJQUFJQSxRQUFRQSxJQUFJQSxZQUFZQSxDQUFDQSxHQUFJQSxDQUFDQSxDQUNyREEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsV0FBWUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFlQSxLQUFLQSxDQUFFQSxDQUFDQTtZQUN4REEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsVUFBV0EsQ0FBQ0E7Z0JBQ3JDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUN6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsU0FBVUEsQ0FBQ0E7Z0JBQ3BDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUNuQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsS0FBTUEsQ0FBQ0E7Z0JBQ2hDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtRQUs3Q0EsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsS0FBS0EsSUFBSUEsUUFBU0EsQ0FBQ0EsQ0FDcENBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLE1BQU9BLENBQUNBLENBQ3RDQSxDQUFDQTtnQkFDR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDekRBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQ3hDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLElBQUtBLENBQUNBLENBQ3pDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtnQkFDN0JBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBO29CQUN4QkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBRTVDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxFQUFFQSxDQUFDQTtZQUN0QkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBVUEsQ0FBQ0EsQ0FDdEJBLENBQUNBO1lBQ0NBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLGdDQUFnQ0EsQ0FBQ0EsQ0FBQUE7UUFDcERBLENBQUNBO0lBQ0hBLENBQUNBO0lBcEZERCxPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQXNCQTtRQUM3Q0UsTUFBTUEsQ0FBQUEsQ0FBRUEsUUFBU0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLE1BQU1BO2dCQUN0QkEsTUFBTUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7WUFDbEJBLEtBQUtBLFlBQVlBLENBQUNBLElBQUlBO2dCQUNwQkEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7WUFDaEJBLEtBQUtBLFlBQVlBLENBQUNBLEdBQUdBO2dCQUNuQkEsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7WUFDZkE7Z0JBQ0VBLE1BQU1BLENBQUNBLEtBQUtBLENBQUNBO1FBQ2pCQSxDQUFDQTtJQUNIQSxDQUFDQTtJQUVERixPQUFPQSxnQkFBZ0JBLENBQUVBLFFBQWdCQTtRQUN2Q0csRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsV0FBV0EsRUFBRUEsSUFBSUEsUUFBU0EsQ0FBQ0E7WUFDdkNBLE1BQU1BLENBQUNBLFlBQVlBLENBQUNBLE1BQU1BLENBQUNBO1FBQzdCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxRQUFRQSxDQUFDQSxXQUFXQSxFQUFFQSxJQUFJQSxNQUFPQSxDQUFDQTtZQUMxQ0EsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7UUFDM0JBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLENBQUNBLFdBQVdBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBO1lBQ3pDQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFDQSxHQUFHQSxDQUFDQTtRQUMxQkEsSUFBSUE7WUFDRkEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBZ0VESCxJQUFJQSxNQUFNQTtRQUVSSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUMvQkEsQ0FBQ0E7SUFFREosSUFBSUEsTUFBTUEsQ0FBRUEsR0FBV0E7UUFFckJJLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBLE1BQU1BLElBQUlBLEdBQUlBLENBQUNBLENBQ25DQSxDQUFDQTtZQUNDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUNsREEsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FDSkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7WUFDekJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1lBQ3ZDQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFREosSUFBSUEsWUFBWUE7UUFFZEssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURMLE1BQU1B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LFFBQVFBLENBQUVBLFFBQWlCQSxFQUFFQSxHQUFTQTtRQUVwQ3VCLElBQUlBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBO1FBQ1hBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBRVZBLE1BQU1BLENBQUFBLENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQ3RDQSxLQUFLQSxZQUFZQSxDQUFDQSxHQUFHQTtnQkFFbkJBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7Z0JBQzdFQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxZQUFZQSxDQUFDQSxNQUFNQTtnQkFDdEJBLE1BQU1BLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBRTlDQSxLQUFLQSxZQUFZQSxDQUFDQSxJQUFJQTtnQkFDcEJBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xEQSxLQUFLQSxDQUFDQTtZQUVSQTtnQkFDRUEsR0FBR0EsQ0FBQUEsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FB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QSxLQUFLQSxDQUFFQSxJQUFJQSxFQUFFQSxXQUFXQSxFQUFFQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQUN2REEsQ0FBQ0E7SUFFTUwsWUFBWUEsQ0FBRUEsSUFBWUEsRUFBRUEsV0FBbUJBLEVBQUVBLElBQUlBLEdBQWlCQSxFQUFFQTtRQUM3RU0sTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsVUFBVUEsQ0FBQ0EsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDbkVBLENBQUNBO0lBRU1OLFdBQVdBLENBQUVBLElBQVlBLEVBQUVBLFdBQW1CQSxFQUFFQSxJQUFJQSxHQUFpQkEsRUFBRUE7UUFDNUVPLElBQUlBLENBQUNBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBLE9BQU9BLElBQUlBLENBQUNBLENBQUNBO1FBQ2pDQSxJQUFJQSxDQUFDQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQSxPQUFPQSxJQUFJQSxVQUFVQSxDQUFDQTtRQUUxQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsVUFBVUEsQ0FBQ0EsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDbkVBLENBQUNBO0lBRU1QLFNBQVNBLENBQUVBLElBQVlBLEVBQUVBLFdBQW1CQSxFQUFFQSxJQUFJQSxHQUFpQkEsRUFBRUE7UUFDMUVRLElBQUlBLENBQUNBLE9BQU9BLEdBQUdBLElBQUlBLENBQUNBLE9BQU9BLElBQUlBLENBQUNBLENBQUNBO1FBQ2pDQSxJQUFJQSxDQUFDQSxPQUFPQSxHQUFHQSxJQUFJQSxDQUFDQSxPQUFPQSxJQUFJQSxHQUFHQSxDQUFDQTtRQUVuQ0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsV0FBV0EsRUFBRUEsVUFBVUEsQ0FBQ0EsT0FBT0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDbkVBLENBQUNB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Q3JCQSxHQUFHQSxHQUFHQSxVQUFVQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtnQkFDekJBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLEtBQUtBLENBQUNBLE9BQU9BLElBQUlBLFNBQVVBLENBQUNBO29CQUNwQ0EsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3RCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxNQUFPQSxDQUFDQTtvQkFDN0JBLEdBQUdBLEdBQUdBLEVBQUVBLENBQUNBO2dCQUNYQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxNQUFPQSxDQUFDQTtvQkFDN0JBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO2dCQUNWQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxVQUFVQSxDQUFDQSxPQUFRQSxDQUFDQTtvQkFDekNBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE9BQU9BLElBQUlBLENBQUNBLENBQUNBO2dCQUMzQkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsSUFBSUEsT0FBUUEsQ0FBQ0E7b0JBQzlCQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDZEEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsSUFBSUEsVUFBVUEsQ0FBQ0EsU0FBVUEsQ0FBQ0E7b0JBQzNDQSxHQUFHQSxHQUFHQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDeEJBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFNBQVNBLElBQUlBLFVBQVVBLENBQUNBLElBQUtBLENBQUNBO29CQUN0Q0EsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzlCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxJQUFLQSxDQUFD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QUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBRXBFRyxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsWUFBWUEsTUFBTUEsQ0FBQ0EsR0FBZUEsU0FBVUEsQ0FBQ0EsSUFBSUEsR0FBV0EsU0FBU0EsQ0FBQ0E7WUFDMUZBLElBQUlBLE1BQU1BLEdBQUdBLEdBQW1CQSxDQUFDQTtZQUNqQ0EsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsT0FBT0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDMUJBLElBQUlBLEVBQUVBLENBQUNBO1lBRVBBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLElBQUtBLENBQUNBO2dCQUNqQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsS0FBS0EsQ0FBRUEsT0FBT0EsR0FBR0EsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsSUFBSUEsR0FBR0Esa0NBQWtDQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUU3RkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsSUFBSUEsSUFBSUEsU0FBVUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ3pDQSxJQUFJQSxHQUFHQSxHQUFlQSxTQUFVQSxDQUFDQSxJQUFJQSxDQUFDQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtnQkFFN0ZBLEVBQUVBLEdBQUdBLElBQUlBLFNBQVNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBLFlBQVlBLENBQUNBO2dCQUV2Q0EsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDWEEsQ0FBQ0E7WUFFREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBTUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQ3JCQSxPQUFPQSxDQUFFQSxJQUFJQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFFQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFDQSxZQUFZQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxFQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxFQUFFQSxFQUFFQSxPQUFPQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtZQUNuSEEsSUFBSUE7Z0JBQ0ZBLE9BQU9BLENBQUVBLElBQUlBLFNBQVNBLEVBQUVBLENBQUVBLENBQUNBO1FBRS9CQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtJQUVESCxTQUFTQSxDQUFDQSxNQUFjQSxFQUFFQSxPQUFrQkEsRUFBRUEsU0FBNkJBLEVBQUVBLFdBQW9CQSxFQUFFQSxTQUFtQkE7UUFDcEhJLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLENBQUVBLFNBQVNBLFlBQVlBLE1BQU1BLENBQUdBLENBQUNBO1lBQ3JDQSxTQUFTQSxHQUFjQSxFQUFFQSxJQUFJQSxFQUFVQSxTQUFTQSxFQUFFQSxDQUFDQTtRQUVyREEsTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLE1BQU1BLEdBQUdBLElBQUlBLFlBQVlBLENBQUVBLE9BQU9BLEVBQUVBLFNBQVNBLEVBQUVBLFdBQVdBLEVBQUVBLFNBQVNBLENBQUVBLENBQUNBO1lBRTVFQSxPQUFPQSxDQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUNyQkEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDSkEsQ0FBQ0E7SUFFREosSUFBSUEsQ0FBRUEsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBQ2xFSyxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsSUFBSUEsTUFBTUEsR0FBR0EsR0FBbUJBLENBQUNBO1lBRWpDQSxPQUFPQSxDQUFFQSxJQUFJQSxTQUFTQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFFQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFDQSxZQUFZQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUVuR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFLT0wsR0FBR0EsQ0FBRUEsR0FBZUEsRUFBRUEsT0FBbUJBLEVBQUVBLE9BQWVBLEVBQUVBLElBQVlBLEVBQUVBLEVBQWVBLEVBQUVBLE9BQWdCQTtRQUtqSE0sd0JBQXlCQSxHQUFHQTtZQUUxQkMsSUFBSUEsS0FBS0EsR0FBR0EsdUJBQXVCQSxDQUFDQSxLQUFLQSxDQUFDQTtZQUUxQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsS0FBTUEsQ0FBQ0EsQ0FDYkEsQ0FBQ0E7Z0JBRUNBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsR0FBR0E7b0JBQ3RDQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFFQSxDQUFFQTtvQkFDNUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3JKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDOUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO29CQUMzSUEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3ZKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDcktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUNqTEEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDN0pBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO29CQUNuSkEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ25MQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdEtBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLENBQUNBLENBQUVBO2lCQUM5R0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7WUFHREEsSUFBSUEsVUFBVUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFeENBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFdBQVdBLENBQUNBLEVBQUVBLEdBQUdBLFVBQVVBLENBQUNBLENBQUNBO1lBRTVDQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVoRUEsSUFBSUEsUUFBUUEsRUFBRUEsU0FBU0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0E7WUFFeENBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQy9CQSxDQUFDQTtnQkFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3pFQSxLQUFLQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFFekVBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ25GQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtnQkFFbkRBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUN0R0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBR2JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLE1BQU1BLEVBQUVBLENBQUNBLEVBQUVBLEVBQ3BDQSxDQUFDQTtvQkFFQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTt3QkFDQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBQUNBLEtBQUtBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO29CQUM1RUEsQ0FBQ0E7b0JBQ0RBLElBQUlBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFNNUJBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNuRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzNFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDMUVBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUMvQ0EsU0FBU0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ3JFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDOUVBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUM5RUEsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ2xEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxTQUFTQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtvQkFDcERBLElBQUlBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBO29CQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxTQUFTQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDcEVBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBQ2RBLENBQUNBO1FBR0RELElBQUlBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7UUFFMUNBLEVBQUVBLENBQUNBLENBQUVBLEtBQUtBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pCQSxDQUFDQTtZQUNDQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLEdBQUdBO2dCQUN0Q0EsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pmQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDam9CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDcm1CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDempCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTthQUN0bEJBLENBQUNBO1FBQ0pBLENBQUNBO1FBR0RBLElBQUlBLElBQUlBLEdBQUdBLGNBQWNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxPQUFPQSxDQUFDQTtRQUMxQ0EsSUFBSUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBQUE7UUFDMUNBLElBQUlBLEdBQUdBLEdBQUdBLE9BQU9BLENBQUNBLE1BQU1BLENBQUNBO1FBR3pCQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUUzQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLE9BQU9BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO1FBQ3BEQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNsR0EsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsT0FBT0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FDbkRBLENBQUNBO1lBQ0NBLElBQUlBLGVBQWVBLEdBQUdBLE9BQU9BLENBQUNBO1lBQzlCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUVwQkEsT0FBT0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDcENBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLGVBQWVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBRWxDQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7Z0JBQ0NBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtvQkFDekZBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxDQUFDQTtvQkFDTkEsQ0FBQ0E7d0JBQ0NBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUU5RUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ1hBLEdBQUdBLElBQUVBLENBQUNBLENBQUNBO3dCQUVUQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDdkZBLEtBQUtBLENBQUNBO1lBRVZBLENBQUNBO1lBRURBLEdBQUdBLElBQUlBLENBQUNBLEdBQUNBLENBQUNBLEdBQUdBLEdBQUNBLENBQUNBLENBQUNBLENBQUFBO1FBQ2xCQSxDQUFDQTtRQUdEQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVuQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFWEEsT0FBT0EsR0FBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDNUVBLFFBQVFBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBO1FBQzlFQSxDQUFDQTtRQUVEQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdYQSxPQUFPQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUNkQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUN6RkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFHekZBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsT0FBT0EsQ0FBQ0E7b0JBQUNBLEtBQUtBLElBQUlBLFFBQVFBLENBQUNBO2dCQUNyQ0EsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtvQkFDbkJBLFNBQVNBLEdBQUdBLFFBQVFBLENBQUNBO29CQUNyQkEsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQ2pGQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRS9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNyQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHeENBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLElBQUVBLENBQUNBLEVBQzVCQSxDQUFDQTtnQkFDQ0EsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzNCQSxJQUFJQSxPQUFPQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFHM0JBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLE9BQU9BLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQ3pDQSxDQUFDQTtvQkFDQ0EsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzdCQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFHekRBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO29CQUNaQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtvQkFDYkEsS0FBS0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQ3JGQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDNUVBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNyRkEsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2hHQSxDQUFDQTtnQkFFREEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUFDQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtZQUMxQ0EsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHL0VBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxJQUFJQSxJQUFJQSxRQUFRQSxDQUFDQTtvQkFDakJBLEtBQUtBLElBQUlBLFNBQVNBLENBQUNBO2dCQUNyQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFFREEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsVUFBVUEsQ0FBR0EsQ0FBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsS0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsRUFBRUEsQ0FBQ0EsS0FBS0EsS0FBR0EsRUFBRUEsQ0FBQ0Es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QSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUV4Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFYkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNVCxVQUFVQSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ1UsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBLENBQ2xCQSxDQUFDQTtZQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtZQUV2REEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFFekJBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEtBQUtBLENBQUNBO1lBRWhCQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtZQUUvQkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFDbERBLENBQUNBO0lBQ0hBLENBQUNBO0lBRU1WLFVBQVVBLENBQUVBLEVBQVVBO1FBRTNCVyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBS0EsQ0FBQ0E7WUFDVEEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFdkRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQ2xDQSxDQUFDQTtJQUVNWCxXQUFXQSxDQUFFQSxFQUFVQTtRQUU1QlksTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDM0JBLENBQUNBO0lBRU1aLE9BQU9BLENBQUVBLEVBQVVBLEVBQUVBLFVBQWVBO1FBRXpDYSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUV4Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFYkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNYixVQUFVQSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ2MsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBRXpCQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtRQUV2REEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsS0FBS0EsQ0FBQ0E7UUFFaEJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRWhEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQUNqQ0EsQ0FBQ0E7SUFFTWQsVUFBVUEsQ0FBRUEsRUFBVUE7UUFFM0JlLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBQ2pDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQTtZQUNUQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV2REEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDbENBLENBQUNBO0lBRU1mLGFBQWFBLENBQUVBLEVBQVVBLEVBQUVBLFVBQWNBO1FBRTlDZ0IsVUFBVUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFdEJBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFVBQVVBLENBQUVBLENBQUNBO1FBRXBEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUU1QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7QUFDSGhCLENBQUNBO0FBN1BRLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBRWxDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQXVQekM7O09DMVFNLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxxQkFBcUI7QUFLdEQ7SUFVRWlCLFlBQWFBLE1BQW9CQSxFQUFFQSxTQUFvQkE7UUFDckRDLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3JCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7SUFNREQsbUJBQW1CQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsZ0JBQWdCQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUM3REEsQ0FBQ0E7QUFFSEYsQ0FBQ0E7QUFBQSIsImZpbGUiOiJjcnlwdG9ncmFwaGl4LXNpbS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNsYXNzIEhleENvZGVjXG57XG4gIHByaXZhdGUgc3RhdGljIGhleERlY29kZU1hcDogbnVtYmVyW107XG5cbiAgc3RhdGljIGRlY29kZSggYTogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmICggSGV4Q29kZWMuaGV4RGVjb2RlTWFwID09IHVuZGVmaW5lZCApXG4gICAge1xuICAgICAgdmFyIGhleCA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiO1xuICAgICAgdmFyIGFsbG93ID0gXCIgXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICB2YXIgZGVjOiBudW1iZXJbXSA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBoZXggPSBoZXgudG9Mb3dlckNhc2UoKTtcbiAgICAgIGZvciAodmFyIGkgPSAxMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgZGVjW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYWxsb3cubGVuZ3RoOyArK2kpXG4gICAgICAgICAgZGVjW2FsbG93LmNoYXJBdChpKV0gPSAtMTtcbiAgICAgIEhleENvZGVjLmhleERlY29kZU1hcCA9IGRlYztcbiAgICB9XG5cbiAgICB2YXIgb3V0OiBudW1iZXJbXSA9IFtdO1xuICAgIHZhciBiaXRzID0gMCwgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKVxuICAgIHtcbiAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgYnJlYWs7XG4gICAgICB2YXIgYiA9IEhleENvZGVjLmhleERlY29kZU1hcFtjXTtcbiAgICAgIGlmIChiID09IC0xKVxuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgaWYgKGIgPT0gdW5kZWZpbmVkKVxuICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICBiaXRzIHw9IGI7XG4gICAgICBpZiAoKytjaGFyX2NvdW50ID49IDIpIHtcbiAgICAgICAgICBvdXQucHVzaCggYml0cyApO1xuICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBiaXRzIDw8PSA0O1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChjaGFyX2NvdW50KVxuICAgICAgdGhyb3cgXCJIZXggZW5jb2RpbmcgaW5jb21wbGV0ZTogNCBiaXRzIG1pc3NpbmdcIjtcblxuICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oIG91dCApO1xuICB9XG59XG4iLCJ0eXBlIGJ5dGUgPSBudW1iZXI7XG5cbmVudW0gQkFTRTY0U1BFQ0lBTFMge1xuICBQTFVTID0gJysnLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIID0gJy8nLmNoYXJDb2RlQXQoMCksXG4gIE5VTUJFUiA9ICcwJy5jaGFyQ29kZUF0KDApLFxuICBMT1dFUiA9ICdhJy5jaGFyQ29kZUF0KDApLFxuICBVUFBFUiA9ICdBJy5jaGFyQ29kZUF0KDApLFxuICBQTFVTX1VSTF9TQUZFID0gJy0nLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIX1VSTF9TQUZFID0gJ18nLmNoYXJDb2RlQXQoMClcbn1cblxuZXhwb3J0IGNsYXNzIEJhc2U2NENvZGVjXG57XG4gIHN0YXRpYyBkZWNvZGUoIGI2NDogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmIChiNjQubGVuZ3RoICUgNCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBiYXNlNjQgc3RyaW5nLiBMZW5ndGggbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBkZWNvZGUoIGVsdDogU3RyaW5nICk6IG51bWJlclxuICAgIHtcbiAgICAgIHZhciBjb2RlID0gZWx0LmNoYXJDb2RlQXQoMCk7XG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTIHx8IGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlBMVVNfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MjsgLy8gJysnXG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSCB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSF9VUkxfU0FGRSlcbiAgICAgICAgcmV0dXJuIDYzOyAvLyAnLydcblxuICAgICAgaWYgKGNvZGUgPj0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSKVxuICAgICAge1xuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDEwKVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSICsgMjYgKyAyNjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLlVQUEVSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5VUFBFUjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLkxPV0VSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2O1xuICAgICAgfVxuXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gQ2hhcmFjdGVyIG5vdCB2YWxpZCcpO1xuICAgIH1cblxuICAgIC8vIHRoZSBudW1iZXIgb2YgZXF1YWwgc2lnbnMgKHBsYWNlIGhvbGRlcnMpXG4gICAgLy8gaWYgdGhlcmUgYXJlIHR3byBwbGFjZWhvbGRlcnMsIHRoYW4gdGhlIHR3byBjaGFyYWN0ZXJzIGJlZm9yZSBpdFxuICAgIC8vIHJlcHJlc2VudCBvbmUgYnl0ZVxuICAgIC8vIGlmIHRoZXJlIGlzIG9ubHkgb25lLCB0aGVuIHRoZSB0aHJlZSBjaGFyYWN0ZXJzIGJlZm9yZSBpdCByZXByZXNlbnQgMiBieXRlc1xuICAgIC8vIHRoaXMgaXMganVzdCBhIGNoZWFwIGhhY2sgdG8gbm90IGRvIGluZGV4T2YgdHdpY2VcbiAgICBsZXQgbGVuID0gYjY0Lmxlbmd0aDtcbiAgICBsZXQgcGxhY2VIb2xkZXJzID0gYjY0LmNoYXJBdChsZW4gLSAyKSA9PT0gJz0nID8gMiA6IGI2NC5jaGFyQXQobGVuIC0gMSkgPT09ICc9JyA/IDEgOiAwO1xuXG4gICAgLy8gYmFzZTY0IGlzIDQvMyArIHVwIHRvIHR3byBjaGFyYWN0ZXJzIG9mIHRoZSBvcmlnaW5hbCBkYXRhXG4gICAgbGV0IGFyciA9IG5ldyBVaW50OEFycmF5KCBiNjQubGVuZ3RoICogMyAvIDQgLSBwbGFjZUhvbGRlcnMgKTtcblxuICAgIC8vIGlmIHRoZXJlIGFyZSBwbGFjZWhvbGRlcnMsIG9ubHkgZ2V0IHVwIHRvIHRoZSBsYXN0IGNvbXBsZXRlIDQgY2hhcnNcbiAgICBsZXQgbCA9IHBsYWNlSG9sZGVycyA+IDAgPyBiNjQubGVuZ3RoIC0gNCA6IGI2NC5sZW5ndGg7XG5cbiAgICB2YXIgTCA9IDA7XG5cbiAgICBmdW5jdGlvbiBwdXNoICh2OiBieXRlKSB7XG4gICAgICBhcnJbTCsrXSA9IHY7XG4gICAgfVxuXG4gICAgbGV0IGkgPSAwLCBqID0gMDtcblxuICAgIGZvciAoOyBpIDwgbDsgaSArPSA0LCBqICs9IDMpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDE4KSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDEyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMikpIDw8IDYpIHwgZGVjb2RlKGI2NC5jaGFyQXQoaSArIDMpKTtcbiAgICAgIHB1c2goKHRtcCAmIDB4RkYwMDAwKSA+PiAxNik7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDApID4+IDgpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICBpZiAocGxhY2VIb2xkZXJzID09PSAyKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpID4+IDQpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9IGVsc2UgaWYgKHBsYWNlSG9sZGVycyA9PT0gMSkge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMTApIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPDwgNCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA+PiAyKTtcbiAgICAgIHB1c2goKHRtcCA+PiA4KSAmIDB4RkYpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXJyO1xuICB9XG5cbiAgc3RhdGljIGVuY29kZSggdWludDg6IFVpbnQ4QXJyYXkgKTogc3RyaW5nXG4gIHtcbiAgICB2YXIgaTogbnVtYmVyO1xuICAgIHZhciBleHRyYUJ5dGVzID0gdWludDgubGVuZ3RoICUgMzsgLy8gaWYgd2UgaGF2ZSAxIGJ5dGUgbGVmdCwgcGFkIDIgYnl0ZXNcbiAgICB2YXIgb3V0cHV0ID0gJyc7XG5cbiAgICBjb25zdCBsb29rdXAgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLyc7XG4gICAgZnVuY3Rpb24gZW5jb2RlKCBudW06IGJ5dGUgKSB7XG4gICAgICByZXR1cm4gbG9va3VwLmNoYXJBdChudW0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyaXBsZXRUb0Jhc2U2NCggbnVtOiBudW1iZXIgKSB7XG4gICAgICByZXR1cm4gZW5jb2RlKG51bSA+PiAxOCAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiAxMiAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiA2ICYgMHgzRikgKyBlbmNvZGUobnVtICYgMHgzRik7XG4gICAgfVxuXG4gICAgLy8gZ28gdGhyb3VnaCB0aGUgYXJyYXkgZXZlcnkgdGhyZWUgYnl0ZXMsIHdlJ2xsIGRlYWwgd2l0aCB0cmFpbGluZyBzdHVmZiBsYXRlclxuICAgIGxldCBsZW5ndGggPSB1aW50OC5sZW5ndGggLSBleHRyYUJ5dGVzO1xuICAgIGZvciAoaSA9IDA7IGkgPCBsZW5ndGg7IGkgKz0gMykge1xuICAgICAgbGV0IHRlbXAgPSAodWludDhbaV0gPDwgMTYpICsgKHVpbnQ4W2kgKyAxXSA8PCA4KSArICh1aW50OFtpICsgMl0pO1xuICAgICAgb3V0cHV0ICs9IHRyaXBsZXRUb0Jhc2U2NCh0ZW1wKTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIGVuZCB3aXRoIHplcm9zLCBidXQgbWFrZSBzdXJlIHRvIG5vdCBmb3JnZXQgdGhlIGV4dHJhIGJ5dGVzXG4gICAgc3dpdGNoIChleHRyYUJ5dGVzKSB7XG4gICAgICBjYXNlIDE6XG4gICAgICAgIGxldCB0ZW1wID0gdWludDhbdWludDgubGVuZ3RoIC0gMV07XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAyKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCA0KSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz09JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgdGVtcCA9ICh1aW50OFt1aW50OC5sZW5ndGggLSAyXSA8PCA4KSArICh1aW50OFt1aW50OC5sZW5ndGggLSAxXSk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAxMCk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPj4gNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCAyKSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz0nO1xuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSGV4Q29kZWMgfSBmcm9tICcuL2hleC1jb2RlYyc7XG5pbXBvcnQgeyBCYXNlNjRDb2RlYyB9IGZyb20gJy4vYmFzZTY0LWNvZGVjJztcblxuZXhwb3J0IGVudW0gQnl0ZUVuY29kaW5nIHtcbiAgUkFXLFxuICBIRVgsXG4gIEJBU0U2NCxcbiAgVVRGOFxufVxuXG5leHBvcnQgY2xhc3MgQnl0ZUFycmF5IC8vZXh0ZW5kcyBVaW50OEFycmF5XG57XG4gIHB1YmxpYyBzdGF0aWMgUkFXID0gQnl0ZUVuY29kaW5nLlJBVztcbiAgcHVibGljIHN0YXRpYyBIRVggPSBCeXRlRW5jb2RpbmcuSEVYO1xuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XG4gIHB1YmxpYyBzdGF0aWMgVVRGOCA9IEJ5dGVFbmNvZGluZy5VVEY4O1xuXG4gIHN0YXRpYyBlbmNvZGluZ1RvU3RyaW5nKCBlbmNvZGluZzogQnl0ZUVuY29kaW5nICk6IHN0cmluZyB7XG4gICAgc3dpdGNoKCBlbmNvZGluZyApIHtcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkJBU0U2NDpcbiAgICAgICAgcmV0dXJuICdCQVNFNjQnO1xuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuVVRGODpcbiAgICAgICAgcmV0dXJuICdVVEY4JztcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkhFWDpcbiAgICAgICAgcmV0dXJuICdIRVgnO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuICdSQVcnO1xuICAgIH1cbiAgfVxuXG4gIHN0YXRpYyBzdHJpbmdUb0VuY29kaW5nKCBlbmNvZGluZzogc3RyaW5nICk6IEJ5dGVFbmNvZGluZyB7XG4gICAgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdCQVNFNjQnIClcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuQkFTRTY0O1xuICAgIGVsc2UgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdVVEY4JyApXG4gICAgICByZXR1cm4gQnl0ZUVuY29kaW5nLlVURjg7XG4gICAgZWxzZSBpZiAoIGVuY29kaW5nLnRvVXBwZXJDYXNlKCkgPT0gJ0hFWCcgKVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5IRVg7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5SQVc7XG4gIH1cblxuXG4gIHByaXZhdGUgYnl0ZUFycmF5OiBVaW50OEFycmF5O1xuICAvKipcbiAgICogQ3JlYXRlIGEgQnl0ZUFycmF5XG4gICAqIEBwYXJhbSBieXRlcyAtIGluaXRpYWwgY29udGVudHMsIG9wdGlvbmFsXG4gICAqICAgbWF5IGJlOlxuICAgKiAgICAgYW4gZXhpc3RpbmcgQnl0ZUFycmF5XG4gICAqICAgICBhbiBBcnJheSBvZiBudW1iZXJzICgwLi4yNTUpXG4gICAqICAgICBhIHN0cmluZywgdG8gYmUgY29udmVydGVkXG4gICAqICAgICBhbiBBcnJheUJ1ZmZlclxuICAgKiAgICAgYSBVaW50OEFycmF5XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYnl0ZXM/OiBCeXRlQXJyYXkgfCBBcnJheTxudW1iZXI+IHwgU3RyaW5nIHwgQXJyYXlCdWZmZXIgfCBVaW50OEFycmF5LCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGlmICggIWJ5dGVzIClcbiAgICB7XG4gICAgICAvLyB6ZXJvLWxlbmd0aCBhcnJheVxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggMCApO1xuICAgIH1cbiAgICBlbHNlIGlmICggIWVuY29kaW5nIHx8IGVuY29kaW5nID09IEJ5dGVFbmNvZGluZy5SQVcgKVxuICAgIHtcbiAgICAgIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlciApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxBcnJheUJ1ZmZlcj5ieXRlcyApO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgVWludDhBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYnl0ZXM7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzLmJ5dGVBcnJheTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIEFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggYnl0ZXMgKTtcbiAgICAgIC8vZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICAgIC8ve1xuLy8gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIC8vfVxuICAgIH1cbiAgICBlbHNlIGlmICggdHlwZW9mIGJ5dGVzID09IFwic3RyaW5nXCIgKVxuICAgIHtcbiAgICAgIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLkJBU0U2NCApXG4gICAgICB7XG4gICAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBCYXNlNjRDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuSEVYIClcbiAgICAgIHtcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBIZXhDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuVVRGOCApXG4gICAgICB7XG4gICAgICAgIGxldCBsID0gKCA8c3RyaW5nPmJ5dGVzICkubGVuZ3RoO1xuICAgICAgICBsZXQgYmEgPSBuZXcgVWludDhBcnJheSggbCApO1xuICAgICAgICBmb3IoIGxldCBpID0gMDsgaSA8IGw7ICsraSApXG4gICAgICAgICAgYmFbaV0gPSAoIDxzdHJpbmc+Ynl0ZXMgKS5jaGFyQ29kZUF0KCBpICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBiYTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBNdXN0IGhhdmUgZXhlYyBvbmUgb2YgYWJvdmUgYWxsb2NhdG9yc1xuICAgIGlmICggIXRoaXMuYnl0ZUFycmF5IClcbiAgICB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiSW52YWxpZCBQYXJhbXMgZm9yIEJ5dGVBcnJheSgpXCIpXG4gICAgfVxuICB9XG5cbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XG4gIH1cblxuICBzZXQgbGVuZ3RoKCBsZW46IG51bWJlciApXG4gIHtcbiAgICBpZiAoIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCA+PSBsZW4gKVxuICAgIHtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdGhpcy5ieXRlQXJyYXkuc2xpY2UoIDAsIGxlbiApO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbGV0IG9sZCA9IHRoaXMuYnl0ZUFycmF5O1xuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG4gICAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIG9sZCwgMCApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBiYWNraW5nQXJyYXkoKTogVWludDhBcnJheVxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5O1xuICB9XG5cbiAgZXF1YWxzKCB2YWx1ZTogQnl0ZUFycmF5ICk6IGJvb2xlYW5cbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG4gICAgdmFyIG9rID0gKCBiYS5sZW5ndGggPT0gdmJhLmxlbmd0aCApO1xuXG4gICAgaWYgKCBvayApXG4gICAge1xuICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICAgIG9rID0gb2sgJiYgKCBiYVtpXSA9PSB2YmFbaV0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gb2s7XG4gIH1cblxuICAvKipcbiAgICAqIGdldCBieXRlIGF0IG9mZnNldFxuICAgICovXG4gIGJ5dGVBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdO1xuICB9XG5cbiAgd29yZEF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gPDwgIDggKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gICAgICAgKTtcbiAgfVxuXG4gIGxpdHRsZUVuZGlhbldvcmRBdCggb2Zmc2V0ICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAgOCApO1xuICB9XG5cbiAgZHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8IDI0IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdIDw8IDE2IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMiBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMyBdICAgICAgICk7XG4gIH1cblxuICAvKipcbiAgICAqIHNldCBieXRlIGF0IG9mZnNldFxuICAgICogQGZsdWVudFxuICAgICovXG4gIHNldEJ5dGVBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0IF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0Qnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIHZhbHVlLmJ5dGVBcnJheSwgb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGNsb25lKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEV4dHJhY3QgYSBzZWN0aW9uIChvZmZzZXQsIGNvdW50KSBmcm9tIHRoZSBCeXRlQXJyYXlcbiAgKiBAZmx1ZW50XG4gICogQHJldHVybnMgYSBCeXRlQXJyYXkgY29udGFpbmluZyBhIGNsb25lIG9mIHRoZSByZXF1ZXN0ZWQgc2VjdGlvbi5cbiAgKi9cbiAgYnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIGNvdW50PzogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgaWYgKCAhTnVtYmVyLmlzSW50ZWdlciggY291bnQgKSApXG4gICAgICBjb3VudCA9ICggdGhpcy5sZW5ndGggLSBvZmZzZXQgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSggb2Zmc2V0LCBvZmZzZXQgKyBjb3VudCApICk7XG4gIH1cblxuICAvKipcbiAgKiBDcmVhdGUgYSB2aWV3IGludG8gdGhlIEJ5dGVBcnJheVxuICAqXG4gICogQHJldHVybnMgYSBCeXRlQXJyYXkgcmVmZXJlbmNpbmcgdGhlIHJlcXVlc3RlZCBzZWN0aW9uIG9mIG9yaWdpbmFsIEJ5dGVBcnJheS5cbiAgKi9cbiAgdmlld0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnN1YmFycmF5KCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFwcGVuZCBieXRlXG4gICogQGZsdWVudFxuICAqL1xuICBhZGRCeXRlKCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGxlbiA9IHRoaXMuYnl0ZUFycmF5Lmxlbmd0aDtcblxuICAgIHRoaXMubGVuZ3RoKys7XG4gICAgdGhpcy5ieXRlQXJyYXlbIGxlbiBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldExlbmd0aCggbGVuOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmxlbmd0aCA9IGxlbjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgY29uY2F0KCBieXRlczogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IG9yaWcgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgbGVuID0gdGhpcy5sZW5ndGg7XG5cbiAgICB0aGlzLmxlbmd0aCArPSBieXRlcy5sZW5ndGg7XG5cbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIG9yaWcgKTtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIGJ5dGVzLmJ5dGVBcnJheSwgbGVuICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG5vdCggKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeMHhGRjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgYW5kKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSAmIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBvciggdmFsdWU6IEJ5dGVBcnJheSApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG5cbiAgICBmb3IoIGxldCBpID0gMDsgaSA8IGJhLmxlbmd0aDsgKytpIClcbiAgICAgIGJhW2ldID0gYmFbaV0gfCB2YmFbIGkgXTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgeG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB0b1N0cmluZyggZW5jb2Rpbmc/OiBudW1iZXIsIG9wdD86IGFueSApXG4gIHtcbiAgICBsZXQgcyA9IFwiXCI7XG4gICAgbGV0IGkgPSAwO1xuXG4gICAgc3dpdGNoKCBlbmNvZGluZyB8fCBCeXRlRW5jb2RpbmcuSEVYICkge1xuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuSEVYOlxuICAgICAgICAvL3JldHVybiBIZXhDb2RlYy5lbmNvZGUoIHRoaXMuYnl0ZUFycmF5ICk7XG4gICAgICAgIGZvciggaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgKytpIClcbiAgICAgICAgICBzICs9ICggXCIwXCIgKyB0aGlzLmJ5dGVBcnJheVsgaSBdLnRvU3RyaW5nKCAxNiApKS5zbGljZSggLTIgKS50b1VwcGVyQ2FzZSgpO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuQkFTRTY0OlxuICAgICAgICByZXR1cm4gQmFzZTY0Q29kZWMuZW5jb2RlKCB0aGlzLmJ5dGVBcnJheSApO1xuXG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5VVEY4OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHJldHVybiBzO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgS2luZCB9IGZyb20gJy4va2luZCc7XG5cbmV4cG9ydCBjbGFzcyBFbnVtIHtcbn1cblxuZXhwb3J0IGNsYXNzIEludGVnZXIgZXh0ZW5kcyBOdW1iZXIge1xufVxuXG4vKipcbiAqIFNldCBvZiBkYXRhIHR5cGVzIHRoYXQgYXJlIHZhbGlkIGFzIEtpbmQgZmllbGRzXG4gKiBpbmNsdWRlcyBGaWVsZFR5cGVBcnJheSBrbHVkZ2UgcmVxdWlyZWQgZm9yIFRTIHRvIHBhcnNlIHJlY3Vyc2l2ZVxuICogdHlwZSBkZWZpbml0aW9uc1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRBcnJheSBleHRlbmRzIEFycmF5PEZpZWxkVHlwZT4ge31cbmV4cG9ydCB0eXBlIEZpZWxkVHlwZSA9IFN0cmluZyB8IE51bWJlciB8IEludGVnZXIgfCBFbnVtIHwgQnl0ZUFycmF5IHwgS2luZCB8IEZpZWxkQXJyYXk7XG5cbmV4cG9ydCBjbGFzcyBGaWVsZEFycmF5IGltcGxlbWVudHMgRmllbGRBcnJheSB7fVxuXG5leHBvcnQgY29uc3QgRmllbGRUeXBlcyA9IHtcbiAgQm9vbGVhbjogQm9vbGVhbixcblxuICBOdW1iZXI6IE51bWJlcixcblxuICBJbnRlZ2VyOiBJbnRlZ2VyLFxuXG4gIEJ5dGVBcnJheTogQnl0ZUFycmF5LFxuXG4gIEVudW06IEVudW0sXG5cbiAgQXJyYXk6IEZpZWxkQXJyYXksXG5cbiAgU3RyaW5nOiBTdHJpbmcsXG5cbiAgS2luZDogS2luZFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkT3B0aW9ucyB7XG4gIC8qKlxuICAqIG1pbmltdW0gbGVuZ3RoIGZvciBTdHJpbmcsIG1pbmltdW0gdmFsdWUgZm9yIE51bWJlci9JbnRlZ2VyXG4gICovXG4gIG1pbmltdW0/OiBudW1iZXI7XG5cbiAgLyoqXG4gICogbWF4aW11bSBsZW5ndGggZm9yIFN0cmluZywgbWF4aW11bSB2YWx1ZSBmb3IgTnVtYmVyL0ludGVnZXJcbiAgKi9cbiAgbWF4aW11bT86IG51bWJlcjtcblxuICAvKipcbiAgKiBkZWZhdWx0IHZhbHVlIGR1cmluZyBpbml0aWFsaXphdGlvblxuICAqL1xuICBcImRlZmF1bHRcIj86IGFueTtcblxuICAvKipcbiAgKiBkb2VzIG5vdCBleGlzdCBhcyBhbiBvd25Qcm9wZXJ0eVxuICAqL1xuICBjYWxjdWxhdGVkPzogYm9vbGVhbjtcblxuICAvKipcbiAgKiBzdWIta2luZCwgd2hlbiBmaWVsZCBpcyB0eXBlIEtpbmRcbiAgKi9cbiAga2luZD86IEtpbmQ7XG5cbiAgLyoqXG4gICogc3ViLWZpZWxkIGluZm8sIHdoZW4gZmllbGQgaXMgdHlwZSBGaWVsZEFycmF5XG4gICovXG4gIGFycmF5SW5mbz86IEZpZWxkSW5mbztcblxuICAvKipcbiAgKiBpbmRleC92YWx1ZSBtYXAsIHdoZW4gZmllbGQgaWYgdHlwZSBFbnVtXG4gICovXG4gIGVudW1NYXA/OiBNYXA8bnVtYmVyLCBzdHJpbmc+O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkSW5mbyBleHRlbmRzIEZpZWxkT3B0aW9ucyB7XG4gIC8qKlxuICAqIERlc2NyaXB0aW9uIGZvciBmaWVsZFxuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIFR5cGUgb2YgZmllbGQsIG9uZSBvZiBGaWVsZFR5cGVzXG4gICovXG4gIGZpZWxkVHlwZTogRmllbGRUeXBlO1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi9ieXRlLWFycmF5JztcbmltcG9ydCB7IEZpZWxkVHlwZSwgRmllbGRUeXBlcywgRmllbGRPcHRpb25zLCBGaWVsZEluZm8gfSBmcm9tICcuL2ZpZWxkLWluZm8nO1xuXG4vKipcbiogTWV0YWRhdGEgYWJvdXQgYSBLaW5kLiBDb250YWlucyBuYW1lLCBkZXNjcmlwdGlvbiBhbmQgYSBtYXAgb2ZcbiogcHJvcGVydHktZGVzY3JpcHRvcnMgdGhhdCBkZXNjcmliZSB0aGUgc2VyaWFsaXphYmxlIGZpZWxkcyBvZlxuKiBhbiBvYmplY3Qgb2YgdGhhdCBLaW5kLlxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kSW5mb1xue1xuICBuYW1lOiBzdHJpbmc7XG5cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICBmaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBGaWVsZEluZm8gfSA9IHt9O1xufVxuXG4vKipcbiogQnVpbGRlciBmb3IgJ0tpbmQnIG1ldGFkYXRhXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRCdWlsZGVyXG57XG4gIHByaXZhdGUgY3RvcjogS2luZENvbnN0cnVjdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKSB7XG4gICAgdGhpcy5jdG9yID0gY3RvcjtcblxuICAgIGN0b3Iua2luZEluZm8gPSB7XG4gICAgICBuYW1lOiBjdG9yLm5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24sXG4gICAgICBmaWVsZHM6IHt9XG4gICAgfVxuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IEtpbmRCdWlsZGVyKCBjdG9yLCBkZXNjcmlwdGlvbiApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgZmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZmllbGRUeXBlOiBGaWVsZFR5cGUsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyXG4gIHtcbiAgICBsZXQgZmllbGQ6IEZpZWxkSW5mbyA9IDxGaWVsZEluZm8+b3B0cztcblxuICAgIGZpZWxkLmRlc2NyaXB0aW9uID0gZGVzY3JpcHRpb247XG4gICAgZmllbGQuZmllbGRUeXBlID0gZmllbGRUeXBlO1xuXG4gICAgdGhpcy5jdG9yLmtpbmRJbmZvLmZpZWxkc1sgbmFtZSBdID0gZmllbGQ7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBib29sRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgQm9vbGVhbiwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIG51bWJlckZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIE51bWJlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGludGVnZXJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBGaWVsZFR5cGVzLkludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyB1aW50MzJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgb3B0cy5taW5pbXVtID0gb3B0cy5taW5pbXVtIHx8IDA7XG4gICAgb3B0cy5tYXhpbXVtID0gb3B0cy5tYXhpbXVtIHx8IDB4RkZGRkZGRkY7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEZpZWxkVHlwZXMuSW50ZWdlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGJ5dGVGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgb3B0cy5taW5pbXVtID0gb3B0cy5taW5pbXVtIHx8IDA7XG4gICAgb3B0cy5tYXhpbXVtID0gb3B0cy5tYXhpbXVtIHx8IDI1NTtcblxuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgRmllbGRUeXBlcy5JbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgc3RyaW5nRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgU3RyaW5nLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMga2luZEZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGtpbmQ6IEtpbmQsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLmtpbmQgPSBraW5kO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBLaW5kLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgZW51bUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGVudW1tOiB7IFsgaWR4OiBudW1iZXIgXTogc3RyaW5nIH0sIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcblxuICAgIG9wdHMuZW51bU1hcCA9IG5ldyBNYXA8bnVtYmVyLHN0cmluZz4oICk7XG5cbiAgICBmb3IoIGxldCBpZHggaW4gZW51bW0gKSB7XG4gICAgICBpZiAoIDEgKiBpZHggPT0gaWR4IClcbiAgICAgICAgb3B0cy5lbnVtTWFwLnNldCggaWR4LCBlbnVtbVsgaWR4IF0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEZpZWxkVHlwZXMuRW51bSwgb3B0cyApO1xuICB9XG59XG5cbi8qKlxuKiBSZXByZXNlbnRzIGEgc2VyaWFsaXphYmxlIGFuZCBpbnNwZWN0YWJsZSBkYXRhLXR5cGVcbiogaW1wbGVtZW50ZWQgYXMgYSBzdGFuZGFyZCBqYXZhc2NyaXB0IG9iamVjdCBlbmhhbmNlZCB3aXRoIG1ldGFkYXRhXG4qIHRoYXQgZGVzY3JpYmVzIGVhY2ggZmllbGQuXG4qL1xuZXhwb3J0IGludGVyZmFjZSBLaW5kXG57XG4gIC8qKlxuICAgKiBTZXJpYWxpemF0aW9uLCByZXR1cm5zIGEgSlNPTiBvYmplY3RcbiAgICovXG4gIHRvSlNPTj8oKToge307XG5cbiAgLyoqXG4gICAqIEVuY29kZXJcbiAgICovXG4gIGVuY29kZUJ5dGVzPyggb3B0aW9ucz86IHt9ICk6IEJ5dGVBcnJheTtcblxuICAvKipcbiAgKiBEZWNvZGVyLCBjaGFpbmFibGVcbiAgKi9cbiAgZGVjb2RlQnl0ZXM/KCBieXRlQXJyYXk6IEJ5dGVBcnJheSwgb3B0aW9ucz86IHt9ICk6IHRoaXM7XG59XG5cbmV4cG9ydCBjbGFzcyBLaW5kIGltcGxlbWVudHMgS2luZCB7XG4gIC8vIFF1aWNrIGFuZCBOYXN0eSB0ZXN0IGZvciBcIktpbmRcIlxuICBzdGF0aWMgaXNLaW5kKCBraW5kOiBLaW5kICk6IGJvb2xlYW4ge1xuICAgIC8vICEhIHRyYW5zZm9ybXMgb2JqZWN0cyBpbnRvIGJvb2xlYW5cbiAgICByZXR1cm4gISEoIGtpbmQgJiYga2luZC5jb25zdHJ1Y3RvciAmJiAoPEtpbmRDb25zdHJ1Y3Rvcj4oa2luZC5jb25zdHJ1Y3RvcikpLmtpbmRJbmZvKTtcbiAgfVxuXG4gIHN0YXRpYyBnZXRLaW5kQ29uc3RydWN0b3IoIGtpbmQ6IEtpbmQgKTogS2luZENvbnN0cnVjdG9yIHtcbiAgICByZXR1cm4ga2luZCAmJiBraW5kLmNvbnN0cnVjdG9yICYmIDxLaW5kQ29uc3RydWN0b3I+KGtpbmQuY29uc3RydWN0b3IpO1xuICB9XG5cbiAgc3RhdGljIGdldEtpbmRJbmZvKCBraW5kOiBLaW5kICk6IEtpbmRJbmZvIHtcbiAgICByZXR1cm4gKDxLaW5kQ29uc3RydWN0b3I+KGtpbmQuY29uc3RydWN0b3IpKS5raW5kSW5mbztcbiAgfVxuXG4gIHN0YXRpYyBpbml0RmllbGRzKCBraW5kOiBLaW5kLCBhdHRyaWJ1dGVzOiB7fSA9IHt9ICApIHtcbiAgICBsZXQga2luZEluZm8gPSBLaW5kLmdldEtpbmRJbmZvKCBraW5kICk7XG5cbiAgICBmb3IoIGxldCBpZCBpbiBraW5kSW5mby5maWVsZHMgKSB7XG4gICAgICBsZXQgZmllbGQgPSBraW5kSW5mby5maWVsZHNbIGlkIF07XG4gICAgICBsZXQgZmllbGRUeXBlID0gZmllbGQuZmllbGRUeXBlO1xuXG4gICAgICBsZXQgdmFsOiBhbnk7XG5cbiAgICAgIGlmICggIWZpZWxkLmNhbGN1bGF0ZWQgKSB7XG4gICAgICAgIC8vIHdlIG9ubHkgc2V0ICdub24nLWNhbGN1bGF0ZWQgZmllbGQsIHNpbmNlIGNhbGN1bGF0ZWQgZmllbGQgaGF2ZVxuICAgICAgICAvLyBubyBzZXR0ZXJcblxuICAgICAgICAvLyBnb3QgYSB2YWx1ZSBmb3IgdGhpcyBmaWVsZCA/XG4gICAgICAgIGlmICggYXR0cmlidXRlc1sgaWQgXSApXG4gICAgICAgICAgdmFsID0gYXR0cmlidXRlc1sgaWQgXTtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkLmRlZmF1bHQgIT0gdW5kZWZpbmVkIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5kZWZhdWx0O1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IFN0cmluZyApXG4gICAgICAgICAgdmFsID0gJyc7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gTnVtYmVyIClcbiAgICAgICAgICB2YWwgPSAwO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEZpZWxkVHlwZXMuSW50ZWdlciApXG4gICAgICAgICAgdmFsID0gZmllbGQubWluaW11bSB8fCAwO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEJvb2xlYW4gKVxuICAgICAgICAgIHZhbCA9IGZhbHNlO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEZpZWxkVHlwZXMuQnl0ZUFycmF5IClcbiAgICAgICAgICB2YWwgPSBuZXcgQnl0ZUFycmF5KCk7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gRmllbGRUeXBlcy5FbnVtIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5lbnVtTWFwLmtleXNbMF07XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gS2luZCApIHtcbiAgICAgICAgICBsZXQgY3RvciA9ICg8S2luZD5maWVsZFR5cGUpLmNvbnN0cnVjdG9yO1xuICAgICAgICAgIHZhbCA9IE9iamVjdC5jcmVhdGUoIGN0b3IgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGtpbmRbIGlkIF0gPSB2YWw7XG4gICAgICB9XG4gICAgfVxuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2luZENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIGF0dHJpYnV0ZXM/OiB7fSwgLi4uYXJncyApOiBLaW5kO1xuXG4gIGtpbmRJbmZvPzogS2luZEluZm87XG59XG4iLCJpbXBvcnQgeyBLaW5kIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuXG4vKlxuKiBNZXNzYWdlIEhlYWRlclxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgTWVzc2FnZUhlYWRlclxue1xuICAvKlxuICAqIE1lc3NhZ2UgTmFtZSwgaW5kaWNhdGVzIGEgY29tbWFuZCAvIG1ldGhvZCAvIHJlc3BvbnNlIHRvIGV4ZWN1dGVcbiAgKi9cbiAgbWV0aG9kPzogc3RyaW5nO1xuXG4gIC8qXG4gICogTWVzc2FnZSBJZGVudGlmaWVyICh1bmlxdWUpIGZvciBlYWNoIHNlbnQgbWVzc2FnZSAob3IgQ01ELVJFU1AgcGFpcilcbiAgKi9cbiAgaWQ/OiBudW1iZXI7XG5cblxuICAvKlxuICAqIERlc2NyaXB0aW9uLCB1c2VmdWwgZm9yIHRyYWNpbmcgYW5kIGxvZ2dpbmdcbiAgKi9cbiAgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG5cbiAgLypcbiAgKiBGb3IgQ01EL1JFU1Agc3R5bGUgcHJvdG9jb2xzLCBpbmRpY2F0ZXMgdGhhdCBtZXNzYWdlIGRpc3BhdGNoZWRcbiAgKiBpbiByZXNwb25zZSB0byBhIHByZXZpb3VzIGNvbW1hbmRcbiAgKi9cbiAgaXNSZXNwb25zZT86IGJvb2xlYW47XG5cbiAgLypcbiAgKiBFbmRQb2ludCB0aGF0IG9yaWdpbmF0ZWQgdGhlIG1lc3NhZ2VcbiAgKi9cbiAgb3JpZ2luPzogRW5kUG9pbnQ7XG5cblxuICAvKlxuICAqIEluZGljYXRlcyB0aGUgS2luZCBvZiBkYXRhICh3aGVuIHNlcmlhbGl6ZWQpXG4gICovXG4gIGtpbmROYW1lPzogc3RyaW5nO1xufVxuXG4vKlxuKiBBIFR5cGVkIE1lc3NhZ2UsIHdpdGggaGVhZGVyIGFuZCBwYXlsb2FkXG4qL1xuZXhwb3J0IGNsYXNzIE1lc3NhZ2U8VD5cbntcbiAgcHJpdmF0ZSBfaGVhZGVyOiBNZXNzYWdlSGVhZGVyO1xuICBwcml2YXRlIF9wYXlsb2FkOiBUO1xuXG4gIGNvbnN0cnVjdG9yKCBoZWFkZXI6IE1lc3NhZ2VIZWFkZXIsIHBheWxvYWQ6IFQgKVxuICB7XG4gICAgdGhpcy5faGVhZGVyID0gaGVhZGVyIHx8IHt9O1xuICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICB9XG5cbiAgZ2V0IGhlYWRlcigpOiBNZXNzYWdlSGVhZGVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faGVhZGVyO1xuICB9XG5cbiAgZ2V0IHBheWxvYWQoKTogVFxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BheWxvYWQ7XG4gIH1cbn1cblxuLypcbiogQSB0eXBlZCBNZXNzYWdlIHdob3NlIHBheWxvYWQgaXMgYSBLaW5kXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRNZXNzYWdlPEsgZXh0ZW5kcyBLaW5kPiBleHRlbmRzIE1lc3NhZ2U8Sz5cbntcbn1cbiIsImV4cG9ydCB0eXBlIFRhc2sgPSAoKSA9PiB2b2lkO1xuZXhwb3J0IHR5cGUgRmx1c2hGdW5jID0gKCkgPT4gdm9pZDtcbnZhciB3aW5kb3cgPSB3aW5kb3cgfHwge307XG5cbmV4cG9ydCBjbGFzcyBUYXNrU2NoZWR1bGVyXG57XG4gIHN0YXRpYyBtYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpOiBGbHVzaEZ1bmNcbiAge1xuICAgIHZhciB0b2dnbGUgPSAxO1xuXG4gICAgdmFyIG9ic2VydmVyID0gbmV3IFRhc2tTY2hlZHVsZXIuQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpO1xuXG4gICAgdmFyIG5vZGU6IE9iamVjdCA9IGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKCcnKTtcblxuICAgIG9ic2VydmVyLm9ic2VydmUobm9kZSwgeyBjaGFyYWN0ZXJEYXRhOiB0cnVlIH0pO1xuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpXG4gICAge1xuICAgICAgdG9nZ2xlID0gLXRvZ2dsZTtcbiAgICAgIG5vZGVbXCJkYXRhXCJdID0gdG9nZ2xlO1xuICAgIH07XG4gIH1cblxuICBzdGF0aWMgbWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lcihmbHVzaCk6IEZsdXNoRnVuY1xuICB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpIHtcbiAgICAgIHZhciB0aW1lb3V0SGFuZGxlID0gc2V0VGltZW91dChoYW5kbGVGbHVzaFRpbWVyLCAwKTtcblxuICAgICAgdmFyIGludGVydmFsSGFuZGxlID0gc2V0SW50ZXJ2YWwoaGFuZGxlRmx1c2hUaW1lciwgNTApO1xuICAgICAgZnVuY3Rpb24gaGFuZGxlRmx1c2hUaW1lcigpXG4gICAgICB7XG4gICAgICAgIGNsZWFyVGltZW91dCh0aW1lb3V0SGFuZGxlKTtcbiAgICAgICAgY2xlYXJJbnRlcnZhbChpbnRlcnZhbEhhbmRsZSk7XG4gICAgICAgIGZsdXNoKCk7XG4gICAgICB9XG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBCcm93c2VyTXV0YXRpb25PYnNlcnZlciA9IHdpbmRvd1sgXCJNdXRhdGlvbk9ic2VydmVyXCIgXSB8fCB3aW5kb3dbIFwiV2ViS2l0TXV0YXRpb25PYnNlcnZlclwiXTtcbiAgc3RhdGljIGhhc1NldEltbWVkaWF0ZSA9IHR5cGVvZiBzZXRJbW1lZGlhdGUgPT09ICdmdW5jdGlvbic7XG5cbiAgc3RhdGljIHRhc2tRdWV1ZUNhcGFjaXR5ID0gMTAyNDtcbiAgdGFza1F1ZXVlOiBUYXNrW107XG5cbiAgcmVxdWVzdEZsdXNoVGFza1F1ZXVlOiBGbHVzaEZ1bmM7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy50YXNrUXVldWUgPSBbXTtcblxuICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgIGlmICh0eXBlb2YgVGFza1NjaGVkdWxlci5Ccm93c2VyTXV0YXRpb25PYnNlcnZlciA9PT0gJ2Z1bmN0aW9uJylcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSA9IFRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHNlbGYuZmx1c2hUYXNrUXVldWUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUgPSBUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIoZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gc2VsZi5mbHVzaFRhc2tRdWV1ZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgVGFza1NjaGVkdWxlciwgY2FuY2VsbGluZyBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgc2h1dGRvd24oKVxuICB7XG4gIH1cblxuICBxdWV1ZVRhc2soIHRhc2spXG4gIHtcbiAgICBpZiAoIHRoaXMudGFza1F1ZXVlLmxlbmd0aCA8IDEgKVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlKCk7XG4gICAgfVxuXG4gICAgdGhpcy50YXNrUXVldWUucHVzaCh0YXNrKTtcbiAgfVxuXG4gIGZsdXNoVGFza1F1ZXVlKClcbiAge1xuICAgIHZhciBxdWV1ZSA9IHRoaXMudGFza1F1ZXVlLFxuICAgICAgICBjYXBhY2l0eSA9IFRhc2tTY2hlZHVsZXIudGFza1F1ZXVlQ2FwYWNpdHksXG4gICAgICAgIGluZGV4ID0gMCxcbiAgICAgICAgdGFzaztcblxuICAgIHdoaWxlIChpbmRleCA8IHF1ZXVlLmxlbmd0aClcbiAgICB7XG4gICAgICB0YXNrID0gcXVldWVbaW5kZXhdO1xuXG4gICAgICB0cnlcbiAgICAgIHtcbiAgICAgICAgdGFzay5jYWxsKCk7XG4gICAgICB9XG4gICAgICBjYXRjaCAoZXJyb3IpXG4gICAgICB7XG4gICAgICAgIHRoaXMub25FcnJvcihlcnJvciwgdGFzayk7XG4gICAgICB9XG5cbiAgICAgIGluZGV4Kys7XG5cbiAgICAgIGlmIChpbmRleCA+IGNhcGFjaXR5KVxuICAgICAge1xuICAgICAgICBmb3IgKHZhciBzY2FuID0gMDsgc2NhbiA8IGluZGV4OyBzY2FuKyspXG4gICAgICAgIHtcbiAgICAgICAgICBxdWV1ZVtzY2FuXSA9IHF1ZXVlW3NjYW4gKyBpbmRleF07XG4gICAgICAgIH1cblxuICAgICAgICBxdWV1ZS5sZW5ndGggLT0gaW5kZXg7XG4gICAgICAgIGluZGV4ID0gMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBxdWV1ZS5sZW5ndGggPSAwO1xuICB9XG5cbiAgb25FcnJvcihlcnJvciwgdGFzaylcbiAge1xuICAgIGlmICgnb25FcnJvcicgaW4gdGFzaykge1xuICAgICAgdGFzay5vbkVycm9yKGVycm9yKTtcbiAgICB9XG4gICAgZWxzZSBpZiAoIFRhc2tTY2hlZHVsZXIuaGFzU2V0SW1tZWRpYXRlIClcbiAgICB7XG4gICAgICBzZXRJbW1lZGlhdGUoZnVuY3Rpb24gKCkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgc2V0VGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSwgMCk7XG4gICAgfVxuICB9XG59XG4iLCJpbXBvcnQgeyBUYXNrU2NoZWR1bGVyIH0gZnJvbSAnLi4vcnVudGltZS90YXNrLXNjaGVkdWxlcic7XG5pbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5cbi8qKlxuKiBBIG1lc3NhZ2UtcGFzc2luZyBjaGFubmVsIGJldHdlZW4gbXVsdGlwbGUgRW5kUG9pbnRzXG4qXG4qIEVuZFBvaW50cyBtdXN0IGZpcnN0IHJlZ2lzdGVyIHdpdGggdGhlIENoYW5uZWwuIFdoZW5ldmVyIHRoZSBDaGFubmVsIGlzIGluXG4qIGFuIGFjdGl2ZSBzdGF0ZSwgY2FsbHMgdG8gc2VuZE1lc3NhZ2Ugd2lsbCBmb3J3YXJkIHRoZSBtZXNzYWdlIHRvIGFsbFxuKiByZWdpc3RlcmVkIEVuZFBvaW50cyAoZXhjZXB0IHRoZSBvcmlnaW5hdG9yIEVuZFBvaW50KS5cbiovXG5cbmV4cG9ydCB0eXBlIENoYW5uZWxIb29rSW5mbyA9IHsgbWVzc2FnZTogTWVzc2FnZTxhbnk+OyBjaGFubmVsOiBDaGFubmVsOyBvcmlnaW46IEVuZFBvaW50OyBkZXN0aW5hdGlvbjogRW5kUG9pbnQ7IHNlbmRNZXNzYWdlOiAoKSA9PiB2b2lkIH07XG5cbmV4cG9ydCBjbGFzcyBDaGFubmVsXG57XG4gIC8vIHByZURlbGl2ZXJ5SG9vayggdGFzaywgb3JpZ2luLCBlbmRQb2ludCwgdGFza1NjaGVkdWxlciApXG4gIHByaXZhdGUgc3RhdGljIF9kZWxpdmVyeUhvb2s6ICggaW5mbzogQ2hhbm5lbEhvb2tJbmZvICkgPT4gYm9vbGVhbjtcblxuICBzdGF0aWMgc2V0RGVsaXZlcnlIb29rKCBkZWxpdmVyeUhvb2s6ICggaW5mbzogQ2hhbm5lbEhvb2tJbmZvICkgPT4gYm9vbGVhbiApIHtcbiAgICBDaGFubmVsLl9kZWxpdmVyeUhvb2sgPSBkZWxpdmVyeUhvb2s7XG4gIH07XG5cbiAgLyoqXG4gICogVHJ1ZSBpZiBDaGFubmVsIGlzIGFjdGl2ZVxuICAqL1xuICBwcml2YXRlIF9hY3RpdmU6IGJvb2xlYW47XG5cbiAgLyoqXG4gICogQXJyYXkgb2YgRW5kUG9pbnRzIGF0dGFjaGVkIHRvIHRoaXMgQ2hhbm5lbFxuICAqL1xuICBwcml2YXRlIF9lbmRQb2ludHM6IEVuZFBvaW50W107XG5cbiAgLyoqXG4gICogUHJpdmF0ZSBUYXNrU2NoZWR1bGVyIHVzZWQgdG8gbWFrZSBtZXNzYWdlLXNlbmRzIGFzeW5jaHJvbm91cy5cbiAgKi9cbiAgcHJpdmF0ZSBfdGFza1NjaGVkdWxlcjogVGFza1NjaGVkdWxlcjtcblxuICAvKipcbiAgKiBDcmVhdGUgYSBuZXcgQ2hhbm5lbCwgaW5pdGlhbGx5IGluYWN0aXZlXG4gICovXG4gIGNvbnN0cnVjdG9yKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuICAgIHRoaXMuX2VuZFBvaW50cyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgQ2hhbm5lbCwgZGVhY3RpdmF0ZSwgcmVtb3ZlIGFsbCBFbmRQb2ludHMgYW5kXG4gICogYWJvcnQgYW55IHBlbmRpbmcgY29tbXVuaWNhdGlvbnMuXG4gICovXG4gIHB1YmxpYyBzaHV0ZG93bigpXG4gIHtcbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcblxuICAgIHRoaXMuX2VuZFBvaW50cyA9IFtdO1xuXG4gICAgaWYgKCB0aGlzLl90YXNrU2NoZWR1bGVyIClcbiAgICB7XG4gICAgICB0aGlzLl90YXNrU2NoZWR1bGVyLnNodXRkb3duKCk7XG5cbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogSXMgQ2hhbm5lbCBhY3RpdmU/XG4gICpcbiAgKiBAcmV0dXJucyB0cnVlIGlmIGNoYW5uZWwgaXMgYWN0aXZlLCBmYWxzZSBvdGhlcndpc2VcbiAgKi9cbiAgcHVibGljIGdldCBhY3RpdmUoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2FjdGl2ZTtcbiAgfVxuXG4gIC8qKlxuICAqIEFjdGl2YXRlIHRoZSBDaGFubmVsLCBlbmFibGluZyBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBhY3RpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gbmV3IFRhc2tTY2hlZHVsZXIoKTtcblxuICAgIHRoaXMuX2FjdGl2ZSA9IHRydWU7XG4gIH1cblxuICAvKipcbiAgKiBEZWFjdGl2YXRlIHRoZSBDaGFubmVsLCBkaXNhYmxpbmcgYW55IGZ1cnRoZXIgY29tbXVuaWNhdGlvblxuICAqL1xuICBwdWJsaWMgZGVhY3RpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLl90YXNrU2NoZWR1bGVyID0gdW5kZWZpbmVkO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgKiBSZWdpc3RlciBhbiBFbmRQb2ludCB0byBzZW5kIGFuZCByZWNlaXZlIG1lc3NhZ2VzIHZpYSB0aGlzIENoYW5uZWwuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gcmVnaXN0ZXJcbiAgKi9cbiAgcHVibGljIGFkZEVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgdGhpcy5fZW5kUG9pbnRzLnB1c2goIGVuZFBvaW50ICk7XG4gIH1cblxuICAvKipcbiAgKiBVbnJlZ2lzdGVyIGFuIEVuZFBvaW50LlxuICAqXG4gICogQHBhcmFtIGVuZFBvaW50IC0gdGhlIEVuZFBvaW50IHRvIHVucmVnaXN0ZXJcbiAgKi9cbiAgcHVibGljIHJlbW92ZUVuZFBvaW50KCBlbmRQb2ludDogRW5kUG9pbnQgKVxuICB7XG4gICAgbGV0IGlkeCA9IHRoaXMuX2VuZFBvaW50cy5pbmRleE9mKCBlbmRQb2ludCApO1xuXG4gICAgaWYgKCBpZHggPj0gMCApXG4gICAge1xuICAgICAgdGhpcy5fZW5kUG9pbnRzLnNwbGljZSggaWR4LCAxICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogR2V0IEVuZFBvaW50cyByZWdpc3RlcmVkIHdpdGggdGhpcyBDaGFubmVsXG4gICpcbiAgKiBAcmV0dXJuIEFycmF5IG9mIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgZ2V0IGVuZFBvaW50cygpOiBFbmRQb2ludFtdXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnRzO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIG1lc3NhZ2UgdG8gYWxsIGxpc3RlbmVycyAoZXhjZXB0IG9yaWdpbilcbiAgKlxuICAqIEBwYXJhbSBvcmlnaW4gLSBFbmRQb2ludCB0aGF0IGlzIHNlbmRpbmcgdGhlIG1lc3NhZ2VcbiAgKiBAcGFyYW0gbWVzc2FnZSAtIE1lc3NhZ2UgdG8gYmUgc2VudFxuICAqL1xuICBwdWJsaWMgc2VuZE1lc3NhZ2UoIG9yaWdpbjogRW5kUG9pbnQsIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiApXG4gIHtcbiAgICBsZXQgaXNSZXNwb25zZSA9ICggbWVzc2FnZS5oZWFkZXIgJiYgbWVzc2FnZS5oZWFkZXIuaXNSZXNwb25zZSApO1xuXG4gICAgaWYgKCAhdGhpcy5fYWN0aXZlIClcbiAgICAgIHJldHVybjtcblxuICAgIGlmICggb3JpZ2luLmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uSU4gJiYgIWlzUmVzcG9uc2UgKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCAnVW5hYmxlIHRvIHNlbmQgb24gSU4gcG9ydCcpO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzLmZvckVhY2goIGVuZFBvaW50ID0+IHtcbiAgICAgIC8vIFNlbmQgdG8gYWxsIGxpc3RlbmVycywgZXhjZXB0IGZvciBvcmlnaW5hdG9yIC4uLlxuICAgICAgaWYgKCBvcmlnaW4gIT0gZW5kUG9pbnQgKVxuICAgICAge1xuICAgICAgICAvLyBPbmx5IHNlbmQgdG8gSU4gb3IgSU5PVVQgbGlzdGVuZXJzLCBVTkxFU1MgbWVzc2FnZSBpcyBhXG4gICAgICAgIC8vIHJlcGx5IChpbiBhIGNsaWVudC1zZXJ2ZXIpIGNvbmZpZ3VyYXRpb25cbiAgICAgICAgaWYgKCBlbmRQb2ludC5kaXJlY3Rpb24gIT0gRGlyZWN0aW9uLk9VVCB8fCBpc1Jlc3BvbnNlIClcbiAgICAgICAge1xuICAgICAgICAgIGxldCB0YXNrID0gKCkgPT4ge1xuICAgICAgICAgICAgZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgb3JpZ2luLCB0aGlzICk7XG4gICAgICAgICAgfTtcblxuICAgICAgICAgIGxldCBjYW5TZW5kID0gdHJ1ZTtcblxuICAgICAgICAgIGlmICggQ2hhbm5lbC5fZGVsaXZlcnlIb29rICkge1xuICAgICAgICAgICAgbGV0IHNjaGVkdWxlciA9IHRoaXMuX3Rhc2tTY2hlZHVsZXI7XG5cbiAgICAgICAgICAgIGxldCBtZXNzYWdlSG9va0luZm8gPSB7XG4gICAgICAgICAgICAgIG1lc3NhZ2U6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgIGNoYW5uZWw6IHRoaXMsXG4gICAgICAgICAgICAgIG9yaWdpbjogb3JpZ2luLFxuICAgICAgICAgICAgICBkZXN0aW5hdGlvbjogZW5kUG9pbnQsXG4gICAgICAgICAgICAgIHNlbmRNZXNzYWdlOiAoKSA9PiB7IHNjaGVkdWxlci5xdWV1ZVRhc2soIHRhc2sgKSB9XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBjYW5TZW5kID0gIUNoYW5uZWwuX2RlbGl2ZXJ5SG9vayggbWVzc2FnZUhvb2tJbmZvICk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKCBjYW5TZW5kIClcbiAgICAgICAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIucXVldWVUYXNrKCB0YXNrICk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi9jaGFubmVsJztcblxuZXhwb3J0IGVudW0gRGlyZWN0aW9uIHtcbiAgSU4gPSAxLFxuICBPVVQgPSAyLFxuICBJTk9VVCA9IDNcbn07XG5cbmV4cG9ydCB0eXBlIEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZSA9ICggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCByZWNlaXZpbmdFbmRQb2ludD86IEVuZFBvaW50LCByZWNlaXZpbmdDaGFubmVsPzogQ2hhbm5lbCApID0+IHZvaWQ7XG5cbi8qKlxuKiBBbiBFbmRQb2ludCBpcyBhIHNlbmRlci9yZWNlaXZlciBmb3IgbWVzc2FnZS1wYXNzaW5nLiBJdCBoYXMgYW4gaWRlbnRpZmllclxuKiBhbmQgYW4gb3B0aW9uYWwgZGlyZWN0aW9uLCB3aGljaCBtYXkgYmUgSU4sIE9VVCBvciBJTi9PVVQgKGRlZmF1bHQpLlxuKlxuKiBFbmRQb2ludHMgbWF5IGhhdmUgbXVsdGlwbGUgY2hhbm5lbHMgYXR0YWNoZWQsIGFuZCB3aWxsIGZvcndhcmQgbWVzc2FnZXNcbiogdG8gYWxsIG9mIHRoZW0uXG4qL1xuZXhwb3J0IGNsYXNzIEVuZFBvaW50XG57XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICAvKipcbiAgKiBBIGxpc3Qgb2YgYXR0YWNoZWQgQ2hhbm5lbHNcbiAgKi9cbiAgcHJvdGVjdGVkIF9jaGFubmVsczogQ2hhbm5lbFtdO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX21lc3NhZ2VMaXN0ZW5lcnM6IEhhbmRsZU1lc3NhZ2VEZWxlZ2F0ZVtdO1xuXG4gIHByaXZhdGUgX2RpcmVjdGlvbjogRGlyZWN0aW9uO1xuXG4gIGNvbnN0cnVjdG9yKCBpZDogc3RyaW5nLCBkaXJlY3Rpb246IERpcmVjdGlvbiA9IERpcmVjdGlvbi5JTk9VVCApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fZGlyZWN0aW9uID0gZGlyZWN0aW9uO1xuXG4gICAgdGhpcy5fY2hhbm5lbHMgPSBbXTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIENsZWFudXAgdGhlIEVuZFBvaW50LCBkZXRhY2hpbmcgYW55IGF0dGFjaGVkIENoYW5uZWxzIGFuZCByZW1vdmluZyBhbnlcbiAgKiBtZXNzYWdlLWxpc3RlbmVycy4gQ2FsbGluZyBzaHV0ZG93bigpIGlzIG1hbmRhdG9yeSB0byBhdm9pZCBtZW1vcnktbGVha3NcbiAgKiBkdWUgdG8gdGhlIGNpcmN1bGFyIHJlZmVyZW5jZXMgdGhhdCBleGlzdCBiZXR3ZWVuIENoYW5uZWxzIGFuZCBFbmRQb2ludHNcbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuZGV0YWNoQWxsKCk7XG5cbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzID0gW107XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBFbmRQb2ludCdzIGlkXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cblxuICAvKipcbiAgKiBBdHRhY2ggYSBDaGFubmVsIHRvIHRoaXMgRW5kUG9pbnQuIE9uY2UgYXR0YWNoZWQsIHRoZSBDaGFubmVsIHdpbGwgZm9yd2FyZFxuICAqIG1lc3NhZ2VzIHRvIHRoaXMgRW5kUG9pbnQsIGFuZCB3aWxsIGFjY2VwdCBtZXNzYWdlcyBvcmlnaW5hdGVkIGhlcmUuXG4gICogQW4gRW5kUG9pbnQgY2FuIGhhdmUgbXVsdGlwbGUgQ2hhbm5lbHMgYXR0YWNoZWQsIGluIHdoaWNoIGNhc2UgaXQgd2lsbFxuICAqIGJyb2FkY2FzdCB0byB0aGVtIGFsbCB3aGVuIHNlbmRpbmcsIGFuZCB3aWxsIHJlY2VpdmUgbWVzc2FnZXMgaW5cbiAgKiBhcnJpdmFsLW9yZGVyLlxuICAqL1xuICBwdWJsaWMgYXR0YWNoKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLnB1c2goIGNoYW5uZWwgKTtcblxuICAgIGNoYW5uZWwuYWRkRW5kUG9pbnQoIHRoaXMgKTtcbiAgfVxuXG4gIC8qKlxuICAqIERldGFjaCBhIHNwZWNpZmljIENoYW5uZWwgZnJvbSB0aGlzIEVuZFBvaW50LlxuICAqL1xuICBwdWJsaWMgZGV0YWNoKCBjaGFubmVsVG9EZXRhY2g6IENoYW5uZWwgKVxuICB7XG4gICAgbGV0IGlkeCA9IHRoaXMuX2NoYW5uZWxzLmluZGV4T2YoIGNoYW5uZWxUb0RldGFjaCApO1xuXG4gICAgaWYgKCBpZHggPj0gMCApXG4gICAge1xuICAgICAgY2hhbm5lbFRvRGV0YWNoLnJlbW92ZUVuZFBvaW50KCB0aGlzICk7XG5cbiAgICAgIHRoaXMuX2NoYW5uZWxzLnNwbGljZSggaWR4LCAxICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGFsbCBDaGFubmVscyBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2hBbGwoKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMuZm9yRWFjaCggY2hhbm5lbCA9PiB7XG4gICAgICBjaGFubmVsLnJlbW92ZUVuZFBvaW50KCB0aGlzICk7XG4gICAgfSApO1xuXG4gICAgdGhpcy5fY2hhbm5lbHMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAqIEFyZSBhbnkgY2hhbm5lbHMgYXR0YWNoZWQgdG8gdGhpcyBFbmRQb2ludD9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgRW5kcG9pbnQgaXMgYXR0YWNoZWQgdG8gYXQtbGVhc3Qtb25lIENoYW5uZWxcbiAgKi9cbiAgZ2V0IGF0dGFjaGVkKClcbiAge1xuICAgIHJldHVybiAoIHRoaXMuX2NoYW5uZWxzLmxlbmd0aCA+IDAgKTtcbiAgfVxuXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZGlyZWN0aW9uO1xuICB9XG5cbiAgLyoqXG4gICogSGFuZGxlIGFuIGluY29taW5nIE1lc3NhZ2UsIG1ldGhvZCBjYWxsZWQgYnkgQ2hhbm5lbC5cbiAgKi9cbiAgcHVibGljIGhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiwgZnJvbUVuZFBvaW50OiBFbmRQb2ludCwgZnJvbUNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5mb3JFYWNoKCBtZXNzYWdlTGlzdGVuZXIgPT4ge1xuICAgICAgbWVzc2FnZUxpc3RlbmVyKCBtZXNzYWdlLCB0aGlzLCBmcm9tQ2hhbm5lbCApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFNlbmQgYSBNZXNzYWdlLlxuICAqL1xuICBwdWJsaWMgc2VuZE1lc3NhZ2UoIG1lc3NhZ2U6IE1lc3NhZ2U8YW55PiApXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwuc2VuZE1lc3NhZ2UoIHRoaXMsIG1lc3NhZ2UgKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgKiBSZWdpc3RlciBhIGRlbGVnYXRlIHRvIHJlY2VpdmUgaW5jb21pbmcgTWVzc2FnZXNcbiAgKlxuICAqIEBwYXJhbSBtZXNzYWdlTGlzdGVuZXIgLSBkZWxlZ2F0ZSB0byBiZSBjYWxsZWQgd2l0aCByZWNlaXZlZCBNZXNzYWdlXG4gICovXG4gIHB1YmxpYyBvbk1lc3NhZ2UoIG1lc3NhZ2VMaXN0ZW5lcjogSGFuZGxlTWVzc2FnZURlbGVnYXRlIClcbiAge1xuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMucHVzaCggbWVzc2FnZUxpc3RlbmVyICk7XG4gIH1cbn1cblxuLyoqXG4qIEFuIGluZGV4ZWQgY29sbGVjdGlvbiBvZiBFbmRQb2ludCBvYmplY3RzLCBub3JtYWxseSBpbmRleGVkIHZpYSBFbmRQb2ludCdzXG4qIHVuaXF1ZSBpZGVudGlmaWVyXG4qL1xuZXhwb3J0IHR5cGUgRW5kUG9pbnRDb2xsZWN0aW9uID0geyBbaWQ6IHN0cmluZ106IEVuZFBvaW50OyB9O1xuIiwiaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5pbXBvcnQgeyBLaW5kLCBLaW5kSW5mbyB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5cbmV4cG9ydCBlbnVtIFByb3RvY29sVHlwZUJpdHNcbntcbiAgUEFDS0VUID0gMCwgICAgICAgICAvKiogRGF0YWdyYW0tb3JpZW50ZWQgKGFsd2F5cyBjb25uZWN0ZWQuLi4pICovXG4gIFNUUkVBTSA9IDEsICAgICAgICAgLyoqIENvbm5lY3Rpb24tb3JpZW50ZWQgKi9cblxuICBPTkVXQVkgPSAwLCAgICAgICAgIC8qKiBVbmlkaXJlY3Rpb25hbCBPVVQgKHNvdXJjZSkgLT4gSU4gKHNpbmspICovXG4gIENMSUVOVFNFUlZFUiA9IDQsICAgLyoqIENvbW1hbmQgT1VULT5JTiwgUmVzcG9uc2UgSU4tPk9VVCAqL1xuICBQRUVSMlBFRVIgPSA2LCAgICAgIC8qKiBCaWRpcmVjdGlvbmFsOiBJTk9VVCA8LT4gSU5PVVQgKi9cblxuICBVTlRZUEVEID0gMCwgICAgICAgIC8qKiBVbnR5cGVkIGRhdGEgKi9cbiAgVFlQRUQgPSA4LCAgICAgICAgICAvKiogVHlwZWQgZGF0YSAqKi9cbn1cblxuZXhwb3J0IHR5cGUgUHJvdG9jb2xUeXBlID0gbnVtYmVyO1xuXG5leHBvcnQgY2xhc3MgUHJvdG9jb2w8VD5cbntcbiAgc3RhdGljIHByb3RvY29sVHlwZTogUHJvdG9jb2xUeXBlID0gMDtcbn1cblxuLyoqXG4qIEEgQ2xpZW50LVNlcnZlciBQcm90b2NvbCwgdG8gYmUgdXNlZCBiZXR3ZWVuXG4qL1xuY2xhc3MgQ2xpZW50U2VydmVyUHJvdG9jb2w8VD4gZXh0ZW5kcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSBQcm90b2NvbFR5cGVCaXRzLkNMSUVOVFNFUlZFUiB8IFByb3RvY29sVHlwZUJpdHMuVFlQRUQ7XG59XG5cbmNsYXNzIEFQRFUgaW1wbGVtZW50cyBLaW5kIHtcbiAga2luZEluZm86IEtpbmRJbmZvO1xuICBwcm9wZXJ0aWVzO1xufVxuXG5jbGFzcyBBUERVTWVzc2FnZSBleHRlbmRzIE1lc3NhZ2U8QVBEVT5cbntcbn1cblxuY2xhc3MgQVBEVVByb3RvY29sIGV4dGVuZHMgQ2xpZW50U2VydmVyUHJvdG9jb2w8QVBEVU1lc3NhZ2U+XG57XG5cbn1cbiIsImltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5cbi8qKlxuKiBAY2xhc3MgUG9ydEluZm9cbipcbiogTWV0YWRhdGEgYWJvdXQgYSBjb21wb25lbnQncyBQb3J0XG4qL1xuZXhwb3J0IGNsYXNzIFBvcnRJbmZvXG57XG4gIC8qKlxuICAqIEJyaWVmIGRlc2NyaXB0aW9uIGZvciB0aGUgcG9ydCwgdG8gYXBwZWFyIGluICdoaW50J1xuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIERpcmVjdGlvbjogSU4sIE9VVCwgb3IgSU5PVVRcbiAgKiAgIGZvciBjbGllbnQtc2VydmVyLCBPVVQ9Q2xpZW50LCBJTj1TZXJ2ZXJcbiAgKi9cbiAgZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgLyoqXG4gICogUHJvdG9jb2wgaW1wbGVtZW50ZWQgYnkgdGhlIHBvcnRcbiAgKi9cbiAgcHJvdG9jb2w6IFByb3RvY29sPGFueT47XG5cbiAgLyoqXG4gICogUkZVIC0gaW5kZXhhYmxlIHBvcnRzXG4gICovXG4gIGNvdW50OiBudW1iZXIgPSAwO1xuXG4gIC8qKlxuICAqIHRydWUgaXMgcG9ydCBtdXN0IGJlIGNvbm5lY3RlZCBmb3IgY29tcG9uZW50IHRvIGV4ZWN1dGVcbiAgKi9cbiAgcmVxdWlyZWQ6IGJvb2xlYW4gPSBmYWxzZTtcbn1cbiIsImltcG9ydCB7IEtpbmQsIEtpbmRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24sIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuXG5pbXBvcnQgeyBQb3J0SW5mbyB9IGZyb20gJy4vcG9ydC1pbmZvJztcblxuLyoqXG4qIEBjbGFzcyBDb21wb25lbnRJbmZvXG4qXG4qIE1ldGFkYXRhIGFib3V0IGEgQ29tcG9uZW50XG4qL1xuZXhwb3J0IGNsYXNzIENvbXBvbmVudEluZm9cbntcbiAgLyoqXG4gICogQ29tcG9uZW50IE5hbWVcbiAgKi9cbiAgbmFtZTogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEJyaWVmIGRlc2NyaXB0aW9uIGZvciB0aGUgY29tcG9uZW50LCB0byBhcHBlYXIgaW4gJ2hpbnQnXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogTGluayB0byBkZXRhaWxlZCBpbmZvcm1hdGlvbiBmb3IgdGhlIGNvbXBvbmVudFxuICAqL1xuICBkZXRhaWxMaW5rOiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBDYXRlZ29yeSBuYW1lIGZvciB0aGUgY29tcG9uZW50LCBncm91cHMgc2FtZSBjYXRlZ29yaWVzIHRvZ2V0aGVyXG4gICovXG4gIGNhdGVnb3J5OiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBBdXRob3IncyBuYW1lXG4gICovXG4gIGF1dGhvcjogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQXJyYXkgb2YgUG9ydCBkZXNjcmlwdG9ycy4gV2hlbiBhY3RpdmUsIHRoZSBjb21wb25lbnQgd2lsbCBjb21tdW5pY2F0ZVxuICAqIHRocm91Z2ggY29ycmVzcG9uZGluZyBFbmRQb2ludHNcbiAgKi9cbiAgcG9ydHM6IHsgW2lkOiBzdHJpbmddOiBQb3J0SW5mbyB9ID0ge307XG4gIHN0b3JlczogeyBbaWQ6IHN0cmluZ106IFBvcnRJbmZvIH0gPSB7fTtcblxuICAvKipcbiAgKlxuICAqL1xuICBjb25maWdLaW5kOiBLaW5kQ29uc3RydWN0b3I7XG4gIGRlZmF1bHRDb25maWc6IEtpbmQ7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cbn1cbiIsIlxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgY29tcG9uZW50J3MgU3RvcmVcbiogVE9ETzogXG4qL1xuZXhwb3J0IGNsYXNzIFN0b3JlSW5mb1xue1xufVxuIiwiaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5pbXBvcnQgeyBTdG9yZUluZm8gfSBmcm9tICcuL3N0b3JlLWluZm8nO1xuaW1wb3J0IHsgQ29tcG9uZW50SW5mbyB9IGZyb20gJy4vY29tcG9uZW50LWluZm8nO1xuaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuaW1wb3J0IHsgS2luZCwgS2luZENvbnN0cnVjdG9yIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdDb21wb25lbnQnIG1ldGFkYXRhIChzdGF0aWMgY29tcG9uZW50SW5mbylcbiovXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50QnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApIHtcblxuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmNvbXBvbmVudEluZm8gPSB7XG4gICAgICBuYW1lOiBuYW1lIHx8IGN0b3IubmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIGRldGFpbExpbms6ICcnLFxuICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5LFxuICAgICAgYXV0aG9yOiAnJyxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIHN0b3Jlczoge30sXG4gICAgICBjb25maWdLaW5kOiBLaW5kLFxuICAgICAgZGVmYXVsdENvbmZpZzoge31cbiAgICB9O1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApOiBDb21wb25lbnRCdWlsZGVyXG4gIHtcbiAgICBsZXQgYnVpbGRlciA9IG5ldyBDb21wb25lbnRCdWlsZGVyKCBjdG9yLCBuYW1lLCBkZXNjcmlwdGlvbiwgY2F0ZWdvcnkgKTtcblxuICAgIHJldHVybiBidWlsZGVyO1xuICB9XG5cbiAgcHVibGljIGNvbmZpZyggY29uZmlnS2luZDogS2luZENvbnN0cnVjdG9yLCBkZWZhdWx0Q29uZmlnPzogS2luZCApOiB0aGlzIHtcblxuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLmNvbmZpZ0tpbmQgPSBjb25maWdLaW5kO1xuICAgIHRoaXMuY3Rvci5jb21wb25lbnRJbmZvLmRlZmF1bHRDb25maWcgPSBkZWZhdWx0Q29uZmlnO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBwdWJsaWMgcG9ydCggaWQ6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZGlyZWN0aW9uOiBEaXJlY3Rpb24sIG9wdHM/OiB7IHByb3RvY29sPzogUHJvdG9jb2w8YW55PjsgY291bnQ/OiBudW1iZXI7IHJlcXVpcmVkPzogYm9vbGVhbiB9ICk6IHRoaXNcbiAge1xuICAgIG9wdHMgPSBvcHRzIHx8IHt9O1xuXG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8ucG9ydHNbIGlkIF0gPSB7XG4gICAgICBkaXJlY3Rpb246IGRpcmVjdGlvbixcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIHByb3RvY29sOiBvcHRzLnByb3RvY29sLFxuICAgICAgY291bnQ6IG9wdHMuY291bnQsXG4gICAgICByZXF1aXJlZDogb3B0cy5yZXF1aXJlZFxuICAgIH07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG4vKipcbiogQ29tcG9uZW50cyBhcmUgcnVudGltZSBvYmplY3RzIHRoYXQgZXhlY3V0ZSB3aXRoaW4gYSBHcmFwaC5cbipcbiogQSBncmFwaCBOb2RlIGlzIGEgcGxhY2Vob2xkZXIgZm9yIHRoZSBhY3R1YWwgQ29tcG9uZW50IHRoYXRcbiogd2lsbCBleGVjdXRlLlxuKlxuKiBUaGlzIGludGVyZmFjZSBkZWZpbmVzIHRoZSBzdGFuZGFyZCBtZXRob2RzIGFuZCBwcm9wZXJ0aWVzIHRoYXQgYSBDb21wb25lbnRcbiogY2FuIG9wdGlvbmFsbHkgaW1wbGVtZW50LlxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ29tcG9uZW50XG57XG4gIC8vIEluaXRpYWxpemF0aW9uIGFuZCBzaHV0ZG93blxuICBpbml0aWFsaXplPyggY29uZmlnPzogS2luZCApOiBFbmRQb2ludFtdO1xuICB0ZWFyZG93bj8oKTtcblxuICAvLyBSdW5uaW5nXG4gIHN0YXJ0PygpO1xuICBzdG9wPygpO1xuXG4gIC8vIFBhdXNpbmcgYW5kIGNvbnRpbnVpbmcgZXhlY3V0aW9uICh3aXRob3V0IHJlc2V0dGluZyAuLilcbiAgcGF1c2U/KCk7XG4gIHJlc3VtZT8oKTtcblxuICBiaW5kVmlldz8oIHZpZXc6IGFueSApO1xuICB1bmJpbmRWaWV3PygpO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENvbXBvbmVudENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIC4uLmFyZ3MgKTogQ29tcG9uZW50O1xuXG4gIGNvbXBvbmVudEluZm8/OiBDb21wb25lbnRJbmZvO1xufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi4va2luZC9ieXRlLWFycmF5JztcblxuZXhwb3J0IGVudW0gQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiB7XG4gIEVOQ1JZUFQsXG4gIERFQ1JZUFQsXG4gIERJR0VTVCxcbiAgU0lHTixcbiAgVkVSSUZZLFxuICBERVJJVkVfQklUUyxcblxuICBERVJJVkVfS0VZLFxuICBJTVBPUlRfS0VZLFxuICBFWFBPUlRfS0VZLFxuICBHRU5FUkFURV9LRVksXG4gIFdSQVBfS0VZLFxuICBVTldSQVBfS0VZLFxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyeXB0b2dyYXBoaWNTZXJ2aWNlIHtcbiAgZW5jcnlwdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcbiAgZGVjcnlwdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcblxuICBkaWdlc3Q/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcblxuICBzaWduPyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuICB2ZXJpZnk/KCBhbGdvcml0aG06IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIGRlcml2ZUJpdHM/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBsZW5ndGg6IG51bWJlciApOiBQcm9taXNlPEJ5dGVBcnJheT47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3RvciB7XG4gIG5ldygpOiBDcnlwdG9ncmFwaGljU2VydmljZTtcblxuICBzdXBwb3J0ZWRPcGVyYXRpb25zPzogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgZGVyaXZlS2V5PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgZGVyaXZlZEtleVR5cGU6IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuXG4gIHdyYXBLZXk/KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IEFsZ29yaXRobSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG4gIHVud3JhcEtleT8oIGZvcm1hdDogc3RyaW5nLCB3cmFwcGVkS2V5OiBCeXRlQXJyYXksIHVud3JhcHBpbmdLZXk6IENyeXB0b0tleSwgdW53cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0sIHVud3JhcHBlZEtleUFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PjtcblxuICBpbXBvcnRLZXk/KCBmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5LCBhbGdvcml0aG06IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuICBnZW5lcmF0ZUtleT8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+O1xuICBleHBvcnRLZXk/KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3Ige1xuICBuZXcoKTogQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2U7XG5cbiAgc3VwcG9ydGVkT3BlcmF0aW9ucz86IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXTtcbn1cblxuZXhwb3J0IGNsYXNzIENyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkge1xuICBwcml2YXRlIF9zZXJ2aWNlTWFwOiBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPjtcbiAgcHJpdmF0ZSBfa2V5U2VydmljZU1hcDogTWFwPHN0cmluZywgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3Rvcj47XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5fc2VydmljZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yPigpO1xuICAgIHRoaXMuX2tleVNlcnZpY2VNYXAgPSBuZXcgTWFwPHN0cmluZywgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3Rvcj4oKTtcbiAgfVxuXG4gIGdldFNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtICk6IHsgbmFtZTogc3RyaW5nLCBpbnN0YW5jZTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2UgfSB7XG4gICAgbGV0IGFsZ28gPSAoIGFsZ29yaXRobSBpbnN0YW5jZW9mIE9iamVjdCApID8gKDxBbGdvcml0aG0+YWxnb3JpdGhtKS5uYW1lIDogPHN0cmluZz5hbGdvcml0aG07XG4gICAgbGV0IHNlcnZpY2UgPSB0aGlzLl9zZXJ2aWNlTWFwLmdldCggYWxnbyApO1xuXG4gICAgcmV0dXJuIHsgbmFtZTogYWxnbywgaW5zdGFuY2U6IHNlcnZpY2UgPyBuZXcgc2VydmljZSgpIDogbnVsbCB9O1xuICB9XG5cbiAgZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0gKTogeyBuYW1lOiBzdHJpbmcsIGluc3RhbmNlOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB9IHtcbiAgICBsZXQgYWxnbyA9ICggYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0ICkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICBsZXQgc2VydmljZSA9IHRoaXMuX2tleVNlcnZpY2VNYXAuZ2V0KCBhbGdvICk7XG5cbiAgICByZXR1cm4geyBuYW1lOiBhbGdvLCBpbnN0YW5jZTogc2VydmljZSA/IG5ldyBzZXJ2aWNlKCkgOiBudWxsIH07XG4gIH1cblxuICBzZXRTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBjdG9yLnN1cHBvcnRlZE9wZXJhdGlvbnMgPSBvcGVycztcblxuICAgIHRoaXMuX3NlcnZpY2VNYXAuc2V0KCBhbGdvcml0aG0sIGN0b3IgKTtcbiAgfVxuICBzZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBjdG9yLnN1cHBvcnRlZE9wZXJhdGlvbnMgPSBvcGVycztcblxuICAgIHRoaXMuX2tleVNlcnZpY2VNYXAuc2V0KCBhbGdvcml0aG0sIGN0b3IgKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciBpbXBsZW1lbnRzIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB7XG4gIC8vIHNpbmdsZXRvbiByZWdpc3RyeVxuICBwcml2YXRlIHN0YXRpYyBfcmVnaXN0cnk6IENyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkgPSBuZXcgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSgpO1xuXG4gIHB1YmxpYyBzdGF0aWMgcmVnaXN0ZXJTZXJ2aWNlKCBuYW1lOiBzdHJpbmcsIGN0b3I6IENyeXB0b2dyYXBoaWNTZXJ2aWNlQ29uc3RydWN0b3IsIG9wZXJzOiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW10gKSB7XG4gICAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnkuc2V0U2VydmljZSggbmFtZSwgY3Rvciwgb3BlcnMgKTtcbiAgfVxuICBwdWJsaWMgc3RhdGljIHJlZ2lzdGVyS2V5U2VydmljZSggbmFtZTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuX3JlZ2lzdHJ5LnNldEtleVNlcnZpY2UoIG5hbWUsIGN0b3IsIG9wZXJzICk7XG4gIH1cblxuICBnZXQgcmVnaXN0cnkoKTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSB7XG4gICAgcmV0dXJuIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuX3JlZ2lzdHJ5O1xuICB9XG5cbiAgZW5jcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5lbmNyeXB0IClcbiAgICAgID8gaW5zdGFuY2UuZW5jcnlwdCggbmFtZSwga2V5LCBkYXRhIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgZGVjcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZWNyeXB0IClcbiAgICAgID8gaW5zdGFuY2UuZGVjcnlwdCggbmFtZSwga2V5LCBkYXRhIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgZGlnZXN0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZGlnZXN0IClcbiAgICAgID8gaW5zdGFuY2UuZGlnZXN0KCBuYW1lLCBkYXRhIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgc2lnbiggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLnNpZ24gKVxuICAgICAgPyBpbnN0YW5jZS5zaWduKCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB2ZXJpZnkoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBzaWduYXR1cmU6IEJ5dGVBcnJheSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLnZlcmlmeSApXG4gICAgICA/IGluc3RhbmNlLnZlcmlmeSggbmFtZSwga2V5LCBzaWduYXR1cmUsIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBleHBvcnRLZXkoIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGtleS5hbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmV4cG9ydEtleSApXG4gICAgICA/IGluc3RhbmNlLmV4cG9ydEtleSggZm9ybWF0LCBrZXkgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBnZW5lcmF0ZUtleSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZ2VuZXJhdGVLZXkgKVxuICAgICAgPyBpbnN0YW5jZS5nZW5lcmF0ZUtleSggbmFtZSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApXG4gICAgICA6IFByb21pc2UucmVqZWN0PENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+KCBcIlwiICk7XG4gIH1cblxuICBpbXBvcnRLZXkoIGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXkgLCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmltcG9ydEtleSApXG4gICAgICA/IGluc3RhbmNlLmltcG9ydEtleSggZm9ybWF0LCBrZXlEYXRhLCBuYW1lLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG5cbiAgZGVyaXZlS2V5KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZGVyaXZlS2V5IClcbiAgICAgID8gaW5zdGFuY2UuZGVyaXZlS2V5KCBuYW1lLCBiYXNlS2V5LCBkZXJpdmVkS2V5VHlwZSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApXG4gICAgICA6IFByb21pc2UucmVqZWN0PENyeXB0b0tleT4oIFwiXCIgKTtcbiAgfVxuXG4gIGRlcml2ZUJpdHMoIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGxlbmd0aDogbnVtYmVyICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZXJpdmVCaXRzIClcbiAgICAgID8gaW5zdGFuY2UuZGVyaXZlQml0cyggbmFtZSwgYmFzZUtleSwgbGVuZ3RoIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgd3JhcEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5LCB3cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB3cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0gKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRLZXlTZXJ2aWNlKCBrZXkuYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS53cmFwS2V5IClcbiAgICAgID8gaW5zdGFuY2Uud3JhcEtleSggZm9ybWF0LCBrZXksIHdyYXBwaW5nS2V5LCB3cmFwQWxnb3JpdGhtIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Qnl0ZUFycmF5PiggXCJcIiApO1xuICB9XG5cbiAgdW53cmFwS2V5KCBmb3JtYXQ6IHN0cmluZywgd3JhcHBlZEtleTogQnl0ZUFycmF5LCB1bndyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHVud3JhcEFsZ29yaXRobTogQWxnb3JpdGhtLCB1bndyYXBwZWRLZXlBbGdvcml0aG06IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIHVud3JhcEFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UudW53cmFwS2V5IClcbiAgICAgID8gaW5zdGFuY2UudW53cmFwS2V5KCBmb3JtYXQsIHdyYXBwZWRLZXksIHVud3JhcHBpbmdLZXksIG5hbWUsIHVud3JhcHBlZEtleUFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApXG4gICAgICA6IFByb21pc2UucmVqZWN0PENyeXB0b0tleT4oIFwiXCIgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi4va2luZC9ieXRlLWFycmF5JztcbmltcG9ydCB7IENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24sIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB9IGZyb20gJy4vY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlLXJlZ2lzdHJ5JztcblxuZGVjbGFyZSB2YXIgbXNyY3J5cHRvLCBjcnlwdG8sIHdpbmRvdztcblxuZXhwb3J0IGNsYXNzIFdlYkNyeXB0b1NlcnZpY2UgaW1wbGVtZW50cyBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBwcm90ZWN0ZWQgY3J5cHRvOiBTdWJ0bGVDcnlwdG87XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gIH1cblxuICBzdGF0aWMgX3N1YnRsZTogU3VidGxlQ3J5cHRvO1xuICBzdGF0aWMgZ2V0IHN1YnRsZSgpOiBTdWJ0bGVDcnlwdG8ge1xuICAgIGxldCBzdWJ0bGUgPSBXZWJDcnlwdG9TZXJ2aWNlLl9zdWJ0bGVcbi8vICAgICAgfHwgKCBjcnlwdG8gJiYgY3J5cHRvLnN1YnRsZSApXG4gICAgICB8fCAoIHdpbmRvdyAmJiB3aW5kb3cuY3J5cHRvICYmIHdpbmRvdy5jcnlwdG8uc3VidGxlIClcbi8vICAgICAgfHwgbXNyY3J5cHRvXG4gICAgICA7XG5cbiAgICBpZiAoICFXZWJDcnlwdG9TZXJ2aWNlLl9zdWJ0bGUgKVxuICAgICAgIFdlYkNyeXB0b1NlcnZpY2UuX3N1YnRsZSA9IHN1YnRsZTtcblxuICAgIHJldHVybiBzdWJ0bGU7XG4gIH1cblxuICBlbmNyeXB0KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmVuY3J5cHQoYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZGVjcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZGVjcnlwdChhbGdvcml0aG0sIGtleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IGFueSB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZGlnZXN0KGFsZ29yaXRobSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZXhwb3J0S2V5KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5leHBvcnRLZXkoZm9ybWF0LCBrZXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBnZW5lcmF0ZUtleSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG5cbiAgIH0pO1xuICB9XG5cbiAgaW1wb3J0S2V5KGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENyeXB0b0tleT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuaW1wb3J0S2V5KGZvcm1hdCwga2V5RGF0YS5iYWNraW5nQXJyYXksIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcylcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKHJlcyk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgIH0pO1xuICB9XG5cbiAgc2lnbihhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuc2lnbihhbGdvcml0aG0sIGtleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICB2ZXJpZnkoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBzaWduYXR1cmU6IEJ5dGVBcnJheSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS52ZXJpZnkoYWxnb3JpdGhtLCBrZXksIHNpZ25hdHVyZS5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG59XG5cbi8qY2xhc3MgU0hBMUNyeXB0b1NlcnZpY2UgaW1wbGVtZW50cyBDcnlwdG9ncmFwaGljU2VydmljZSB7XG4gIGRpZ2VzdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIFRPRE86IEltcGxlbWVudCBTSEEtMVxuICAgICAgbXNyY3J5cHRvLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxufVxuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS0xJywgU0hBMUNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ESUdFU1QgXSApO1xuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS0yNTYnLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnU0hBLTUxMicsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ESUdFU1QgXSApO1xuKi9cblxuaWYgKCBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSApIHtcbiAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdBRVMtQ0JDJywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkVOQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uREVDUllQVCBdICk7XG4gIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnQUVTLUdDTScsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQgXSApO1xuICAvL0NyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnUlNBU1NBLVhZWicsIFdlYkNyeXB0b1NlcnZpY2UgKTtcblxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi4va2luZC9ieXRlLWFycmF5JztcbmltcG9ydCB7IENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24sIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB9IGZyb20gJy4vY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlLXJlZ2lzdHJ5JztcblxuY2xhc3MgREVTU2VjcmV0S2V5IGltcGxlbWVudHMgQ3J5cHRvS2V5IHtcbiAgcHJpdmF0ZSBfa2V5TWF0ZXJpYWw6IEJ5dGVBcnJheTtcbiAgcHJpdmF0ZSBfZXh0cmFjdGFibGU6IGJvb2xlYW47XG4gIHByaXZhdGUgX2FsZ29yaXRobTogS2V5QWxnb3JpdGhtO1xuICBwcml2YXRlIF90eXBlOiBzdHJpbmc7XG4gIHByaXZhdGUgX3VzYWdlczogc3RyaW5nW107XG5cbiAgY29uc3RydWN0b3IoIGtleU1hdGVyaWFsOiBCeXRlQXJyYXksIGFsZ29yaXRobTogS2V5QWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwgdXNhZ2VzOiBzdHJpbmdbXSApIHtcblxuICAgIHRoaXMuX2tleU1hdGVyaWFsID0ga2V5TWF0ZXJpYWw7XG5cbiAgICB0aGlzLl9hbGdvcml0aG0gPSBhbGdvcml0aG07XG5cbiAgICB0aGlzLl9leHRyYWN0YWJsZSA9IGV4dHJhY3RhYmxlO1xuXG4gICAgdGhpcy5fdHlwZSA9ICdzZWNyZXQnO1xuXG4gICAgdGhpcy5fdXNhZ2VzID0gdXNhZ2VzO1xuICAgIE9iamVjdC5mcmVlemUoIHRoaXMuX3VzYWdlcyApO1xuICB9XG5cbiAgZ2V0IGFsZ29yaXRobSgpIHsgcmV0dXJuIHRoaXMuX2FsZ29yaXRobTsgfVxuICBnZXQgZXh0cmFjdGFibGUoKTogYm9vbGVhbiB7IHJldHVybiB0aGlzLl9leHRyYWN0YWJsZTsgfVxuICBnZXQgdHlwZSgpIHsgcmV0dXJuIHRoaXMuX3R5cGU7IH1cbiAgZ2V0IHVzYWdlcygpOiBzdHJpbmdbXSB7IHJldHVybiBBcnJheS5mcm9tKCB0aGlzLl91c2FnZXMgKTsgfVxuXG4gIGdldCBrZXlNYXRlcmlhbCgpIHsgcmV0dXJuIHRoaXMuX2tleU1hdGVyaWFsIH07XG59XG5cbmV4cG9ydCBjbGFzcyBERVNDcnlwdG9ncmFwaGljU2VydmljZSBpbXBsZW1lbnRzIENyeXB0b2dyYXBoaWNTZXJ2aWNlLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZSB7XG4gIGNvbnN0cnVjdG9yKCkge1xuICB9XG5cbiAgLy8gcGFkZGluZzpcbiAgLy8gMCA9IHplcm8tcGFkXG4gIC8vIDEgPSBQS0NTN1xuICAvLyAyID0gc3BhY2VzXG4gIC8vIDQgPSBuby1wYWRcblxuICBlbmNyeXB0KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBhbGcgPSAoYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0KSA/ICg8QWxnb3JpdGhtPmFsZ29yaXRobSkubmFtZSA6IDxzdHJpbmc+YWxnb3JpdGhtO1xuICAgICAgbGV0IGRlc0tleSA9IGtleSBhcyBERVNTZWNyZXRLZXk7XG4gICAgICBsZXQgbW9kZSA9IDAsIHBhZGRpbmcgPSA0O1xuICAgICAgbGV0IGl2O1xuXG4gICAgICBpZiAoIGFsZyAhPSBkZXNLZXkuYWxnb3JpdGhtLm5hbWUgKVxuICAgICAgICByZWplY3QoIG5ldyBFcnJvciggJ0tleSAoJyArIGRlc0tleS5hbGdvcml0aG0ubmFtZSArICcpIGNhbm5vdCBiZSB1c2VkIGZvciBERVMgZGVjcnlwdCcpICk7XG5cbiAgICAgIGlmICggZGVzS2V5LmFsZ29yaXRobS5uYW1lID09ICdERVMtQ0JDJyApIHtcbiAgICAgICAgbGV0IGl2eCA9ICg8QWxnb3JpdGhtPmFsZ29yaXRobSlbJ2l2J10gfHwgWyAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwLCAweDAwIF07XG5cbiAgICAgICAgaXYgPSBuZXcgQnl0ZUFycmF5KCBpdnggKS5iYWNraW5nQXJyYXk7XG5cbiAgICAgICAgbW9kZSA9IDE7XG4gICAgICB9XG5cbiAgICAgIGlmICggKCBkYXRhLmxlbmd0aCA+PSA4ICkgfHwgKCBwYWRkaW5nICE9IDQgKSApXG4gICAgICAgIHJlc29sdmUoIG5ldyBCeXRlQXJyYXkoIHRoaXMuZGVzKCBkZXNLZXkua2V5TWF0ZXJpYWwuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSwgMSwgbW9kZSwgaXYsIHBhZGRpbmcgKSApICk7XG4gICAgICBlbHNlXG4gICAgICAgIHJlc29sdmUoIG5ldyBCeXRlQXJyYXkoKSApO1xuICAgIH0pO1xuICB9XG5cbiAgZGVjcnlwdChhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgYWxnID0gKGFsZ29yaXRobSBpbnN0YW5jZW9mIE9iamVjdCkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuICAgICAgbGV0IG1vZGUgPSAwLCBwYWRkaW5nID0gNDtcbiAgICAgIGxldCBpdjtcblxuICAgICAgaWYgKCBhbGcgIT0gZGVzS2V5LmFsZ29yaXRobS5uYW1lIClcbiAgICAgICAgcmVqZWN0KCBuZXcgRXJyb3IoICdLZXkgKCcgKyBkZXNLZXkuYWxnb3JpdGhtLm5hbWUgKyAnKSBjYW5ub3QgYmUgdXNlZCBmb3IgREVTIGRlY3J5cHQnKSApO1xuXG4gICAgICBpZiAoIGRlc0tleS5hbGdvcml0aG0ubmFtZSA9PSAnREVTLUNCQycgKSB7XG4gICAgICAgIGxldCBpdnggPSAoPEFsZ29yaXRobT5hbGdvcml0aG0pWydpdiddIHx8IFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdO1xuXG4gICAgICAgIGl2ID0gbmV3IEJ5dGVBcnJheSggaXZ4ICkuYmFja2luZ0FycmF5O1xuXG4gICAgICAgIG1vZGUgPSAxO1xuICAgICAgfVxuXG4gICAgICBpZiAoIGRhdGEubGVuZ3RoID49IDggKVxuICAgICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDAsIG1vZGUsIGl2LCBwYWRkaW5nICkgKSApO1xuICAgICAgZWxzZVxuICAgICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCkgKTtcbiAgICAgIC8vY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBpbXBvcnRLZXkoZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSwgYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICBpZiAoICEoIGFsZ29yaXRobSBpbnN0YW5jZW9mIE9iamVjdCApIClcbiAgICAgIGFsZ29yaXRobSA9IDxBbGdvcml0aG0+eyBuYW1lOiA8c3RyaW5nPmFsZ29yaXRobSB9O1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENyeXB0b0tleT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGRlc0tleSA9IG5ldyBERVNTZWNyZXRLZXkoIGtleURhdGEsIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcyApO1xuXG4gICAgICByZXNvbHZlKCBkZXNLZXkgKTtcbiAgIH0pO1xuICB9XG5cbiAgc2lnbiggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuXG4gICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDAsIDAgKSApICk7XG4gICAgICAvL2NhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgc3RhdGljIGRlc1BDO1xuICBzdGF0aWMgZGVzU1A7XG5cbiAgcHJpdmF0ZSBkZXMoIGtleTogVWludDhBcnJheSwgbWVzc2FnZTogVWludDhBcnJheSwgZW5jcnlwdDogbnVtYmVyLCBtb2RlOiBudW1iZXIsIGl2PzogVWludDhBcnJheSwgcGFkZGluZz86IG51bWJlciApOiBVaW50OEFycmF5XG4gIHtcbiAgICAvL2Rlc19jcmVhdGVLZXlzXG4gICAgLy90aGlzIHRha2VzIGFzIGlucHV0IGEgNjQgYml0IGtleSAoZXZlbiB0aG91Z2ggb25seSA1NiBiaXRzIGFyZSB1c2VkKVxuICAgIC8vYXMgYW4gYXJyYXkgb2YgMiBpbnRlZ2VycywgYW5kIHJldHVybnMgMTYgNDggYml0IGtleXNcbiAgICBmdW5jdGlvbiBkZXNfY3JlYXRlS2V5cyAoa2V5KVxuICAgIHtcbiAgICAgIGxldCBkZXNQQyA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1BDO1xuXG4gICAgICBpZiAoICFkZXNQQyApXG4gICAgICB7XG4gICAgICAgIC8vZGVjbGFyaW5nIHRoaXMgbG9jYWxseSBzcGVlZHMgdGhpbmdzIHVwIGEgYml0XG4gICAgICAgIGRlc1BDID0gREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzUEMgPSB7XG4gICAgICAgICAgcGMyYnl0ZXMwIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0LDB4MjAwMDAwMDAsMHgyMDAwMDAwNCwweDEwMDAwLDB4MTAwMDQsMHgyMDAxMDAwMCwweDIwMDEwMDA0LDB4MjAwLDB4MjA0LDB4MjAwMDAyMDAsMHgyMDAwMDIwNCwweDEwMjAwLDB4MTAyMDQsMHgyMDAxMDIwMCwweDIwMDEwMjA0IF0gKSxcbiAgICAgICAgICBwYzJieXRlczEgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEsMHgxMDAwMDAsMHgxMDAwMDEsMHg0MDAwMDAwLDB4NDAwMDAwMSwweDQxMDAwMDAsMHg0MTAwMDAxLDB4MTAwLDB4MTAxLDB4MTAwMTAwLDB4MTAwMTAxLDB4NDAwMDEwMCwweDQwMDAxMDEsMHg0MTAwMTAwLDB4NDEwMDEwMV0gKSxcbiAgICAgICAgICBwYzJieXRlczIgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDgsMHg4MDAsMHg4MDgsMHgxMDAwMDAwLDB4MTAwMDAwOCwweDEwMDA4MDAsMHgxMDAwODA4LDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOF0gKSxcbiAgICAgICAgICBwYzJieXRlczMgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDIwMDAwMCwweDgwMDAwMDAsMHg4MjAwMDAwLDB4MjAwMCwweDIwMjAwMCwweDgwMDIwMDAsMHg4MjAyMDAwLDB4MjAwMDAsMHgyMjAwMDAsMHg4MDIwMDAwLDB4ODIyMDAwMCwweDIyMDAwLDB4MjIyMDAwLDB4ODAyMjAwMCwweDgyMjIwMDBdICksXG4gICAgICAgICAgcGMyYnl0ZXM0IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMCwweDQwMDAwLDB4MTAsMHg0MDAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMCwweDEwMDAsMHg0MTAwMCwweDEwMTAsMHg0MTAxMF0gKSxcbiAgICAgICAgICBwYzJieXRlczUgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQwMCwweDIwLDB4NDIwLDAsMHg0MDAsMHgyMCwweDQyMCwweDIwMDAwMDAsMHgyMDAwNDAwLDB4MjAwMDAyMCwweDIwMDA0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNiA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MTAwMDAwMDAsMHg4MDAwMCwweDEwMDgwMDAwLDB4MiwweDEwMDAwMDAyLDB4ODAwMDIsMHgxMDA4MDAwMiwwLDB4MTAwMDAwMDAsMHg4MDAwMCwweDEwMDgwMDAwLDB4MiwweDEwMDAwMDAyLDB4ODAwMDIsMHgxMDA4MDAwMl0gKSxcbiAgICAgICAgICBwYzJieXRlczcgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwLDB4ODAwLDB4MTA4MDAsMHgyMDAwMDAwMCwweDIwMDEwMDAwLDB4MjAwMDA4MDAsMHgyMDAxMDgwMCwweDIwMDAwLDB4MzAwMDAsMHgyMDgwMCwweDMwODAwLDB4MjAwMjAwMDAsMHgyMDAzMDAwMCwweDIwMDIwODAwLDB4MjAwMzA4MDBdICksXG4gICAgICAgICAgcGMyYnl0ZXM4IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAwMCwwLDB4NDAwMDAsMHgyLDB4NDAwMDIsMHgyLDB4NDAwMDIsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDAsMHgyMDQwMDAwLDB4MjAwMDAwMiwweDIwNDAwMDIsMHgyMDAwMDAyLDB4MjA0MDAwMl0gKSxcbiAgICAgICAgICBwYzJieXRlczkgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAwLDB4OCwweDEwMDAwMDA4LDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwweDQwMCwweDEwMDAwNDAwLDB4NDA4LDB4MTAwMDA0MDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4XSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4MjAsMCwweDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MTAwMDAwLDB4MTAwMDIwLDB4MjAwMCwweDIwMjAsMHgyMDAwLDB4MjAyMCwweDEwMjAwMCwweDEwMjAyMCwweDEwMjAwMCwweDEwMjAyMF0gKSxcbiAgICAgICAgICBwYzJieXRlczExOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAsMHgyMDAsMHgxMDAwMjAwLDB4MjAwMDAwLDB4MTIwMDAwMCwweDIwMDIwMCwweDEyMDAyMDAsMHg0MDAwMDAwLDB4NTAwMDAwMCwweDQwMDAyMDAsMHg1MDAwMjAwLDB4NDIwMDAwMCwweDUyMDAwMDAsMHg0MjAwMjAwLDB4NTIwMDIwMF0gKSxcbiAgICAgICAgICBwYzJieXRlczEyOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAsMHg4MDAwMDAwLDB4ODAwMTAwMCwweDgwMDAwLDB4ODEwMDAsMHg4MDgwMDAwLDB4ODA4MTAwMCwweDEwLDB4MTAxMCwweDgwMDAwMTAsMHg4MDAxMDEwLDB4ODAwMTAsMHg4MTAxMCwweDgwODAwMTAsMHg4MDgxMDEwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzMTM6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NCwweDEwMCwweDEwNCwwLDB4NCwweDEwMCwweDEwNCwweDEsMHg1LDB4MTAxLDB4MTA1LDB4MSwweDUsMHgxMDEsMHgxMDVdIClcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgLy9ob3cgbWFueSBpdGVyYXRpb25zICgxIGZvciBkZXMsIDMgZm9yIHRyaXBsZSBkZXMpXG4gICAgICB2YXIgaXRlcmF0aW9ucyA9IGtleS5sZW5ndGggPiA4ID8gMyA6IDE7IC8vY2hhbmdlZCBieSBQYXVsIDE2LzYvMjAwNyB0byB1c2UgVHJpcGxlIERFUyBmb3IgOSsgYnl0ZSBrZXlzXG4gICAgICAvL3N0b3JlcyB0aGUgcmV0dXJuIGtleXNcbiAgICAgIHZhciBrZXlzID0gbmV3IFVpbnQzMkFycmF5KDMyICogaXRlcmF0aW9ucyk7XG4gICAgICAvL25vdyBkZWZpbmUgdGhlIGxlZnQgc2hpZnRzIHdoaWNoIG5lZWQgdG8gYmUgZG9uZVxuICAgICAgdmFyIHNoaWZ0cyA9IFsgMCwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCwgMSwgMSwgMSwgMSwgMSwgMSwgMCBdO1xuICAgICAgLy9vdGhlciB2YXJpYWJsZXNcbiAgICAgIHZhciBsZWZ0dGVtcCwgcmlnaHR0ZW1wLCBtPTAsIG49MCwgdGVtcDtcblxuICAgICAgZm9yICh2YXIgaj0wOyBqPGl0ZXJhdGlvbnM7IGorKylcbiAgICAgIHsgLy9laXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcbiAgICAgICAgbGVmdCA9ICAoa2V5W20rK10gPDwgMjQpIHwgKGtleVttKytdIDw8IDE2KSB8IChrZXlbbSsrXSA8PCA4KSB8IGtleVttKytdO1xuICAgICAgICByaWdodCA9IChrZXlbbSsrXSA8PCAyNCkgfCAoa2V5W20rK10gPDwgMTYpIHwgKGtleVttKytdIDw8IDgpIHwga2V5W20rK107XG5cbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAyKSBeIHJpZ2h0KSAmIDB4MzMzMzMzMzM7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMik7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAtMTYpIF4gbGVmdCkgJiAweDAwMDBmZmZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IC0xNik7XG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAgICAgLy90aGUgcmlnaHQgc2lkZSBuZWVkcyB0byBiZSBzaGlmdGVkIGFuZCB0byBnZXQgdGhlIGxhc3QgZm91ciBiaXRzIG9mIHRoZSBsZWZ0IHNpZGVcbiAgICAgICAgdGVtcCA9IChsZWZ0IDw8IDgpIHwgKChyaWdodCA+Pj4gMjApICYgMHgwMDAwMDBmMCk7XG4gICAgICAgIC8vbGVmdCBuZWVkcyB0byBiZSBwdXQgdXBzaWRlIGRvd25cbiAgICAgICAgbGVmdCA9IChyaWdodCA8PCAyNCkgfCAoKHJpZ2h0IDw8IDgpICYgMHhmZjAwMDApIHwgKChyaWdodCA+Pj4gOCkgJiAweGZmMDApIHwgKChyaWdodCA+Pj4gMjQpICYgMHhmMCk7XG4gICAgICAgIHJpZ2h0ID0gdGVtcDtcblxuICAgICAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZXNlIHNoaWZ0cyBvbiB0aGUgbGVmdCBhbmQgcmlnaHQga2V5c1xuICAgICAgICBmb3IgKHZhciBpPTA7IGkgPCBzaGlmdHMubGVuZ3RoOyBpKyspXG4gICAgICAgIHtcbiAgICAgICAgICAvL3NoaWZ0IHRoZSBrZXlzIGVpdGhlciBvbmUgb3IgdHdvIGJpdHMgdG8gdGhlIGxlZnRcbiAgICAgICAgICBpZiAoc2hpZnRzW2ldKVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGxlZnQgPSAobGVmdCA8PCAyKSB8IChsZWZ0ID4+PiAyNik7IHJpZ2h0ID0gKHJpZ2h0IDw8IDIpIHwgKHJpZ2h0ID4+PiAyNik7XG4gICAgICAgICAgfVxuICAgICAgICAgIGVsc2VcbiAgICAgICAgICB7XG4gICAgICAgICAgICBsZWZ0ID0gKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMjcpOyByaWdodCA9IChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMjcpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBsZWZ0ICY9IC0weGY7IHJpZ2h0ICY9IC0weGY7XG5cbiAgICAgICAgICAvL25vdyBhcHBseSBQQy0yLCBpbiBzdWNoIGEgd2F5IHRoYXQgRSBpcyBlYXNpZXIgd2hlbiBlbmNyeXB0aW5nIG9yIGRlY3J5cHRpbmdcbiAgICAgICAgICAvL3RoaXMgY29udmVyc2lvbiB3aWxsIGxvb2sgbGlrZSBQQy0yIGV4Y2VwdCBvbmx5IHRoZSBsYXN0IDYgYml0cyBvZiBlYWNoIGJ5dGUgYXJlIHVzZWRcbiAgICAgICAgICAvL3JhdGhlciB0aGFuIDQ4IGNvbnNlY3V0aXZlIGJpdHMgYW5kIHRoZSBvcmRlciBvZiBsaW5lcyB3aWxsIGJlIGFjY29yZGluZyB0b1xuICAgICAgICAgIC8vaG93IHRoZSBTIHNlbGVjdGlvbiBmdW5jdGlvbnMgd2lsbCBiZSBhcHBsaWVkOiBTMiwgUzQsIFM2LCBTOCwgUzEsIFMzLCBTNSwgUzdcbiAgICAgICAgICBsZWZ0dGVtcCA9IGRlc1BDLnBjMmJ5dGVzMFtsZWZ0ID4+PiAyOF0gfCBkZXNQQy5wYzJieXRlczFbKGxlZnQgPj4+IDI0KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzMlsobGVmdCA+Pj4gMjApICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzM1sobGVmdCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgIHwgZGVzUEMucGMyYnl0ZXM0WyhsZWZ0ID4+PiAxMikgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXM1WyhsZWZ0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzNlsobGVmdCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHJpZ2h0dGVtcCA9IGRlc1BDLnBjMmJ5dGVzN1tyaWdodCA+Pj4gMjhdIHwgZGVzUEMucGMyYnl0ZXM4WyhyaWdodCA+Pj4gMjQpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzOVsocmlnaHQgPj4+IDIwKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczEwWyhyaWdodCA+Pj4gMTYpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzMTFbKHJpZ2h0ID4+PiAxMikgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXMxMlsocmlnaHQgPj4+IDgpICYgMHhmXVxuICAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzMTNbKHJpZ2h0ID4+PiA0KSAmIDB4Zl07XG4gICAgICAgICAgdGVtcCA9ICgocmlnaHR0ZW1wID4+PiAxNikgXiBsZWZ0dGVtcCkgJiAweDAwMDBmZmZmO1xuICAgICAgICAgIGtleXNbbisrXSA9IGxlZnR0ZW1wIF4gdGVtcDsga2V5c1tuKytdID0gcmlnaHR0ZW1wIF4gKHRlbXAgPDwgMTYpO1xuICAgICAgICB9XG4gICAgICB9IC8vZm9yIGVhY2ggaXRlcmF0aW9uc1xuXG4gICAgICByZXR1cm4ga2V5cztcbiAgICB9IC8vZW5kIG9mIGRlc19jcmVhdGVLZXlzXG5cbiAgICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICAgIGxldCBkZXNTUCA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1NQO1xuXG4gICAgaWYgKCBkZXNTUCA9PSB1bmRlZmluZWQgKVxuICAgIHtcbiAgICAgIGRlc1NQID0gREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzU1AgPSB7XG4gICAgICAgIHNwZnVuY3Rpb24xOiBuZXcgVWludDMyQXJyYXkoIFsweDEwMTA0MDAsMCwweDEwMDAwLDB4MTAxMDQwNCwweDEwMTAwMDQsMHgxMDQwNCwweDQsMHgxMDAwMCwweDQwMCwweDEwMTA0MDAsMHgxMDEwNDA0LDB4NDAwLDB4MTAwMDQwNCwweDEwMTAwMDQsMHgxMDAwMDAwLDB4NCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDB4MTA0MDAsMHgxMDQwMCwweDEwMTAwMDAsMHgxMDEwMDAwLDB4MTAwMDQwNCwweDEwMDA0LDB4MTAwMDAwNCwweDEwMDAwMDQsMHgxMDAwNCwwLDB4NDA0LDB4MTA0MDQsMHgxMDAwMDAwLDB4MTAwMDAsMHgxMDEwNDA0LDB4NCwweDEwMTAwMDAsMHgxMDEwNDAwLDB4MTAwMDAwMCwweDEwMDAwMDAsMHg0MDAsMHgxMDEwMDA0LDB4MTAwMDAsMHgxMDQwMCwweDEwMDAwMDQsMHg0MDAsMHg0LDB4MTAwMDQwNCwweDEwNDA0LDB4MTAxMDQwNCwweDEwMDA0LDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwMDA0LDB4NDA0LDB4MTA0MDQsMHgxMDEwNDAwLDB4NDA0LDB4MTAwMDQwMCwweDEwMDA0MDAsMCwweDEwMDA0LDB4MTA0MDAsMCwweDEwMTAwMDRdICksXG4gICAgICAgIHNwZnVuY3Rpb24yOiBuZXcgVWludDMyQXJyYXkoIFstMHg3ZmVmN2ZlMCwtMHg3ZmZmODAwMCwweDgwMDAsMHgxMDgwMjAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwtMHg3ZmZmN2ZlMCwtMHg3ZmZmZmZlMCwtMHg3ZmVmN2ZlMCwtMHg3ZmVmODAwMCwtMHg4MDAwMDAwMCwtMHg3ZmZmODAwMCwweDEwMDAwMCwweDIwLC0weDdmZWZmZmUwLDB4MTA4MDAwLDB4MTAwMDIwLC0weDdmZmY3ZmUwLDAsLTB4ODAwMDAwMDAsMHg4MDAwLDB4MTA4MDIwLC0weDdmZjAwMDAwLDB4MTAwMDIwLC0weDdmZmZmZmUwLDAsMHgxMDgwMDAsMHg4MDIwLC0weDdmZWY4MDAwLC0weDdmZjAwMDAwLDB4ODAyMCwwLDB4MTA4MDIwLC0weDdmZWZmZmUwLDB4MTAwMDAwLC0weDdmZmY3ZmUwLC0weDdmZjAwMDAwLC0weDdmZWY4MDAwLDB4ODAwMCwtMHg3ZmYwMDAwMCwtMHg3ZmZmODAwMCwweDIwLC0weDdmZWY3ZmUwLDB4MTA4MDIwLDB4MjAsMHg4MDAwLC0weDgwMDAwMDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwweDEwMDAwMCwtMHg3ZmZmZmZlMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwtMHg3ZmZmZmZlMCwweDEwMDAyMCwweDEwODAwMCwwLC0weDdmZmY4MDAwLDB4ODAyMCwtMHg4MDAwMDAwMCwtMHg3ZmVmZmZlMCwtMHg3ZmVmN2ZlMCwweDEwODAwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjM6IG5ldyBVaW50MzJBcnJheSggWzB4MjA4LDB4ODAyMDIwMCwwLDB4ODAyMDAwOCwweDgwMDAyMDAsMCwweDIwMjA4LDB4ODAwMDIwMCwweDIwMDA4LDB4ODAwMDAwOCwweDgwMDAwMDgsMHgyMDAwMCwweDgwMjAyMDgsMHgyMDAwOCwweDgwMjAwMDAsMHgyMDgsMHg4MDAwMDAwLDB4OCwweDgwMjAyMDAsMHgyMDAsMHgyMDIwMCwweDgwMjAwMDAsMHg4MDIwMDA4LDB4MjAyMDgsMHg4MDAwMjA4LDB4MjAyMDAsMHgyMDAwMCwweDgwMDAyMDgsMHg4LDB4ODAyMDIwOCwweDIwMCwweDgwMDAwMDAsMHg4MDIwMjAwLDB4ODAwMDAwMCwweDIwMDA4LDB4MjA4LDB4MjAwMDAsMHg4MDIwMjAwLDB4ODAwMDIwMCwwLDB4MjAwLDB4MjAwMDgsMHg4MDIwMjA4LDB4ODAwMDIwMCwweDgwMDAwMDgsMHgyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjA4LDB4MjAwMDAsMHg4MDAwMDAwLDB4ODAyMDIwOCwweDgsMHgyMDIwOCwweDIwMjAwLDB4ODAwMDAwOCwweDgwMjAwMDAsMHg4MDAwMjA4LDB4MjA4LDB4ODAyMDAwMCwweDIwMjA4LDB4OCwweDgwMjAwMDgsMHgyMDIwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjQ6IG5ldyBVaW50MzJBcnJheSggWzB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MCwweDgwMDA4MSwweDgwMDAwMSwweDIwMDEsMCwweDgwMjAwMCwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMHg4MDAwODAsMHg4MDAwMDEsMHgxLDB4MjAwMCwweDgwMDAwMCwweDgwMjAwMSwweDgwLDB4ODAwMDAwLDB4MjAwMSwweDIwODAsMHg4MDAwODEsMHgxLDB4MjA4MCwweDgwMDA4MCwweDIwMDAsMHg4MDIwODAsMHg4MDIwODEsMHg4MSwweDgwMDA4MCwweDgwMDAwMSwweDgwMjAwMCwweDgwMjA4MSwweDgxLDAsMCwweDgwMjAwMCwweDIwODAsMHg4MDAwODAsMHg4MDAwODEsMHgxLDB4ODAyMDAxLDB4MjA4MSwweDIwODEsMHg4MCwweDgwMjA4MSwweDgxLDB4MSwweDIwMDAsMHg4MDAwMDEsMHgyMDAxLDB4ODAyMDgwLDB4ODAwMDgxLDB4MjAwMSwweDIwODAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDAsMHg4MDIwODBdICksXG4gICAgICAgIHNwZnVuY3Rpb241OiBuZXcgVWludDMyQXJyYXkoIFsweDEwMCwweDIwODAxMDAsMHgyMDgwMDAwLDB4NDIwMDAxMDAsMHg4MDAwMCwweDEwMCwweDQwMDAwMDAwLDB4MjA4MDAwMCwweDQwMDgwMTAwLDB4ODAwMDAsMHgyMDAwMTAwLDB4NDAwODAxMDAsMHg0MjAwMDEwMCwweDQyMDgwMDAwLDB4ODAxMDAsMHg0MDAwMDAwMCwweDIwMDAwMDAsMHg0MDA4MDAwMCwweDQwMDgwMDAwLDAsMHg0MDAwMDEwMCwweDQyMDgwMTAwLDB4NDIwODAxMDAsMHgyMDAwMTAwLDB4NDIwODAwMDAsMHg0MDAwMDEwMCwwLDB4NDIwMDAwMDAsMHgyMDgwMTAwLDB4MjAwMDAwMCwweDQyMDAwMDAwLDB4ODAxMDAsMHg4MDAwMCwweDQyMDAwMTAwLDB4MTAwLDB4MjAwMDAwMCwweDQwMDAwMDAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4NDAwODAxMDAsMHgyMDAwMTAwLDB4NDAwMDAwMDAsMHg0MjA4MDAwMCwweDIwODAxMDAsMHg0MDA4MDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MjA4MDAwMCwweDQyMDgwMTAwLDB4ODAxMDAsMHg0MjAwMDAwMCwweDQyMDgwMTAwLDB4MjA4MDAwMCwwLDB4NDAwODAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMTAwLDB4ODAwMDAsMCwweDQwMDgwMDAwLDB4MjA4MDEwMCwweDQwMDAwMTAwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNjogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDAwMDAxMCwweDIwNDAwMDAwLDB4NDAwMCwweDIwNDA0MDEwLDB4MjA0MDAwMDAsMHgxMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHg0MDQwMTAsMHg0MDAwMDAsMHgyMDAwMDAxMCwweDQwMDAxMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwweDQwMDAsMHg0MDQwMDAsMHgyMDAwNDAxMCwweDEwLDB4MjA0MDAwMTAsMHgyMDQwMDAxMCwwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMHg0MDEwLDB4NDA0MDAwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDIwMDA0MDAwLDB4MTAsMHgyMDQwMDAxMCwweDQwNDAwMCwweDIwNDA0MDEwLDB4NDAwMDAwLDB4NDAxMCwweDIwMDAwMDEwLDB4NDAwMDAwLDB4MjAwMDQwMDAsMHgyMDAwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDIwNDA0MDEwLDB4NDA0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHgyMDQwNDAwMCwwLDB4MjA0MDAwMTAsMHgxMCwweDQwMDAsMHgyMDQwMDAwMCwweDQwNDAxMCwweDQwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMCwwLDB4MjA0MDQwMDAsMHgyMDAwMDAwMCwweDQwMDAxMCwweDIwMDA0MDEwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNzogbmV3IFVpbnQzMkFycmF5KCBbMHgyMDAwMDAsMHg0MjAwMDAyLDB4NDAwMDgwMiwwLDB4ODAwLDB4NDAwMDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg0MjAwODAyLDB4MjAwMDAwLDAsMHg0MDAwMDAyLDB4MiwweDQwMDAwMDAsMHg0MjAwMDAyLDB4ODAyLDB4NDAwMDgwMCwweDIwMDgwMiwweDIwMDAwMiwweDQwMDA4MDAsMHg0MDAwMDAyLDB4NDIwMDAwMCwweDQyMDA4MDAsMHgyMDAwMDIsMHg0MjAwMDAwLDB4ODAwLDB4ODAyLDB4NDIwMDgwMiwweDIwMDgwMCwweDIsMHg0MDAwMDAwLDB4MjAwODAwLDB4NDAwMDAwMCwweDIwMDgwMCwweDIwMDAwMCwweDQwMDA4MDIsMHg0MDAwODAyLDB4NDIwMDAwMiwweDQyMDAwMDIsMHgyLDB4MjAwMDAyLDB4NDAwMDAwMCwweDQwMDA4MDAsMHgyMDAwMDAsMHg0MjAwODAwLDB4ODAyLDB4MjAwODAyLDB4NDIwMDgwMCwweDgwMiwweDQwMDAwMDIsMHg0MjAwODAyLDB4NDIwMDAwMCwweDIwMDgwMCwwLDB4MiwweDQyMDA4MDIsMCwweDIwMDgwMiwweDQyMDAwMDAsMHg4MDAsMHg0MDAwMDAyLDB4NDAwMDgwMCwweDgwMCwweDIwMDAwMl0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjg6IG5ldyBVaW50MzJBcnJheSggWzB4MTAwMDEwNDAsMHgxMDAwLDB4NDAwMDAsMHgxMDA0MTA0MCwweDEwMDAwMDAwLDB4MTAwMDEwNDAsMHg0MCwweDEwMDAwMDAwLDB4NDAwNDAsMHgxMDA0MDAwMCwweDEwMDQxMDQwLDB4NDEwMDAsMHgxMDA0MTAwMCwweDQxMDQwLDB4MTAwMCwweDQwLDB4MTAwNDAwMDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4MTA0MCwweDQxMDAwLDB4NDAwNDAsMHgxMDA0MDA0MCwweDEwMDQxMDAwLDB4MTA0MCwwLDAsMHgxMDA0MDA0MCwweDEwMDAwMDQwLDB4MTAwMDEwMDAsMHg0MTA0MCwweDQwMDAwLDB4NDEwNDAsMHg0MDAwMCwweDEwMDQxMDAwLDB4MTAwMCwweDQwLDB4MTAwNDAwNDAsMHgxMDAwLDB4NDEwNDAsMHgxMDAwMTAwMCwweDQwLDB4MTAwMDAwNDAsMHgxMDA0MDAwMCwweDEwMDQwMDQwLDB4MTAwMDAwMDAsMHg0MDAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQwMDQwLDB4MTAwMDAwNDAsMHgxMDA0MDAwMCwweDEwMDAxMDAwLDB4MTAwMDEwNDAsMCwweDEwMDQxMDQwLDB4NDEwMDAsMHg0MTAwMCwweDEwNDAsMHgxMDQwLDB4NDAwNDAsMHgxMDAwMDAwMCwweDEwMDQxMDAwXSApLFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvL2NyZWF0ZSB0aGUgMTYgb3IgNDggc3Via2V5cyB3ZSB3aWxsIG5lZWRcbiAgICB2YXIga2V5cyA9IGRlc19jcmVhdGVLZXlzKCBrZXkgKTtcblxuICAgIHZhciBtPTAsIGksIGosIHRlbXAsIGxlZnQsIHJpZ2h0LCBsb29waW5nO1xuICAgIHZhciBjYmNsZWZ0LCBjYmNsZWZ0MiwgY2JjcmlnaHQsIGNiY3JpZ2h0MlxuICAgIHZhciBsZW4gPSBtZXNzYWdlLmxlbmd0aDtcblxuICAgIC8vc2V0IHVwIHRoZSBsb29wcyBmb3Igc2luZ2xlIGFuZCB0cmlwbGUgZGVzXG4gICAgdmFyIGl0ZXJhdGlvbnMgPSBrZXlzLmxlbmd0aCA9PSAzMiA/IDMgOiA5OyAvL3NpbmdsZSBvciB0cmlwbGUgZGVzXG5cbiAgICBpZiAoaXRlcmF0aW9ucyA9PSAzKVxuICAgIHtcbiAgICAgIGxvb3BpbmcgPSBlbmNyeXB0ID8gWyAwLCAzMiwgMiBdIDogWyAzMCwgLTIsIC0yIF07XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICBsb29waW5nID0gZW5jcnlwdCA/IFsgMCwgMzIsIDIsIDYyLCAzMCwgLTIsIDY0LCA5NiwgMiBdIDogWyA5NCwgNjIsIC0yLCAzMiwgNjQsIDIsIDMwLCAtMiwgLTIgXTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIG1lc3NhZ2UgZGVwZW5kaW5nIG9uIHRoZSBwYWRkaW5nIHBhcmFtZXRlclxuICAgIGlmICggKCBwYWRkaW5nICE9IHVuZGVmaW5lZCApICYmICggcGFkZGluZyAhPSA0ICkgKVxuICAgIHtcbiAgICAgIHZhciB1bnBhZGRlZE1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgdmFyIHBhZCA9IDgtKGxlbiU4KTtcblxuICAgICAgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KCBsZW4gKyA4ICk7XG4gICAgICBtZXNzYWdlLnNldCggdW5wYWRkZWRNZXNzYWdlLCAwICk7XG5cbiAgICAgIHN3aXRjaCggcGFkZGluZyApXG4gICAgICB7XG4gICAgICAgIGNhc2UgMDogLy8gemVyby1wYWRcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdICksIGxlbiApO1xuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgIGNhc2UgMTogLy8gUEtDUzcgcGFkZGluZ1xuICAgICAgICB7XG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkXSApLCA4ICk7XG5cbiAgICAgICAgICBpZiAoIHBhZD09OCApXG4gICAgICAgICAgICBsZW4rPTg7XG5cbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuXG4gICAgICAgIGNhc2UgMjogIC8vIHBhZCB0aGUgbWVzc2FnZSB3aXRoIHNwYWNlc1xuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwLCAweDIwIF0gKSwgOCApO1xuICAgICAgICAgIGJyZWFrO1xuXG4gICAgICB9XG5cbiAgICAgIGxlbiArPSA4LShsZW4lOClcbiAgICB9XG5cbiAgICAvLyBzdG9yZSB0aGUgcmVzdWx0IGhlcmVcbiAgICB2YXIgcmVzdWx0ID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiApO1xuXG4gICAgaWYgKG1vZGUgPT0gMSlcbiAgICB7IC8vQ0JDIG1vZGVcbiAgICAgIGxldCBtbSA9IDA7XG5cbiAgICAgIGNiY2xlZnQgPSAgKGl2W21tKytdIDw8IDI0KSB8IChpdlttbSsrXSA8PCAxNikgfCAoaXZbbW0rK10gPDwgOCkgfCBpdlttbSsrXTtcbiAgICAgIGNiY3JpZ2h0ID0gKGl2W21tKytdIDw8IDI0KSB8IChpdlttbSsrXSA8PCAxNikgfCAoaXZbbW0rK10gPDwgOCkgfCBpdlttbSsrXTtcbiAgICB9XG5cbiAgICB2YXIgcm0gPSAwO1xuXG4gICAgLy9sb29wIHRocm91Z2ggZWFjaCA2NCBiaXQgY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICB3aGlsZSAobSA8IGxlbilcbiAgICB7XG4gICAgICBsZWZ0ID0gIChtZXNzYWdlW20rK10gPDwgMjQpIHwgKG1lc3NhZ2VbbSsrXSA8PCAxNikgfCAobWVzc2FnZVttKytdIDw8IDgpIHwgbWVzc2FnZVttKytdO1xuICAgICAgcmlnaHQgPSAobWVzc2FnZVttKytdIDw8IDI0KSB8IChtZXNzYWdlW20rK10gPDwgMTYpIHwgKG1lc3NhZ2VbbSsrXSA8PCA4KSB8IG1lc3NhZ2VbbSsrXTtcblxuICAgICAgLy9mb3IgQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUsIHhvciB0aGUgbWVzc2FnZSB3aXRoIHRoZSBwcmV2aW91cyByZXN1bHRcbiAgICAgIGlmIChtb2RlID09IDEpXG4gICAgICB7XG4gICAgICAgIGlmIChlbmNyeXB0KVxuICAgICAgICB7XG4gICAgICAgICAgbGVmdCBePSBjYmNsZWZ0OyByaWdodCBePSBjYmNyaWdodDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0MiA9IGNiY2xlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQyID0gY2JjcmlnaHQ7XG4gICAgICAgICAgY2JjbGVmdCA9IGxlZnQ7XG4gICAgICAgICAgY2JjcmlnaHQgPSByaWdodDtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvL2ZpcnN0IGVhY2ggNjQgYnV0IGNodW5rIG9mIHRoZSBtZXNzYWdlIG11c3QgYmUgcGVybXV0ZWQgYWNjb3JkaW5nIHRvIElQXG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxNikgXiByaWdodCkgJiAweDAwMDBmZmZmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDE2KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcblxuICAgICAgbGVmdCA9ICgobGVmdCA8PCAxKSB8IChsZWZ0ID4+PiAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0IDw8IDEpIHwgKHJpZ2h0ID4+PiAzMSkpO1xuXG4gICAgICAvL2RvIHRoaXMgZWl0aGVyIDEgb3IgMyB0aW1lcyBmb3IgZWFjaCBjaHVuayBvZiB0aGUgbWVzc2FnZVxuICAgICAgZm9yIChqPTA7IGo8aXRlcmF0aW9uczsgais9MylcbiAgICAgIHtcbiAgICAgICAgdmFyIGVuZGxvb3AgPSBsb29waW5nW2orMV07XG4gICAgICAgIHZhciBsb29waW5jID0gbG9vcGluZ1tqKzJdO1xuXG4gICAgICAgIC8vbm93IGdvIHRocm91Z2ggYW5kIHBlcmZvcm0gdGhlIGVuY3J5cHRpb24gb3IgZGVjcnlwdGlvblxuICAgICAgICBmb3IgKGk9bG9vcGluZ1tqXTsgaSE9ZW5kbG9vcDsgaSs9bG9vcGluYylcbiAgICAgICAgeyAvL2ZvciBlZmZpY2llbmN5XG4gICAgICAgICAgdmFyIHJpZ2h0MSA9IHJpZ2h0IF4ga2V5c1tpXTtcbiAgICAgICAgICB2YXIgcmlnaHQyID0gKChyaWdodCA+Pj4gNCkgfCAocmlnaHQgPDwgMjgpKSBeIGtleXNbaSsxXTtcblxuICAgICAgICAgIC8vdGhlIHJlc3VsdCBpcyBhdHRhaW5lZCBieSBwYXNzaW5nIHRoZXNlIGJ5dGVzIHRocm91Z2ggdGhlIFMgc2VsZWN0aW9uIGZ1bmN0aW9uc1xuICAgICAgICAgIHRlbXAgPSBsZWZ0O1xuICAgICAgICAgIGxlZnQgPSByaWdodDtcbiAgICAgICAgICByaWdodCA9IHRlbXAgXiAoZGVzU1Auc3BmdW5jdGlvbjJbKHJpZ2h0MSA+Pj4gMjQpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uNFsocmlnaHQxID4+PiAxNikgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBkZXNTUC5zcGZ1bmN0aW9uNlsocmlnaHQxID4+PiAgOCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb244W3JpZ2h0MSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IGRlc1NQLnNwZnVuY3Rpb24xWyhyaWdodDIgPj4+IDI0KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjNbKHJpZ2h0MiA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgZGVzU1Auc3BmdW5jdGlvbjVbKHJpZ2h0MiA+Pj4gIDgpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uN1tyaWdodDIgJiAweDNmXSk7XG4gICAgICAgIH1cblxuICAgICAgICB0ZW1wID0gbGVmdDsgbGVmdCA9IHJpZ2h0OyByaWdodCA9IHRlbXA7IC8vdW5yZXZlcnNlIGxlZnQgYW5kIHJpZ2h0XG4gICAgICB9IC8vZm9yIGVpdGhlciAxIG9yIDMgaXRlcmF0aW9uc1xuXG4gICAgICAvL21vdmUgdGhlbiBlYWNoIG9uZSBiaXQgdG8gdGhlIHJpZ2h0XG4gICAgICBsZWZ0ID0gKChsZWZ0ID4+PiAxKSB8IChsZWZ0IDw8IDMxKSk7XG4gICAgICByaWdodCA9ICgocmlnaHQgPj4+IDEpIHwgKHJpZ2h0IDw8IDMxKSk7XG5cbiAgICAgIC8vbm93IHBlcmZvcm0gSVAtMSwgd2hpY2ggaXMgSVAgaW4gdGhlIG9wcG9zaXRlIGRpcmVjdGlvblxuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDgpIF4gbGVmdCkgJiAweDAwZmYwMGZmOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDgpO1xuICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IDIpIF4gbGVmdCkgJiAweDMzMzMzMzMzOyBsZWZ0IF49IHRlbXA7IHJpZ2h0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMTYpIF4gcmlnaHQpICYgMHgwMDAwZmZmZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxNik7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiA0KSBeIHJpZ2h0KSAmIDB4MGYwZjBmMGY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgNCk7XG5cbiAgICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgICBpZiAobW9kZSA9PSAxKVxuICAgICAge1xuICAgICAgICBpZiAoZW5jcnlwdClcbiAgICAgICAge1xuICAgICAgICAgIGNiY2xlZnQgPSBsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0ID0gcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICB7XG4gICAgICAgICAgbGVmdCBePSBjYmNsZWZ0MjtcbiAgICAgICAgICByaWdodCBePSBjYmNyaWdodDI7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmVzdWx0LnNldCggbmV3IFVpbnQ4QXJyYXkgKCBbIChsZWZ0Pj4+MjQpICYgMHhmZiwgKGxlZnQ+Pj4xNikgJiAweGZmLCAobGVmdD4+PjgpICYgMHhmZiwgKGxlZnQpICYgMHhmZiwgKHJpZ2h0Pj4+MjQpICYgMHhmZiwgKHJpZ2h0Pj4+MTYpICYgMHhmZiwgKHJpZ2h0Pj4+OCkgJiAweGZmLCAocmlnaHQpICYgMHhmZiBdICksIHJtICk7XG5cbiAgICAgIHJtICs9IDg7XG4gICAgfSAvL2ZvciBldmVyeSA4IGNoYXJhY3RlcnMsIG9yIDY0IGJpdHMgaW4gdGhlIG1lc3NhZ2VcblxuICAgIHJldHVybiByZXN1bHQ7XG4gIH0gLy9lbmQgb2YgZGVzXG5cbn1cblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdERVMtRUNCJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQgXSApO1xuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ0RFUy1DQkMnLFxuICBERVNDcnlwdG9ncmFwaGljU2VydmljZSxcbiAgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkVOQ1JZUFQsIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uREVDUllQVCwgIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uU0lHTiwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5WRVJJRlkgXSApO1xuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSggJ0RFUy1FQ0InLFxuICBERVNDcnlwdG9ncmFwaGljU2VydmljZSxcbiAgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLklNUE9SVF9LRVkgXSApO1xuXG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSggJ0RFUy1DQkMnLFxuICBERVNDcnlwdG9ncmFwaGljU2VydmljZSxcbiAgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLklNUE9SVF9LRVkgXSApO1xuIixudWxsLCJpbXBvcnQgeyBDb250YWluZXIsIGF1dG9pbmplY3QgYXMgaW5qZWN0IH0gZnJvbSAnYXVyZWxpYS1kZXBlbmRlbmN5LWluamVjdGlvbic7XG5pbXBvcnQgeyBtZXRhZGF0YSB9IGZyb20gJ2F1cmVsaWEtbWV0YWRhdGEnO1xuXG5leHBvcnQgeyBDb250YWluZXIsIGluamVjdCB9O1xuZXhwb3J0IGludGVyZmFjZSBJbmplY3RhYmxlIHtcbiAgbmV3KCAuLi5hcmdzICk6IE9iamVjdDtcbn1cbiIsImltcG9ydCB7IEV2ZW50QWdncmVnYXRvciwgU3Vic2NyaXB0aW9uLCBIYW5kbGVyIGFzIEV2ZW50SGFuZGxlciB9IGZyb20gJ2F1cmVsaWEtZXZlbnQtYWdncmVnYXRvcic7XG5cbi8vZXhwb3J0IHsgRXZlbnRIYW5kbGVyIH07XG5cbmV4cG9ydCBjbGFzcyBFdmVudEh1Ylxue1xuICBfZXZlbnRBZ2dyZWdhdG9yOiBFdmVudEFnZ3JlZ2F0b3I7XG5cbiAgY29uc3RydWN0b3IoIClcbiAge1xuICAgIHRoaXMuX2V2ZW50QWdncmVnYXRvciA9IG5ldyBFdmVudEFnZ3JlZ2F0b3IoKTtcbiAgfVxuXG4gIHB1YmxpYyBwdWJsaXNoKCBldmVudDogc3RyaW5nLCBkYXRhPzogYW55IClcbiAge1xuICAgIHRoaXMuX2V2ZW50QWdncmVnYXRvci5wdWJsaXNoKCBldmVudCwgZGF0YSApO1xuICB9XG5cbiAgcHVibGljIHN1YnNjcmliZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZSggZXZlbnQsIGhhbmRsZXIgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmVPbmNlKCBldmVudDogc3RyaW5nLCBoYW5kbGVyOiBGdW5jdGlvbiApOiBTdWJzY3JpcHRpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9ldmVudEFnZ3JlZ2F0b3Iuc3Vic2NyaWJlT25jZSggZXZlbnQsIGhhbmRsZXIgKTtcbiAgfVxufVxuXG4vKmZ1bmN0aW9uIGV2ZW50SHViKCk6IGFueSB7XG4gIHJldHVybiBmdW5jdGlvbiBldmVudEh1YjxURnVuY3Rpb24gZXh0ZW5kcyBGdW5jdGlvbiwgRXZlbnRIdWI+KHRhcmdldDogVEZ1bmN0aW9uKTogVEZ1bmN0aW9uIHtcblxuICAgIHRhcmdldC5wcm90b3R5cGUuc3Vic2NyaWJlID0gbmV3Q29uc3RydWN0b3IucHJvdG90eXBlID0gT2JqZWN0LmNyZWF0ZSh0YXJnZXQucHJvdG90eXBlKTtcbiAgICBuZXdDb25zdHJ1Y3Rvci5wcm90b3R5cGUuY29uc3RydWN0b3IgPSB0YXJnZXQ7XG5cbiAgICByZXR1cm4gPGFueT4gbmV3Q29uc3RydWN0b3I7XG4gIH1cbn1cblxuQGV2ZW50SHViKClcbmNsYXNzIE15Q2xhc3Mge307XG4qL1xuIiwiaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuXG4vKipcbiogQSBQb3J0IGlzIGEgcGxhY2Vob2xkZXIgZm9yIGFuIEVuZFBvaW50IHB1Ymxpc2hlZCBieSB0aGUgdW5kZXJseWluZ1xuKiBjb21wb25lbnQgb2YgYSBOb2RlLlxuKi9cbmV4cG9ydCBjbGFzcyBQb3J0XG57XG4gIHByb3RlY3RlZCBfb3duZXI6IE5vZGU7XG4gIHByb3RlY3RlZCBfcHJvdG9jb2xJRDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfZW5kUG9pbnQ6IEVuZFBvaW50O1xuXG4gIHB1YmxpYyBtZXRhZGF0YTogYW55O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogTm9kZSwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICAvLyBXYXMgYW4gRW5kUG9pbnQgc3VwcGxpZWQ/XG4gICAgaWYgKCAhZW5kUG9pbnQgKVxuICAgIHtcbiAgICAgIGxldCBkaXJlY3Rpb24gPSBhdHRyaWJ1dGVzLmRpcmVjdGlvbiB8fCBEaXJlY3Rpb24uSU5PVVQ7XG5cbiAgICAgIGlmICggdHlwZW9mIGF0dHJpYnV0ZXMuZGlyZWN0aW9uID09IFwic3RyaW5nXCIgKVxuICAgICAgICBkaXJlY3Rpb24gPSBEaXJlY3Rpb25bIGRpcmVjdGlvbi50b1VwcGVyQ2FzZSgpIF07XG5cbiAgICAgIC8vIENyZWF0ZSBhIFwiZHVtbXlcIiBlbmRQb2ludCB3aXRoIGNvcnJlY3QgaWQgKyBkaXJlY3Rpb25cbiAgICAgIGVuZFBvaW50ID0gbmV3IEVuZFBvaW50KCBhdHRyaWJ1dGVzLmlkLCBkaXJlY3Rpb24gKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2VuZFBvaW50ID0gZW5kUG9pbnQ7XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gYXR0cmlidXRlc1sgJ3Byb3RvY29sJyBdIHx8ICdhbnknO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB4OiAxMDAsIHk6IDEwMCB9O1xuICB9XG5cbiAgcHVibGljIGdldCBlbmRQb2ludCgpIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQ7XG4gIH1cbiAgcHVibGljIHNldCBlbmRQb2ludCggZW5kUG9pbnQ6IEVuZFBvaW50ICkge1xuICAgIHRoaXMuX2VuZFBvaW50ID0gZW5kUG9pbnQ7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIFBPSk8gZm9yIHNlcmlhbGl6YXRpb25cbiAgICovXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIHBvcnQgPSB7XG4gICAgICBpZDogdGhpcy5fZW5kUG9pbnQuaWQsXG4gICAgICBkaXJlY3Rpb246IHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbixcbiAgICAgIHByb3RvY29sOiAoIHRoaXMuX3Byb3RvY29sSUQgIT0gJ2FueScgKSA/IHRoaXMuX3Byb3RvY29sSUQgOiB1bmRlZmluZWQsXG4gICAgICBtZXRhZGF0YTogdGhpcy5tZXRhZGF0YSxcbiAgICB9O1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3Mgb3duZXJcbiAgICovXG4gIGdldCBvd25lcigpOiBOb2RlIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXJcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBwcm90b2NvbCBJRFxuICAgKi9cbiAgZ2V0IHByb3RvY29sSUQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcHJvdG9jb2xJRDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBJRFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50LmlkO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIEVuZFBvaW50IERpcmVjdGlvblxuICAgKi9cbiAgZ2V0IGRpcmVjdGlvbigpOiBEaXJlY3Rpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb247XG4gIH1cblxufVxuXG5leHBvcnQgY2xhc3MgUHVibGljUG9ydCBleHRlbmRzIFBvcnRcbntcbiAgcHJveHlFbmRQb2ludDogRW5kUG9pbnQ7XG4gIHByb3h5Q2hhbm5lbDogQ2hhbm5lbDtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBlbmRQb2ludDogRW5kUG9pbnQsIGF0dHJpYnV0ZXM6IHt9IClcbiAge1xuICAgIHN1cGVyKCBvd25lciwgZW5kUG9pbnQsIGF0dHJpYnV0ZXMgKTtcblxuICAgIGxldCBwcm94eURpcmVjdGlvbiA9XG4gICAgICAoIHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uSU4gKVxuICAgICAgICA/IERpcmVjdGlvbi5PVVRcbiAgICAgICAgOiAoIHRoaXMuX2VuZFBvaW50LmRpcmVjdGlvbiA9PSBEaXJlY3Rpb24uT1VUIClcbiAgICAgICAgICA/IERpcmVjdGlvbi5JTlxuICAgICAgICAgIDogRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgLy8gQ3JlYXRlIGFuIEVuZFBvaW50IHRvIHByb3h5IGJldHdlZW4gdGhlIFB1YmxpYyBhbmQgUHJpdmF0ZSAoaW50ZXJuYWwpXG4gICAgLy8gc2lkZXMgb2YgdGhlIFBvcnQuXG4gICAgdGhpcy5wcm94eUVuZFBvaW50ID0gbmV3IEVuZFBvaW50KCB0aGlzLl9lbmRQb2ludC5pZCwgcHJveHlEaXJlY3Rpb24gKTtcblxuICAgIC8vIFdpcmUtdXAgcHJveHkgLVxuXG4gICAgLy8gRm9yd2FyZCBpbmNvbWluZyBwYWNrZXRzIChmcm9tIHB1YmxpYyBpbnRlcmZhY2UpIHRvIHByaXZhdGVcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQub25NZXNzYWdlKCAoIG1lc3NhZ2UgKSA9PiB7XG4gICAgICB0aGlzLl9lbmRQb2ludC5oYW5kbGVNZXNzYWdlKCBtZXNzYWdlLCB0aGlzLnByb3h5RW5kUG9pbnQsIHRoaXMucHJveHlDaGFubmVsICk7XG4gICAgfSk7XG5cbiAgICAvLyBGb3J3YXJkIG91dGdvaW5nIHBhY2tldHMgKGZyb20gcHJpdmF0ZSBpbnRlcmZhY2UpIHRvIHB1YmxpY1xuICAgIHRoaXMuX2VuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5wcm94eUVuZFBvaW50LnNlbmRNZXNzYWdlKCBtZXNzYWdlICk7XG4gICAgfSk7XG5cbiAgICAvLyBub3QgeWV0IGNvbm5lY3RlZFxuICAgIHRoaXMucHJveHlDaGFubmVsID0gbnVsbDtcbiAgfVxuXG4gIC8vIENvbm5lY3QgdG8gUHJpdmF0ZSAoaW50ZXJuYWwpIEVuZFBvaW50LiBUbyBiZSBjYWxsZWQgZHVyaW5nIGdyYXBoXG4gIC8vIHdpcmVVcCBwaGFzZVxuICBwdWJsaWMgY29ubmVjdFByaXZhdGUoIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5wcm94eUNoYW5uZWwgPSBjaGFubmVsO1xuXG4gICAgdGhpcy5wcm94eUVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICB9XG5cbiAgcHVibGljIGRpc2Nvbm5lY3RQcml2YXRlKClcbiAge1xuICAgIHRoaXMucHJveHlFbmRQb2ludC5kZXRhY2goIHRoaXMucHJveHlDaGFubmVsICk7XG4gIH1cblxuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0gc3VwZXIudG9PYmplY3QoIG9wdHMgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG59XG4iLCJpbXBvcnQgeyBSdW50aW1lQ29udGV4dCB9IGZyb20gJy4uL3J1bnRpbWUvcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IFBvcnQgfSBmcm9tICcuL3BvcnQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcblxuZXhwb3J0IGNsYXNzIE5vZGUgZXh0ZW5kcyBFdmVudEh1Ylxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBHcmFwaDtcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfY29tcG9uZW50OiBzdHJpbmc7XG4gIHByb3RlY3RlZCBfaW5pdGlhbERhdGE6IE9iamVjdDtcblxuICBwcm90ZWN0ZWQgX3BvcnRzOiBNYXA8c3RyaW5nLCBQb3J0PjtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICAvKipcbiAgICogUnVudGltZSBhbmQgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgICovXG4gIHByb3RlY3RlZCBfY29udGV4dDogUnVudGltZUNvbnRleHQ7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5faWQgPSBhdHRyaWJ1dGVzLmlkIHx8ICcnO1xuICAgIHRoaXMuX2NvbXBvbmVudCA9IGF0dHJpYnV0ZXMuY29tcG9uZW50O1xuICAgIHRoaXMuX2luaXRpYWxEYXRhID0gYXR0cmlidXRlcy5pbml0aWFsRGF0YSB8fCB7fTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IH07XG5cbiAgICAvLyBJbml0aWFsbHkgY3JlYXRlICdwbGFjZWhvbGRlcicgcG9ydHMuIE9uY2UgY29tcG9uZW50IGhhcyBiZWVuXG4gICAgLy8gbG9hZGVkIGFuZCBpbnN0YW50aWF0ZWQsIHRoZXkgd2lsbCBiZSBjb25uZWN0ZWQgY29ubmVjdGVkIHRvXG4gICAgLy8gdGhlIGNvbXBvbmVudCdzIGNvbW11bmljYXRpb24gZW5kLXBvaW50c1xuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLnBvcnRzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZFBsYWNlaG9sZGVyUG9ydCggaWQsIGF0dHJpYnV0ZXMucG9ydHNbIGlkIF0gKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIFBPSk8gZm9yIHNlcmlhbGl6YXRpb25cbiAgICovXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIG5vZGUgPSB7XG4gICAgICBpZDogdGhpcy5pZCxcbiAgICAgIGNvbXBvbmVudDogdGhpcy5fY29tcG9uZW50LFxuICAgICAgaW5pdGlhbERhdGE6IHRoaXMuX2luaXRpYWxEYXRhLFxuICAgICAgcG9ydHM6IHt9LFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGFcbiAgICB9O1xuXG4gICAgdGhpcy5fcG9ydHMuZm9yRWFjaCggKCBwb3J0LCBpZCApID0+IHtcbiAgICAgIG5vZGUucG9ydHNbIGlkIF0gPSBwb3J0LnRvT2JqZWN0KCk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBOb2RlJ3Mgb3duZXJcbiAgICovXG4gIHB1YmxpYyBnZXQgb3duZXIoKTogR3JhcGgge1xuICAgIHJldHVybiB0aGlzLl9vd25lclxuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIGlkXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cbiAgLyoqXG4gICAqIFNldCB0aGUgTm9kZSdzIGlkXG4gICAqIEBwYXJhbSBpZCAtIG5ldyBpZGVudGlmaWVyXG4gICAqL1xuICBzZXQgaWQoIGlkOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIHB1YmxpYyB1cGRhdGVQb3J0cyggZW5kUG9pbnRzOiBFbmRQb2ludFtdICkge1xuICAgIGxldCBjdXJyZW50UG9ydHMgPSB0aGlzLl9wb3J0cztcbiAgICBsZXQgbmV3UG9ydHM6IE1hcDxzdHJpbmcsUG9ydD4gPSBuZXcgTWFwPHN0cmluZywgUG9ydD4oKTtcblxuICAgIC8vIFBhcmFtIGVuZFBvaW50cyBpcyBhbiBhcnJheSBvZiBFbmRQb2ludHMgZXhwb3J0ZWQgYnkgYSBjb21wb25lbnRcbiAgICAvLyB1cGRhdGUgb3VyIG1hcCBvZiBQb3J0cyB0byByZWZsZWN0IHRoaXMgYXJyYXlcbiAgICAvLyBUaGlzIG1heSBtZWFuIGluY2x1ZGluZyBhIG5ldyBQb3J0LCB1cGRhdGluZyBhbiBleGlzdGluZyBQb3J0IHRvXG4gICAgLy8gdXNlIHRoaXMgc3VwcGxpZWQgRW5kUG9pbnQsIG9yIGV2ZW4gZGVsZXRpbmcgYSAnbm8tbG9uZ2VyJyB2YWxpZCBQb3J0XG4gICAgZW5kUG9pbnRzLmZvckVhY2goIChlcDogRW5kUG9pbnQgKSA9PiB7XG4gICAgICBsZXQgaWQgPSBlcC5pZDtcblxuICAgICAgaWYgKCBjdXJyZW50UG9ydHMuaGFzKCBpZCApICkge1xuICAgICAgICBsZXQgcG9ydCA9IGN1cnJlbnRQb3J0cy5nZXQoIGlkICk7XG5cbiAgICAgICAgcG9ydC5lbmRQb2ludCA9IGVwO1xuXG4gICAgICAgIG5ld1BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgICAgICBjdXJyZW50UG9ydHMuZGVsZXRlKCBpZCApO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIC8vIGVuZFBvaW50IG5vdCBmb3VuZCwgY3JlYXRlIGEgcG9ydCBmb3IgaXRcbiAgICAgICAgbGV0IHBvcnQgPSBuZXcgUG9ydCggdGhpcywgZXAsIHsgaWQ6IGlkLCBkaXJlY3Rpb246IGVwLmRpcmVjdGlvbiB9ICk7XG5cbiAgICAgICAgbmV3UG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgdGhpcy5fcG9ydHMgPSBuZXdQb3J0cztcbiAgfVxuXG5cbiAgLyoqXG4gICAqIEFkZCBhIHBsYWNlaG9sZGVyIFBvcnRcbiAgICovXG4gIHByb3RlY3RlZCBhZGRQbGFjZWhvbGRlclBvcnQoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IHt9ICk6IFBvcnRcbiAge1xuICAgIGF0dHJpYnV0ZXNbXCJpZFwiXSA9IGlkO1xuXG4gICAgbGV0IHBvcnQgPSBuZXcgUG9ydCggdGhpcywgbnVsbCwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5fcG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIHBvcnRzIGFzIGFuIGFycmF5IG9mIFBvcnRzXG4gICAqXG4gICAqIEByZXR1cm4gUG9ydFtdXG4gICAqL1xuICBnZXQgcG9ydHMoKTogTWFwPHN0cmluZywgUG9ydD5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cztcbiAgfVxuXG4gIGdldFBvcnRBcnJheSgpOiBQb3J0W10ge1xuICAgIGxldCB4cG9ydHM6IFBvcnRbXSA9IFtdO1xuXG4gICAgdGhpcy5fcG9ydHMuZm9yRWFjaCggKCBwb3J0LCBpZCApID0+IHtcbiAgICAgIHhwb3J0cy5wdXNoKCBwb3J0ICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIHhwb3J0cztcbiAgfVxuXG4gIC8qKlxuICAgKiBMb29rdXAgYSBQb3J0IGJ5IGl0J3MgSURcbiAgICogQHBhcmFtIGlkIC0gcG9ydCBpZGVudGlmaWVyXG4gICAqXG4gICAqIEByZXR1cm4gUG9ydCBvciB1bmRlZmluZWRcbiAgICovXG4gIGdldFBvcnRCeUlEKCBpZDogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5nZXQoIGlkICk7XG4gIH1cblxuICBpZGVudGlmeVBvcnQoIGlkOiBzdHJpbmcsIHByb3RvY29sSUQ/OiBzdHJpbmcgKTogUG9ydFxuICB7XG4gICAgdmFyIHBvcnQ6IFBvcnQ7XG5cbiAgICBpZiAoIGlkIClcbiAgICAgIHBvcnQgPSB0aGlzLl9wb3J0cy5nZXQoIGlkICk7XG4gICAgZWxzZSBpZiAoIHByb3RvY29sSUQgKVxuICAgIHtcbiAgICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcCwgaWQgKSA9PiB7XG4gICAgICAgIGlmICggcC5wcm90b2NvbElEID09IHByb3RvY29sSUQgKVxuICAgICAgICAgIHBvcnQgPSBwO1xuICAgICAgfSwgdGhpcyApO1xuICAgIH1cblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZSBhIFBvcnQgZnJvbSB0aGlzIE5vZGVcbiAgICogQHBhcmFtIGlkIC0gaWRlbnRpZmllciBvZiBQb3J0IHRvIGJlIHJlbW92ZWRcbiAgICogQHJldHVybiB0cnVlIC0gcG9ydCByZW1vdmVkXG4gICAqICAgICAgICAgZmFsc2UgLSBwb3J0IGluZXhpc3RlbnRcbiAgICovXG4gIHJlbW92ZVBvcnQoIGlkOiBzdHJpbmcgKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BvcnRzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnkgKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdGhpcy51bmxvYWRDb21wb25lbnQoKTtcblxuICAgIC8vIEdldCBhIENvbXBvbmVudENvbnRleHQgcmVzcG9uc2FibGUgZm9yIENvbXBvbmVudCdzIGxpZmUtY3ljbGUgY29udHJvbFxuICAgIGxldCBjdHggPSB0aGlzLl9jb250ZXh0ID0gZmFjdG9yeS5jcmVhdGVDb250ZXh0KCB0aGlzLl9jb21wb25lbnQsIHRoaXMuX2luaXRpYWxEYXRhICk7XG5cbiAgICAvLyBNYWtlIG91cnNlbHZlcyB2aXNpYmxlIHRvIGNvbnRleHQgKGFuZCBpbnN0YW5jZSlcbiAgICBjdHgubm9kZSA9IHRoaXM7XG5cbiAgICAvL2xldCBtZSA9IHRoaXM7XG5cbiAgICAvLyBMb2FkIGNvbXBvbmVudFxuICAgIHJldHVybiBjdHgubG9hZCgpO1xuICB9XG5cbiAgcHVibGljIGdldCBjb250ZXh0KCk6IFJ1bnRpbWVDb250ZXh0IHtcbiAgICByZXR1cm4gdGhpcy5fY29udGV4dDtcbiAgfVxuXG4gIHVubG9hZENvbXBvbmVudCgpXG4gIHtcbiAgICBpZiAoIHRoaXMuX2NvbnRleHQgKVxuICAgIHtcbiAgICAgIHRoaXMuX2NvbnRleHQucmVsZWFzZSgpO1xuXG4gICAgICB0aGlzLl9jb250ZXh0ID0gbnVsbDtcbiAgICB9XG4gIH1cblxufVxuIiwiaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludCwgRW5kUG9pbnRDb2xsZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi4vZ3JhcGgvbm9kZSc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi4vZ3JhcGgvcG9ydCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IENvbXBvbmVudCB9IGZyb20gJy4uL2NvbXBvbmVudC9jb21wb25lbnQnO1xuXG5pbXBvcnQgeyBDb250YWluZXIsIEluamVjdGFibGUgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuXG5leHBvcnQgZW51bSBSdW5TdGF0ZSB7XG4gIE5FV0JPUk4sICAgICAgLy8gTm90IHlldCBsb2FkZWRcbiAgTE9BRElORywgICAgICAvLyBXYWl0aW5nIGZvciBhc3luYyBsb2FkIHRvIGNvbXBsZXRlXG4gIExPQURFRCwgICAgICAgLy8gQ29tcG9uZW50IGxvYWRlZCwgbm90IHlldCBleGVjdXRhYmxlXG4gIFJFQURZLCAgICAgICAgLy8gUmVhZHkgZm9yIEV4ZWN1dGlvblxuICBSVU5OSU5HLCAgICAgIC8vIE5ldHdvcmsgYWN0aXZlLCBhbmQgcnVubmluZ1xuICBQQVVTRUQgICAgICAgIC8vIE5ldHdvcmsgdGVtcG9yYXJpbHkgcGF1c2VkXG59XG5cbi8qKlxuKiBUaGUgcnVudGltZSBjb250ZXh0IGluZm9ybWF0aW9uIGZvciBhIENvbXBvbmVudCBpbnN0YW5jZVxuKi9cbmV4cG9ydCBjbGFzcyBSdW50aW1lQ29udGV4dFxue1xuICAvKipcbiAgKiBUaGUgY29tcG9uZW50IGlkIC8gYWRkcmVzc1xuICAqL1xuICBwcml2YXRlIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIFRoZSBydW50aW1lIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICovXG4gIHByaXZhdGUgX2luc3RhbmNlOiBDb21wb25lbnQ7XG5cbiAgLyoqXG4gICogSW5pdGlhbCBEYXRhIGZvciB0aGUgY29tcG9uZW50IGluc3RhbmNlXG4gICovXG4gIHByaXZhdGUgX2NvbmZpZzoge307XG5cbiAgLyoqXG4gICogVGhlIHJ1bnRpbWUgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgKi9cbiAgcHJpdmF0ZSBfY29udGFpbmVyOiBDb250YWluZXI7XG5cbiAgLyoqXG4gICogVGhlIGNvbXBvbmVudCBmYWN0b3J5IHRoYXQgY3JlYXRlZCB1c1xuICAqL1xuICBwcml2YXRlIF9mYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5O1xuXG4gIC8qKlxuICAqIFRoZSBub2RlXG4gICovXG4gIHByaXZhdGUgX25vZGU6IE5vZGU7XG5cbiAgLyoqXG4gICpcbiAgKlxuICAqL1xuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgY29udGFpbmVyOiBDb250YWluZXIsIGlkOiBzdHJpbmcsIGNvbmZpZzoge30sIGRlcHM6IEluamVjdGFibGVbXSA9IFtdICkge1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG5cbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fY29uZmlnID0gY29uZmlnO1xuXG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyO1xuXG4gICAgLy8gUmVnaXN0ZXIgYW55IGNvbnRleHQgZGVwZW5kZW5jaWVzXG4gICAgZm9yKCBsZXQgaSBpbiBkZXBzIClcbiAgICB7XG4gICAgICBpZiAoICF0aGlzLl9jb250YWluZXIuaGFzUmVzb2x2ZXIoIGRlcHNbaV0gKSApXG4gICAgICAgIHRoaXMuX2NvbnRhaW5lci5yZWdpc3RlclNpbmdsZXRvbiggZGVwc1tpXSwgZGVwc1tpXSApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBub2RlKCk6IE5vZGUge1xuICAgIHJldHVybiB0aGlzLl9ub2RlO1xuICB9XG4gIHNldCBub2RlKCBub2RlOiBOb2RlICkge1xuICAgIHRoaXMuX25vZGUgPSBub2RlO1xuXG4gICAgLy8gbWFrZSBub2RlICdpbmplY3RhYmxlJyBpbiBjb250YWluZXJcbiAgICB0aGlzLl9jb250YWluZXIucmVnaXN0ZXJJbnN0YW5jZSggTm9kZSwgdGhpcyApO1xuICB9XG5cbiAgZ2V0IGluc3RhbmNlKCk6IENvbXBvbmVudCB7XG4gICAgcmV0dXJuIHRoaXMuX2luc3RhbmNlO1xuICB9XG5cbiAgZ2V0IGNvbnRhaW5lcigpOiBDb250YWluZXIge1xuICAgIHJldHVybiB0aGlzLl9jb250YWluZXI7XG4gIH1cblxuICBsb2FkKCApOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBnZXQgYW4gaW5zdGFuY2UgZnJvbSB0aGUgZmFjdG9yeVxuICAgICAgbWUuX3J1blN0YXRlID0gUnVuU3RhdGUuTE9BRElORztcbiAgICAgIHRoaXMuX2ZhY3RvcnkubG9hZENvbXBvbmVudCggdGhpcywgdGhpcy5faWQgKVxuICAgICAgICAudGhlbiggKGluc3RhbmNlKSA9PiB7XG4gICAgICAgICAgLy8gQ29tcG9uZW50IChhbmQgYW55IGRlcGVuZGVuY2llcykgaGF2ZSBiZWVuIGxvYWRlZFxuICAgICAgICAgIG1lLl9pbnN0YW5jZSA9IGluc3RhbmNlO1xuICAgICAgICAgIG1lLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5MT0FERUQgKTtcblxuICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoZXJyKSA9PiB7XG4gICAgICAgICAgLy8gVW5hYmxlIHRvIGxvYWRcbiAgICAgICAgICBtZS5fcnVuU3RhdGUgPSBSdW5TdGF0ZS5ORVdCT1JOO1xuXG4gICAgICAgICAgcmVqZWN0KCBlcnIgKTtcbiAgICAgICAgfSk7XG4gICAgfSApO1xuICB9XG5cbiAgX3J1blN0YXRlOiBSdW5TdGF0ZSA9IFJ1blN0YXRlLk5FV0JPUk47XG4gIGdldCBydW5TdGF0ZSgpIHtcbiAgICByZXR1cm4gdGhpcy5fcnVuU3RhdGU7XG4gIH1cblxuICBwcml2YXRlIGluU3RhdGUoIHN0YXRlczogUnVuU3RhdGVbXSApOiBib29sZWFuIHtcbiAgICByZXR1cm4gbmV3IFNldDxSdW5TdGF0ZT4oIHN0YXRlcyApLmhhcyggdGhpcy5fcnVuU3RhdGUgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFRyYW5zaXRpb24gY29tcG9uZW50IHRvIG5ldyBzdGF0ZVxuICAqIFN0YW5kYXJkIHRyYW5zaXRpb25zLCBhbmQgcmVzcGVjdGl2ZSBhY3Rpb25zLCBhcmU6XG4gICogICBMT0FERUQgLT4gUkVBRFkgICAgICBpbnN0YW50aWF0ZSBhbmQgaW5pdGlhbGl6ZSBjb21wb25lbnRcbiAgKiAgIFJFQURZIC0+IExPQURFRCAgICAgIHRlYXJkb3duIGFuZCBkZXN0cm95IGNvbXBvbmVudFxuICAqXG4gICogICBSRUFEWSAtPiBSVU5OSU5HICAgICBzdGFydCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICogICBSVU5OSU5HIC0+IFJFQURZICAgICBzdG9wIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKlxuICAqICAgUlVOTklORyAtPiBQQVVTRUQgICAgcGF1c2UgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqICAgUEFVU0VEIC0+IFJVTk5JTkcgICAgcmVzdW1lIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKlxuICAqL1xuICBzZXRSdW5TdGF0ZSggcnVuU3RhdGU6IFJ1blN0YXRlICkge1xuICAgIGxldCBpbnN0ID0gdGhpcy5pbnN0YW5jZTtcblxuICAgIHN3aXRjaCggcnVuU3RhdGUgKSAvLyB0YXJnZXQgc3RhdGUgLi5cbiAgICB7XG4gICAgICBjYXNlIFJ1blN0YXRlLkxPQURFRDogLy8ganVzdCBsb2FkZWQsIG9yIHRlYXJkb3duXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJFQURZLCBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHRlYXJkb3duIGFuZCBkZXN0cm95IGNvbXBvbmVudFxuICAgICAgICAgIGlmICggaW5zdC50ZWFyZG93biApXG4gICAgICAgICAge1xuICAgICAgICAgICAgaW5zdC50ZWFyZG93bigpO1xuXG4gICAgICAgICAgICAvLyBhbmQgZGVzdHJveSBpbnN0YW5jZVxuICAgICAgICAgICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5SRUFEWTogIC8vIGluaXRpYWxpemUgb3Igc3RvcCBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLkxPQURFRCBdICkgKSB7XG4gICAgICAgICAgLy8gaW5pdGlhbGl6ZSBjb21wb25lbnRcblxuICAgICAgICAgIGxldCBlbmRQb2ludHM6IEVuZFBvaW50W10gPSBbXTtcblxuICAgICAgICAgIGlmICggaW5zdC5pbml0aWFsaXplIClcbiAgICAgICAgICAgIGVuZFBvaW50cyA9IHRoaXMuaW5zdGFuY2UuaW5pdGlhbGl6ZSggPEtpbmQ+dGhpcy5fY29uZmlnICk7XG5cbiAgICAgICAgICBpZiAoIHRoaXMuX25vZGUgKVxuICAgICAgICAgICAgdGhpcy5fbm9kZS51cGRhdGVQb3J0cyggZW5kUG9pbnRzICk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHN0b3AgY29tcG9uZW50XG4gICAgICAgICAgaWYgKCBpbnN0LnN0b3AgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5zdG9wKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgaW5pdGlhbGl6ZWQsIG5vdCBsb2FkZWQnICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlJVTk5JTkc6ICAvLyBzdGFydC9yZXN1bWUgbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SRUFEWSwgUnVuU3RhdGUuUlVOTklORyBdICkgKSB7XG4gICAgICAgICAgLy8gc3RhcnQgY29tcG9uZW50IGV4ZWN1dGlvblxuICAgICAgICAgIGlmICggaW5zdC5zdGFydCApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnN0YXJ0KCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIHJlc3VtZSBjb21wb25lbnQgZXhlY3V0aW9uIGFmdGVyIHBhdXNlXG4gICAgICAgICAgaWYgKCBpbnN0LnJlc3VtZSApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnJlc3VtZSgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIHN0YXJ0ZWQsIG5vdCByZWFkeScgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUEFVU0VEOiAgLy8gcGF1c2Ugbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HXSApICkge1xuICAgICAgICAgIGlmICggaW5zdC5wYXVzZSApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnBhdXNlKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5QQVVTRUQgXSApICkge1xuICAgICAgICAgIC8vIGFscmVhZHkgcGF1c2VkXG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgcGF1c2VkJyApO1xuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICB0aGlzLl9ydW5TdGF0ZSA9IHJ1blN0YXRlO1xuICB9XG5cbiAgcmVsZWFzZSgpIHtcbiAgICAvLyByZWxlYXNlIGluc3RhbmNlLCB0byBhdm9pZCBtZW1vcnkgbGVha3NcbiAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gbnVsbFxuICB9XG59XG4iLCJleHBvcnQgaW50ZXJmYWNlIE1vZHVsZUxvYWRlciB7XG4gIGhhc01vZHVsZT8oIGlkOiBzdHJpbmcgKTogYm9vbGVhbjtcblxuICBsb2FkTW9kdWxlKCBpZDogc3RyaW5nICk6IFByb21pc2U8YW55Pjtcbn1cblxuZGVjbGFyZSBpbnRlcmZhY2UgU3lzdGVtIHtcbiAgbm9ybWFsaXplU3luYyggaWQgKTtcbiAgaW1wb3J0KCBpZCApO1xufTtcbmRlY2xhcmUgdmFyIFN5c3RlbTogU3lzdGVtO1xuXG5jbGFzcyBNb2R1bGVSZWdpc3RyeUVudHJ5IHtcbiAgY29uc3RydWN0b3IoIGFkZHJlc3M6IHN0cmluZyApIHtcblxuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTeXN0ZW1Nb2R1bGVMb2FkZXIgaW1wbGVtZW50cyBNb2R1bGVMb2FkZXIge1xuXG4gIHByaXZhdGUgbW9kdWxlUmVnaXN0cnk6IE1hcDxzdHJpbmcsIE1vZHVsZVJlZ2lzdHJ5RW50cnk+O1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMubW9kdWxlUmVnaXN0cnkgPSBuZXcgTWFwPHN0cmluZywgTW9kdWxlUmVnaXN0cnlFbnRyeT4oKTtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0T3JDcmVhdGVNb2R1bGVSZWdpc3RyeUVudHJ5KGFkZHJlc3M6IHN0cmluZyk6IE1vZHVsZVJlZ2lzdHJ5RW50cnkge1xuICAgIHJldHVybiB0aGlzLm1vZHVsZVJlZ2lzdHJ5W2FkZHJlc3NdIHx8ICh0aGlzLm1vZHVsZVJlZ2lzdHJ5W2FkZHJlc3NdID0gbmV3IE1vZHVsZVJlZ2lzdHJ5RW50cnkoYWRkcmVzcykpO1xuICB9XG5cbiAgbG9hZE1vZHVsZSggaWQ6IHN0cmluZyApOiBQcm9taXNlPGFueT4ge1xuICAgIGxldCBuZXdJZCA9IFN5c3RlbS5ub3JtYWxpemVTeW5jKGlkKTtcbiAgICBsZXQgZXhpc3RpbmcgPSB0aGlzLm1vZHVsZVJlZ2lzdHJ5W25ld0lkXTtcblxuICAgIGlmIChleGlzdGluZykge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShleGlzdGluZyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIFN5c3RlbS5pbXBvcnQobmV3SWQpLnRoZW4obSA9PiB7XG4gICAgICB0aGlzLm1vZHVsZVJlZ2lzdHJ5W25ld0lkXSA9IG07XG4gICAgICByZXR1cm4gbTsgLy9lbnN1cmVPcmlnaW5PbkV4cG9ydHMobSwgbmV3SWQpO1xuICAgIH0pO1xuICB9XG5cbn1cbiIsImltcG9ydCB7IENvbXBvbmVudCwgQ29tcG9uZW50Q29uc3RydWN0b3IgfSBmcm9tICcuLi9jb21wb25lbnQvY29tcG9uZW50JztcbmltcG9ydCB7IFJ1bnRpbWVDb250ZXh0IH0gZnJvbSAnLi9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgTW9kdWxlTG9hZGVyIH0gZnJvbSAnLi9tb2R1bGUtbG9hZGVyJztcblxuaW1wb3J0IHsgQ29udGFpbmVyLCBJbmplY3RhYmxlIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcbmltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50RmFjdG9yeSB7XG4gIHByaXZhdGUgX2xvYWRlcjogTW9kdWxlTG9hZGVyO1xuICBwcml2YXRlIF9jb250YWluZXI6IENvbnRhaW5lcjtcbiAgcHJpdmF0ZSBfY29tcG9uZW50czogTWFwPHN0cmluZywgQ29tcG9uZW50Q29uc3RydWN0b3I+O1xuXG4gIGNvbnN0cnVjdG9yKCBjb250YWluZXI/OiBDb250YWluZXIsIGxvYWRlcj86IE1vZHVsZUxvYWRlciApIHtcbiAgICB0aGlzLl9sb2FkZXIgPSBsb2FkZXI7XG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyIHx8IG5ldyBDb250YWluZXIoKTtcbiAgICB0aGlzLl9jb21wb25lbnRzID0gbmV3IE1hcDxzdHJpbmcsIENvbXBvbmVudENvbnN0cnVjdG9yPigpO1xuXG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIHVuZGVmaW5lZCwgT2JqZWN0ICk7XG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIFwiXCIsIE9iamVjdCApO1xuICB9XG5cbiAgY3JlYXRlQ29udGV4dCggaWQ6IHN0cmluZywgY29uZmlnOiB7fSwgZGVwczogSW5qZWN0YWJsZVtdID0gW10gKTogUnVudGltZUNvbnRleHRcbiAge1xuICAgIGxldCBjaGlsZENvbnRhaW5lcjogQ29udGFpbmVyID0gdGhpcy5fY29udGFpbmVyLmNyZWF0ZUNoaWxkKCk7XG5cbiAgICByZXR1cm4gbmV3IFJ1bnRpbWVDb250ZXh0KCB0aGlzLCBjaGlsZENvbnRhaW5lciwgaWQsIGNvbmZpZywgZGVwcyApO1xuICB9XG5cbiAgZ2V0Q2hpbGRDb250YWluZXIoKTogQ29udGFpbmVyIHtcbiAgICByZXR1cm4gO1xuICB9XG5cbiAgbG9hZENvbXBvbmVudCggY3R4OiBSdW50aW1lQ29udGV4dCwgaWQ6IHN0cmluZyApOiBQcm9taXNlPENvbXBvbmVudD5cbiAge1xuICAgIGxldCBjcmVhdGVDb21wb25lbnQgPSBmdW5jdGlvbiggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKTogQ29tcG9uZW50XG4gICAge1xuICAgICAgbGV0IG5ld0luc3RhbmNlOiBDb21wb25lbnQgPSBjdHguY29udGFpbmVyLmludm9rZSggY3RvciApO1xuXG4gICAgICByZXR1cm4gbmV3SW5zdGFuY2U7XG4gICAgfVxuXG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDb21wb25lbnQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBDaGVjayBjYWNoZVxuICAgICAgbGV0IGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yID0gdGhpcy5nZXQoIGlkICk7XG5cbiAgICAgIGlmICggY3RvciApIHtcbiAgICAgICAgLy8gdXNlIGNhY2hlZCBjb25zdHJ1Y3RvclxuICAgICAgICByZXNvbHZlKCBjcmVhdGVDb21wb25lbnQoIGN0b3IgKSApO1xuICAgICAgfVxuICAgICAgZWxzZSBpZiAoIHRoaXMuX2xvYWRlciApIHtcbiAgICAgICAgLy8gZ290IGEgbG9hZGVkLCBzbyB0cnkgdG8gbG9hZCB0aGUgbW9kdWxlIC4uLlxuICAgICAgICB0aGlzLl9sb2FkZXIubG9hZE1vZHVsZSggaWQgKVxuICAgICAgICAgIC50aGVuKCAoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICkgPT4ge1xuXG4gICAgICAgICAgICAvLyByZWdpc3RlciBsb2FkZWQgY29tcG9uZW50XG4gICAgICAgICAgICBtZS5fY29tcG9uZW50cy5zZXQoIGlkLCBjdG9yICk7XG5cbiAgICAgICAgICAgIC8vIGluc3RhbnRpYXRlIGFuZCByZXNvbHZlXG4gICAgICAgICAgICByZXNvbHZlKCBjcmVhdGVDb21wb25lbnQoIGN0b3IgKSApO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLmNhdGNoKCAoIGUgKSA9PiB7XG4gICAgICAgICAgICByZWplY3QoICdDb21wb25lbnRGYWN0b3J5OiBVbmFibGUgdG8gbG9hZCBjb21wb25lbnQgXCInICsgaWQgKyAnXCIgLSAnICsgZSApO1xuICAgICAgICAgIH0gKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBvb3BzLiBubyBsb2FkZXIgLi4gbm8gY29tcG9uZW50XG4gICAgICAgIHJlamVjdCggJ0NvbXBvbmVudEZhY3Rvcnk6IENvbXBvbmVudCBcIicgKyBpZCArICdcIiBub3QgcmVnaXN0ZXJlZCwgYW5kIExvYWRlciBub3QgYXZhaWxhYmxlJyApO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgZ2V0KCBpZDogc3RyaW5nICk6IENvbXBvbmVudENvbnN0cnVjdG9yIHtcbiAgICByZXR1cm4gdGhpcy5fY29tcG9uZW50cy5nZXQoIGlkICk7XG4gIH1cbiAgcmVnaXN0ZXIoIGlkOiBzdHJpbmcsIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICkge1xuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCBpZCwgY3RvciApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbmV4cG9ydCB0eXBlIEVuZFBvaW50UmVmID0geyBub2RlSUQ6IHN0cmluZywgcG9ydElEOiBzdHJpbmcgfTtcblxuZXhwb3J0IGNsYXNzIExpbmtcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NoYW5uZWw6IENoYW5uZWw7XG4gIHByb3RlY3RlZCBfZnJvbTogRW5kUG9pbnRSZWY7XG4gIHByb3RlY3RlZCBfdG86IEVuZFBvaW50UmVmO1xuXG4gIHByb3RlY3RlZCBfcHJvdG9jb2xJRDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCBcIlwiO1xuICAgIC8vdGhpcy5fY2hhbm5lbCA9IG51bGw7XG4gICAgdGhpcy5fZnJvbSA9IGF0dHJpYnV0ZXNbICdmcm9tJyBdO1xuICAgIHRoaXMuX3RvID0gYXR0cmlidXRlc1sgJ3RvJyBdO1xuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBhdHRyaWJ1dGVzWyAncHJvdG9jb2wnIF0gfHwgJ2FueSc7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IHg6IDEwMCwgeTogMTAwIH07XG4gIH1cblxuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIGxldCBsaW5rID0ge1xuICAgICAgaWQ6IHRoaXMuX2lkLFxuICAgICAgcHJvdG9jb2w6ICggdGhpcy5fcHJvdG9jb2xJRCAhPSAnYW55JyApID8gdGhpcy5fcHJvdG9jb2xJRCA6IHVuZGVmaW5lZCxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhLFxuICAgICAgZnJvbTogdGhpcy5fZnJvbSxcbiAgICAgIHRvOiB0aGlzLl90b1xuICAgIH07XG5cbiAgICByZXR1cm4gbGluaztcbiAgfVxuXG4gIHNldCBpZCggaWQ6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLl9pZCA9IGlkO1xuICB9XG5cbiAgY29ubmVjdCggY2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICAvLyBpZGVudGlmeSBmcm9tUG9ydCBpbiBmcm9tTm9kZVxuICAgIGxldCBmcm9tUG9ydDogUG9ydCA9IHRoaXMuZnJvbU5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl9mcm9tLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApO1xuXG4gICAgLy8gaWRlbnRpZnkgdG9Qb3J0IGluIHRvTm9kZVxuICAgIGxldCB0b1BvcnQ6IFBvcnQgPSB0aGlzLnRvTm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX3RvLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApO1xuXG4gICAgdGhpcy5fY2hhbm5lbCA9IGNoYW5uZWw7XG5cbiAgICBmcm9tUG9ydC5lbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgICB0b1BvcnQuZW5kUG9pbnQuYXR0YWNoKCBjaGFubmVsICk7XG4gIH1cblxuICBkaXNjb25uZWN0KCk6IENoYW5uZWxcbiAge1xuICAgIGxldCBjaGFuID0gdGhpcy5fY2hhbm5lbDtcblxuICAgIGlmICggY2hhbiApXG4gICAge1xuICAgICAgdGhpcy5fY2hhbm5lbC5lbmRQb2ludHMuZm9yRWFjaCggKCBlbmRQb2ludCApID0+IHtcbiAgICAgICAgZW5kUG9pbnQuZGV0YWNoKCB0aGlzLl9jaGFubmVsICk7XG4gICAgICB9ICk7XG5cbiAgICAgIHRoaXMuX2NoYW5uZWwgPSB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIGNoYW47XG4gIH1cblxuICBnZXQgZnJvbU5vZGUoKTogTm9kZVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyLmdldE5vZGVCeUlEKCB0aGlzLl9mcm9tLm5vZGVJRCApO1xuICB9XG5cbiAgZ2V0IGZyb21Qb3J0KCk6IFBvcnRcbiAge1xuICAgIGxldCBub2RlID0gdGhpcy5mcm9tTm9kZTtcblxuICAgIHJldHVybiAobm9kZSkgPyBub2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fZnJvbS5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKSA6IHVuZGVmaW5lZDtcbiAgfVxuXG4gIHNldCBmcm9tUG9ydCggcG9ydDogUG9ydCApXG4gIHtcbiAgICB0aGlzLl9mcm9tID0ge1xuICAgICAgbm9kZUlEOiBwb3J0Lm93bmVyLmlkLFxuICAgICAgcG9ydElEOiBwb3J0LmlkXG4gICAgfTtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBwb3J0LnByb3RvY29sSUQ7XG4gIH1cblxuICBnZXQgdG9Ob2RlKCk6IE5vZGVcbiAge1xuICAgIHJldHVybiB0aGlzLl9vd25lci5nZXROb2RlQnlJRCggdGhpcy5fdG8ubm9kZUlEICk7XG4gIH1cblxuICBnZXQgdG9Qb3J0KCk6IFBvcnRcbiAge1xuICAgIGxldCBub2RlID0gdGhpcy50b05vZGU7XG5cbiAgICByZXR1cm4gKG5vZGUpID8gbm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX3RvLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApIDogdW5kZWZpbmVkO1xuICB9XG5cbiAgc2V0IHRvUG9ydCggcG9ydDogUG9ydCApXG4gIHtcbiAgICB0aGlzLl90byA9IHtcbiAgICAgIG5vZGVJRDogcG9ydC5vd25lci5pZCxcbiAgICAgIHBvcnRJRDogcG9ydC5pZFxuICAgIH07XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gcG9ydC5wcm90b2NvbElEO1xuICB9XG5cbiAgZ2V0IHByb3RvY29sSUQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcHJvdG9jb2xJRDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3RvcnkgfSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IFJ1bnRpbWVDb250ZXh0LCBSdW5TdGF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBMaW5rIH0gZnJvbSAnLi9saW5rJztcbmltcG9ydCB7IFBvcnQsIFB1YmxpY1BvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG5leHBvcnQgY2xhc3MgTmV0d29yayBleHRlbmRzIEV2ZW50SHViXG57XG4gIHN0YXRpYyBFVkVOVF9TVEFURV9DSEFOR0UgPSAnbmV0d29yazpzdGF0ZS1jaGFuZ2UnO1xuICBzdGF0aWMgRVZFTlRfR1JBUEhfQ0hBTkdFID0gJ25ldHdvcms6Z3JhcGgtY2hhbmdlJztcblxuICBwcml2YXRlIF9ncmFwaDogR3JhcGg7XG5cbiAgcHJpdmF0ZSBfZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeTtcblxuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgZ3JhcGg/OiBHcmFwaCApXG4gIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG4gICAgdGhpcy5fZ3JhcGggPSBncmFwaCB8fCBuZXcgR3JhcGgoIG51bGwsIHt9ICk7XG5cbiAgICBsZXQgbWUgPSB0aGlzO1xuICAgIHRoaXMuX2dyYXBoLnN1YnNjcmliZSggR3JhcGguRVZFTlRfQUREX05PREUsICggZGF0YTogeyBub2RlOiBOb2RlIH0gKT0+IHtcbiAgICAgIGxldCBydW5TdGF0ZTogUnVuU3RhdGUgPSBtZS5fZ3JhcGguY29udGV4dC5ydW5TdGF0ZTtcblxuICAgICAgaWYgKCBydW5TdGF0ZSAhPSBSdW5TdGF0ZS5ORVdCT1JOIClcbiAgICAgIHtcbiAgICAgICAgbGV0IHsgbm9kZSB9ID0gZGF0YTtcblxuICAgICAgICBub2RlLmxvYWRDb21wb25lbnQoIG1lLl9mYWN0b3J5IClcbiAgICAgICAgICAudGhlbiggKCk9PiB7XG4gICAgICAgICAgICBpZiAoIE5ldHdvcmsuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQsIFJ1blN0YXRlLlJFQURZIF0sIHJ1blN0YXRlICkgKVxuICAgICAgICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBub2RlLCBSdW5TdGF0ZS5SRUFEWSApO1xuXG4gICAgICAgICAgICBpZiAoIE5ldHdvcmsuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SVU5OSU5HLCBSdW5TdGF0ZS5QQVVTRUQgXSwgcnVuU3RhdGUgKSApXG4gICAgICAgICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIG5vZGUsIHJ1blN0YXRlICk7XG5cbiAgICAgICAgICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9HUkFQSF9DSEFOR0UsIHsgbm9kZTogbm9kZSB9ICk7XG4gICAgICAgICAgfSlcbiAgICAgIH1cbiAgICB9ICk7XG4gIH1cblxuICBnZXQgZ3JhcGgoKTogR3JhcGgge1xuICAgIHJldHVybiB0aGlzLl9ncmFwaDtcbiAgfVxuXG4gIC8qKlxuICAqIExvYWQgYWxsIGNvbXBvbmVudHNcbiAgKi9cbiAgbG9hZENvbXBvbmVudHMoKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IFJ1blN0YXRlLkxPQURJTkcgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX2dyYXBoLmxvYWRDb21wb25lbnQoIHRoaXMuX2ZhY3RvcnkgKS50aGVuKCAoKT0+IHtcbiAgICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IFJ1blN0YXRlLkxPQURFRCB9ICk7XG4gICAgfSk7XG4gIH1cblxuICBpbml0aWFsaXplKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJFQURZICk7XG4gIH1cblxuICB0ZWFyZG93bigpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5MT0FERUQgKTtcbiAgfVxuXG4gIHN0YXRpYyBpblN0YXRlKCBzdGF0ZXM6IFJ1blN0YXRlW10sIHJ1blN0YXRlOiBSdW5TdGF0ZSApOiBib29sZWFuIHtcbiAgICByZXR1cm4gbmV3IFNldDxSdW5TdGF0ZT4oIHN0YXRlcyApLmhhcyggcnVuU3RhdGUgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFsdGVyIHJ1bi1zdGF0ZSBvZiBhIE5vZGUgLSBMT0FERUQsIFJFQURZLCBSVU5OSU5HIG9yIFBBVVNFRC5cbiAgKiBUcmlnZ2VycyBTZXR1cCBvciBUZWFyZG93biBpZiB0cmFuc2l0aW9uaW5nIGJldHdlZW4gUkVBRFkgYW5kIExPQURFRFxuICAqIFdpcmV1cCBhIGdyYXBoLCBjcmVhdGluZyBDaGFubmVsIGJldHdlZW4gbGlua2VkIE5vZGVzXG4gICogQWN0cyByZWN1cnNpdmVseSwgd2lyaW5nIHVwIGFueSBzdWItZ3JhcGhzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHNldFJ1blN0YXRlKCBub2RlOiBOb2RlLCBydW5TdGF0ZTogUnVuU3RhdGUgKVxuICB7XG4gICAgbGV0IGN0eCA9IG5vZGUuY29udGV4dDtcbiAgICBsZXQgY3VycmVudFN0YXRlID0gY3R4LnJ1blN0YXRlO1xuXG4gICAgaWYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKVxuICAgIHtcbiAgICAgIC8vIDEuIFByZXByb2Nlc3NcbiAgICAgIC8vICAgIGEuIEhhbmRsZSB0ZWFyZG93blxuICAgICAgLy8gICAgYi4gUHJvcGFnYXRlIHN0YXRlIGNoYW5nZSB0byBzdWJuZXRzXG4gICAgICBsZXQgbm9kZXM6IE1hcDxzdHJpbmcsIE5vZGU+ID0gbm9kZS5ub2RlcztcblxuICAgICAgaWYgKCAoIHJ1blN0YXRlID09IFJ1blN0YXRlLkxPQURFRCApICYmICggY3VycmVudFN0YXRlID49IFJ1blN0YXRlLlJFQURZICkgKSB7XG4gICAgICAgIC8vIHRlYXJpbmcgZG93biAuLiB1bmxpbmsgZ3JhcGggZmlyc3RcbiAgICAgICAgbGV0IGxpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPiA9IG5vZGUubGlua3M7XG5cbiAgICAgICAgLy8gdW53aXJlIChkZWFjdGl2YXRlIGFuZCBkZXN0cm95ICkgQ2hhbm5lbHMgYmV0d2VlbiBsaW5rZWQgbm9kZXNcbiAgICAgICAgbGlua3MuZm9yRWFjaCggKCBsaW5rICkgPT5cbiAgICAgICAge1xuICAgICAgICAgIE5ldHdvcmsudW53aXJlTGluayggbGluayApO1xuICAgICAgICB9ICk7XG4gICAgICB9XG5cbiAgICAgIC8vIFByb3BhZ2F0ZSBzdGF0ZSBjaGFuZ2UgdG8gc3ViLW5ldHMgZmlyc3RcbiAgICAgIG5vZGVzLmZvckVhY2goIGZ1bmN0aW9uKCBzdWJOb2RlIClcbiAgICAgIHtcbiAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggc3ViTm9kZSwgcnVuU3RhdGUgKTtcbiAgICAgIH0gKTtcblxuICAgICAgLy8gMi4gQ2hhbmdlIHN0YXRlIC4uLlxuICAgICAgY3R4LnNldFJ1blN0YXRlKCBydW5TdGF0ZSApO1xuXG4gICAgICAvLyAzLiBQb3N0cHJvY2Vzc1xuICAgICAgLy8gICAgYS4gSGFuZGxlIHNldHVwXG4gICAgICBpZiAoICggcnVuU3RhdGUgPT0gUnVuU3RhdGUuUkVBRFkgKSAmJiAoIGN1cnJlbnRTdGF0ZSA+PSBSdW5TdGF0ZS5MT0FERUQgKSApIHtcblxuICAgICAgICAvLyBzZXR0aW5nIHVwIC4uIGxpbmt1cCBncmFwaCBmaXJzdFxuICAgICAgICBsZXQgbGlua3M6IE1hcDxzdHJpbmcsIExpbms+ID0gbm9kZS5saW5rcztcbiAgICAgICAgLy8gdHJlYXQgZ3JhcGggcmVjdXJzaXZlbHlcblxuICAgICAgICAvLyAyLiB3aXJldXAgKGNyZWF0ZSBhbmQgYWN0aXZhdGUpIGEgQ2hhbm5lbCBiZXR3ZWVuIGxpbmtlZCBub2Rlc1xuICAgICAgICBsaW5rcy5mb3JFYWNoKCAoIGxpbmsgKSA9PlxuICAgICAgICB7XG4gICAgICAgICAgTmV0d29yay53aXJlTGluayggbGluayApO1xuICAgICAgICB9ICk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIENoYW5nZSBzdGF0ZSAuLi5cbiAgICAgIGN0eC5zZXRSdW5TdGF0ZSggcnVuU3RhdGUgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBVbndpcmUgYSBsaW5rLCByZW1vdmluZyB0aGUgQ2hhbm5lbCBiZXR3ZWVuIHRoZSBsaW5rZWQgTm9kZXNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgdW53aXJlTGluayggbGluazogTGluayApXG4gIHtcbiAgICAvLyBnZXQgbGlua2VkIG5vZGVzIChMaW5rIGZpbmRzIE5vZGVzIGluIHBhcmVudCBHcmFwaClcbiAgICBsZXQgZnJvbU5vZGUgPSBsaW5rLmZyb21Ob2RlO1xuICAgIGxldCB0b05vZGUgPSBsaW5rLnRvTm9kZTtcblxuICAgIGxldCBjaGFuOiBDaGFubmVsID0gbGluay5kaXNjb25uZWN0KCk7XG5cbiAgICBpZiAoIGNoYW4gKVxuICAgICAgY2hhbi5kZWFjdGl2YXRlKCk7XG4gIH1cblxuICAvKipcbiAgKiBXaXJldXAgYSBsaW5rLCBjcmVhdGluZyBDaGFubmVsIGJldHdlZW4gdGhlIGxpbmtlZCBOb2Rlc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyB3aXJlTGluayggbGluazogTGluayApXG4gIHtcbiAgICAvLyBnZXQgbGlua2VkIG5vZGVzIChMaW5rIGZpbmRzIE5vZGVzIGluIHBhcmVudCBHcmFwaClcbiAgICBsZXQgZnJvbU5vZGUgPSBsaW5rLmZyb21Ob2RlO1xuICAgIGxldCB0b05vZGUgPSBsaW5rLnRvTm9kZTtcblxuICAgIC8vZGVidWdNZXNzYWdlKCBcIkxpbmsoXCIrbGluay5pZCtcIik6IFwiICsgbGluay5mcm9tICsgXCIgLT4gXCIgKyBsaW5rLnRvICsgXCIgcHJvdG89XCIrbGluay5wcm90b2NvbCApO1xuXG4gICAgbGV0IGNoYW5uZWwgPSBuZXcgQ2hhbm5lbCgpO1xuXG4gICAgbGluay5jb25uZWN0KCBjaGFubmVsICk7XG5cbiAgICBjaGFubmVsLmFjdGl2YXRlKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0UnVuU3RhdGUoIHJ1blN0YXRlOiBSdW5TdGF0ZSApXG4gIHtcbiAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCB0aGlzLl9ncmFwaCwgcnVuU3RhdGUgKTtcblxuICAgIHRoaXMucHVibGlzaCggTmV0d29yay5FVkVOVF9TVEFURV9DSEFOR0UsIHsgc3RhdGU6IHJ1blN0YXRlIH0gKTtcbiAgfVxuXG4gIHN0YXJ0KCBpbml0aWFsbHlQYXVzZWQ6IGJvb2xlYW4gPSBmYWxzZSApIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBpbml0aWFsbHlQYXVzZWQgPyBSdW5TdGF0ZS5QQVVTRUQgOiBSdW5TdGF0ZS5SVU5OSU5HICk7XG4gIH1cblxuICBzdGVwKCkge1xuICAgIC8vIFRPRE86IFNpbmdsZS1zdGVwXG4gIH1cblxuICBzdG9wKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJFQURZICk7XG4gIH1cblxuICBwYXVzZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5QQVVTRUQgKTtcbiAgfVxuXG4gIHJlc3VtZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SVU5OSU5HICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgRXZlbnRIdWIgfSBmcm9tICcuLi9ldmVudC1odWIvZXZlbnQtaHViJztcblxuaW1wb3J0IHsgTmV0d29yayB9IGZyb20gJy4vbmV0d29yayc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IExpbmsgfSBmcm9tICcuL2xpbmsnO1xuaW1wb3J0IHsgUG9ydCwgUHVibGljUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbi8qKlxuICogQSBHcmFwaCBpcyBhIGNvbGxlY3Rpb24gb2YgTm9kZXMgaW50ZXJjb25uZWN0ZWQgdmlhIExpbmtzLlxuICogQSBHcmFwaCBpcyBpdHNlbGYgYSBOb2RlLCB3aG9zZSBQb3J0cyBhY3QgYXMgcHVibGlzaGVkIEVuZFBvaW50cywgdG8gdGhlIEdyYXBoLlxuICovXG5leHBvcnQgY2xhc3MgR3JhcGggZXh0ZW5kcyBOb2RlXG57XG4gIHN0YXRpYyBFVkVOVF9BRERfTk9ERSA9ICdncmFwaDphZGQtbm9kZSc7XG4gIHN0YXRpYyBFVkVOVF9VUERfTk9ERSA9ICdncmFwaDp1cGQtbm9kZSc7XG4gIHN0YXRpYyBFVkVOVF9ERUxfTk9ERSA9ICdncmFwaDpkZWwtbm9kZSc7XG5cbiAgc3RhdGljIEVWRU5UX0FERF9MSU5LID0gJ2dyYXBoOmFkZC1saW5rJztcbiAgc3RhdGljIEVWRU5UX1VQRF9MSU5LID0gJ2dyYXBoOnVwZC1saW5rJztcbiAgc3RhdGljIEVWRU5UX0RFTF9MSU5LID0gJ2dyYXBoOmRlbC1saW5rJztcblxuICAvKipcbiAgKiBOb2RlcyBpbiB0aGlzIGdyYXBoLiBFYWNoIG5vZGUgbWF5IGJlOlxuICAqICAgMS4gQSBDb21wb25lbnRcbiAgKiAgIDIuIEEgc3ViLWdyYXBoXG4gICovXG4gIHByb3RlY3RlZCBfbm9kZXM6IE1hcDxzdHJpbmcsIE5vZGU+O1xuXG4gIC8vIExpbmtzIGluIHRoaXMgZ3JhcGguIEVhY2ggbm9kZSBtYXkgYmU6XG4gIHByb3RlY3RlZCBfbGlua3M6IE1hcDxzdHJpbmcsIExpbms+O1xuXG4gIC8vIFB1YmxpYyBQb3J0cyBpbiB0aGlzIGdyYXBoLiBJbmhlcml0ZWQgZnJvbSBOb2RlXG4gIC8vIHByaXZhdGUgUG9ydHM7XG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCBvd25lciwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5pbml0RnJvbU9iamVjdCggYXR0cmlidXRlcyApO1xuICB9XG5cbiAgaW5pdEZyb21TdHJpbmcoIGpzb25TdHJpbmc6IHN0cmluZyApXG4gIHtcbiAgICB0aGlzLmluaXRGcm9tT2JqZWN0KCBKU09OLnBhcnNlKCBqc29uU3RyaW5nICkgKTtcbiAgfVxuXG4gIGluaXRGcm9tT2JqZWN0KCBhdHRyaWJ1dGVzOiBhbnkgKSB7XG5cbiAgICB0aGlzLmlkID0gYXR0cmlidXRlcy5pZCB8fCBcIiRncmFwaFwiO1xuXG4gICAgdGhpcy5fbm9kZXMgPSBuZXcgTWFwPHN0cmluZywgTm9kZT4oKTtcbiAgICB0aGlzLl9saW5rcyA9IG5ldyBNYXA8c3RyaW5nLCBMaW5rPigpO1xuXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMubm9kZXMgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkTm9kZSggaWQsIGF0dHJpYnV0ZXMubm9kZXNbIGlkIF0gKTtcbiAgICB9KTtcblxuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLmxpbmtzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZExpbmsoIGlkLCBhdHRyaWJ1dGVzLmxpbmtzWyBpZCBdICk7XG4gICAgfSk7XG4gIH1cblxuICB0b09iamVjdCggb3B0czogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIGdyYXBoID0gc3VwZXIudG9PYmplY3QoKTtcblxuICAgIGxldCBub2RlcyA9IGdyYXBoWyBcIm5vZGVzXCIgXSA9IHt9O1xuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4vLyAgICAgIGlmICggbm9kZSAhPSB0aGlzIClcbiAgICAgICAgbm9kZXNbIGlkIF0gPSBub2RlLnRvT2JqZWN0KCk7XG4gICAgfSk7XG5cbiAgICBsZXQgbGlua3MgPSBncmFwaFsgXCJsaW5rc1wiIF0gPSB7fTtcbiAgICB0aGlzLl9saW5rcy5mb3JFYWNoKCAoIGxpbmssIGlkICkgPT4ge1xuICAgICAgbGlua3NbIGlkIF0gPSBsaW5rLnRvT2JqZWN0KCk7XG4gICAgfSk7XG5cbiAgICByZXR1cm4gZ3JhcGg7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IHBlbmRpbmdDb3VudCA9IDA7XG5cbiAgICAgIGxldCBub2RlcyA9IG5ldyBNYXA8c3RyaW5nLCBOb2RlPiggdGhpcy5fbm9kZXMgKTtcbiAgICAgIG5vZGVzLnNldCggJyRncmFwaCcsIHRoaXMgKTtcblxuICAgICAgbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgICAgbGV0IGRvbmU6IFByb21pc2U8dm9pZD47XG5cbiAgICAgICAgcGVuZGluZ0NvdW50Kys7XG5cbiAgICAgICAgaWYgKCBub2RlID09IHRoaXMgKSB7XG4gICAgICAgICAgZG9uZSA9IHN1cGVyLmxvYWRDb21wb25lbnQoIGZhY3RvcnkgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICBkb25lID0gbm9kZS5sb2FkQ29tcG9uZW50KCBmYWN0b3J5ICk7XG4gICAgICAgIH1cblxuICAgICAgICBkb25lLnRoZW4oICgpID0+IHtcbiAgICAgICAgICAtLXBlbmRpbmdDb3VudDtcbiAgICAgICAgICBpZiAoIHBlbmRpbmdDb3VudCA9PSAwIClcbiAgICAgICAgICAgIHJlc29sdmUoKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKCAoIHJlYXNvbiApID0+IHtcbiAgICAgICAgICByZWplY3QoIHJlYXNvbiApO1xuICAgICAgICB9ICk7XG4gICAgICB9ICk7XG4gICAgfSApO1xuICB9XG5cbiAgcHVibGljIGdldCBub2RlcygpOiBNYXA8c3RyaW5nLCBOb2RlPlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX25vZGVzO1xuICB9XG5cbi8qICBwdWJsaWMgZ2V0QWxsTm9kZXMoKTogTm9kZVtdXG4gIHtcbiAgICBsZXQgbm9kZXM6IE5vZGVbXSA9IFtdO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIC8vIERvbid0IHJlY3Vyc2Ugb24gZ3JhcGgncyBwc2V1ZG8tbm9kZVxuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBub2RlcyA9IG5vZGVzLmNvbmNhdCggbm9kZS5nZXRBbGxOb2RlcygpICk7XG5cbiAgICAgIG5vZGVzLnB1c2goIG5vZGUgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbm9kZXM7XG4gIH0qL1xuXG4gIHB1YmxpYyBnZXQgbGlua3MoKTogTWFwPHN0cmluZywgTGluaz5cbiAge1xuICAgIHJldHVybiB0aGlzLl9saW5rcztcbiAgfVxuXG4vKiAgcHVibGljIGdldEFsbExpbmtzKCk6IExpbmtbXVxuICB7XG4gICAgbGV0IGxpbmtzOiBMaW5rW10gPSBbXTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIGxpbmtzID0gbGlua3MuY29uY2F0KCBub2RlLmdldEFsbExpbmtzKCkgKTtcbiAgICB9IClcblxuICAgIHRoaXMuX2xpbmtzLmZvckVhY2goICggbGluaywgaWQgKSA9PiB7XG4gICAgICBsaW5rcy5wdXNoKCBsaW5rICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIGxpbmtzO1xuICB9Ki9cblxuLyogIHB1YmxpYyBnZXRBbGxQb3J0cygpOiBQb3J0W11cbiAge1xuICAgIGxldCBwb3J0czogUG9ydFtdID0gc3VwZXIuZ2V0UG9ydEFycmF5KCk7XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBwb3J0cyA9IHBvcnRzLmNvbmNhdCggbm9kZS5nZXRBbGxQb3J0cygpICk7XG4gICAgICBlbHNlXG4gICAgICAgIHBvcnRzID0gcG9ydHMuY29uY2F0KCBub2RlLmdldFBvcnRBcnJheSgpICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIHBvcnRzO1xuICB9Ki9cblxuICBwdWJsaWMgZ2V0Tm9kZUJ5SUQoIGlkOiBzdHJpbmcgKTogTm9kZVxuICB7XG4gICAgaWYgKCBpZCA9PSAnJGdyYXBoJyApXG4gICAgICByZXR1cm4gdGhpcztcblxuICAgIHJldHVybiB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgYWRkTm9kZSggaWQ6IHN0cmluZywgYXR0cmlidXRlcz86IHt9ICk6IE5vZGUge1xuXG4gICAgbGV0IG5vZGUgPSBuZXcgTm9kZSggdGhpcywgYXR0cmlidXRlcyApO1xuXG4gICAgbm9kZS5pZCA9IGlkO1xuXG4gICAgdGhpcy5fbm9kZXMuc2V0KCBpZCwgbm9kZSApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9BRERfTk9ERSwgeyBub2RlOiBub2RlIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgcHVibGljIHJlbmFtZU5vZGUoIGlkOiBzdHJpbmcsIG5ld0lEOiBzdHJpbmcgKSB7XG5cbiAgICBsZXQgbm9kZSA9IHRoaXMuX25vZGVzLmdldCggaWQgKTtcblxuICAgIGlmICggaWQgIT0gbmV3SUQgKVxuICAgIHtcbiAgICAgIGxldCBldmVudERhdGEgPSB7IG5vZGU6IG5vZGUsIGF0dHJzOiB7IGlkOiBub2RlLmlkIH0gfTtcblxuICAgICAgdGhpcy5fbm9kZXMuZGVsZXRlKCBpZCApO1xuXG4gICAgICBub2RlLmlkID0gbmV3SUQ7XG5cbiAgICAgIHRoaXMuX25vZGVzLnNldCggbmV3SUQsIG5vZGUgKTtcblxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9VUERfTk9ERSwgZXZlbnREYXRhICk7XG4gICAgfVxuICB9XG5cbiAgcHVibGljIHJlbW92ZU5vZGUoIGlkOiBzdHJpbmcgKTogYm9vbGVhbiB7XG5cbiAgICBsZXQgbm9kZSA9IHRoaXMuX25vZGVzLmdldCggaWQgKTtcbiAgICBpZiAoIG5vZGUgKVxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9ERUxfTk9ERSwgeyBub2RlOiBub2RlIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9ub2Rlcy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0TGlua0J5SUQoIGlkOiBzdHJpbmcgKTogTGluayB7XG5cbiAgICByZXR1cm4gdGhpcy5fbGlua3NbIGlkIF07XG4gIH1cblxuICBwdWJsaWMgYWRkTGluayggaWQ6IHN0cmluZywgYXR0cmlidXRlcz86IHt9ICk6IExpbmsge1xuXG4gICAgbGV0IGxpbmsgPSBuZXcgTGluayggdGhpcywgYXR0cmlidXRlcyApO1xuXG4gICAgbGluay5pZCA9IGlkO1xuXG4gICAgdGhpcy5fbGlua3Muc2V0KCBpZCwgbGluayApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9BRERfTElOSywgeyBsaW5rOiBsaW5rIH0gKTtcblxuICAgIHJldHVybiBsaW5rO1xuICB9XG5cbiAgcHVibGljIHJlbmFtZUxpbmsoIGlkOiBzdHJpbmcsIG5ld0lEOiBzdHJpbmcgKSB7XG5cbiAgICBsZXQgbGluayA9IHRoaXMuX2xpbmtzLmdldCggaWQgKTtcblxuICAgIHRoaXMuX2xpbmtzLmRlbGV0ZSggaWQgKTtcblxuICAgIGxldCBldmVudERhdGEgPSB7IGxpbms6IGxpbmssIGF0dHJzOiB7IGlkOiBsaW5rLmlkIH0gfTtcblxuICAgIGxpbmsuaWQgPSBuZXdJRDtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfVVBEX05PREUsIGV2ZW50RGF0YSApO1xuXG4gICAgdGhpcy5fbGlua3Muc2V0KCBuZXdJRCwgbGluayApO1xuICB9XG5cbiAgcHVibGljIHJlbW92ZUxpbmsoIGlkOiBzdHJpbmcgKTogYm9vbGVhbiB7XG5cbiAgICBsZXQgbGluayA9IHRoaXMuX2xpbmtzLmdldCggaWQgKTtcbiAgICBpZiAoIGxpbmsgKVxuICAgICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9ERUxfTElOSywgeyBsaW5rOiBsaW5rIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9saW5rcy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBwdWJsaWMgYWRkUHVibGljUG9ydCggaWQ6IHN0cmluZywgYXR0cmlidXRlczoge30gKTogUHVibGljUG9ydFxuICB7XG4gICAgYXR0cmlidXRlc1tcImlkXCJdID0gaWQ7XG5cbiAgICBsZXQgcG9ydCA9IG5ldyBQdWJsaWNQb3J0KCB0aGlzLCBudWxsLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLl9wb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlTG9hZGVyIH0gZnJvbSAnLi9tb2R1bGUtbG9hZGVyJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3RvcnkgfSBmcm9tICcuL2NvbXBvbmVudC1mYWN0b3J5JztcblxuaW1wb3J0IHsgQ29udGFpbmVyIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcblxuXG5leHBvcnQgY2xhc3MgU2ltdWxhdGlvbkVuZ2luZVxue1xuICBsb2FkZXI6IE1vZHVsZUxvYWRlcjtcbiAgY29udGFpbmVyOiBDb250YWluZXI7XG5cbiAgLyoqXG4gICogQ3JlYXRlcyBhbiBpbnN0YW5jZSBvZiBTaW11bGF0aW9uRW5naW5lLlxuICAqIEBwYXJhbSBsb2FkZXIgVGhlIG1vZHVsZSBsb2FkZXIuXG4gICogQHBhcmFtIGNvbnRhaW5lciBUaGUgcm9vdCBESSBjb250YWluZXIgZm9yIHRoZSBzaW11bGF0aW9uLlxuICAqL1xuICBjb25zdHJ1Y3RvciggbG9hZGVyOiBNb2R1bGVMb2FkZXIsIGNvbnRhaW5lcjogQ29udGFpbmVyICkge1xuICAgIHRoaXMubG9hZGVyID0gbG9hZGVyO1xuICAgIHRoaXMuY29udGFpbmVyID0gY29udGFpbmVyO1xuICB9XG5cblxuICAvKipcbiAgKiBSZXR1cm4gYSBDb21wb25lbnRGYWN0b3J5IGZhY2FkZVxuICAqL1xuICBnZXRDb21wb25lbnRGYWN0b3J5KCk6IENvbXBvbmVudEZhY3Rvcnkge1xuICAgIHJldHVybiBuZXcgQ29tcG9uZW50RmFjdG9yeSggdGhpcy5jb250YWluZXIsIHRoaXMubG9hZGVyICk7XG4gIH1cblxufVxuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
