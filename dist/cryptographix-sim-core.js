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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJraW5kL2tpbmQudHMiLCJtZXNzYWdpbmcvbWVzc2FnZS50cyIsInJ1bnRpbWUvdGFzay1zY2hlZHVsZXIudHMiLCJtZXNzYWdpbmcvY2hhbm5lbC50cyIsIm1lc3NhZ2luZy9lbmQtcG9pbnQudHMiLCJtZXNzYWdpbmcvcHJvdG9jb2wudHMiLCJjb21wb25lbnQvcG9ydC1pbmZvLnRzIiwiY29tcG9uZW50L2NvbXBvbmVudC1pbmZvLnRzIiwiY29tcG9uZW50L3N0b3JlLWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL3dlYmNyeXB0by50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvZGVzLnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9jcnlwdG9ncmFwaGljLXNlcnZpY2UuanMiLCJkZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXIudHMiLCJldmVudC1odWIvZXZlbnQtaHViLnRzIiwiZ3JhcGgvcG9ydC50cyIsImdyYXBoL25vZGUudHMiLCJydW50aW1lL3J1bnRpbWUtY29udGV4dC50cyIsInJ1bnRpbWUvbW9kdWxlLWxvYWRlci50cyIsInJ1bnRpbWUvY29tcG9uZW50LWZhY3RvcnkudHMiLCJncmFwaC9saW5rLnRzIiwiZ3JhcGgvbmV0d29yay50cyIsImdyYXBoL2dyYXBoLnRzIiwicnVudGltZS9zaW11bGF0aW9uLWVuZ2luZS50cyJdLCJuYW1lcyI6WyJIZXhDb2RlYyIsIkhleENvZGVjLmRlY29kZSIsIkJBU0U2NFNQRUNJQUxTIiwiQmFzZTY0Q29kZWMiLCJCYXNlNjRDb2RlYy5kZWNvZGUiLCJCYXNlNjRDb2RlYy5kZWNvZGUuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLnB1c2giLCJCYXNlNjRDb2RlYy5lbmNvZGUiLCJCYXNlNjRDb2RlYy5lbmNvZGUuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLnRyaXBsZXRUb0Jhc2U2NCIsIkJ5dGVFbmNvZGluZyIsIkJ5dGVBcnJheSIsIkJ5dGVBcnJheS5jb25zdHJ1Y3RvciIsIkJ5dGVBcnJheS5lbmNvZGluZ1RvU3RyaW5nIiwiQnl0ZUFycmF5LnN0cmluZ1RvRW5jb2RpbmciLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJFbnVtIiwiSW50ZWdlciIsIkZpZWxkQXJyYXkiLCJLaW5kSW5mbyIsIktpbmRJbmZvLmNvbnN0cnVjdG9yIiwiS2luZEJ1aWxkZXIiLCJLaW5kQnVpbGRlci5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyLmluaXQiLCJLaW5kQnVpbGRlci5maWVsZCIsIktpbmRCdWlsZGVyLmJvb2xGaWVsZCIsIktpbmRCdWlsZGVyLm51bWJlckZpZWxkIiwiS2luZEJ1aWxkZXIuaW50ZWdlckZpZWxkIiwiS2luZEJ1aWxkZXIudWludDMyRmllbGQiLCJLaW5kQnVpbGRlci5ieXRlRmllbGQiLCJLaW5kQnVpbGRlci5zdHJpbmdGaWVsZCIsIktpbmRCdWlsZGVyLmtpbmRGaWVsZCIsIktpbmRCdWlsZGVyLmVudW1GaWVsZCIsIktpbmQiLCJLaW5kLmdldEtpbmRJbmZvIiwiS2luZC5pbml0RmllbGRzIiwiTWVzc2FnZSIsIk1lc3NhZ2UuY29uc3RydWN0b3IiLCJNZXNzYWdlLmhlYWRlciIsIk1lc3NhZ2UucGF5bG9hZCIsIktpbmRNZXNzYWdlIiwiVGFza1NjaGVkdWxlciIsIlRhc2tTY2hlZHVsZXIuY29uc3RydWN0b3IiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlciIsIlRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyLnJlcXVlc3RGbHVzaCIsIlRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lciIsIlRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoLmhhbmRsZUZsdXNoVGltZXIiLCJUYXNrU2NoZWR1bGVyLnNodXRkb3duIiwiVGFza1NjaGVkdWxlci5xdWV1ZVRhc2siLCJUYXNrU2NoZWR1bGVyLmZsdXNoVGFza1F1ZXVlIiwiVGFza1NjaGVkdWxlci5vbkVycm9yIiwiQ2hhbm5lbCIsIkNoYW5uZWwuY29uc3RydWN0b3IiLCJDaGFubmVsLnNldERlbGl2ZXJ5SG9vayIsIkNoYW5uZWwuc2h1dGRvd24iLCJDaGFubmVsLmFjdGl2ZSIsIkNoYW5uZWwuYWN0aXZhdGUiLCJDaGFubmVsLmRlYWN0aXZhdGUiLCJDaGFubmVsLmFkZEVuZFBvaW50IiwiQ2hhbm5lbC5yZW1vdmVFbmRQb2ludCIsIkNoYW5uZWwuZW5kUG9pbnRzIiwiQ2hhbm5lbC5zZW5kTWVzc2FnZSIsIkRpcmVjdGlvbiIsIkVuZFBvaW50IiwiRW5kUG9pbnQuY29uc3RydWN0b3IiLCJFbmRQb2ludC5zaHV0ZG93biIsIkVuZFBvaW50LmlkIiwiRW5kUG9pbnQuYXR0YWNoIiwiRW5kUG9pbnQuZGV0YWNoIiwiRW5kUG9pbnQuZGV0YWNoQWxsIiwiRW5kUG9pbnQuYXR0YWNoZWQiLCJFbmRQb2ludC5kaXJlY3Rpb24iLCJFbmRQb2ludC5oYW5kbGVNZXNzYWdlIiwiRW5kUG9pbnQuc2VuZE1lc3NhZ2UiLCJFbmRQb2ludC5vbk1lc3NhZ2UiLCJQcm90b2NvbFR5cGVCaXRzIiwiUHJvdG9jb2wiLCJDbGllbnRTZXJ2ZXJQcm90b2NvbCIsIkFQRFUiLCJBUERVTWVzc2FnZSIsIkFQRFVQcm90b2NvbCIsIlBvcnRJbmZvIiwiUG9ydEluZm8uY29uc3RydWN0b3IiLCJDb21wb25lbnRJbmZvIiwiQ29tcG9uZW50SW5mby5jb25zdHJ1Y3RvciIsIlN0b3JlSW5mbyIsIkNvbXBvbmVudEJ1aWxkZXIiLCJDb21wb25lbnRCdWlsZGVyLmNvbnN0cnVjdG9yIiwiQ29tcG9uZW50QnVpbGRlci5pbml0IiwiQ29tcG9uZW50QnVpbGRlci5jb25maWciLCJDb21wb25lbnRCdWlsZGVyLnBvcnQiLCJDcnlwdG9ncmFwaGljT3BlcmF0aW9uIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUmVnaXN0cnkuY29uc3RydWN0b3IiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LmdldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldFNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5LnNldEtleVNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyS2V5U2VydmljZSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0cnkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmVuY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRpZ2VzdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuc2lnbiIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudmVyaWZ5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5leHBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmdlbmVyYXRlS2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5pbXBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLmRlcml2ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIuZGVyaXZlQml0cyIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIud3JhcEtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIudW53cmFwS2V5IiwiV2ViQ3J5cHRvU2VydmljZSIsIldlYkNyeXB0b1NlcnZpY2UuY29uc3RydWN0b3IiLCJXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZSIsIldlYkNyeXB0b1NlcnZpY2UuZW5jcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGVjcnlwdCIsIldlYkNyeXB0b1NlcnZpY2UuZGlnZXN0IiwiV2ViQ3J5cHRvU2VydmljZS5leHBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLmdlbmVyYXRlS2V5IiwiV2ViQ3J5cHRvU2VydmljZS5pbXBvcnRLZXkiLCJXZWJDcnlwdG9TZXJ2aWNlLnNpZ24iLCJXZWJDcnlwdG9TZXJ2aWNlLnZlcmlmeSIsIkRFU1NlY3JldEtleSIsIkRFU1NlY3JldEtleS5jb25zdHJ1Y3RvciIsIkRFU1NlY3JldEtleS5hbGdvcml0aG0iLCJERVNTZWNyZXRLZXkuZXh0cmFjdGFibGUiLCJERVNTZWNyZXRLZXkudHlwZSIsIkRFU1NlY3JldEtleS51c2FnZXMiLCJERVNTZWNyZXRLZXkua2V5TWF0ZXJpYWwiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZSIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmNvbnN0cnVjdG9yIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZW5jcnlwdCIsIkRFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlY3J5cHQiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5pbXBvcnRLZXkiLCJERVNDcnlwdG9ncmFwaGljU2VydmljZS5zaWduIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzIiwiREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVzLmRlc19jcmVhdGVLZXlzIiwiRXZlbnRIdWIiLCJFdmVudEh1Yi5jb25zdHJ1Y3RvciIsIkV2ZW50SHViLnB1Ymxpc2giLCJFdmVudEh1Yi5zdWJzY3JpYmUiLCJFdmVudEh1Yi5zdWJzY3JpYmVPbmNlIiwiUG9ydCIsIlBvcnQuY29uc3RydWN0b3IiLCJQb3J0LmVuZFBvaW50IiwiUG9ydC50b09iamVjdCIsIlBvcnQub3duZXIiLCJQb3J0LnByb3RvY29sSUQiLCJQb3J0LmlkIiwiUG9ydC5kaXJlY3Rpb24iLCJQdWJsaWNQb3J0IiwiUHVibGljUG9ydC5jb25zdHJ1Y3RvciIsIlB1YmxpY1BvcnQuY29ubmVjdFByaXZhdGUiLCJQdWJsaWNQb3J0LmRpc2Nvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC50b09iamVjdCIsIk5vZGUiLCJOb2RlLmNvbnN0cnVjdG9yIiwiTm9kZS50b09iamVjdCIsIk5vZGUub3duZXIiLCJOb2RlLmlkIiwiTm9kZS51cGRhdGVQb3J0cyIsIk5vZGUuYWRkUGxhY2Vob2xkZXJQb3J0IiwiTm9kZS5wb3J0cyIsIk5vZGUuZ2V0UG9ydEFycmF5IiwiTm9kZS5nZXRQb3J0QnlJRCIsIk5vZGUuaWRlbnRpZnlQb3J0IiwiTm9kZS5yZW1vdmVQb3J0IiwiTm9kZS5sb2FkQ29tcG9uZW50IiwiTm9kZS5jb250ZXh0IiwiTm9kZS51bmxvYWRDb21wb25lbnQiLCJSdW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0IiwiUnVudGltZUNvbnRleHQuY29uc3RydWN0b3IiLCJSdW50aW1lQ29udGV4dC5ub2RlIiwiUnVudGltZUNvbnRleHQuaW5zdGFuY2UiLCJSdW50aW1lQ29udGV4dC5jb250YWluZXIiLCJSdW50aW1lQ29udGV4dC5sb2FkIiwiUnVudGltZUNvbnRleHQucnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dC5pblN0YXRlIiwiUnVudGltZUNvbnRleHQuc2V0UnVuU3RhdGUiLCJSdW50aW1lQ29udGV4dC5yZWxlYXNlIiwiTW9kdWxlUmVnaXN0cnlFbnRyeSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkuY29uc3RydWN0b3IiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIuY29uc3RydWN0b3IiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIuZ2V0T3JDcmVhdGVNb2R1bGVSZWdpc3RyeUVudHJ5IiwiU3lzdGVtTW9kdWxlTG9hZGVyLmxvYWRNb2R1bGUiLCJDb21wb25lbnRGYWN0b3J5IiwiQ29tcG9uZW50RmFjdG9yeS5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEZhY3RvcnkuY3JlYXRlQ29udGV4dCIsIkNvbXBvbmVudEZhY3RvcnkuZ2V0Q2hpbGRDb250YWluZXIiLCJDb21wb25lbnRGYWN0b3J5LmxvYWRDb21wb25lbnQiLCJDb21wb25lbnRGYWN0b3J5LmdldCIsIkNvbXBvbmVudEZhY3RvcnkucmVnaXN0ZXIiLCJMaW5rIiwiTGluay5jb25zdHJ1Y3RvciIsIkxpbmsudG9PYmplY3QiLCJMaW5rLmlkIiwiTGluay5jb25uZWN0IiwiTGluay5kaXNjb25uZWN0IiwiTGluay5mcm9tTm9kZSIsIkxpbmsuZnJvbVBvcnQiLCJMaW5rLnRvTm9kZSIsIkxpbmsudG9Qb3J0IiwiTGluay5wcm90b2NvbElEIiwiTmV0d29yayIsIk5ldHdvcmsuY29uc3RydWN0b3IiLCJOZXR3b3JrLmdyYXBoIiwiTmV0d29yay5sb2FkQ29tcG9uZW50cyIsIk5ldHdvcmsuaW5pdGlhbGl6ZSIsIk5ldHdvcmsudGVhcmRvd24iLCJOZXR3b3JrLmluU3RhdGUiLCJOZXR3b3JrLnNldFJ1blN0YXRlIiwiTmV0d29yay51bndpcmVMaW5rIiwiTmV0d29yay53aXJlTGluayIsIk5ldHdvcmsuc3RhcnQiLCJOZXR3b3JrLnN0ZXAiLCJOZXR3b3JrLnN0b3AiLCJOZXR3b3JrLnBhdXNlIiwiTmV0d29yay5yZXN1bWUiLCJHcmFwaCIsIkdyYXBoLmNvbnN0cnVjdG9yIiwiR3JhcGguaW5pdEZyb21TdHJpbmciLCJHcmFwaC5pbml0RnJvbU9iamVjdCIsIkdyYXBoLnRvT2JqZWN0IiwiR3JhcGgubG9hZENvbXBvbmVudCIsIkdyYXBoLm5vZGVzIiwiR3JhcGgubGlua3MiLCJHcmFwaC5nZXROb2RlQnlJRCIsIkdyYXBoLmFkZE5vZGUiLCJHcmFwaC5yZW5hbWVOb2RlIiwiR3JhcGgucmVtb3ZlTm9kZSIsIkdyYXBoLmdldExpbmtCeUlEIiwiR3JhcGguYWRkTGluayIsIkdyYXBoLnJlbmFtZUxpbmsiLCJHcmFwaC5yZW1vdmVMaW5rIiwiR3JhcGguYWRkUHVibGljUG9ydCIsIlNpbXVsYXRpb25FbmdpbmUiLCJTaW11bGF0aW9uRW5naW5lLmNvbnN0cnVjdG9yIiwiU2ltdWxhdGlvbkVuZ2luZS5nZXRDb21wb25lbnRGYWN0b3J5Il0sIm1hcHBpbmdzIjoiQUFBQTtJQUlFQSxPQUFPQSxNQUFNQSxDQUFFQSxDQUFTQTtRQUV0QkMsRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsWUFBWUEsSUFBSUEsU0FBVUEsQ0FBQ0EsQ0FDekNBLENBQUNBO1lBQ0NBLElBQUlBLEdBQUdBLEdBQUdBLGtCQUFrQkEsQ0FBQ0E7WUFDN0JBLElBQUlBLEtBQUtBLEdBQUdBLDZCQUE2QkEsQ0FBQ0E7WUFDMUNBLElBQUlBLEdBQUdBLEdBQWFBLEVBQUVBLENBQUNBO1lBQ3ZCQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtnQkFDdkJBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBQzNCQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxXQUFXQSxFQUFFQSxDQUFDQTtZQUN4QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3hCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ2pDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUM5QkEsUUFBUUEsQ0FBQ0EsWUFBWUEsR0FBR0EsR0FBR0EsQ0FBQ0E7UUFDOUJBLENBQUNBO1FBRURBLElBQUlBLEdBQUdBLEdBQWFBLEVBQUVBLENBQUNBO1FBQ3ZCQSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFDQSxFQUFFQSxVQUFVQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM3QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFDakNBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENB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QSxDQUFFQSxDQUFDQTtRQUc5REEsSUFBSUEsQ0FBQ0EsR0FBR0EsWUFBWUEsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7UUFFdkRBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBRVZBLGNBQWVBLENBQU9BO1lBQ3BCRSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNmQSxDQUFDQTtRQUVERixJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVqQkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7WUFDN0JBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQzNJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxRQUFRQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUM3QkEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDMUJBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1FBQ25CQSxDQUFDQTtRQUVEQSxFQUFFQSxDQUFDQSxDQUFDQSxZQUFZQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUN2QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDMUVBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1FBQ25CQSxDQUFDQTtRQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxZQUFZQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUM5QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUdBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1lBQ3hCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDYkEsQ0FBQ0E7SUFFREQsT0FBT0EsTUFBTUEsQ0FBRUEsS0FBaUJBO1FBRTlCSSxJQUFJQSxDQUFTQSxDQUFDQTtRQUNkQSxJQUFJQSxVQUFVQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNsQ0EsSUFBSUEsTUFBTUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFaEJBLE1BQU1BLE1BQU1BLEdBQUdBLGtFQUFrRUEsQ0FBQ0E7UUFDbEZBLGdCQUFpQkEsR0FBU0E7WUFDeEJDLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBQzVCQSxDQUFDQTtRQUVERCx5QkFBMEJBLEdBQVdBO1lBQ25DRSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUM1R0EsQ0FBQ0E7UUFHREYsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsVUFBVUEsQ0FBQ0E7UUFDdkNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQy9CQSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuRUEsTUFBTUEsSUFBSUEsZUFBZUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbENBLENBQUNBO1FBR0RBLE1BQU1BLENBQUNBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBO1lBQ25CQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ25DQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDNUJBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQ2ZBLEtBQUtBLENBQUFBO1lBQ1BBLEtBQUtBLENBQUNBO2dCQUNKQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDbEVBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO2dCQUM3QkEsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtn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LENBQUVBLFFBQVFBLElBQUlBLFlBQVlBLENBQUNBLEdBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQ3RDQSxLQUFLQSxZQUFZQSxDQUFDQSxHQUFHQTtnQkFFbkJBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsQ0FBRUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7Z0JBQy9EQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxZQUFZQSxDQUFDQSxNQUFNQTtnQkFDdEJBLE1BQU1BLENBQUNBLFdBQVdBLENBQUNBLE1BQU1BLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLENBQUVBLENBQUNBO1lBRTlDQSxLQUFLQSxZQUFZQSxDQUFDQSxJQUFJQTtnQkFDcEJBLEdBQUdBLENBQUFBLENBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO29CQUM5QkEsQ0FBQ0EsSUFBSUEsTUFBTUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsQ0FBQ0E7Z0JBQ2xEQSxLQUFLQSxDQUFDQTtZQUVSQTtnQkFDRUEsR0FBR0EsQ0FBQUEsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0E7b0JBQzlCQSxDQUFDQSxJQUFJQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxDQUFDQTtnQkFD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QSxDQUFDQTtJQUVESixPQUFPQSxDQUFDQSxTQUE2QkEsRUFBRUEsR0FBY0EsRUFBRUEsSUFBZUE7UUFDcEVLLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRS9EQSxNQUFNQSxDQUFDQSxDQUFFQSxRQUFRQSxJQUFJQSxRQUFRQSxDQUFDQSxPQUFPQSxDQUFFQTtjQUNuQ0EsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsSUFBSUEsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBRUE7Y0FDbkNBLE9BQU9BLENBQUNBLE1BQU1BLENBQWFBLEVBQUVBLENBQUVBLENBQUNBO0lBQ3RDQSxDQUFDQTtJQUVETCxNQUFNQSxDQUFDQSxTQUE2QkEsRUFBRUEsSUFBZUE7UUFDbkRNLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRS9EQSxNQUFNQSxDQUFDQSxDQUFFQSxRQUFRQSxJQUFJQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQTtjQUNsQ0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUE7Y0FDN0JBLE9BQU9BLENBQUNBLE1BQU1BLENBQWFBLEVBQUVBLENBQUVBLENBQUNBO0lBQ3RDQSxDQUFDQTtJQUVETixJQUFJQSxDQUFFQSxTQUE2QkEsRUFBRUEsR0FBY0EsRUFBRUEsSUFBZUE7UUFDbEVPLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFFBQVFBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFVBQVVBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRS9EQSxNQUFNQSxDQUFDQSxDQUFFQSxRQUFRQSxJQUFJQSxRQUFRQSxDQUFDQSxJQUFJQSxDQUFFQTtjQUNoQ0EsUUFBUUEsQ0FBQ0Es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Q0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLFNBQVNBLFlBQVlBLE1BQU1BLENBQUNBLEdBQWVBLFNBQVVBLENBQUNBLElBQUlBLEdBQVdBLFNBQVNBLENBQUNBO1lBQzFGQSxJQUFJQSxNQUFNQSxHQUFHQSxHQUFtQkEsQ0FBQ0E7WUFDakNBLElBQUlBLElBQUlBLEdBQUdBLENBQUNBLEVBQUVBLE9BQU9BLEdBQUdBLENBQUNBLENBQUNBO1lBQzFCQSxJQUFJQSxFQUFFQSxDQUFDQTtZQUVQQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxJQUFJQSxNQUFNQSxDQUFDQSxTQUFTQSxDQUFDQSxJQUFLQSxDQUFDQTtnQkFDakNBLE1BQU1BLENBQUVBLElBQUlBLEtBQUtBLENBQUVBLE9BQU9BLEdBQUdBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEdBQUdBLGtDQUFrQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFN0ZBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLElBQUlBLFNBQVVBLENBQUNBLENBQUNBLENBQUNBO2dCQUN6Q0EsSUFBSUEsR0FBR0EsR0FBZUEsU0FBVUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBRTdGQSxFQUFFQSxHQUFHQSxJQUFJQSxTQUFTQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQSxZQUFZQSxDQUFDQTtnQkFFdkNBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBO1lBQ1hBLENBQUNBO1lBRURBLEVBQUVBLENBQUNBLENBQUVBLENBQUVBLElBQUlBLENBQUNBLE1BQU1BLElBQUlBLENBQUNBLENBQUVBLElBQUlBLENBQUVBLE9BQU9BLElBQUlBLENBQUNBLENBQUdBLENBQUNBO2dCQUM3Q0EsT0FBT0EsQ0FBRUEsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsWUFBWUEsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsRUFBRUEsQ0FBQ0EsRUFBRUEsSUFBSUEsRUFBRUEsRUFBRUEsRUFBRUEsT0FBT0EsQ0FBRUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7WUFDbkhBLElBQUlBO2dCQUNGQSxPQUFPQSxDQUFFQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUMvQkEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFFREYsT0FBT0EsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQWNBLEVBQUVBLElBQWVBO1FBRXBFRyxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsU0FBU0EsWUFBWUEsTUFBTUEsQ0FBQ0EsR0FBZUEsU0FBVUEsQ0FBQ0EsSUFBSUEsR0FBV0EsU0FBU0EsQ0FBQ0E7WUFDMUZBLElBQUlBLE1BQU1BLEdBQUdBLEdBQW1CQSxDQUFDQTtZQUNqQ0EsSUFBSUEsSUFBSUEsR0FBR0EsQ0FBQ0EsRUFBRUEsT0FBT0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDMUJBLElBQUlBLEVBQUVBLENBQUNBO1lBRVBBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLElBQUlBLE1BQU1BLENBQUNBLFNBQVNBLENBQUNBLElBQUtBLENBQUNBO2dCQUNqQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsS0FBS0EsQ0FBRUEsT0FBT0EsR0FBR0EsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsSUFBSUEsR0FBR0Esa0NBQWtDQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUU3RkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsSUFBSUEsSUFBSUEsU0FBVUEsQ0FBQ0EsQ0FBQ0Es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QUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFFQSxDQUFFQTtvQkFDNUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLEVBQUNBLFNBQVNBLENBQUNBLENBQUVBO29CQUN2S0EsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3JKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDOUtBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLElBQUlBLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLEVBQUNBLE1BQU1BLEVBQUNBLE9BQU9BLENBQUNBLENBQUVBO29CQUMzSUEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsSUFBSUEsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ3ZKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDcktBLFNBQVNBLEVBQUdBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLE9BQU9BLEVBQUNBLEtBQUtBLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLE9BQU9BLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLEVBQUNBLFVBQVVBLENBQUNBLENBQUVBO29CQUNqTEEsU0FBU0EsRUFBR0EsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQzdKQSxTQUFTQSxFQUFHQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxHQUFHQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtvQkFDN0pBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLENBQUNBLEVBQUNBLElBQUlBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLE1BQU1BLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLEVBQUNBLFFBQVFBLENBQUNBLENBQUVBO29CQUNuSkEsVUFBVUEsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsUUFBUUEsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7b0JBQ25MQSxVQUFVQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFFQSxDQUFDQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxDQUFDQSxDQUFFQTtvQkFDdEtBLFVBQVVBLEVBQUVBLElBQUlBLFdBQVdBLENBQUVBLENBQUVBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLENBQUNBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLEVBQUNBLEdBQUdBLEVBQUNBLEdBQUdBLEVBQUNBLEtBQUtBLEVBQUNBLEtBQUtBLENBQUNBLENBQUVBO2lCQUM5R0EsQ0FBQ0E7WUFDSkEsQ0FBQ0E7WUFHREEsSUFBSUEsVUFBVUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFeENBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFdBQVdBLENBQUNBLEVBQUVBLEdBQUdBLFVBQVVBLENBQUNBLENBQUNBO1lBRTVDQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUVoRUEsSUFBSUEsUUFBUUEsRUFBRUEsU0FBU0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0E7WUFFeENBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLEVBQUVBLEVBQy9CQSxDQUFDQTtnQkFDQ0EsSUFBSUEsR0FBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3pFQSxLQUFLQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFFekVBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBO2dCQUNuRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ25GQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtnQkFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO2dCQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtnQkFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQSxDQUFDQTtnQkFFbkRBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLFFBQVFBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUN0R0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBR2JBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLE1BQU1BLEVBQUVBLENBQUNBLEVBQUVBLEVBQ3BDQSxDQUFDQTtvQkFFQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7d0JBQ0NBLElBQUlBLEdBQUdBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO3dCQUFDQSxLQUFLQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQTtvQkFDNUVBLENBQUNBO29CQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTt3QkFDQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7d0JBQUNBLEtBQUtBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLENBQUNBO29CQUM1RUEsQ0FBQ0E7b0JBQ0RBLElBQUlBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBO29CQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQTtvQkFNNUJBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUNuRUEsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQzNFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDMUVBLEtBQUtBLENBQUNBLFNBQVNBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO29CQUMvQ0EsU0FBU0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsU0FBU0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0E7MEJBQ3JFQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxVQUFVQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxHQUFHQSxDQUFDQTswQkFDOUVBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBOzBCQUM5RUEsS0FBS0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7b0JBQ2xEQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxTQUFTQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtvQkFDcERBLElBQUlBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBO29CQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxTQUFTQSxHQUFHQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtnQkFDcEVBLENBQUNBO1lBQ0hBLENBQUNBO1lBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO1FBQ2RBLENBQUNBO1FBR0RELElBQUlBLEtBQUtBLEdBQUdBLHVCQUF1QkEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7UUFFMUNBLEVBQUVBLENBQUNBLENBQUVBLEtBQUtBLElBQUlBLFNBQVVBLENBQUNBLENBQ3pCQSxDQUFDQTtZQUNDQSxLQUFLQSxHQUFHQSx1QkFBdUJBLENBQUNBLEtBQUtBLEdBQUdBO2dCQUN0Q0EsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsQ0FBQ0EsVUFBVUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ3JvQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsS0FBS0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsR0FBR0EsRUFBQ0EsT0FBT0EsRUFBQ0EsT0FBT0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsU0FBU0EsRUFBQ0EsS0FBS0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsRUFBQ0EsR0FBR0EsRUFBQ0EsU0FBU0EsRUFBQ0EsT0FBT0EsQ0FBQ0EsQ0FBRUE7Z0JBQ3ppQkEsV0FBV0EsRUFBRUEsSUFBSUEsV0FBV0EsQ0FBRUEsQ0FBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsQ0FBQ0EsRUFBQ0EsQ0FBQ0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsR0FBR0EsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsR0FBR0EsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsRUFBQ0EsUUFBUUEsRUFBQ0EsSUFBSUEsRUFBQ0EsUUFBUUEsRUFBQ0EsTUFBTUEsRUFBQ0EsUUFBUUEsQ0FBQ0EsQ0FBRUE7Z0JBQ2pmQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxLQUFLQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxTQUFTQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDam9CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxNQUFNQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxNQUFNQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxRQUFRQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTtnQkFDcm1CQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxHQUFHQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxRQUFRQSxFQUFDQSxDQUFDQSxFQUFDQSxHQUFHQSxFQUFDQSxTQUFTQSxFQUFDQSxDQUFDQSxFQUFDQSxRQUFRQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxTQUFTQSxFQUFDQSxTQUFTQSxFQUFDQSxLQUFLQSxFQUFDQSxRQUFRQSxDQUFDQSxDQUFFQTtnQkFDempCQSxXQUFXQSxFQUFFQSxJQUFJQSxXQUFXQSxDQUFFQSxDQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxDQUFDQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxJQUFJQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxFQUFDQSxDQUFDQSxFQUFDQSxVQUFVQSxFQUFDQSxPQUFPQSxFQUFDQSxPQUFPQSxFQUFDQSxNQUFNQSxFQUFDQSxNQUFNQSxFQUFDQSxPQUFPQSxFQUFDQSxVQUFVQSxFQUFDQSxVQUFVQSxDQUFDQSxDQUFFQTthQUN0bEJBLENBQUNBO1FBQ0pBLENBQUNBO1FBR0RBLElBQUlBLElBQUlBLEdBQUdBLGNBQWNBLENBQUVBLEdBQUdBLENBQUVBLENBQUNBO1FBRWpDQSxJQUFJQSxDQUFDQSxHQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxPQUFPQSxDQUFDQTtRQUMxQ0EsSUFBSUEsT0FBT0EsRUFBRUEsUUFBUUEsRUFBRUEsUUFBUUEsRUFBRUEsU0FBU0EsQ0FBQUE7UUFDMUNBLElBQUlBLEdBQUdBLEdBQUdBLE9BQU9BLENBQUNBLE1BQU1BLENBQUNBO1FBR3pCQSxJQUFJQSxVQUFVQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUUzQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO1lBQ0NBLE9BQU9BLEdBQUdBLE9BQU9BLEdBQUdBLENBQUVBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUVBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLENBQUVBLENBQUNBO1FBQ3BEQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUNKQSxDQUFDQTtZQUNDQSxPQUFPQSxHQUFHQSxPQUFPQSxHQUFHQSxDQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUNsR0EsQ0FBQ0E7UUFHREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsT0FBT0EsSUFBSUEsU0FBU0EsQ0FBRUEsSUFBSUEsQ0FBRUEsT0FBT0EsSUFBSUEsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FDbkRBLENBQUNBO1lBQ0NBLElBQUlBLGVBQWVBLEdBQUdBLE9BQU9BLENBQUNBO1lBQzlCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxHQUFDQSxDQUFDQSxHQUFHQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUVwQkEsT0FBT0EsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsR0FBR0EsR0FBR0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDcENBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLGVBQWVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO1lBRWxDQSxNQUFNQSxDQUFBQSxDQUFFQSxPQUFRQSxDQUFDQSxDQUNqQkEsQ0FBQ0E7Z0JBQ0NBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtvQkFDekZBLEtBQUtBLENBQUNBO2dCQUVSQSxLQUFLQSxDQUFDQTtvQkFDTkEsQ0FBQ0E7d0JBQ0NBLE9BQU9BLENBQUNBLEdBQUdBLENBQUVBLElBQUlBLFVBQVVBLENBQUVBLENBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLEVBQUVBLEdBQUdBLENBQUNBLENBQUVBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBO3dCQUU5RUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsR0FBR0EsSUFBRUEsQ0FBRUEsQ0FBQ0E7NEJBQ1hBLEdBQUdBLElBQUVBLENBQUNBLENBQUNBO3dCQUVUQSxLQUFLQSxDQUFDQTtvQkFDUkEsQ0FBQ0E7Z0JBRURBLEtBQUtBLENBQUNBO29CQUNKQSxPQUFPQSxDQUFDQSxHQUFHQSxDQUFFQSxJQUFJQSxVQUFVQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFFQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQTtvQkFDdkZBLEtBQUtBLENBQUNBO1lBRVZBLENBQUNBO1lBRURBLEdBQUdBLElBQUlBLENBQUNBLEdBQUNBLENBQUNBLEdBQUdBLEdBQUNBLENBQUNBLENBQUNBLENBQUFBO1FBQ2xCQSxDQUFDQTtRQUdEQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtRQUVuQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FDZEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFFWEEsT0FBT0EsR0FBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0EsRUFBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFDNUVBLFFBQVFBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEVBQUVBLENBQUNBLENBQUNBO1FBQzlFQSxDQUFDQTtRQUVEQSxJQUFJQSxFQUFFQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUdYQSxPQUFPQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUNkQSxDQUFDQTtZQUNDQSxJQUFJQSxHQUFJQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUN6RkEsS0FBS0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7WUFHekZBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsSUFBSUEsSUFBSUEsT0FBT0EsQ0FBQ0E7b0JBQUNBLEtBQUtBLElBQUlBLFFBQVFBLENBQUNBO2dCQUNyQ0EsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtvQkFDbkJBLFNBQVNBLEdBQUdBLFFBQVFBLENBQUNBO29CQUNyQkEsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7WUFDSEEsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQ2pGQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBRS9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNyQ0EsS0FBS0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsS0FBS0EsS0FBS0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHeENBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLENBQUNBLEVBQUVBLENBQUNBLEdBQUNBLFVBQVVBLEVBQUVBLENBQUNBLElBQUVBLENBQUNBLEVBQzVCQSxDQUFDQTtnQkFDQ0EsSUFBSUEsT0FBT0EsR0FBR0EsT0FBT0EsQ0FBQ0EsQ0FBQ0EsR0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzNCQSxJQUFJQSxPQUFPQSxHQUFHQSxPQUFPQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFHM0JBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUNBLE9BQU9BLENBQUNBLENBQUNBLENBQUNBLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQUVBLENBQUNBLElBQUVBLE9BQU9BLEVBQ3pDQSxDQUFDQTtvQkFDQ0EsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzdCQSxJQUFJQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxLQUFLQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFHekRBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO29CQUNaQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQTtvQkFDYkEsS0FBS0EsR0FBR0EsSUFBSUEsR0FBR0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBS0EsRUFBRUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0E7MEJBQ3JGQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxDQUFDQSxNQUFNQSxLQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxXQUFXQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQTswQkFDNUVBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLEtBQUtBLENBQUNBLFdBQVdBLENBQUNBLENBQUNBLE1BQU1BLEtBQUtBLEVBQUVBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBOzBCQUNyRkEsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsS0FBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsV0FBV0EsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ2hHQSxDQUFDQTtnQkFFREEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBQUNBLElBQUlBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUFDQSxLQUFLQSxHQUFHQSxJQUFJQSxDQUFDQTtZQUMxQ0EsQ0FBQ0E7WUFHREEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsSUFBSUEsSUFBSUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDckNBLEtBQUtBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBO1lBR3hDQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMvRUEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsS0FBS0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDL0VBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLFVBQVVBLENBQUNBO1lBQUNBLElBQUlBLElBQUlBLElBQUlBLENBQUNBO1lBQUNBLEtBQUtBLElBQUlBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO1lBQy9FQSxJQUFJQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxLQUFLQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxHQUFHQSxVQUFVQSxDQUFDQTtZQUFDQSxLQUFLQSxJQUFJQSxJQUFJQSxDQUFDQTtZQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxJQUFJQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUNqRkEsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsR0FBR0EsVUFBVUEsQ0FBQ0E7WUFBQ0EsS0FBS0EsSUFBSUEsSUFBSUEsQ0FBQ0E7WUFBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFHL0VBLEVBQUVBLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQ2RBLENBQUNBO2dCQUNDQSxFQUFFQSxDQUFDQSxDQUFDQSxPQUFPQSxDQUFDQSxDQUNaQSxDQUFDQTtvQkFDQ0EsT0FBT0EsR0FBR0EsSUFBSUEsQ0FBQ0E7b0JBQ2ZBLFFBQVFBLEdBQUdBLEtBQUtBLENBQUNBO2dCQUNuQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQ0pBLENBQUNBO29CQUNDQSxJQUFJQSxJQUFJQSxR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LENBQUNBLENBQUVBLENBQUNBLFFBQVNBLENBQUNBLENBQ2hCQSxDQUFDQTtZQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxVQUFVQSxDQUFDQSxTQUFTQSxJQUFJQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFDQTtZQUV4REEsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsVUFBVUEsQ0FBQ0EsU0FBU0EsSUFBSUEsUUFBU0EsQ0FBQ0E7Z0JBQzVDQSxTQUFTQSxHQUFHQSxTQUFTQSxDQUFFQSxTQUFTQSxDQUFDQSxXQUFXQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUduREEsUUFBUUEsR0FBR0EsSUFBSUEsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBQ0EsRUFBRUEsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFDdERBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBO1FBQ3BCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtRQUUxQkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsVUFBVUEsQ0FBRUEsVUFBVUEsQ0FBRUEsSUFBSUEsS0FBS0EsQ0FBQ0E7UUFFckRBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFVBQVVBLENBQUNBLFFBQVFBLElBQUlBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO0lBQzVEQSxDQUFDQTtJQUVERCxJQUFXQSxRQUFRQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBQ0RGLElBQVdBLFFBQVFBLENBQUVBLFFBQWtCQTtRQUNyQ0UsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBS0RGLFFBQVFBLENBQUVBLElBQVVBO1FBRWxCRyxJQUFJQSxJQUFJQSxHQUFHQTtZQUNUQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxFQUFFQTtZQUNyQkEsU0FBU0Es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RUEsQ0FBQ0E7UUFFL0JBLElBQUlBLENBQUNBLEtBQUtBLEdBQUdBLFVBQVVBLENBQUVBLE1BQU1BLENBQUVBLENBQUNBO1FBQ2xDQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxVQUFVQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUM5QkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsVUFBVUEsQ0FBRUEsVUFBVUEsQ0FBRUEsSUFBSUEsS0FBS0EsQ0FBQ0E7UUFFckRBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFVBQVVBLENBQUNBLFFBQVFBLElBQUlBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO0lBQzVEQSxDQUFDQTtJQUVERCxRQUFRQSxDQUFFQSxJQUFVQTtRQUVsQkUsSUFBSUEsSUFBSUEsR0FBR0E7WUFDVEEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7WUFDWkEsUUFBUUEsRUFBRUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsSUFBSUEsS0FBS0EsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsU0FBU0E7WUFDdEVBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFFBQVFBO1lBQ3ZCQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFDQSxLQUFLQTtZQUNoQkEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0E7U0FDYkEsQ0FBQ0E7UUFFRkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7SUFFREYsSUFBSUEsRUFBRUEsQ0FBRUEsRUFBVUE7UUFFaEJHLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLEVBQUVBLENBQUNBO0lBQ2hCQSxDQUFDQTtJQUVESCxPQUFPQSxDQUFFQSxPQUFnQkE7UUFHdkJJLElBQUlBLFFBQVFBLEdBQVNBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLENBQUNBO1FBR3ZGQSxJQUFJQSxNQUFNQSxHQUFTQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxDQUFDQTtRQUVqRkEsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsT0FBT0EsQ0FBQ0E7UUFFeEJBLFFBQVFBLENBQUNBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLE9BQU9BLENBQUVBLENBQUNBO1FBQ3BDQSxNQUFNQSxDQUFDQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxPQUFPQSxDQUFFQSxDQUFDQTtJQUNwQ0EsQ0FBQ0E7SUFFREosVUFBVUE7UUFFUkssSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7UUFFekJBLEVBQUVBLENBQUNBLENBQUVBLElBQUtBLENBQUNBLENBQ1hBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFNBQVNBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBO2dCQUN6Q0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0E7WUFDbkNBLENBQUNBLENBQUVBLENBQUNBO1lBRUpBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFNBQVNBLENBQUNBO1FBQzVCQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVETCxJQUFJQSxRQUFRQTtRQUVWTSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUN0REEsQ0FBQ0E7SUFFRE4sSUFBSUEsUUFBUUE7UUFFVk8sSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7UUFFekJBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLEdBQUdBLFNBQVNBLENBQUNBO0lBQ3ZGQSxDQUFDQTtJQUVEUCxJQUFJQSxRQUFRQSxDQUFFQSxJQUFVQTtRQUV0Qk8sSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0E7WUFDWEEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsRUFBRUE7WUFDckJBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ2hCQSxDQUFDQTtRQUVGQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtJQUNyQ0EsQ0FBQ0E7SUFFRFAsSUFBSUEsTUFBTUE7UUFFUlEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDcERBLENBQUNBO0lBRURSLElBQUlBLE1BQU1BO1FBRVJTLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBO1FBRXZCQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUNyRkEsQ0FBQ0E7SUFFRFQsSUFBSUEsTUFBTUEsQ0FBRUEsSUFBVUE7UUFFcEJTLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBO1lBQ1RBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLEVBQUVBO1lBQ3JCQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQTtTQUNoQkEsQ0FBQ0E7UUFFRkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsSUFB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Q0E7UUFDN0NBLENBQUNBLENBQUNBLENBQUNBO1FBRUhBLE1BQU1BLENBQUNBLElBQUlBLENBQUVBLFVBQVVBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBLEVBQUVBO1lBQ2hEQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxFQUFFQSxFQUFFQSxVQUFVQSxDQUFDQSxLQUFLQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUM3Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFFREgsUUFBUUEsQ0FBRUEsSUFBU0E7UUFFakJJLElBQUlBLEtBQUtBLEdBQUdBLEtBQUtBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO1FBRTdCQSxJQUFJQSxLQUFLQSxHQUFHQSxLQUFLQSxDQUFFQSxPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNsQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUE7WUFFM0JBLEtBQUtBLENBQUVBLEVBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO1FBQ2xDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUVIQSxJQUFJQSxLQUFLQSxHQUFHQSxLQUFLQSxDQUFFQSxPQUFPQSxDQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUNsQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUE7WUFDN0JBLEtBQUtBLENBQUVBLEVBQUVBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLEVBQUVBLENBQUNBO1FBQ2hDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUVIQSxNQUFNQSxDQUFDQSxLQUFLQSxDQUFDQTtJQUNmQSxDQUFDQTtJQUVESixhQUFhQSxDQUFFQSxPQUF5QkE7UUFFdENLLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVFBLENBQUNBLE9BQU9BLEVB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bGUiOiJjcnlwdG9ncmFwaGl4LXNpbS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNsYXNzIEhleENvZGVjXG57XG4gIHByaXZhdGUgc3RhdGljIGhleERlY29kZU1hcDogbnVtYmVyW107XG5cbiAgc3RhdGljIGRlY29kZSggYTogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmICggSGV4Q29kZWMuaGV4RGVjb2RlTWFwID09IHVuZGVmaW5lZCApXG4gICAge1xuICAgICAgdmFyIGhleCA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiO1xuICAgICAgdmFyIGFsbG93ID0gXCIgXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICB2YXIgZGVjOiBudW1iZXJbXSA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBoZXggPSBoZXgudG9Mb3dlckNhc2UoKTtcbiAgICAgIGZvciAodmFyIGkgPSAxMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgZGVjW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYWxsb3cubGVuZ3RoOyArK2kpXG4gICAgICAgICAgZGVjW2FsbG93LmNoYXJBdChpKV0gPSAtMTtcbiAgICAgIEhleENvZGVjLmhleERlY29kZU1hcCA9IGRlYztcbiAgICB9XG5cbiAgICB2YXIgb3V0OiBudW1iZXJbXSA9IFtdO1xuICAgIHZhciBiaXRzID0gMCwgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKVxuICAgIHtcbiAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgYnJlYWs7XG4gICAgICB2YXIgYiA9IEhleENvZGVjLmhleERlY29kZU1hcFtjXTtcbiAgICAgIGlmIChiID09IC0xKVxuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgaWYgKGIgPT0gdW5kZWZpbmVkKVxuICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICBiaXRzIHw9IGI7XG4gICAgICBpZiAoKytjaGFyX2NvdW50ID49IDIpIHtcbiAgICAgICAgICBvdXQucHVzaCggYml0cyApO1xuICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBiaXRzIDw8PSA0O1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChjaGFyX2NvdW50KVxuICAgICAgdGhyb3cgXCJIZXggZW5jb2RpbmcgaW5jb21wbGV0ZTogNCBiaXRzIG1pc3NpbmdcIjtcblxuICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oIG91dCApO1xuICB9XG59XG4iLCJ0eXBlIGJ5dGUgPSBudW1iZXI7XG5cbmVudW0gQkFTRTY0U1BFQ0lBTFMge1xuICBQTFVTID0gJysnLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIID0gJy8nLmNoYXJDb2RlQXQoMCksXG4gIE5VTUJFUiA9ICcwJy5jaGFyQ29kZUF0KDApLFxuICBMT1dFUiA9ICdhJy5jaGFyQ29kZUF0KDApLFxuICBVUFBFUiA9ICdBJy5jaGFyQ29kZUF0KDApLFxuICBQTFVTX1VSTF9TQUZFID0gJy0nLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIX1VSTF9TQUZFID0gJ18nLmNoYXJDb2RlQXQoMClcbn1cblxuZXhwb3J0IGNsYXNzIEJhc2U2NENvZGVjXG57XG4gIHN0YXRpYyBkZWNvZGUoIGI2NDogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmIChiNjQubGVuZ3RoICUgNCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBiYXNlNjQgc3RyaW5nLiBMZW5ndGggbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBkZWNvZGUoIGVsdDogU3RyaW5nICk6IG51bWJlclxuICAgIHtcbiAgICAgIHZhciBjb2RlID0gZWx0LmNoYXJDb2RlQXQoMCk7XG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTIHx8IGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlBMVVNfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MjsgLy8gJysnXG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSCB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSF9VUkxfU0FGRSlcbiAgICAgICAgcmV0dXJuIDYzOyAvLyAnLydcblxuICAgICAgaWYgKGNvZGUgPj0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSKVxuICAgICAge1xuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDEwKVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSICsgMjYgKyAyNjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLlVQUEVSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5VUFBFUjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLkxPV0VSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2O1xuICAgICAgfVxuXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gQ2hhcmFjdGVyIG5vdCB2YWxpZCcpO1xuICAgIH1cblxuICAgIC8vIHRoZSBudW1iZXIgb2YgZXF1YWwgc2lnbnMgKHBsYWNlIGhvbGRlcnMpXG4gICAgLy8gaWYgdGhlcmUgYXJlIHR3byBwbGFjZWhvbGRlcnMsIHRoYW4gdGhlIHR3byBjaGFyYWN0ZXJzIGJlZm9yZSBpdFxuICAgIC8vIHJlcHJlc2VudCBvbmUgYnl0ZVxuICAgIC8vIGlmIHRoZXJlIGlzIG9ubHkgb25lLCB0aGVuIHRoZSB0aHJlZSBjaGFyYWN0ZXJzIGJlZm9yZSBpdCByZXByZXNlbnQgMiBieXRlc1xuICAgIC8vIHRoaXMgaXMganVzdCBhIGNoZWFwIGhhY2sgdG8gbm90IGRvIGluZGV4T2YgdHdpY2VcbiAgICBsZXQgbGVuID0gYjY0Lmxlbmd0aDtcbiAgICBsZXQgcGxhY2VIb2xkZXJzID0gYjY0LmNoYXJBdChsZW4gLSAyKSA9PT0gJz0nID8gMiA6IGI2NC5jaGFyQXQobGVuIC0gMSkgPT09ICc9JyA/IDEgOiAwO1xuXG4gICAgLy8gYmFzZTY0IGlzIDQvMyArIHVwIHRvIHR3byBjaGFyYWN0ZXJzIG9mIHRoZSBvcmlnaW5hbCBkYXRhXG4gICAgbGV0IGFyciA9IG5ldyBVaW50OEFycmF5KCBiNjQubGVuZ3RoICogMyAvIDQgLSBwbGFjZUhvbGRlcnMgKTtcblxuICAgIC8vIGlmIHRoZXJlIGFyZSBwbGFjZWhvbGRlcnMsIG9ubHkgZ2V0IHVwIHRvIHRoZSBsYXN0IGNvbXBsZXRlIDQgY2hhcnNcbiAgICBsZXQgbCA9IHBsYWNlSG9sZGVycyA+IDAgPyBiNjQubGVuZ3RoIC0gNCA6IGI2NC5sZW5ndGg7XG5cbiAgICB2YXIgTCA9IDA7XG5cbiAgICBmdW5jdGlvbiBwdXNoICh2OiBieXRlKSB7XG4gICAgICBhcnJbTCsrXSA9IHY7XG4gICAgfVxuXG4gICAgbGV0IGkgPSAwLCBqID0gMDtcblxuICAgIGZvciAoOyBpIDwgbDsgaSArPSA0LCBqICs9IDMpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDE4KSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDEyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMikpIDw8IDYpIHwgZGVjb2RlKGI2NC5jaGFyQXQoaSArIDMpKTtcbiAgICAgIHB1c2goKHRtcCAmIDB4RkYwMDAwKSA+PiAxNik7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDApID4+IDgpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICBpZiAocGxhY2VIb2xkZXJzID09PSAyKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpID4+IDQpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9IGVsc2UgaWYgKHBsYWNlSG9sZGVycyA9PT0gMSkge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMTApIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPDwgNCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA+PiAyKTtcbiAgICAgIHB1c2goKHRtcCA+PiA4KSAmIDB4RkYpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXJyO1xuICB9XG5cbiAgc3RhdGljIGVuY29kZSggdWludDg6IFVpbnQ4QXJyYXkgKTogc3RyaW5nXG4gIHtcbiAgICB2YXIgaTogbnVtYmVyO1xuICAgIHZhciBleHRyYUJ5dGVzID0gdWludDgubGVuZ3RoICUgMzsgLy8gaWYgd2UgaGF2ZSAxIGJ5dGUgbGVmdCwgcGFkIDIgYnl0ZXNcbiAgICB2YXIgb3V0cHV0ID0gJyc7XG5cbiAgICBjb25zdCBsb29rdXAgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLyc7XG4gICAgZnVuY3Rpb24gZW5jb2RlKCBudW06IGJ5dGUgKSB7XG4gICAgICByZXR1cm4gbG9va3VwLmNoYXJBdChudW0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyaXBsZXRUb0Jhc2U2NCggbnVtOiBudW1iZXIgKSB7XG4gICAgICByZXR1cm4gZW5jb2RlKG51bSA+PiAxOCAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiAxMiAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiA2ICYgMHgzRikgKyBlbmNvZGUobnVtICYgMHgzRik7XG4gICAgfVxuXG4gICAgLy8gZ28gdGhyb3VnaCB0aGUgYXJyYXkgZXZlcnkgdGhyZWUgYnl0ZXMsIHdlJ2xsIGRlYWwgd2l0aCB0cmFpbGluZyBzdHVmZiBsYXRlclxuICAgIGxldCBsZW5ndGggPSB1aW50OC5sZW5ndGggLSBleHRyYUJ5dGVzO1xuICAgIGZvciAoaSA9IDA7IGkgPCBsZW5ndGg7IGkgKz0gMykge1xuICAgICAgbGV0IHRlbXAgPSAodWludDhbaV0gPDwgMTYpICsgKHVpbnQ4W2kgKyAxXSA8PCA4KSArICh1aW50OFtpICsgMl0pO1xuICAgICAgb3V0cHV0ICs9IHRyaXBsZXRUb0Jhc2U2NCh0ZW1wKTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIGVuZCB3aXRoIHplcm9zLCBidXQgbWFrZSBzdXJlIHRvIG5vdCBmb3JnZXQgdGhlIGV4dHJhIGJ5dGVzXG4gICAgc3dpdGNoIChleHRyYUJ5dGVzKSB7XG4gICAgICBjYXNlIDE6XG4gICAgICAgIGxldCB0ZW1wID0gdWludDhbdWludDgubGVuZ3RoIC0gMV07XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAyKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCA0KSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz09JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgdGVtcCA9ICh1aW50OFt1aW50OC5sZW5ndGggLSAyXSA8PCA4KSArICh1aW50OFt1aW50OC5sZW5ndGggLSAxXSk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAxMCk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPj4gNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCAyKSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz0nO1xuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSGV4Q29kZWMgfSBmcm9tICcuL2hleC1jb2RlYyc7XG5pbXBvcnQgeyBCYXNlNjRDb2RlYyB9IGZyb20gJy4vYmFzZTY0LWNvZGVjJztcblxuZXhwb3J0IGVudW0gQnl0ZUVuY29kaW5nIHtcbiAgUkFXLFxuICBIRVgsXG4gIEJBU0U2NCxcbiAgVVRGOFxufVxuXG5leHBvcnQgY2xhc3MgQnl0ZUFycmF5IC8vZXh0ZW5kcyBVaW50OEFycmF5XG57XG4gIHB1YmxpYyBzdGF0aWMgUkFXID0gQnl0ZUVuY29kaW5nLlJBVztcbiAgcHVibGljIHN0YXRpYyBIRVggPSBCeXRlRW5jb2RpbmcuSEVYO1xuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IEJ5dGVFbmNvZGluZy5CQVNFNjQ7XG4gIHB1YmxpYyBzdGF0aWMgVVRGOCA9IEJ5dGVFbmNvZGluZy5VVEY4O1xuXG4gIHN0YXRpYyBlbmNvZGluZ1RvU3RyaW5nKCBlbmNvZGluZzogQnl0ZUVuY29kaW5nICk6IHN0cmluZyB7XG4gICAgc3dpdGNoKCBlbmNvZGluZyApIHtcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkJBU0U2NDpcbiAgICAgICAgcmV0dXJuICdCQVNFNjQnO1xuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuVVRGODpcbiAgICAgICAgcmV0dXJuICdVVEY4JztcbiAgICAgIGNhc2UgQnl0ZUVuY29kaW5nLkhFWDpcbiAgICAgICAgcmV0dXJuICdIRVgnO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuICdSQVcnO1xuICAgIH1cbiAgfVxuXG4gIHN0YXRpYyBzdHJpbmdUb0VuY29kaW5nKCBlbmNvZGluZzogc3RyaW5nICk6IEJ5dGVFbmNvZGluZyB7XG4gICAgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdCQVNFNjQnIClcbiAgICAgIHJldHVybiBCeXRlRW5jb2RpbmcuQkFTRTY0O1xuICAgIGVsc2UgaWYgKCBlbmNvZGluZy50b1VwcGVyQ2FzZSgpID09ICdVVEY4JyApXG4gICAgICByZXR1cm4gQnl0ZUVuY29kaW5nLlVURjg7XG4gICAgZWxzZSBpZiAoIGVuY29kaW5nLnRvVXBwZXJDYXNlKCkgPT0gJ0hFWCcgKVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5IRVg7XG4gICAgZWxzZVxuICAgICAgcmV0dXJuIEJ5dGVFbmNvZGluZy5SQVc7XG4gIH1cblxuXG4gIHByaXZhdGUgYnl0ZUFycmF5OiBVaW50OEFycmF5O1xuICAvKipcbiAgICogQ3JlYXRlIGEgQnl0ZUFycmF5XG4gICAqIEBwYXJhbSBieXRlcyAtIGluaXRpYWwgY29udGVudHMsIG9wdGlvbmFsXG4gICAqICAgbWF5IGJlOlxuICAgKiAgICAgYW4gZXhpc3RpbmcgQnl0ZUFycmF5XG4gICAqICAgICBhbiBBcnJheSBvZiBudW1iZXJzICgwLi4yNTUpXG4gICAqICAgICBhIHN0cmluZywgdG8gYmUgY29udmVydGVkXG4gICAqICAgICBhbiBBcnJheUJ1ZmZlclxuICAgKiAgICAgYSBVaW50OEFycmF5XG4gICAqL1xuICBjb25zdHJ1Y3RvciggYnl0ZXM/OiBCeXRlQXJyYXkgfCBBcnJheTxudW1iZXI+IHwgU3RyaW5nIHwgQXJyYXlCdWZmZXIgfCBVaW50OEFycmF5LCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGlmICggIWJ5dGVzIClcbiAgICB7XG4gICAgICAvLyB6ZXJvLWxlbmd0aCBhcnJheVxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggMCApO1xuICAgIH1cbiAgICBlbHNlIGlmICggIWVuY29kaW5nIHx8IGVuY29kaW5nID09IEJ5dGVFbmNvZGluZy5SQVcgKVxuICAgIHtcbiAgICAgIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlciApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxBcnJheUJ1ZmZlcj5ieXRlcyApO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgVWludDhBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYnl0ZXM7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzLmJ5dGVBcnJheTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIEFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggYnl0ZXMgKTtcbiAgICAgIC8vZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICAgIC8ve1xuLy8gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIC8vfVxuICAgIH1cbiAgICBlbHNlIGlmICggdHlwZW9mIGJ5dGVzID09IFwic3RyaW5nXCIgKVxuICAgIHtcbiAgICAgIGlmICggZW5jb2RpbmcgPT0gQnl0ZUVuY29kaW5nLkJBU0U2NCApXG4gICAgICB7XG4gICAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBCYXNlNjRDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuSEVYIClcbiAgICAgIHtcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBIZXhDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBlbmNvZGluZyA9PSBCeXRlRW5jb2RpbmcuVVRGOCApXG4gICAgICB7XG4gICAgICAgIGxldCBsID0gKCA8c3RyaW5nPmJ5dGVzICkubGVuZ3RoO1xuICAgICAgICBsZXQgYmEgPSBuZXcgVWludDhBcnJheSggbCApO1xuICAgICAgICBmb3IoIGxldCBpID0gMDsgaSA8IGw7ICsraSApXG4gICAgICAgICAgYmFbaV0gPSAoIDxzdHJpbmc+Ynl0ZXMgKS5jaGFyQ29kZUF0KCBpICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBiYTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBNdXN0IGhhdmUgZXhlYyBvbmUgb2YgYWJvdmUgYWxsb2NhdG9yc1xuICAgIGlmICggIXRoaXMuYnl0ZUFycmF5IClcbiAgICB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiSW52YWxpZCBQYXJhbXMgZm9yIEJ5dGVBcnJheSgpXCIpXG4gICAgfVxuICB9XG5cbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XG4gIH1cblxuICBzZXQgbGVuZ3RoKCBsZW46IG51bWJlciApXG4gIHtcbiAgICBpZiAoIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCA+PSBsZW4gKVxuICAgIHtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdGhpcy5ieXRlQXJyYXkuc2xpY2UoIDAsIGxlbiApO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbGV0IG9sZCA9IHRoaXMuYnl0ZUFycmF5O1xuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG4gICAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIG9sZCwgMCApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBiYWNraW5nQXJyYXkoKTogVWludDhBcnJheVxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5O1xuICB9XG5cbiAgZXF1YWxzKCB2YWx1ZTogQnl0ZUFycmF5ICk6IGJvb2xlYW5cbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG4gICAgdmFyIG9rID0gKCBiYS5sZW5ndGggPT0gdmJhLmxlbmd0aCApO1xuXG4gICAgaWYgKCBvayApXG4gICAge1xuICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICAgIG9rID0gb2sgJiYgKCBiYVtpXSA9PSB2YmFbaV0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gb2s7XG4gIH1cblxuICAvKipcbiAgICAqIGdldCBieXRlIGF0IG9mZnNldFxuICAgICovXG4gIGJ5dGVBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdO1xuICB9XG5cbiAgd29yZEF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gPDwgIDggKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gICAgICAgKTtcbiAgfVxuXG4gIGxpdHRsZUVuZGlhbldvcmRBdCggb2Zmc2V0ICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAgOCApO1xuICB9XG5cbiAgZHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8IDI0IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdIDw8IDE2IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMiBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMyBdICAgICAgICk7XG4gIH1cblxuICAvKipcbiAgICAqIHNldCBieXRlIGF0IG9mZnNldFxuICAgICogQGZsdWVudFxuICAgICovXG4gIHNldEJ5dGVBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0IF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0Qnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIHZhbHVlLmJ5dGVBcnJheSwgb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGNsb25lKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEV4dHJhY3QgYSBzZWN0aW9uIChvZmZzZXQsIGNvdW50KSBmcm9tIHRoZSBCeXRlQXJyYXlcbiAgKiBAZmx1ZW50XG4gICogQHJldHVybnMgYSBuZXcgQnl0ZUFycmF5IGNvbnRhaW5pbmcgYSBzZWN0aW9uLlxuICAqL1xuICBieXRlc0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIENyZWF0ZSBhIHZpZXcgaW50byB0aGUgQnl0ZUFycmF5XG4gICpcbiAgKiBAcmV0dXJucyBhIEJ5dGVBcnJheSByZWZlcmVuY2luZyBhIHNlY3Rpb24gb2Ygb3JpZ2luYWwgQnl0ZUFycmF5LlxuICAqL1xuICB2aWV3QXQoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIGlmICggIU51bWJlci5pc0ludGVnZXIoIGNvdW50ICkgKVxuICAgICAgY291bnQgPSAoIHRoaXMubGVuZ3RoIC0gb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gbmV3IEJ5dGVBcnJheSggdGhpcy5ieXRlQXJyYXkuc3ViYXJyYXkoIG9mZnNldCwgb2Zmc2V0ICsgY291bnQgKSApO1xuICB9XG5cbiAgLyoqXG4gICogQXBwZW5kIGJ5dGVcbiAgKiBAZmx1ZW50XG4gICovXG4gIGFkZEJ5dGUoIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgdGhpcy5ieXRlQXJyYXkubGVuZ3RoIF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0TGVuZ3RoKCBsZW46IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIHRoaXMubGVuZ3RoID0gbGVuO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjb25jYXQoIGJ5dGVzOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJhLmxlbmd0aCArIGJ5dGVzLmxlbmd0aCApO1xuXG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBiYSApO1xuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYnl0ZXMuYnl0ZUFycmF5LCBiYS5sZW5ndGggKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgbm90KCApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4weEZGO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBhbmQoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldICYgdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSB8IHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB4b3IoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4gdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHRvU3RyaW5nKCBlbmNvZGluZz86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGxldCBzID0gXCJcIjtcbiAgICBsZXQgaSA9IDA7XG5cbiAgICBzd2l0Y2goIGVuY29kaW5nIHx8IEJ5dGVFbmNvZGluZy5IRVggKSB7XG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5IRVg6XG4gICAgICAgIC8vcmV0dXJuIEhleENvZGVjLmVuY29kZSggdGhpcy5ieXRlQXJyYXkgKTtcbiAgICAgICAgZm9yKCBpID0gMDsgaSA8IHRoaXMubGVuZ3RoOyArK2kgKVxuICAgICAgICAgIHMgKz0gKCBcIjBcIiArIHRoaXMuYnl0ZUFycmF5WyBpIF0udG9TdHJpbmcoIDE2ICkpLnNsaWNlKCAtMiApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBCeXRlRW5jb2RpbmcuQkFTRTY0OlxuICAgICAgICByZXR1cm4gQmFzZTY0Q29kZWMuZW5jb2RlKCB0aGlzLmJ5dGVBcnJheSApO1xuXG4gICAgICBjYXNlIEJ5dGVFbmNvZGluZy5VVEY4OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBmb3IoIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICAgICAgcyArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKCB0aGlzLmJ5dGVBcnJheVsgaSBdICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHJldHVybiBzO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgY2xhc3MgRW51bSB7XG59XG5cbmV4cG9ydCBjbGFzcyBJbnRlZ2VyIGV4dGVuZHMgTnVtYmVyIHtcbn1cblxuLyoqXG4gKiBTZXQgb2YgZGF0YSB0eXBlcyB0aGF0IGFyZSB2YWxpZCBhcyBLaW5kIGZpZWxkc1xuICogaW5jbHVkZXMgRmllbGRUeXBlQXJyYXkga2x1ZGdlIHJlcXVpcmVkIGZvciBUUyB0byBwYXJzZSByZWN1cnNpdmVcbiAqIHR5cGUgZGVmaW5pdGlvbnNcbiAqL1xuXG5leHBvcnQgaW50ZXJmYWNlIEZpZWxkQXJyYXkgZXh0ZW5kcyBBcnJheTxGaWVsZFR5cGU+IHt9XG5leHBvcnQgdHlwZSBGaWVsZFR5cGUgPSBTdHJpbmcgfCBOdW1iZXIgfCBJbnRlZ2VyIHwgRW51bSB8IEJ5dGVBcnJheSB8IEtpbmQgfCBGaWVsZEFycmF5O1xuXG5leHBvcnQgY2xhc3MgRmllbGRBcnJheSBpbXBsZW1lbnRzIEZpZWxkQXJyYXkge31cblxuZXhwb3J0IHZhciBGaWVsZFR5cGVzID0ge1xuICBCb29sZWFuOiBCb29sZWFuLFxuXG4gIE51bWJlcjogTnVtYmVyLFxuXG4gIEludGVnZXI6IEludGVnZXIsXG5cbiAgQnl0ZUFycmF5OiBCeXRlQXJyYXksXG5cbiAgRW51bTogRW51bSxcblxuICBBcnJheTogRmllbGRBcnJheSxcblxuICBTdHJpbmc6IFN0cmluZyxcblxuICBLaW5kOiBLaW5kXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRPcHRpb25zIHtcbiAgLyoqXG4gICogbWluaW11bSBsZW5ndGggZm9yIFN0cmluZywgbWluaW11bSB2YWx1ZSBmb3IgTnVtYmVyL0ludGVnZXJcbiAgKi9cbiAgbWluaW11bT86IG51bWJlcjtcblxuICAvKipcbiAgKiBtYXhpbXVtIGxlbmd0aCBmb3IgU3RyaW5nLCBtYXhpbXVtIHZhbHVlIGZvciBOdW1iZXIvSW50ZWdlclxuICAqL1xuICBtYXhpbXVtPzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIGRlZmF1bHQgdmFsdWUgZHVyaW5nIGluaXRpYWxpemF0aW9uXG4gICovXG4gIFwiZGVmYXVsdFwiPzogYW55O1xuXG4gIC8qKlxuICAqIGRvZXMgbm90IGV4aXN0IGFzIGFuIG93blByb3BlcnR5XG4gICovXG4gIGNhbGN1bGF0ZWQ/OiBib29sZWFuO1xuXG4gIC8qKlxuICAqIHN1Yi1raW5kLCB3aGVuIGZpZWxkIGlzIHR5cGUgS2luZFxuICAqL1xuICBraW5kPzogS2luZDtcblxuICAvKipcbiAgKiBzdWItZmllbGQgaW5mbywgd2hlbiBmaWVsZCBpcyB0eXBlIEZpZWxkQXJyYXlcbiAgKi9cbiAgYXJyYXlJbmZvPzogRmllbGRJbmZvO1xuXG4gIC8qKlxuICAqIGluZGV4L3ZhbHVlIG1hcCwgd2hlbiBmaWVsZCBpZiB0eXBlIEVudW1cbiAgKi9cbiAgZW51bU1hcD86IE1hcDxudW1iZXIsIHN0cmluZz47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRJbmZvIGV4dGVuZHMgRmllbGRPcHRpb25zIHtcbiAgLyoqXG4gICogRGVzY3JpcHRpb24gZm9yIGZpZWxkXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogVHlwZSBvZiBmaWVsZCwgb25lIG9mIEZpZWxkVHlwZXNcbiAgKi9cbiAgZmllbGRUeXBlOiBGaWVsZFR5cGU7XG59XG5cblxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgS2luZC4gQ29udGFpbnMgbmFtZSwgZGVzY3JpcHRpb24gYW5kIGEgbWFwIG9mXG4qIHByb3BlcnR5LWRlc2NyaXB0b3JzIHRoYXQgZGVzY3JpYmUgdGhlIHNlcmlhbGl6YWJsZSBmaWVsZHMgb2ZcbiogYW4gb2JqZWN0IG9mIHRoYXQgS2luZC5cbiovXG5leHBvcnQgY2xhc3MgS2luZEluZm9cbntcbiAgbmFtZTogc3RyaW5nO1xuXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgZmllbGRzOiB7IFtpZDogc3RyaW5nXTogRmllbGRJbmZvIH0gPSB7fTtcbn1cblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdLaW5kJyBtZXRhZGF0YVxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kQnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IEtpbmRDb25zdHJ1Y3RvcjtcblxuICBjb25zdHJ1Y3RvciggY3RvcjogS2luZENvbnN0cnVjdG9yLCBkZXNjcmlwdGlvbjogc3RyaW5nICkge1xuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmtpbmRJbmZvID0ge1xuICAgICAgbmFtZTogY3Rvci5uYW1lLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZmllbGRzOiB7fVxuICAgIH1cbiAgfVxuXG5cbiAgcHJpdmF0ZSBraW5kSW5mbzogS2luZEluZm87XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IEtpbmRCdWlsZGVyKCBjdG9yLCBkZXNjcmlwdGlvbiApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgZmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZmllbGRUeXBlOiBGaWVsZFR5cGUsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyXG4gIHtcbiAgICBsZXQgZmllbGQ6IEZpZWxkSW5mbyA9IDxGaWVsZEluZm8+b3B0cztcblxuICAgIGZpZWxkLmRlc2NyaXB0aW9uID0gZGVzY3JpcHRpb247XG4gICAgZmllbGQuZmllbGRUeXBlID0gZmllbGRUeXBlO1xuXG4gICAgdGhpcy5jdG9yLmtpbmRJbmZvLmZpZWxkc1sgbmFtZSBdID0gZmllbGQ7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBib29sRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgQm9vbGVhbiwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIG51bWJlckZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIE51bWJlciwgb3B0cyApO1xuICB9XG5cbiAgcHVibGljIGludGVnZXJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgdWludDMyRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMubWluaW11bSA9IG9wdHMubWluaW11bSB8fCAwO1xuICAgIG9wdHMubWF4aW11bSA9IG9wdHMubWF4aW11bSB8fCAweEZGRkZGRkZGO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgYnl0ZUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLm1pbmltdW0gPSBvcHRzLm1pbmltdW0gfHwgMDtcbiAgICBvcHRzLm1heGltdW0gPSBvcHRzLm1heGltdW0gfHwgMjU1O1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBJbnRlZ2VyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgc3RyaW5nRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgU3RyaW5nLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMga2luZEZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGtpbmQ6IEtpbmQsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICBvcHRzLmtpbmQgPSBraW5kO1xuXG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBLaW5kLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgZW51bUZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGVudW1tOiB7IFsgaWR4OiBudW1iZXIgXTogc3RyaW5nIH0sIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcblxuICAgIG9wdHMuZW51bU1hcCA9IG5ldyBNYXA8bnVtYmVyLHN0cmluZz4oICk7XG5cbiAgICBmb3IoIGxldCBpZHggaW4gZW51bW0gKSB7XG4gICAgICBpZiAoIDEgKiBpZHggPT0gaWR4IClcbiAgICAgICAgb3B0cy5lbnVtTWFwLnNldCggaWR4LCBlbnVtbVsgaWR4IF0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEVudW0sIG9wdHMgKTtcbiAgfVxufVxuXG4vKiAgbWFrZUtpbmQoIGtpbmRDb25zdHJ1Y3Rvciwga2luZE9wdGlvbnMgKVxuICB7XG4gICAgdmFyICRraW5kSW5mbyA9IGtpbmRPcHRpb25zLmtpbmRJbmZvO1xuXG4gICAga2luZENvbnN0cnVjdG9yLiRraW5kTmFtZSA9ICRraW5kSW5mby50aXRsZTtcblxuICAgIHZhciBrZXlzID0gT2JqZWN0LmtleXMoIGtpbmRPcHRpb25zLmtpbmRNZXRob2RzICk7XG5cbiAgICBmb3IgKCB2YXIgaiA9IDAsIGpqID0ga2V5cy5sZW5ndGg7IGogPCBqajsgaisrICkge1xuICAgICAgdmFyIGtleSA9IGtleXNbal07XG4gICAgICBraW5kQ29uc3RydWN0b3Jba2V5XSA9IGtpbmRPcHRpb25zLmtpbmRNZXRob2RzW2tleV07XG4gICAgfVxuXG4gICAga2luZENvbnN0cnVjdG9yLmdldEtpbmRJbmZvID0ga2luZENvbnN0cnVjdG9yLnByb3RvdHlwZS5nZXRLaW5kSW5mbyA9IGZ1bmN0aW9uIGdldEtpbmRJbmZvKCkge1xuICAgICAgcmV0dXJuICRraW5kSW5mbztcbiAgICB9XG5cbiAgICByZXR1cm4ga2luZENvbnN0cnVjdG9yO1xuICB9XG4qL1xuXG4vKipcbiogUmVwcmVzZW50cyBhIHNlcmlhbGl6YWJsZSBhbmQgaW5zcGVjdGFibGUgZGF0YS10eXBlXG4qIGltcGxlbWVudGVkIGFzIGEgaGFzaC1tYXAgY29udGFpbmluZyBrZXktdmFsdWUgcGFpcnMsXG4qIGFsb25nIHdpdGggbWV0YWRhdGEgdGhhdCBkZXNjcmliZXMgZWFjaCBmaWVsZCB1c2luZyBhIGpzb24tc2NoZW1lIGxpa2VcbiovXG5leHBvcnQgaW50ZXJmYWNlIEtpbmRcbntcbi8vICBjb25zdHJ1Y3Rvcj8oIGF0dHJpYnV0ZXM/OiB7fSApO1xufVxuXG5leHBvcnQgY2xhc3MgS2luZCBpbXBsZW1lbnRzIEtpbmQge1xuICBzdGF0aWMgZ2V0S2luZEluZm8oIGtpbmQ6IEtpbmQgKTogS2luZEluZm8ge1xuICAgIHJldHVybiAoPEtpbmRDb25zdHJ1Y3Rvcj4oa2luZC5jb25zdHJ1Y3RvcikpLmtpbmRJbmZvO1xuICB9XG5cbiAgc3RhdGljIGluaXRGaWVsZHMoIGtpbmQ6IEtpbmQsIGF0dHJpYnV0ZXM6IHt9ID0ge30gICkge1xuICAgIGxldCBraW5kSW5mbyA9IEtpbmQuZ2V0S2luZEluZm8oIGtpbmQgKTtcblxuICAgIGZvciggbGV0IGlkIGluIGtpbmRJbmZvLmZpZWxkcyApIHtcbiAgICAgIGxldCBmaWVsZCA9IGtpbmRJbmZvLmZpZWxkc1sgaWQgXTtcbiAgICAgIGxldCBmaWVsZFR5cGUgPSBmaWVsZC5maWVsZFR5cGU7XG5cbi8vICAgICAgY29uc29sZS5sb2coIGlkICsgJzonICsgZmllbGRUeXBlICk7XG4vLyAgICAgIGNvbnNvbGUubG9nKCBraW5kLmhhc093blByb3BlcnR5KGlkKSAgKTtcblxuICAgICAgbGV0IHZhbDogYW55O1xuXG4gICAgICBpZiAoICFmaWVsZC5jYWxjdWxhdGVkICkge1xuICAgICAgICAvLyB3ZSBvbmx5IHNldCAnbm9uJy1jYWxjdWxhdGVkIGZpZWxkLCBzaW5jZSBjYWxjdWxhdGVkIGZpZWxkIGhhdmVcbiAgICAgICAgLy8gbm8gc2V0dGVyXG5cbiAgICAgICAgLy8gZ290IGEgdmFsdWUgZm9yIHRoaXMgZmllbGQgP1xuICAgICAgICBpZiAoIGF0dHJpYnV0ZXNbIGlkIF0gKVxuICAgICAgICAgIHZhbCA9IGF0dHJpYnV0ZXNbIGlkIF07XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZC5kZWZhdWx0ICE9IHVuZGVmaW5lZCApXG4gICAgICAgICAgdmFsID0gZmllbGQuZGVmYXVsdDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBTdHJpbmcgKVxuICAgICAgICAgIHZhbCA9ICcnO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IE51bWJlciApXG4gICAgICAgICAgdmFsID0gMDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBJbnRlZ2VyIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5taW5pbXVtIHx8IDA7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gQm9vbGVhbiApXG4gICAgICAgICAgdmFsID0gZmFsc2U7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gQnl0ZUFycmF5IClcbiAgICAgICAgICB2YWwgPSBuZXcgQnl0ZUFycmF5KCk7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gRW51bSApXG4gICAgICAgICAgdmFsID0gZmllbGQuZW51bU1hcC5rZXlzWzBdO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEtpbmQgKSB7XG4gICAgICAgICAgbGV0IHh4ID0gKDxLaW5kPmZpZWxkVHlwZSkuY29uc3RydWN0b3I7XG4gICAgICAgICAgdmFsID0gT2JqZWN0LmNyZWF0ZSggeHggKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGtpbmRbIGlkIF0gPSB2YWw7XG5cbi8vICAgICAgICBjb25zb2xlLmxvZygga2luZFtpZF0gKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBLaW5kQ29uc3RydWN0b3JcbntcbiAgbmV3ICggYXR0cmlidXRlcz86IHt9LCAuLi5hcmdzICk6IEtpbmQ7XG5cbiAga2luZEluZm8/OiBLaW5kSW5mbztcbn1cbiIsImltcG9ydCB7IEtpbmQgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuL2VuZC1wb2ludCc7XG5cbi8qXG4qIE1lc3NhZ2UgSGVhZGVyXG4qL1xuZXhwb3J0IGludGVyZmFjZSBNZXNzYWdlSGVhZGVyXG57XG4gIC8qXG4gICogTWVzc2FnZSBOYW1lLCBpbmRpY2F0ZXMgYSBjb21tYW5kIC8gbWV0aG9kIC8gcmVzcG9uc2UgdG8gZXhlY3V0ZVxuICAqL1xuICBtZXRob2Q/OiBzdHJpbmc7XG5cbiAgLypcbiAgKiBNZXNzYWdlIElkZW50aWZpZXIgKHVuaXF1ZSkgZm9yIGVhY2ggc2VudCBtZXNzYWdlIChvciBDTUQtUkVTUCBwYWlyKVxuICAqL1xuICBpZD86IG51bWJlcjtcblxuXG4gIC8qXG4gICogRGVzY3JpcHRpb24sIHVzZWZ1bCBmb3IgdHJhY2luZyBhbmQgbG9nZ2luZ1xuICAqL1xuICBkZXNjcmlwdGlvbj86IHN0cmluZztcblxuICAvKlxuICAqIEZvciBDTUQvUkVTUCBzdHlsZSBwcm90b2NvbHMsIGluZGljYXRlcyB0aGF0IG1lc3NhZ2UgZGlzcGF0Y2hlZFxuICAqIGluIHJlc3BvbnNlIHRvIGEgcHJldmlvdXMgY29tbWFuZFxuICAqL1xuICBpc1Jlc3BvbnNlPzogYm9vbGVhbjtcblxuICAvKlxuICAqIEVuZFBvaW50IHRoYXQgb3JpZ2luYXRlZCB0aGUgbWVzc2FnZVxuICAqL1xuICBvcmlnaW4/OiBFbmRQb2ludDtcblxuXG4gIC8qXG4gICogSW5kaWNhdGVzIHRoZSBLaW5kIG9mIGRhdGEgKHdoZW4gc2VyaWFsaXplZClcbiAgKi9cbiAga2luZE5hbWU/OiBzdHJpbmc7XG59XG5cbi8qXG4qIEEgVHlwZWQgTWVzc2FnZSwgd2l0aCBoZWFkZXIgYW5kIHBheWxvYWRcbiovXG5leHBvcnQgY2xhc3MgTWVzc2FnZTxUPlxue1xuICBwcml2YXRlIF9oZWFkZXI6IE1lc3NhZ2VIZWFkZXI7XG4gIHByaXZhdGUgX3BheWxvYWQ6IFQ7XG5cbiAgY29uc3RydWN0b3IoIGhlYWRlcjogTWVzc2FnZUhlYWRlciwgcGF5bG9hZDogVCApXG4gIHtcbiAgICB0aGlzLl9oZWFkZXIgPSBoZWFkZXIgfHwge307XG4gICAgdGhpcy5fcGF5bG9hZCA9IHBheWxvYWQ7XG4gIH1cblxuICBnZXQgaGVhZGVyKCk6IE1lc3NhZ2VIZWFkZXJcbiAge1xuICAgIHJldHVybiB0aGlzLl9oZWFkZXI7XG4gIH1cblxuICBnZXQgcGF5bG9hZCgpOiBUXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcGF5bG9hZDtcbiAgfVxufVxuXG4vKlxuKiBBIHR5cGVkIE1lc3NhZ2Ugd2hvc2UgcGF5bG9hZCBpcyBhIEtpbmRcbiovXG5leHBvcnQgY2xhc3MgS2luZE1lc3NhZ2U8SyBleHRlbmRzIEtpbmQ+IGV4dGVuZHMgTWVzc2FnZTxLPlxue1xufVxuIiwiZXhwb3J0IHR5cGUgVGFzayA9ICgpID0+IHZvaWQ7XG5leHBvcnQgdHlwZSBGbHVzaEZ1bmMgPSAoKSA9PiB2b2lkO1xudmFyIHdpbmRvdyA9IHdpbmRvdyB8fCB7fTtcblxuZXhwb3J0IGNsYXNzIFRhc2tTY2hlZHVsZXJcbntcbiAgc3RhdGljIG1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlcihmbHVzaCk6IEZsdXNoRnVuY1xuICB7XG4gICAgdmFyIHRvZ2dsZSA9IDE7XG5cbiAgICB2YXIgb2JzZXJ2ZXIgPSBuZXcgVGFza1NjaGVkdWxlci5Ccm93c2VyTXV0YXRpb25PYnNlcnZlcihmbHVzaCk7XG5cbiAgICB2YXIgbm9kZTogT2JqZWN0ID0gZG9jdW1lbnQuY3JlYXRlVGV4dE5vZGUoJycpO1xuXG4gICAgb2JzZXJ2ZXIub2JzZXJ2ZShub2RlLCB7IGNoYXJhY3RlckRhdGE6IHRydWUgfSk7XG5cbiAgICByZXR1cm4gZnVuY3Rpb24gcmVxdWVzdEZsdXNoKClcbiAgICB7XG4gICAgICB0b2dnbGUgPSAtdG9nZ2xlO1xuICAgICAgbm9kZVtcImRhdGFcIl0gPSB0b2dnbGU7XG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBtYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyKGZsdXNoKTogRmx1c2hGdW5jXG4gIHtcbiAgICByZXR1cm4gZnVuY3Rpb24gcmVxdWVzdEZsdXNoKCkge1xuICAgICAgdmFyIHRpbWVvdXRIYW5kbGUgPSBzZXRUaW1lb3V0KGhhbmRsZUZsdXNoVGltZXIsIDApO1xuXG4gICAgICB2YXIgaW50ZXJ2YWxIYW5kbGUgPSBzZXRJbnRlcnZhbChoYW5kbGVGbHVzaFRpbWVyLCA1MCk7XG4gICAgICBmdW5jdGlvbiBoYW5kbGVGbHVzaFRpbWVyKClcbiAgICAgIHtcbiAgICAgICAgY2xlYXJUaW1lb3V0KHRpbWVvdXRIYW5kbGUpO1xuICAgICAgICBjbGVhckludGVydmFsKGludGVydmFsSGFuZGxlKTtcbiAgICAgICAgZmx1c2goKTtcbiAgICAgIH1cbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIEJyb3dzZXJNdXRhdGlvbk9ic2VydmVyID0gd2luZG93WyBcIk11dGF0aW9uT2JzZXJ2ZXJcIiBdIHx8IHdpbmRvd1sgXCJXZWJLaXRNdXRhdGlvbk9ic2VydmVyXCJdO1xuICBzdGF0aWMgaGFzU2V0SW1tZWRpYXRlID0gdHlwZW9mIHNldEltbWVkaWF0ZSA9PT0gJ2Z1bmN0aW9uJztcblxuICBzdGF0aWMgdGFza1F1ZXVlQ2FwYWNpdHkgPSAxMDI0O1xuICB0YXNrUXVldWU6IFRhc2tbXTtcblxuICByZXF1ZXN0Rmx1c2hUYXNrUXVldWU6IEZsdXNoRnVuYztcblxuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgICB0aGlzLnRhc2tRdWV1ZSA9IFtdO1xuXG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgaWYgKHR5cGVvZiBUYXNrU2NoZWR1bGVyLkJyb3dzZXJNdXRhdGlvbk9ic2VydmVyID09PSAnZnVuY3Rpb24nKVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlID0gVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIoZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gc2VsZi5mbHVzaFRhc2tRdWV1ZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSA9IFRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lcihmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBzZWxmLmZsdXNoVGFza1F1ZXVlKCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBUYXNrU2NoZWR1bGVyLCBjYW5jZWxsaW5nIGFueSBwZW5kaW5nIGNvbW11bmljYXRpb25zLlxuICAqL1xuICBzaHV0ZG93bigpXG4gIHtcbiAgfVxuXG4gIHF1ZXVlVGFzayggdGFzaylcbiAge1xuICAgIGlmICggdGhpcy50YXNrUXVldWUubGVuZ3RoIDwgMSApXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUoKTtcbiAgICB9XG5cbiAgICB0aGlzLnRhc2tRdWV1ZS5wdXNoKHRhc2spO1xuICB9XG5cbiAgZmx1c2hUYXNrUXVldWUoKVxuICB7XG4gICAgdmFyIHF1ZXVlID0gdGhpcy50YXNrUXVldWUsXG4gICAgICAgIGNhcGFjaXR5ID0gVGFza1NjaGVkdWxlci50YXNrUXVldWVDYXBhY2l0eSxcbiAgICAgICAgaW5kZXggPSAwLFxuICAgICAgICB0YXNrO1xuXG4gICAgd2hpbGUgKGluZGV4IDwgcXVldWUubGVuZ3RoKVxuICAgIHtcbiAgICAgIHRhc2sgPSBxdWV1ZVtpbmRleF07XG5cbiAgICAgIHRyeVxuICAgICAge1xuICAgICAgICB0YXNrLmNhbGwoKTtcbiAgICAgIH1cbiAgICAgIGNhdGNoIChlcnJvcilcbiAgICAgIHtcbiAgICAgICAgdGhpcy5vbkVycm9yKGVycm9yLCB0YXNrKTtcbiAgICAgIH1cblxuICAgICAgaW5kZXgrKztcblxuICAgICAgaWYgKGluZGV4ID4gY2FwYWNpdHkpXG4gICAgICB7XG4gICAgICAgIGZvciAodmFyIHNjYW4gPSAwOyBzY2FuIDwgaW5kZXg7IHNjYW4rKylcbiAgICAgICAge1xuICAgICAgICAgIHF1ZXVlW3NjYW5dID0gcXVldWVbc2NhbiArIGluZGV4XTtcbiAgICAgICAgfVxuXG4gICAgICAgIHF1ZXVlLmxlbmd0aCAtPSBpbmRleDtcbiAgICAgICAgaW5kZXggPSAwO1xuICAgICAgfVxuICAgIH1cblxuICAgIHF1ZXVlLmxlbmd0aCA9IDA7XG4gIH1cblxuICBvbkVycm9yKGVycm9yLCB0YXNrKVxuICB7XG4gICAgaWYgKCdvbkVycm9yJyBpbiB0YXNrKSB7XG4gICAgICB0YXNrLm9uRXJyb3IoZXJyb3IpO1xuICAgIH1cbiAgICBlbHNlIGlmICggVGFza1NjaGVkdWxlci5oYXNTZXRJbW1lZGlhdGUgKVxuICAgIHtcbiAgICAgIHNldEltbWVkaWF0ZShmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG4gICAgfVxuICAgIGVsc2VcbiAgICB7XG4gICAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9LCAwKTtcbiAgICB9XG4gIH1cbn1cbiIsImltcG9ydCB7IFRhc2tTY2hlZHVsZXIgfSBmcm9tICcuLi9ydW50aW1lL3Rhc2stc2NoZWR1bGVyJztcbmltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcblxuLyoqXG4qIEEgbWVzc2FnZS1wYXNzaW5nIGNoYW5uZWwgYmV0d2VlbiBtdWx0aXBsZSBFbmRQb2ludHNcbipcbiogRW5kUG9pbnRzIG11c3QgZmlyc3QgcmVnaXN0ZXIgd2l0aCB0aGUgQ2hhbm5lbC4gV2hlbmV2ZXIgdGhlIENoYW5uZWwgaXMgaW5cbiogYW4gYWN0aXZlIHN0YXRlLCBjYWxscyB0byBzZW5kTWVzc2FnZSB3aWxsIGZvcndhcmQgdGhlIG1lc3NhZ2UgdG8gYWxsXG4qIHJlZ2lzdGVyZWQgRW5kUG9pbnRzIChleGNlcHQgdGhlIG9yaWdpbmF0b3IgRW5kUG9pbnQpLlxuKi9cblxuZXhwb3J0IHR5cGUgQ2hhbm5lbEhvb2tJbmZvID0geyBtZXNzYWdlOiBNZXNzYWdlPGFueT47IGNoYW5uZWw6IENoYW5uZWw7IG9yaWdpbjogRW5kUG9pbnQ7IGRlc3RpbmF0aW9uOiBFbmRQb2ludDsgc2VuZE1lc3NhZ2U6ICgpID0+IHZvaWQgfTtcblxuZXhwb3J0IGNsYXNzIENoYW5uZWxcbntcbiAgLy8gcHJlRGVsaXZlcnlIb29rKCB0YXNrLCBvcmlnaW4sIGVuZFBvaW50LCB0YXNrU2NoZWR1bGVyIClcbiAgcHJpdmF0ZSBzdGF0aWMgX2RlbGl2ZXJ5SG9vazogKCBpbmZvOiBDaGFubmVsSG9va0luZm8gKSA9PiBib29sZWFuO1xuXG4gIHN0YXRpYyBzZXREZWxpdmVyeUhvb2soIGRlbGl2ZXJ5SG9vazogKCBpbmZvOiBDaGFubmVsSG9va0luZm8gKSA9PiBib29sZWFuICkge1xuICAgIENoYW5uZWwuX2RlbGl2ZXJ5SG9vayA9IGRlbGl2ZXJ5SG9vaztcbiAgfTtcblxuICAvKipcbiAgKiBUcnVlIGlmIENoYW5uZWwgaXMgYWN0aXZlXG4gICovXG4gIHByaXZhdGUgX2FjdGl2ZTogYm9vbGVhbjtcblxuICAvKipcbiAgKiBBcnJheSBvZiBFbmRQb2ludHMgYXR0YWNoZWQgdG8gdGhpcyBDaGFubmVsXG4gICovXG4gIHByaXZhdGUgX2VuZFBvaW50czogRW5kUG9pbnRbXTtcblxuICAvKipcbiAgKiBQcml2YXRlIFRhc2tTY2hlZHVsZXIgdXNlZCB0byBtYWtlIG1lc3NhZ2Utc2VuZHMgYXN5bmNocm9ub3VzLlxuICAqL1xuICBwcml2YXRlIF90YXNrU2NoZWR1bGVyOiBUYXNrU2NoZWR1bGVyO1xuXG4gIC8qKlxuICAqIENyZWF0ZSBhIG5ldyBDaGFubmVsLCBpbml0aWFsbHkgaW5hY3RpdmVcbiAgKi9cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBDaGFubmVsLCBkZWFjdGl2YXRlLCByZW1vdmUgYWxsIEVuZFBvaW50cyBhbmRcbiAgKiBhYm9ydCBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG5cbiAgICBpZiAoIHRoaXMuX3Rhc2tTY2hlZHVsZXIgKVxuICAgIHtcbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIuc2h1dGRvd24oKTtcblxuICAgICAgdGhpcy5fdGFza1NjaGVkdWxlciA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBJcyBDaGFubmVsIGFjdGl2ZT9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgY2hhbm5lbCBpcyBhY3RpdmUsIGZhbHNlIG90aGVyd2lzZVxuICAqL1xuICBwdWJsaWMgZ2V0IGFjdGl2ZSgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fYWN0aXZlO1xuICB9XG5cbiAgLyoqXG4gICogQWN0aXZhdGUgdGhlIENoYW5uZWwsIGVuYWJsaW5nIGNvbW11bmljYXRpb25cbiAgKi9cbiAgcHVibGljIGFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSBuZXcgVGFza1NjaGVkdWxlcigpO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gdHJ1ZTtcbiAgfVxuXG4gIC8qKlxuICAqIERlYWN0aXZhdGUgdGhlIENoYW5uZWwsIGRpc2FibGluZyBhbnkgZnVydGhlciBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBkZWFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG5cbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGFuIEVuZFBvaW50IHRvIHNlbmQgYW5kIHJlY2VpdmUgbWVzc2FnZXMgdmlhIHRoaXMgQ2hhbm5lbC5cbiAgKlxuICAqIEBwYXJhbSBlbmRQb2ludCAtIHRoZSBFbmRQb2ludCB0byByZWdpc3RlclxuICAqL1xuICBwdWJsaWMgYWRkRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICB0aGlzLl9lbmRQb2ludHMucHVzaCggZW5kUG9pbnQgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFVucmVnaXN0ZXIgYW4gRW5kUG9pbnQuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gdW5yZWdpc3RlclxuICAqL1xuICBwdWJsaWMgcmVtb3ZlRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fZW5kUG9pbnRzLmluZGV4T2YoIGVuZFBvaW50ICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICB0aGlzLl9lbmRQb2ludHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBHZXQgRW5kUG9pbnRzIHJlZ2lzdGVyZWQgd2l0aCB0aGlzIENoYW5uZWxcbiAgKlxuICAqIEByZXR1cm4gQXJyYXkgb2YgRW5kUG9pbnRzXG4gICovXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnRzKCk6IEVuZFBvaW50W11cbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludHM7XG4gIH1cblxuICAvKipcbiAgKiBTZW5kIGEgbWVzc2FnZSB0byBhbGwgbGlzdGVuZXJzIChleGNlcHQgb3JpZ2luKVxuICAqXG4gICogQHBhcmFtIG9yaWdpbiAtIEVuZFBvaW50IHRoYXQgaXMgc2VuZGluZyB0aGUgbWVzc2FnZVxuICAqIEBwYXJhbSBtZXNzYWdlIC0gTWVzc2FnZSB0byBiZSBzZW50XG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggb3JpZ2luOiBFbmRQb2ludCwgbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIGxldCBpc1Jlc3BvbnNlID0gKCBtZXNzYWdlLmhlYWRlciAmJiBtZXNzYWdlLmhlYWRlci5pc1Jlc3BvbnNlICk7XG5cbiAgICBpZiAoICF0aGlzLl9hY3RpdmUgKVxuICAgICAgcmV0dXJuO1xuXG4gICAgaWYgKCBvcmlnaW4uZGlyZWN0aW9uID09IERpcmVjdGlvbi5JTiAmJiAhaXNSZXNwb25zZSApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdVbmFibGUgdG8gc2VuZCBvbiBJTiBwb3J0Jyk7XG5cbiAgICB0aGlzLl9lbmRQb2ludHMuZm9yRWFjaCggZW5kUG9pbnQgPT4ge1xuICAgICAgLy8gU2VuZCB0byBhbGwgbGlzdGVuZXJzLCBleGNlcHQgZm9yIG9yaWdpbmF0b3IgLi4uXG4gICAgICBpZiAoIG9yaWdpbiAhPSBlbmRQb2ludCApXG4gICAgICB7XG4gICAgICAgIC8vIE9ubHkgc2VuZCB0byBJTiBvciBJTk9VVCBsaXN0ZW5lcnMsIFVOTEVTUyBtZXNzYWdlIGlzIGFcbiAgICAgICAgLy8gcmVwbHkgKGluIGEgY2xpZW50LXNlcnZlcikgY29uZmlndXJhdGlvblxuICAgICAgICBpZiAoIGVuZFBvaW50LmRpcmVjdGlvbiAhPSBEaXJlY3Rpb24uT1VUIHx8IGlzUmVzcG9uc2UgKVxuICAgICAgICB7XG4gICAgICAgICAgbGV0IHRhc2sgPSAoKSA9PiB7XG4gICAgICAgICAgICBlbmRQb2ludC5oYW5kbGVNZXNzYWdlKCBtZXNzYWdlLCBvcmlnaW4sIHRoaXMgKTtcbiAgICAgICAgICB9O1xuXG4gICAgICAgICAgbGV0IGNhblNlbmQgPSB0cnVlO1xuXG4gICAgICAgICAgaWYgKCBDaGFubmVsLl9kZWxpdmVyeUhvb2sgKSB7XG4gICAgICAgICAgICBsZXQgc2NoZWR1bGVyID0gdGhpcy5fdGFza1NjaGVkdWxlcjtcblxuICAgICAgICAgICAgbGV0IG1lc3NhZ2VIb29rSW5mbyA9IHtcbiAgICAgICAgICAgICAgbWVzc2FnZTogbWVzc2FnZSxcbiAgICAgICAgICAgICAgY2hhbm5lbDogdGhpcyxcbiAgICAgICAgICAgICAgb3JpZ2luOiBvcmlnaW4sXG4gICAgICAgICAgICAgIGRlc3RpbmF0aW9uOiBlbmRQb2ludCxcbiAgICAgICAgICAgICAgc2VuZE1lc3NhZ2U6ICgpID0+IHsgc2NoZWR1bGVyLnF1ZXVlVGFzayggdGFzayApIH1cbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIGNhblNlbmQgPSAhQ2hhbm5lbC5fZGVsaXZlcnlIb29rKCBtZXNzYWdlSG9va0luZm8gKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoIGNhblNlbmQgKVxuICAgICAgICAgICAgdGhpcy5fdGFza1NjaGVkdWxlci5xdWV1ZVRhc2soIHRhc2sgKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuL2NoYW5uZWwnO1xuXG5leHBvcnQgZW51bSBEaXJlY3Rpb24ge1xuICBJTiA9IDEsXG4gIE9VVCA9IDIsXG4gIElOT1VUID0gM1xufTtcblxuZXhwb3J0IHR5cGUgSGFuZGxlTWVzc2FnZURlbGVnYXRlID0gKCBtZXNzYWdlOiBNZXNzYWdlPGFueT4sIHJlY2VpdmluZ0VuZFBvaW50PzogRW5kUG9pbnQsIHJlY2VpdmluZ0NoYW5uZWw/OiBDaGFubmVsICkgPT4gdm9pZDtcblxuLyoqXG4qIEFuIEVuZFBvaW50IGlzIGEgc2VuZGVyL3JlY2VpdmVyIGZvciBtZXNzYWdlLXBhc3NpbmcuIEl0IGhhcyBhbiBpZGVudGlmaWVyXG4qIGFuZCBhbiBvcHRpb25hbCBkaXJlY3Rpb24sIHdoaWNoIG1heSBiZSBJTiwgT1VUIG9yIElOL09VVCAoZGVmYXVsdCkuXG4qXG4qIEVuZFBvaW50cyBtYXkgaGF2ZSBtdWx0aXBsZSBjaGFubmVscyBhdHRhY2hlZCwgYW5kIHdpbGwgZm9yd2FyZCBtZXNzYWdlc1xuKiB0byBhbGwgb2YgdGhlbS5cbiovXG5leHBvcnQgY2xhc3MgRW5kUG9pbnRcbntcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX2NoYW5uZWxzOiBDaGFubmVsW107XG5cbiAgLyoqXG4gICogQSBsaXN0IG9mIGF0dGFjaGVkIENoYW5uZWxzXG4gICovXG4gIHByb3RlY3RlZCBfbWVzc2FnZUxpc3RlbmVyczogSGFuZGxlTWVzc2FnZURlbGVnYXRlW107XG5cbiAgcHJpdmF0ZSBfZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgY29uc3RydWN0b3IoIGlkOiBzdHJpbmcsIGRpcmVjdGlvbjogRGlyZWN0aW9uID0gRGlyZWN0aW9uLklOT1VUIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG5cbiAgICB0aGlzLl9kaXJlY3Rpb24gPSBkaXJlY3Rpb247XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuXG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgRW5kUG9pbnQsIGRldGFjaGluZyBhbnkgYXR0YWNoZWQgQ2hhbm5lbHMgYW5kIHJlbW92aW5nIGFueVxuICAqIG1lc3NhZ2UtbGlzdGVuZXJzLiBDYWxsaW5nIHNodXRkb3duKCkgaXMgbWFuZGF0b3J5IHRvIGF2b2lkIG1lbW9yeS1sZWFrc1xuICAqIGR1ZSB0byB0aGUgY2lyY3VsYXIgcmVmZXJlbmNlcyB0aGF0IGV4aXN0IGJldHdlZW4gQ2hhbm5lbHMgYW5kIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgc2h1dGRvd24oKVxuICB7XG4gICAgdGhpcy5kZXRhY2hBbGwoKTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIEVuZFBvaW50J3MgaWRcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9pZDtcbiAgfVxuXG4gIC8qKlxuICAqIEF0dGFjaCBhIENoYW5uZWwgdG8gdGhpcyBFbmRQb2ludC4gT25jZSBhdHRhY2hlZCwgdGhlIENoYW5uZWwgd2lsbCBmb3J3YXJkXG4gICogbWVzc2FnZXMgdG8gdGhpcyBFbmRQb2ludCwgYW5kIHdpbGwgYWNjZXB0IG1lc3NhZ2VzIG9yaWdpbmF0ZWQgaGVyZS5cbiAgKiBBbiBFbmRQb2ludCBjYW4gaGF2ZSBtdWx0aXBsZSBDaGFubmVscyBhdHRhY2hlZCwgaW4gd2hpY2ggY2FzZSBpdCB3aWxsXG4gICogYnJvYWRjYXN0IHRvIHRoZW0gYWxsIHdoZW4gc2VuZGluZywgYW5kIHdpbGwgcmVjZWl2ZSBtZXNzYWdlcyBpblxuICAqIGFycml2YWwtb3JkZXIuXG4gICovXG4gIHB1YmxpYyBhdHRhY2goIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMucHVzaCggY2hhbm5lbCApO1xuXG4gICAgY2hhbm5lbC5hZGRFbmRQb2ludCggdGhpcyApO1xuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGEgc3BlY2lmaWMgQ2hhbm5lbCBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2goIGNoYW5uZWxUb0RldGFjaDogQ2hhbm5lbCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fY2hhbm5lbHMuaW5kZXhPZiggY2hhbm5lbFRvRGV0YWNoICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICBjaGFubmVsVG9EZXRhY2gucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBEZXRhY2ggYWxsIENoYW5uZWxzIGZyb20gdGhpcyBFbmRQb2ludC5cbiAgKi9cbiAgcHVibGljIGRldGFjaEFsbCgpXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcbiAgICB9ICk7XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQXJlIGFueSBjaGFubmVscyBhdHRhY2hlZCB0byB0aGlzIEVuZFBvaW50P1xuICAqXG4gICogQHJldHVybnMgdHJ1ZSBpZiBFbmRwb2ludCBpcyBhdHRhY2hlZCB0byBhdC1sZWFzdC1vbmUgQ2hhbm5lbFxuICAqL1xuICBnZXQgYXR0YWNoZWQoKVxuICB7XG4gICAgcmV0dXJuICggdGhpcy5fY2hhbm5lbHMubGVuZ3RoID4gMCApO1xuICB9XG5cbiAgZ2V0IGRpcmVjdGlvbigpOiBEaXJlY3Rpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9kaXJlY3Rpb247XG4gIH1cblxuICAvKipcbiAgKiBIYW5kbGUgYW4gaW5jb21pbmcgTWVzc2FnZSwgbWV0aG9kIGNhbGxlZCBieSBDaGFubmVsLlxuICAqL1xuICBwdWJsaWMgaGFuZGxlTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCBmcm9tRW5kUG9pbnQ6IEVuZFBvaW50LCBmcm9tQ2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzLmZvckVhY2goIG1lc3NhZ2VMaXN0ZW5lciA9PiB7XG4gICAgICBtZXNzYWdlTGlzdGVuZXIoIG1lc3NhZ2UsIHRoaXMsIGZyb21DaGFubmVsICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIE1lc3NhZ2UuXG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLmZvckVhY2goIGNoYW5uZWwgPT4ge1xuICAgICAgY2hhbm5lbC5zZW5kTWVzc2FnZSggdGhpcywgbWVzc2FnZSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGEgZGVsZWdhdGUgdG8gcmVjZWl2ZSBpbmNvbWluZyBNZXNzYWdlc1xuICAqXG4gICogQHBhcmFtIG1lc3NhZ2VMaXN0ZW5lciAtIGRlbGVnYXRlIHRvIGJlIGNhbGxlZCB3aXRoIHJlY2VpdmVkIE1lc3NhZ2VcbiAgKi9cbiAgcHVibGljIG9uTWVzc2FnZSggbWVzc2FnZUxpc3RlbmVyOiBIYW5kbGVNZXNzYWdlRGVsZWdhdGUgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5wdXNoKCBtZXNzYWdlTGlzdGVuZXIgKTtcbiAgfVxufVxuXG4vKipcbiogQW4gaW5kZXhlZCBjb2xsZWN0aW9uIG9mIEVuZFBvaW50IG9iamVjdHMsIG5vcm1hbGx5IGluZGV4ZWQgdmlhIEVuZFBvaW50J3NcbiogdW5pcXVlIGlkZW50aWZpZXJcbiovXG5leHBvcnQgdHlwZSBFbmRQb2ludENvbGxlY3Rpb24gPSB7IFtpZDogc3RyaW5nXTogRW5kUG9pbnQ7IH07XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IEtpbmQsIEtpbmRJbmZvIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuZXhwb3J0IGVudW0gUHJvdG9jb2xUeXBlQml0c1xue1xuICBQQUNLRVQgPSAwLCAgICAgICAgIC8qKiBEYXRhZ3JhbS1vcmllbnRlZCAoYWx3YXlzIGNvbm5lY3RlZC4uLikgKi9cbiAgU1RSRUFNID0gMSwgICAgICAgICAvKiogQ29ubmVjdGlvbi1vcmllbnRlZCAqL1xuXG4gIE9ORVdBWSA9IDAsICAgICAgICAgLyoqIFVuaWRpcmVjdGlvbmFsIE9VVCAoc291cmNlKSAtPiBJTiAoc2luaykgKi9cbiAgQ0xJRU5UU0VSVkVSID0gNCwgICAvKiogQ29tbWFuZCBPVVQtPklOLCBSZXNwb25zZSBJTi0+T1VUICovXG4gIFBFRVIyUEVFUiA9IDYsICAgICAgLyoqIEJpZGlyZWN0aW9uYWw6IElOT1VUIDwtPiBJTk9VVCAqL1xuXG4gIFVOVFlQRUQgPSAwLCAgICAgICAgLyoqIFVudHlwZWQgZGF0YSAqL1xuICBUWVBFRCA9IDgsICAgICAgICAgIC8qKiBUeXBlZCBkYXRhICoqL1xufVxuXG5leHBvcnQgdHlwZSBQcm90b2NvbFR5cGUgPSBudW1iZXI7XG5cbmV4cG9ydCBjbGFzcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSAwO1xufVxuXG4vKipcbiogQSBDbGllbnQtU2VydmVyIFByb3RvY29sLCB0byBiZSB1c2VkIGJldHdlZW5cbiovXG5jbGFzcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxUPiBleHRlbmRzIFByb3RvY29sPFQ+XG57XG4gIHN0YXRpYyBwcm90b2NvbFR5cGU6IFByb3RvY29sVHlwZSA9IFByb3RvY29sVHlwZUJpdHMuQ0xJRU5UU0VSVkVSIHwgUHJvdG9jb2xUeXBlQml0cy5UWVBFRDtcbn1cblxuY2xhc3MgQVBEVSBpbXBsZW1lbnRzIEtpbmQge1xuICBraW5kSW5mbzogS2luZEluZm87XG4gIHByb3BlcnRpZXM7XG59XG5cbmNsYXNzIEFQRFVNZXNzYWdlIGV4dGVuZHMgTWVzc2FnZTxBUERVPlxue1xufVxuXG5jbGFzcyBBUERVUHJvdG9jb2wgZXh0ZW5kcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxBUERVTWVzc2FnZT5cbntcblxufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuLyoqXG4qIEBjbGFzcyBQb3J0SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIGNvbXBvbmVudCdzIFBvcnRcbiovXG5leHBvcnQgY2xhc3MgUG9ydEluZm9cbntcbiAgLyoqXG4gICogQnJpZWYgZGVzY3JpcHRpb24gZm9yIHRoZSBwb3J0LCB0byBhcHBlYXIgaW4gJ2hpbnQnXG4gICovXG4gIGRlc2NyaXB0aW9uOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogRGlyZWN0aW9uOiBJTiwgT1VULCBvciBJTk9VVFxuICAqICAgZm9yIGNsaWVudC1zZXJ2ZXIsIE9VVD1DbGllbnQsIElOPVNlcnZlclxuICAqL1xuICBkaXJlY3Rpb246IERpcmVjdGlvbjtcblxuICAvKipcbiAgKiBQcm90b2NvbCBpbXBsZW1lbnRlZCBieSB0aGUgcG9ydFxuICAqL1xuICBwcm90b2NvbDogUHJvdG9jb2w8YW55PjtcblxuICAvKipcbiAgKiBSRlUgLSBpbmRleGFibGUgcG9ydHNcbiAgKi9cbiAgY291bnQ6IG51bWJlciA9IDA7XG5cbiAgLyoqXG4gICogdHJ1ZSBpcyBwb3J0IG11c3QgYmUgY29ubmVjdGVkIGZvciBjb21wb25lbnQgdG8gZXhlY3V0ZVxuICAqL1xuICByZXF1aXJlZDogYm9vbGVhbiA9IGZhbHNlO1xufVxuIiwiaW1wb3J0IHsgS2luZCwgS2luZENvbnN0cnVjdG9yIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50Q29sbGVjdGlvbiwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5cbmltcG9ydCB7IFBvcnRJbmZvIH0gZnJvbSAnLi9wb3J0LWluZm8nO1xuXG4vKipcbiogQGNsYXNzIENvbXBvbmVudEluZm9cbipcbiogTWV0YWRhdGEgYWJvdXQgYSBDb21wb25lbnRcbiovXG5leHBvcnQgY2xhc3MgQ29tcG9uZW50SW5mb1xue1xuICAvKipcbiAgKiBDb21wb25lbnQgTmFtZVxuICAqL1xuICBuYW1lOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogQnJpZWYgZGVzY3JpcHRpb24gZm9yIHRoZSBjb21wb25lbnQsIHRvIGFwcGVhciBpbiAnaGludCdcbiAgKi9cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICAvKipcbiAgKiBMaW5rIHRvIGRldGFpbGVkIGluZm9ybWF0aW9uIGZvciB0aGUgY29tcG9uZW50XG4gICovXG4gIGRldGFpbExpbms6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIENhdGVnb3J5IG5hbWUgZm9yIHRoZSBjb21wb25lbnQsIGdyb3VwcyBzYW1lIGNhdGVnb3JpZXMgdG9nZXRoZXJcbiAgKi9cbiAgY2F0ZWdvcnk6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIEF1dGhvcidzIG5hbWVcbiAgKi9cbiAgYXV0aG9yOiBzdHJpbmcgPSAnJztcblxuICAvKipcbiAgKiBBcnJheSBvZiBQb3J0IGRlc2NyaXB0b3JzLiBXaGVuIGFjdGl2ZSwgdGhlIGNvbXBvbmVudCB3aWxsIGNvbW11bmljYXRlXG4gICogdGhyb3VnaCBjb3JyZXNwb25kaW5nIEVuZFBvaW50c1xuICAqL1xuICBwb3J0czogeyBbaWQ6IHN0cmluZ106IFBvcnRJbmZvIH0gPSB7fTtcbiAgc3RvcmVzOiB7IFtpZDogc3RyaW5nXTogUG9ydEluZm8gfSA9IHt9O1xuXG4gIC8qKlxuICAqXG4gICovXG4gIGNvbmZpZ0tpbmQ6IEtpbmRDb25zdHJ1Y3RvcjtcbiAgZGVmYXVsdENvbmZpZzogS2luZDtcblxuICBjb25zdHJ1Y3RvcigpXG4gIHtcbiAgfVxufVxuIiwiXG4vKipcbiogTWV0YWRhdGEgYWJvdXQgYSBjb21wb25lbnQncyBTdG9yZVxuKiBUT0RPOiBcbiovXG5leHBvcnQgY2xhc3MgU3RvcmVJbmZvXG57XG59XG4iLCJpbXBvcnQgeyBQb3J0SW5mbyB9IGZyb20gJy4vcG9ydC1pbmZvJztcbmltcG9ydCB7IFN0b3JlSW5mbyB9IGZyb20gJy4vc3RvcmUtaW5mbyc7XG5pbXBvcnQgeyBDb21wb25lbnRJbmZvIH0gZnJvbSAnLi9jb21wb25lbnQtaW5mbyc7XG5pbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBQcm90b2NvbCB9IGZyb20gJy4uL21lc3NhZ2luZy9wcm90b2NvbCc7XG5pbXBvcnQgeyBLaW5kLCBLaW5kQ29uc3RydWN0b3IgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuXG4vKipcbiogQnVpbGRlciBmb3IgJ0NvbXBvbmVudCcgbWV0YWRhdGEgKHN0YXRpYyBjb21wb25lbnRJbmZvKVxuKi9cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRCdWlsZGVyXG57XG4gIHByaXZhdGUgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3I7XG5cbiAgY29uc3RydWN0b3IoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yLCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGNhdGVnb3J5Pzogc3RyaW5nICkge1xuXG4gICAgdGhpcy5jdG9yID0gY3RvcjtcblxuICAgIGN0b3IuY29tcG9uZW50SW5mbyA9IHtcbiAgICAgIG5hbWU6IG5hbWUgfHwgY3Rvci5uYW1lLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZGV0YWlsTGluazogJycsXG4gICAgICBjYXRlZ29yeTogY2F0ZWdvcnksXG4gICAgICBhdXRob3I6ICcnLFxuICAgICAgcG9ydHM6IHt9LFxuICAgICAgc3RvcmVzOiB7fSxcbiAgICAgIGNvbmZpZ0tpbmQ6IEtpbmQsXG4gICAgICBkZWZhdWx0Q29uZmlnOiB7fVxuICAgIH07XG4gIH1cblxuICBwdWJsaWMgc3RhdGljIGluaXQoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yLCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGNhdGVnb3J5Pzogc3RyaW5nICk6IENvbXBvbmVudEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IENvbXBvbmVudEJ1aWxkZXIoIGN0b3IsIG5hbWUsIGRlc2NyaXB0aW9uLCBjYXRlZ29yeSApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgY29uZmlnKCBjb25maWdLaW5kOiBLaW5kQ29uc3RydWN0b3IsIGRlZmF1bHRDb25maWc/OiBLaW5kICk6IHRoaXMge1xuXG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8uY29uZmlnS2luZCA9IGNvbmZpZ0tpbmQ7XG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8uZGVmYXVsdENvbmZpZyA9IGRlZmF1bHRDb25maWc7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBwb3J0KCBpZDogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBkaXJlY3Rpb246IERpcmVjdGlvbiwgb3B0cz86IHsgcHJvdG9jb2w/OiBQcm90b2NvbDxhbnk+OyBjb3VudD86IG51bWJlcjsgcmVxdWlyZWQ/OiBib29sZWFuIH0gKTogdGhpc1xuICB7XG4gICAgb3B0cyA9IG9wdHMgfHwge307XG5cbiAgICB0aGlzLmN0b3IuY29tcG9uZW50SW5mby5wb3J0c1sgaWQgXSA9IHtcbiAgICAgIGRpcmVjdGlvbjogZGlyZWN0aW9uLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgcHJvdG9jb2w6IG9wdHMucHJvdG9jb2wsXG4gICAgICBjb3VudDogb3B0cy5jb3VudCxcbiAgICAgIHJlcXVpcmVkOiBvcHRzLnJlcXVpcmVkXG4gICAgfTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG59XG5cbi8qKlxuKiBDb21wb25lbnRzIGFyZSBydW50aW1lIG9iamVjdHMgdGhhdCBleGVjdXRlIHdpdGhpbiBhIEdyYXBoLlxuKlxuKiBBIGdyYXBoIE5vZGUgaXMgYSBwbGFjZWhvbGRlciBmb3IgdGhlIGFjdHVhbCBDb21wb25lbnQgdGhhdFxuKiB3aWxsIGV4ZWN1dGUuXG4qXG4qIFRoaXMgaW50ZXJmYWNlIGRlZmluZXMgdGhlIHN0YW5kYXJkIG1ldGhvZHMgYW5kIHByb3BlcnRpZXMgdGhhdCBhIENvbXBvbmVudFxuKiBjYW4gb3B0aW9uYWxseSBpbXBsZW1lbnQuXG4qL1xuZXhwb3J0IGludGVyZmFjZSBDb21wb25lbnRcbntcbiAgLy8gSW5pdGlhbGl6YXRpb24gYW5kIHNodXRkb3duXG4gIGluaXRpYWxpemU/KCBjb25maWc/OiBLaW5kICk6IEVuZFBvaW50W107XG4gIHRlYXJkb3duPygpO1xuXG4gIC8vIFJ1bm5pbmdcbiAgc3RhcnQ/KCk7XG4gIHN0b3A/KCk7XG5cbiAgLy8gUGF1c2luZyBhbmQgY29udGludWluZyBleGVjdXRpb24gKHdpdGhvdXQgcmVzZXR0aW5nIC4uKVxuICBwYXVzZT8oKTtcbiAgcmVzdW1lPygpO1xuXG4gIGJpbmRWaWV3PyggdmlldzogYW55ICk7XG4gIHVuYmluZFZpZXc/KCk7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29tcG9uZW50Q29uc3RydWN0b3JcbntcbiAgbmV3ICggLi4uYXJncyApOiBDb21wb25lbnQ7XG5cbiAgY29tcG9uZW50SW5mbz86IENvbXBvbmVudEluZm87XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuXG5leHBvcnQgZW51bSBDcnlwdG9ncmFwaGljT3BlcmF0aW9uIHtcbiAgRU5DUllQVCxcbiAgREVDUllQVCxcbiAgRElHRVNULFxuICBTSUdOLFxuICBWRVJJRlksXG4gIERFUklWRV9CSVRTLFxuXG4gIERFUklWRV9LRVksXG4gIElNUE9SVF9LRVksXG4gIEVYUE9SVF9LRVksXG4gIEdFTkVSQVRFX0tFWSxcbiAgV1JBUF9LRVksXG4gIFVOV1JBUF9LRVksXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBlbmNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuICBkZWNyeXB0PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIGRpZ2VzdD8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+O1xuXG4gIHNpZ24/KCBhbGdvcml0aG06IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG4gIHZlcmlmeT8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG5cbiAgZGVyaXZlQml0cz8oIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGxlbmd0aDogbnVtYmVyICk6IFByb21pc2U8Qnl0ZUFycmF5Pjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yIHtcbiAgbmV3KCk6IENyeXB0b2dyYXBoaWNTZXJ2aWNlO1xuXG4gIHN1cHBvcnRlZE9wZXJhdGlvbnM/OiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW107XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBkZXJpdmVLZXk/KCBhbGdvcml0aG06IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG5cbiAgd3JhcEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSwgd3JhcHBpbmdLZXk6IENyeXB0b0tleSwgd3JhcEFsZ29yaXRobTogQWxnb3JpdGhtICk6IFByb21pc2U8Qnl0ZUFycmF5PjtcbiAgdW53cmFwS2V5PyggZm9ybWF0OiBzdHJpbmcsIHdyYXBwZWRLZXk6IEJ5dGVBcnJheSwgdW53cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB1bndyYXBBbGdvcml0aG06IEFsZ29yaXRobSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+O1xuXG4gIGltcG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT47XG4gIGdlbmVyYXRlS2V5PyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj47XG4gIGV4cG9ydEtleT8oIGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSApOiBQcm9taXNlPEJ5dGVBcnJheT47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2VDb25zdHJ1Y3RvciB7XG4gIG5ldygpOiBDcnlwdG9ncmFwaGljS2V5U2VydmljZTtcblxuICBzdXBwb3J0ZWRPcGVyYXRpb25zPzogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdO1xufVxuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSB7XG4gIHByaXZhdGUgX3NlcnZpY2VNYXA6IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3I+O1xuICBwcml2YXRlIF9rZXlTZXJ2aWNlTWFwOiBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPjtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLl9zZXJ2aWNlTWFwID0gbmV3IE1hcDxzdHJpbmcsIENyeXB0b2dyYXBoaWNTZXJ2aWNlQ29uc3RydWN0b3I+KCk7XG4gICAgdGhpcy5fa2V5U2VydmljZU1hcCA9IG5ldyBNYXA8c3RyaW5nLCBDcnlwdG9ncmFwaGljS2V5U2VydmljZUNvbnN0cnVjdG9yPigpO1xuICB9XG5cbiAgZ2V0U2VydmljZSggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0gKTogeyBuYW1lOiBzdHJpbmcsIGluc3RhbmNlOiBDcnlwdG9ncmFwaGljU2VydmljZSB9IHtcbiAgICBsZXQgYWxnbyA9ICggYWxnb3JpdGhtIGluc3RhbmNlb2YgT2JqZWN0ICkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICBsZXQgc2VydmljZSA9IHRoaXMuX3NlcnZpY2VNYXAuZ2V0KCBhbGdvICk7XG5cbiAgICByZXR1cm4geyBuYW1lOiBhbGdvLCBpbnN0YW5jZTogc2VydmljZSA/IG5ldyBzZXJ2aWNlKCkgOiBudWxsIH07XG4gIH1cblxuICBnZXRLZXlTZXJ2aWNlKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSApOiB7IG5hbWU6IHN0cmluZywgaW5zdGFuY2U6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0ge1xuICAgIGxldCBhbGdvID0gKCBhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QgKSA/ICg8QWxnb3JpdGhtPmFsZ29yaXRobSkubmFtZSA6IDxzdHJpbmc+YWxnb3JpdGhtO1xuICAgIGxldCBzZXJ2aWNlID0gdGhpcy5fa2V5U2VydmljZU1hcC5nZXQoIGFsZ28gKTtcblxuICAgIHJldHVybiB7IG5hbWU6IGFsZ28sIGluc3RhbmNlOiBzZXJ2aWNlID8gbmV3IHNlcnZpY2UoKSA6IG51bGwgfTtcbiAgfVxuXG4gIHNldFNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fc2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG4gIHNldEtleVNlcnZpY2UoIGFsZ29yaXRobTogc3RyaW5nLCBjdG9yOiBDcnlwdG9ncmFwaGljU2VydmljZUNvbnN0cnVjdG9yLCBvcGVyczogQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbltdICkge1xuICAgIGN0b3Iuc3VwcG9ydGVkT3BlcmF0aW9ucyA9IG9wZXJzO1xuXG4gICAgdGhpcy5fa2V5U2VydmljZU1hcC5zZXQoIGFsZ29yaXRobSwgY3RvciApO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgLy8gc2luZ2xldG9uIHJlZ2lzdHJ5XG4gIHByaXZhdGUgc3RhdGljIF9yZWdpc3RyeTogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VSZWdpc3RyeSA9IG5ldyBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5KCk7XG5cbiAgcHVibGljIHN0YXRpYyByZWdpc3RlclNlcnZpY2UoIG5hbWU6IHN0cmluZywgY3RvcjogQ3J5cHRvZ3JhcGhpY1NlcnZpY2VDb25zdHJ1Y3Rvciwgb3BlcnM6IENyeXB0b2dyYXBoaWNPcGVyYXRpb25bXSApIHtcbiAgICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLl9yZWdpc3RyeS5zZXRTZXJ2aWNlKCBuYW1lLCBjdG9yLCBvcGVycyApO1xuICB9XG4gIHB1YmxpYyBzdGF0aWMgcmVnaXN0ZXJLZXlTZXJ2aWNlKCBuYW1lOiBzdHJpbmcsIGN0b3I6IENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlQ29uc3RydWN0b3IsIG9wZXJzOiBDcnlwdG9ncmFwaGljT3BlcmF0aW9uW10gKSB7XG4gICAgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnkuc2V0S2V5U2VydmljZSggbmFtZSwgY3Rvciwgb3BlcnMgKTtcbiAgfVxuXG4gIGdldCByZWdpc3RyeSgpOiBDcnlwdG9ncmFwaGljU2VydmljZVJlZ2lzdHJ5IHtcbiAgICByZXR1cm4gQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5fcmVnaXN0cnk7XG4gIH1cblxuICBlbmNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmVuY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5lbmNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlY3J5cHQgKVxuICAgICAgPyBpbnN0YW5jZS5kZWNyeXB0KCBuYW1lLCBrZXksIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kaWdlc3QgKVxuICAgICAgPyBpbnN0YW5jZS5kaWdlc3QoIG5hbWUsIGRhdGEgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICBzaWduKCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIGRhdGE6IEJ5dGVBcnJheSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2Uuc2lnbiApXG4gICAgICA/IGluc3RhbmNlLnNpZ24oIG5hbWUsIGtleSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIHZlcmlmeShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBDcnlwdG9LZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldFNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UudmVyaWZ5IClcbiAgICAgID8gaW5zdGFuY2UudmVyaWZ5KCBuYW1lLCBrZXksIHNpZ25hdHVyZSwgZGF0YSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSgga2V5LmFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuZXhwb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuZXhwb3J0S2V5KCBmb3JtYXQsIGtleSApXG4gICAgICA6IFByb21pc2UucmVqZWN0PEJ5dGVBcnJheT4oIFwiXCIgKTtcbiAgfVxuXG4gIGdlbmVyYXRlS2V5KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxDcnlwdG9LZXkgfCBDcnlwdG9LZXlQYWlyPiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5nZW5lcmF0ZUtleSApXG4gICAgICA/IGluc3RhbmNlLmdlbmVyYXRlS2V5KCBuYW1lLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oIFwiXCIgKTtcbiAgfVxuXG4gIGltcG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSAsIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGFsZ29yaXRobSApO1xuXG4gICAgcmV0dXJuICggaW5zdGFuY2UgJiYgaW5zdGFuY2UuaW1wb3J0S2V5IClcbiAgICAgID8gaW5zdGFuY2UuaW1wb3J0S2V5KCBmb3JtYXQsIGtleURhdGEsIG5hbWUsIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxDcnlwdG9LZXk+KCBcIlwiICk7XG4gIH1cblxuICBkZXJpdmVLZXkoIGFsZ29yaXRobTogQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGRlcml2ZWRLZXlUeXBlOiBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdICk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggYWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS5kZXJpdmVLZXkgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVLZXkoIG5hbWUsIGJhc2VLZXksIGRlcml2ZWRLZXlUeXBlLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG5cbiAgZGVyaXZlQml0cyggYWxnb3JpdGhtOiBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgbGVuZ3RoOiBudW1iZXIgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICBsZXQgeyBuYW1lLCBpbnN0YW5jZSB9ID0gdGhpcy5yZWdpc3RyeS5nZXRTZXJ2aWNlKCBhbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLmRlcml2ZUJpdHMgKVxuICAgICAgPyBpbnN0YW5jZS5kZXJpdmVCaXRzKCBuYW1lLCBiYXNlS2V5LCBsZW5ndGggKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB3cmFwS2V5KCBmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IEFsZ29yaXRobSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIGxldCB7IG5hbWUsIGluc3RhbmNlIH0gPSB0aGlzLnJlZ2lzdHJ5LmdldEtleVNlcnZpY2UoIGtleS5hbGdvcml0aG0gKTtcblxuICAgIHJldHVybiAoIGluc3RhbmNlICYmIGluc3RhbmNlLndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS53cmFwS2V5KCBmb3JtYXQsIGtleSwgd3JhcHBpbmdLZXksIHdyYXBBbGdvcml0aG0gKVxuICAgICAgOiBQcm9taXNlLnJlamVjdDxCeXRlQXJyYXk+KCBcIlwiICk7XG4gIH1cblxuICB1bndyYXBLZXkoIGZvcm1hdDogc3RyaW5nLCB3cmFwcGVkS2V5OiBCeXRlQXJyYXksIHVud3JhcHBpbmdLZXk6IENyeXB0b0tleSwgdW53cmFwQWxnb3JpdGhtOiBBbGdvcml0aG0sIHVud3JhcHBlZEtleUFsZ29yaXRobTogQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgbGV0IHsgbmFtZSwgaW5zdGFuY2UgfSA9IHRoaXMucmVnaXN0cnkuZ2V0S2V5U2VydmljZSggdW53cmFwQWxnb3JpdGhtICk7XG5cbiAgICByZXR1cm4gKCBpbnN0YW5jZSAmJiBpbnN0YW5jZS51bndyYXBLZXkgKVxuICAgICAgPyBpbnN0YW5jZS51bndyYXBLZXkoIGZvcm1hdCwgd3JhcHBlZEtleSwgdW53cmFwcGluZ0tleSwgbmFtZSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzIClcbiAgICAgIDogUHJvbWlzZS5yZWplY3Q8Q3J5cHRvS2V5PiggXCJcIiApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlciwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbiwgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIH0gZnJvbSAnLi9jcnlwdG9ncmFwaGljLXNlcnZpY2UtcmVnaXN0cnknO1xuXG5kZWNsYXJlIHZhciBtc3JjcnlwdG87XG5cbmV4cG9ydCBjbGFzcyBXZWJDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsIENyeXB0b2dyYXBoaWNLZXlTZXJ2aWNlIHtcbiAgcHJvdGVjdGVkIGNyeXB0bzogU3VidGxlQ3J5cHRvO1xuXG4gIGNvbnN0cnVjdG9yKCkge1xuICB9XG5cbiAgc3RhdGljIF9zdWJ0bGU6IFN1YnRsZUNyeXB0bztcbiAgc3RhdGljIGdldCBzdWJ0bGUoKTogU3VidGxlQ3J5cHRvIHtcbiAgICBsZXQgc3VidGxlID0gV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlXG4gICAgICB8fCAoIGNyeXB0byAmJiBjcnlwdG8uc3VidGxlIClcbiAgICAgIHx8ICggd2luZG93ICYmIHdpbmRvdy5jcnlwdG8gJiYgd2luZG93LmNyeXB0by5zdWJ0bGUgKVxuICAgICAgfHwgbXNyY3J5cHRvO1xuXG4gICAgaWYgKCAhV2ViQ3J5cHRvU2VydmljZS5fc3VidGxlIClcbiAgICAgICBXZWJDcnlwdG9TZXJ2aWNlLl9zdWJ0bGUgPSBzdWJ0bGU7XG5cbiAgICByZXR1cm4gc3VidGxlO1xuICB9XG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBXZWJDcnlwdG9TZXJ2aWNlLnN1YnRsZS5lbmNyeXB0KGFsZ29yaXRobSwga2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmRlY3J5cHQoYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZGlnZXN0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkpOiBhbnkge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogQ3J5cHRvS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUuZXhwb3J0S2V5KGZvcm1hdCwga2V5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZ2VuZXJhdGVLZXkoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPENyeXB0b0tleSB8IENyeXB0b0tleVBhaXI+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q3J5cHRvS2V5IHwgQ3J5cHRvS2V5UGFpcj4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuXG4gICB9KTtcbiAgfVxuXG4gIGltcG9ydEtleShmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5LCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLmltcG9ydEtleShmb3JtYXQsIGtleURhdGEuYmFja2luZ0FycmF5LCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShyZXMpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICB9KTtcbiAgfVxuXG4gIHNpZ24oYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIFdlYkNyeXB0b1NlcnZpY2Uuc3VidGxlLnNpZ24oYWxnb3JpdGhtLCBrZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgdmVyaWZ5KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgc2lnbmF0dXJlOiBCeXRlQXJyYXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUudmVyaWZ5KGFsZ29yaXRobSwga2V5LCBzaWduYXR1cmUuYmFja2luZ0FycmF5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxufVxuXG4vKmNsYXNzIFNIQTFDcnlwdG9TZXJ2aWNlIGltcGxlbWVudHMgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBkaWdlc3QoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICAvLyBUT0RPOiBJbXBsZW1lbnQgU0hBLTFcbiAgICAgIG1zcmNyeXB0by5kaWdlc3QoYWxnb3JpdGhtLCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cbn1cblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtMScsIFNIQTFDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdTSEEtMjU2JywgV2ViQ3J5cHRvU2VydmljZSwgWyBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRJR0VTVCBdICk7XG5DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1NIQS01MTInLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRElHRVNUIF0gKTtcbiovXG5cbmlmICggV2ViQ3J5cHRvU2VydmljZS5zdWJ0bGUgKSB7XG4gIENyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnQUVTLUNCQycsIFdlYkNyeXB0b1NlcnZpY2UsIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQgXSApO1xuICBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ0FFUy1HQ00nLCBXZWJDcnlwdG9TZXJ2aWNlLCBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ERUNSWVBUIF0gKTtcbiAgLy9DcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLnJlZ2lzdGVyU2VydmljZSggJ1JTQVNTQS1YWVonLCBXZWJDcnlwdG9TZXJ2aWNlICk7XG5cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJy4uL2tpbmQvYnl0ZS1hcnJheSc7XG5pbXBvcnQgeyBDcnlwdG9ncmFwaGljU2VydmljZVByb3ZpZGVyLCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLCBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2UgfSBmcm9tICcuL2NyeXB0b2dyYXBoaWMtc2VydmljZS1yZWdpc3RyeSc7XG5cbmNsYXNzIERFU1NlY3JldEtleSBpbXBsZW1lbnRzIENyeXB0b0tleSB7XG4gIHByaXZhdGUgX2tleU1hdGVyaWFsOiBCeXRlQXJyYXk7XG4gIHByaXZhdGUgX2V4dHJhY3RhYmxlOiBib29sZWFuO1xuICBwcml2YXRlIF9hbGdvcml0aG06IEtleUFsZ29yaXRobTtcbiAgcHJpdmF0ZSBfdHlwZTogc3RyaW5nO1xuICBwcml2YXRlIF91c2FnZXM6IHN0cmluZ1tdO1xuXG4gIGNvbnN0cnVjdG9yKCBrZXlNYXRlcmlhbDogQnl0ZUFycmF5LCBhbGdvcml0aG06IEtleUFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIHVzYWdlczogc3RyaW5nW10gKSB7XG5cbiAgICB0aGlzLl9rZXlNYXRlcmlhbCA9IGtleU1hdGVyaWFsO1xuXG4gICAgdGhpcy5fYWxnb3JpdGhtID0gYWxnb3JpdGhtO1xuXG4gICAgdGhpcy5fZXh0cmFjdGFibGUgPSBleHRyYWN0YWJsZTtcblxuICAgIHRoaXMuX3R5cGUgPSAnc2VjcmV0JztcblxuICAgIHRoaXMuX3VzYWdlcyA9IHVzYWdlcztcbiAgICBPYmplY3QuZnJlZXplKCB0aGlzLl91c2FnZXMgKTtcbiAgfVxuXG4gIGdldCBhbGdvcml0aG0oKSB7IHJldHVybiB0aGlzLl9hbGdvcml0aG07IH1cbiAgZ2V0IGV4dHJhY3RhYmxlKCk6IGJvb2xlYW4geyByZXR1cm4gdGhpcy5fZXh0cmFjdGFibGU7IH1cbiAgZ2V0IHR5cGUoKSB7IHJldHVybiB0aGlzLl90eXBlOyB9XG4gIGdldCB1c2FnZXMoKTogc3RyaW5nW10geyByZXR1cm4gQXJyYXkuZnJvbSggdGhpcy5fdXNhZ2VzICk7IH1cblxuICBnZXQga2V5TWF0ZXJpYWwoKSB7IHJldHVybiB0aGlzLl9rZXlNYXRlcmlhbCB9O1xufVxuXG5leHBvcnQgY2xhc3MgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UgaW1wbGVtZW50cyBDcnlwdG9ncmFwaGljU2VydmljZSwgQ3J5cHRvZ3JhcGhpY0tleVNlcnZpY2Uge1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgfVxuXG4gIC8vIHBhZGRpbmc6XG4gIC8vIDAgPSB6ZXJvLXBhZFxuICAvLyAxID0gUEtDUzdcbiAgLy8gMiA9IHNwYWNlc1xuICAvLyA0ID0gbm8tcGFkXG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgYWxnID0gKGFsZ29yaXRobSBpbnN0YW5jZW9mIE9iamVjdCkgPyAoPEFsZ29yaXRobT5hbGdvcml0aG0pLm5hbWUgOiA8c3RyaW5nPmFsZ29yaXRobTtcbiAgICAgIGxldCBkZXNLZXkgPSBrZXkgYXMgREVTU2VjcmV0S2V5O1xuICAgICAgbGV0IG1vZGUgPSAwLCBwYWRkaW5nID0gNDtcbiAgICAgIGxldCBpdjtcblxuICAgICAgaWYgKCBhbGcgIT0gZGVzS2V5LmFsZ29yaXRobS5uYW1lIClcbiAgICAgICAgcmVqZWN0KCBuZXcgRXJyb3IoICdLZXkgKCcgKyBkZXNLZXkuYWxnb3JpdGhtLm5hbWUgKyAnKSBjYW5ub3QgYmUgdXNlZCBmb3IgREVTIGRlY3J5cHQnKSApO1xuXG4gICAgICBpZiAoIGRlc0tleS5hbGdvcml0aG0ubmFtZSA9PSAnREVTLUNCQycgKSB7XG4gICAgICAgIGxldCBpdnggPSAoPEFsZ29yaXRobT5hbGdvcml0aG0pWydpdiddIHx8IFsgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCBdO1xuXG4gICAgICAgIGl2ID0gbmV3IEJ5dGVBcnJheSggaXZ4ICkuYmFja2luZ0FycmF5O1xuXG4gICAgICAgIG1vZGUgPSAxO1xuICAgICAgfVxuXG4gICAgICBpZiAoICggZGF0YS5sZW5ndGggPj0gOCApIHx8ICggcGFkZGluZyAhPSA0ICkgKVxuICAgICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCB0aGlzLmRlcyggZGVzS2V5LmtleU1hdGVyaWFsLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXksIDEsIG1vZGUsIGl2LCBwYWRkaW5nICkgKSApO1xuICAgICAgZWxzZVxuICAgICAgICByZXNvbHZlKCBuZXcgQnl0ZUFycmF5KCkgKTtcbiAgICB9KTtcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogQ3J5cHRvS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbGV0IGFsZyA9IChhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QpID8gKDxBbGdvcml0aG0+YWxnb3JpdGhtKS5uYW1lIDogPHN0cmluZz5hbGdvcml0aG07XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcbiAgICAgIGxldCBtb2RlID0gMCwgcGFkZGluZyA9IDQ7XG4gICAgICBsZXQgaXY7XG5cbiAgICAgIGlmICggYWxnICE9IGRlc0tleS5hbGdvcml0aG0ubmFtZSApXG4gICAgICAgIHJlamVjdCggbmV3IEVycm9yKCAnS2V5ICgnICsgZGVzS2V5LmFsZ29yaXRobS5uYW1lICsgJykgY2Fubm90IGJlIHVzZWQgZm9yIERFUyBkZWNyeXB0JykgKTtcblxuICAgICAgaWYgKCBkZXNLZXkuYWxnb3JpdGhtLm5hbWUgPT0gJ0RFUy1DQkMnICkge1xuICAgICAgICBsZXQgaXZ4ID0gKDxBbGdvcml0aG0+YWxnb3JpdGhtKVsnaXYnXSB8fCBbIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAgXTtcblxuICAgICAgICBpdiA9IG5ldyBCeXRlQXJyYXkoIGl2eCApLmJhY2tpbmdBcnJheTtcblxuICAgICAgICBtb2RlID0gMTtcbiAgICAgIH1cblxuICAgICAgaWYgKCBkYXRhLmxlbmd0aCA+PSA4IClcbiAgICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAwLCBtb2RlLCBpdiwgcGFkZGluZyApICkgKTtcbiAgICAgIGVsc2VcbiAgICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSgpICk7XG4gICAgICAvL2NhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgaW1wb3J0S2V5KGZvcm1hdDogc3RyaW5nLCBrZXlEYXRhOiBCeXRlQXJyYXksIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgaWYgKCAhKCBhbGdvcml0aG0gaW5zdGFuY2VvZiBPYmplY3QgKSApXG4gICAgICBhbGdvcml0aG0gPSA8QWxnb3JpdGhtPnsgbmFtZTogPHN0cmluZz5hbGdvcml0aG0gfTtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTxDcnlwdG9LZXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBkZXNLZXkgPSBuZXcgREVTU2VjcmV0S2V5KCBrZXlEYXRhLCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBrZXlVc2FnZXMgKTtcblxuICAgICAgcmVzb2x2ZSggZGVzS2V5ICk7XG4gICB9KTtcbiAgfVxuXG4gIHNpZ24oIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IENyeXB0b0tleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgZGVzS2V5ID0ga2V5IGFzIERFU1NlY3JldEtleTtcblxuICAgICAgcmVzb2x2ZSggbmV3IEJ5dGVBcnJheSggdGhpcy5kZXMoIGRlc0tleS5rZXlNYXRlcmlhbC5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5LCAwLCAwICkgKSApO1xuICAgICAgLy9jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHN0YXRpYyBkZXNQQztcbiAgc3RhdGljIGRlc1NQO1xuXG4gIHByaXZhdGUgZGVzKCBrZXk6IFVpbnQ4QXJyYXksIG1lc3NhZ2U6IFVpbnQ4QXJyYXksIGVuY3J5cHQ6IG51bWJlciwgbW9kZTogbnVtYmVyLCBpdj86IFVpbnQ4QXJyYXksIHBhZGRpbmc/OiBudW1iZXIgKTogVWludDhBcnJheVxuICB7XG4gICAgLy9kZXNfY3JlYXRlS2V5c1xuICAgIC8vdGhpcyB0YWtlcyBhcyBpbnB1dCBhIDY0IGJpdCBrZXkgKGV2ZW4gdGhvdWdoIG9ubHkgNTYgYml0cyBhcmUgdXNlZClcbiAgICAvL2FzIGFuIGFycmF5IG9mIDIgaW50ZWdlcnMsIGFuZCByZXR1cm5zIDE2IDQ4IGJpdCBrZXlzXG4gICAgZnVuY3Rpb24gZGVzX2NyZWF0ZUtleXMgKGtleSlcbiAgICB7XG4gICAgICBsZXQgZGVzUEMgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNQQztcblxuICAgICAgaWYgKCAhZGVzUEMgKVxuICAgICAge1xuICAgICAgICAvL2RlY2xhcmluZyB0aGlzIGxvY2FsbHkgc3BlZWRzIHRoaW5ncyB1cCBhIGJpdFxuICAgICAgICBkZXNQQyA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1BDID0ge1xuICAgICAgICAgIHBjMmJ5dGVzMCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NCwweDIwMDAwMDAwLDB4MjAwMDAwMDQsMHgxMDAwMCwweDEwMDA0LDB4MjAwMTAwMDAsMHgyMDAxMDAwNCwweDIwMCwweDIwNCwweDIwMDAwMjAwLDB4MjAwMDAyMDQsMHgxMDIwMCwweDEwMjA0LDB4MjAwMTAyMDAsMHgyMDAxMDIwNCBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxLDB4MTAwMDAwLDB4MTAwMDAxLDB4NDAwMDAwMCwweDQwMDAwMDEsMHg0MTAwMDAwLDB4NDEwMDAwMSwweDEwMCwweDEwMSwweDEwMDEwMCwweDEwMDEwMSwweDQwMDAxMDAsMHg0MDAwMTAxLDB4NDEwMDEwMCwweDQxMDAxMDFdICksXG4gICAgICAgICAgcGMyYnl0ZXMyIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg4LDB4ODAwLDB4ODA4LDB4MTAwMDAwMCwweDEwMDAwMDgsMHgxMDAwODAwLDB4MTAwMDgwOCwwLDB4OCwweDgwMCwweDgwOCwweDEwMDAwMDAsMHgxMDAwMDA4LDB4MTAwMDgwMCwweDEwMDA4MDhdICksXG4gICAgICAgICAgcGMyYnl0ZXMzIDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgyMDAwMDAsMHg4MDAwMDAwLDB4ODIwMDAwMCwweDIwMDAsMHgyMDIwMDAsMHg4MDAyMDAwLDB4ODIwMjAwMCwweDIwMDAwLDB4MjIwMDAwLDB4ODAyMDAwMCwweDgyMjAwMDAsMHgyMjAwMCwweDIyMjAwMCwweDgwMjIwMDAsMHg4MjIyMDAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzNCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwMDAsMHgxMCwweDQwMDEwLDAsMHg0MDAwMCwweDEwLDB4NDAwMTAsMHgxMDAwLDB4NDEwMDAsMHgxMDEwLDB4NDEwMTAsMHgxMDAwLDB4NDEwMDAsMHgxMDEwLDB4NDEwMTBdICksXG4gICAgICAgICAgcGMyYnl0ZXM1IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHg0MDAsMHgyMCwweDQyMCwwLDB4NDAwLDB4MjAsMHg0MjAsMHgyMDAwMDAwLDB4MjAwMDQwMCwweDIwMDAwMjAsMHgyMDAwNDIwLDB4MjAwMDAwMCwweDIwMDA0MDAsMHgyMDAwMDIwLDB4MjAwMDQyMF0gKSxcbiAgICAgICAgICBwYzJieXRlczYgOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDIsMCwweDEwMDAwMDAwLDB4ODAwMDAsMHgxMDA4MDAwMCwweDIsMHgxMDAwMDAwMiwweDgwMDAyLDB4MTAwODAwMDJdICksXG4gICAgICAgICAgcGMyYnl0ZXM3IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMCwweDgwMCwweDEwODAwLDB4MjAwMDAwMDAsMHgyMDAxMDAwMCwweDIwMDAwODAwLDB4MjAwMTA4MDAsMHgyMDAwMCwweDMwMDAwLDB4MjA4MDAsMHgzMDgwMCwweDIwMDIwMDAwLDB4MjAwMzAwMDAsMHgyMDAyMDgwMCwweDIwMDMwODAwXSApLFxuICAgICAgICAgIHBjMmJ5dGVzOCA6IG5ldyBVaW50MzJBcnJheSggWyAwLDB4NDAwMDAsMCwweDQwMDAwLDB4MiwweDQwMDAyLDB4MiwweDQwMDAyLDB4MjAwMDAwMCwweDIwNDAwMDAsMHgyMDAwMDAwLDB4MjA0MDAwMCwweDIwMDAwMDIsMHgyMDQwMDAyLDB4MjAwMDAwMiwweDIwNDAwMDJdICksXG4gICAgICAgICAgcGMyYnl0ZXM5IDogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwMCwweDgsMHgxMDAwMDAwOCwwLDB4MTAwMDAwMDAsMHg4LDB4MTAwMDAwMDgsMHg0MDAsMHgxMDAwMDQwMCwweDQwOCwweDEwMDAwNDA4LDB4NDAwLDB4MTAwMDA0MDAsMHg0MDgsMHgxMDAwMDQwOF0gKSxcbiAgICAgICAgICBwYzJieXRlczEwOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDIwLDAsMHgyMCwweDEwMDAwMCwweDEwMDAyMCwweDEwMDAwMCwweDEwMDAyMCwweDIwMDAsMHgyMDIwLDB4MjAwMCwweDIwMjAsMHgxMDIwMDAsMHgxMDIwMjAsMHgxMDIwMDAsMHgxMDIwMjBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMTogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwMDAwLDB4MjAwLDB4MTAwMDIwMCwweDIwMDAwMCwweDEyMDAwMDAsMHgyMDAyMDAsMHgxMjAwMjAwLDB4NDAwMDAwMCwweDUwMDAwMDAsMHg0MDAwMjAwLDB4NTAwMDIwMCwweDQyMDAwMDAsMHg1MjAwMDAwLDB4NDIwMDIwMCwweDUyMDAyMDBdICksXG4gICAgICAgICAgcGMyYnl0ZXMxMjogbmV3IFVpbnQzMkFycmF5KCBbIDAsMHgxMDAwLDB4ODAwMDAwMCwweDgwMDEwMDAsMHg4MDAwMCwweDgxMDAwLDB4ODA4MDAwMCwweDgwODEwMDAsMHgxMCwweDEwMTAsMHg4MDAwMDEwLDB4ODAwMTAxMCwweDgwMDEwLDB4ODEwMTAsMHg4MDgwMDEwLDB4ODA4MTAxMF0gKSxcbiAgICAgICAgICBwYzJieXRlczEzOiBuZXcgVWludDMyQXJyYXkoIFsgMCwweDQsMHgxMDAsMHgxMDQsMCwweDQsMHgxMDAsMHgxMDQsMHgxLDB4NSwweDEwMSwweDEwNSwweDEsMHg1LDB4MTAxLDB4MTA1XSApXG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIC8vaG93IG1hbnkgaXRlcmF0aW9ucyAoMSBmb3IgZGVzLCAzIGZvciB0cmlwbGUgZGVzKVxuICAgICAgdmFyIGl0ZXJhdGlvbnMgPSBrZXkubGVuZ3RoID4gOCA/IDMgOiAxOyAvL2NoYW5nZWQgYnkgUGF1bCAxNi82LzIwMDcgdG8gdXNlIFRyaXBsZSBERVMgZm9yIDkrIGJ5dGUga2V5c1xuICAgICAgLy9zdG9yZXMgdGhlIHJldHVybiBrZXlzXG4gICAgICB2YXIga2V5cyA9IG5ldyBVaW50MzJBcnJheSgzMiAqIGl0ZXJhdGlvbnMpO1xuICAgICAgLy9ub3cgZGVmaW5lIHRoZSBsZWZ0IHNoaWZ0cyB3aGljaCBuZWVkIHRvIGJlIGRvbmVcbiAgICAgIHZhciBzaGlmdHMgPSBbIDAsIDAsIDEsIDEsIDEsIDEsIDEsIDEsIDAsIDEsIDEsIDEsIDEsIDEsIDEsIDAgXTtcbiAgICAgIC8vb3RoZXIgdmFyaWFibGVzXG4gICAgICB2YXIgbGVmdHRlbXAsIHJpZ2h0dGVtcCwgbT0wLCBuPTAsIHRlbXA7XG5cbiAgICAgIGZvciAodmFyIGo9MDsgajxpdGVyYXRpb25zOyBqKyspXG4gICAgICB7IC8vZWl0aGVyIDEgb3IgMyBpdGVyYXRpb25zXG4gICAgICAgIGxlZnQgPSAgKGtleVttKytdIDw8IDI0KSB8IChrZXlbbSsrXSA8PCAxNikgfCAoa2V5W20rK10gPDwgOCkgfCBrZXlbbSsrXTtcbiAgICAgICAgcmlnaHQgPSAoa2V5W20rK10gPDwgMjQpIHwgKGtleVttKytdIDw8IDE2KSB8IChrZXlbbSsrXSA8PCA4KSB8IGtleVttKytdO1xuXG4gICAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDQpIF4gcmlnaHQpICYgMHgwZjBmMGYwZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCA0KTtcbiAgICAgICAgdGVtcCA9ICgocmlnaHQgPj4+IC0xNikgXiBsZWZ0KSAmIDB4MDAwMGZmZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgLTE2KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMikgXiByaWdodCkgJiAweDMzMzMzMzMzOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDIpO1xuICAgICAgICB0ZW1wID0gKChyaWdodCA+Pj4gLTE2KSBeIGxlZnQpICYgMHgwMDAwZmZmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAtMTYpO1xuICAgICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG4gICAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMSkgXiByaWdodCkgJiAweDU1NTU1NTU1OyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDEpO1xuXG4gICAgICAgIC8vdGhlIHJpZ2h0IHNpZGUgbmVlZHMgdG8gYmUgc2hpZnRlZCBhbmQgdG8gZ2V0IHRoZSBsYXN0IGZvdXIgYml0cyBvZiB0aGUgbGVmdCBzaWRlXG4gICAgICAgIHRlbXAgPSAobGVmdCA8PCA4KSB8ICgocmlnaHQgPj4+IDIwKSAmIDB4MDAwMDAwZjApO1xuICAgICAgICAvL2xlZnQgbmVlZHMgdG8gYmUgcHV0IHVwc2lkZSBkb3duXG4gICAgICAgIGxlZnQgPSAocmlnaHQgPDwgMjQpIHwgKChyaWdodCA8PCA4KSAmIDB4ZmYwMDAwKSB8ICgocmlnaHQgPj4+IDgpICYgMHhmZjAwKSB8ICgocmlnaHQgPj4+IDI0KSAmIDB4ZjApO1xuICAgICAgICByaWdodCA9IHRlbXA7XG5cbiAgICAgICAgLy9ub3cgZ28gdGhyb3VnaCBhbmQgcGVyZm9ybSB0aGVzZSBzaGlmdHMgb24gdGhlIGxlZnQgYW5kIHJpZ2h0IGtleXNcbiAgICAgICAgZm9yICh2YXIgaT0wOyBpIDwgc2hpZnRzLmxlbmd0aDsgaSsrKVxuICAgICAgICB7XG4gICAgICAgICAgLy9zaGlmdCB0aGUga2V5cyBlaXRoZXIgb25lIG9yIHR3byBiaXRzIHRvIHRoZSBsZWZ0XG4gICAgICAgICAgaWYgKHNoaWZ0c1tpXSlcbiAgICAgICAgICB7XG4gICAgICAgICAgICBsZWZ0ID0gKGxlZnQgPDwgMikgfCAobGVmdCA+Pj4gMjYpOyByaWdodCA9IChyaWdodCA8PCAyKSB8IChyaWdodCA+Pj4gMjYpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBlbHNlXG4gICAgICAgICAge1xuICAgICAgICAgICAgbGVmdCA9IChsZWZ0IDw8IDEpIHwgKGxlZnQgPj4+IDI3KTsgcmlnaHQgPSAocmlnaHQgPDwgMSkgfCAocmlnaHQgPj4+IDI3KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgbGVmdCAmPSAtMHhmOyByaWdodCAmPSAtMHhmO1xuXG4gICAgICAgICAgLy9ub3cgYXBwbHkgUEMtMiwgaW4gc3VjaCBhIHdheSB0aGF0IEUgaXMgZWFzaWVyIHdoZW4gZW5jcnlwdGluZyBvciBkZWNyeXB0aW5nXG4gICAgICAgICAgLy90aGlzIGNvbnZlcnNpb24gd2lsbCBsb29rIGxpa2UgUEMtMiBleGNlcHQgb25seSB0aGUgbGFzdCA2IGJpdHMgb2YgZWFjaCBieXRlIGFyZSB1c2VkXG4gICAgICAgICAgLy9yYXRoZXIgdGhhbiA0OCBjb25zZWN1dGl2ZSBiaXRzIGFuZCB0aGUgb3JkZXIgb2YgbGluZXMgd2lsbCBiZSBhY2NvcmRpbmcgdG9cbiAgICAgICAgICAvL2hvdyB0aGUgUyBzZWxlY3Rpb24gZnVuY3Rpb25zIHdpbGwgYmUgYXBwbGllZDogUzIsIFM0LCBTNiwgUzgsIFMxLCBTMywgUzUsIFM3XG4gICAgICAgICAgbGVmdHRlbXAgPSBkZXNQQy5wYzJieXRlczBbbGVmdCA+Pj4gMjhdIHwgZGVzUEMucGMyYnl0ZXMxWyhsZWZ0ID4+PiAyNCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczJbKGxlZnQgPj4+IDIwKSAmIDB4Zl0gfCBkZXNQQy5wYzJieXRlczNbKGxlZnQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICB8IGRlc1BDLnBjMmJ5dGVzNFsobGVmdCA+Pj4gMTIpICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzNVsobGVmdCA+Pj4gOCkgJiAweGZdXG4gICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczZbKGxlZnQgPj4+IDQpICYgMHhmXTtcbiAgICAgICAgICByaWdodHRlbXAgPSBkZXNQQy5wYzJieXRlczdbcmlnaHQgPj4+IDI4XSB8IGRlc1BDLnBjMmJ5dGVzOFsocmlnaHQgPj4+IDI0KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczlbKHJpZ2h0ID4+PiAyMCkgJiAweGZdIHwgZGVzUEMucGMyYnl0ZXMxMFsocmlnaHQgPj4+IDE2KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczExWyhyaWdodCA+Pj4gMTIpICYgMHhmXSB8IGRlc1BDLnBjMmJ5dGVzMTJbKHJpZ2h0ID4+PiA4KSAmIDB4Zl1cbiAgICAgICAgICAgICAgICAgICAgfCBkZXNQQy5wYzJieXRlczEzWyhyaWdodCA+Pj4gNCkgJiAweGZdO1xuICAgICAgICAgIHRlbXAgPSAoKHJpZ2h0dGVtcCA+Pj4gMTYpIF4gbGVmdHRlbXApICYgMHgwMDAwZmZmZjtcbiAgICAgICAgICBrZXlzW24rK10gPSBsZWZ0dGVtcCBeIHRlbXA7IGtleXNbbisrXSA9IHJpZ2h0dGVtcCBeICh0ZW1wIDw8IDE2KTtcbiAgICAgICAgfVxuICAgICAgfSAvL2ZvciBlYWNoIGl0ZXJhdGlvbnNcblxuICAgICAgcmV0dXJuIGtleXM7XG4gICAgfSAvL2VuZCBvZiBkZXNfY3JlYXRlS2V5c1xuXG4gICAgLy9kZWNsYXJpbmcgdGhpcyBsb2NhbGx5IHNwZWVkcyB0aGluZ3MgdXAgYSBiaXRcbiAgICBsZXQgZGVzU1AgPSBERVNDcnlwdG9ncmFwaGljU2VydmljZS5kZXNTUDtcblxuICAgIGlmICggZGVzU1AgPT0gdW5kZWZpbmVkIClcbiAgICB7XG4gICAgICBkZXNTUCA9IERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlc1NQID0ge1xuICAgICAgICBzcGZ1bmN0aW9uMTogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDEwNDAwLDAsMHgxMDAwMCwweDEwMTA0MDQsMHgxMDEwMDA0LDB4MTA0MDQsMHg0LDB4MTAwMDAsMHg0MDAsMHgxMDEwNDAwLDB4MTAxMDQwNCwweDQwMCwweDEwMDA0MDQsMHgxMDEwMDA0LDB4MTAwMDAwMCwweDQsMHg0MDQsMHgxMDAwNDAwLDB4MTAwMDQwMCwweDEwNDAwLDB4MTA0MDAsMHgxMDEwMDAwLDB4MTAxMDAwMCwweDEwMDA0MDQsMHgxMDAwNCwweDEwMDAwMDQsMHgxMDAwMDA0LDB4MTAwMDQsMCwweDQwNCwweDEwNDA0LDB4MTAwMDAwMCwweDEwMDAwLDB4MTAxMDQwNCwweDQsMHgxMDEwMDAwLDB4MTAxMDQwMCwweDEwMDAwMDAsMHgxMDAwMDAwLDB4NDAwLDB4MTAxMDAwNCwweDEwMDAwLDB4MTA0MDAsMHgxMDAwMDA0LDB4NDAwLDB4NCwweDEwMDA0MDQsMHgxMDQwNCwweDEwMTA0MDQsMHgxMDAwNCwweDEwMTAwMDAsMHgxMDAwNDA0LDB4MTAwMDAwNCwweDQwNCwweDEwNDA0LDB4MTAxMDQwMCwweDQwNCwweDEwMDA0MDAsMHgxMDAwNDAwLDAsMHgxMDAwNCwweDEwNDAwLDAsMHgxMDEwMDA0XSApLFxuICAgICAgICBzcGZ1bmN0aW9uMjogbmV3IFVpbnQzMkFycmF5KCBbLTB4N2ZlZjdmZTAsLTB4N2ZmZjgwMDAsMHg4MDAwLDB4MTA4MDIwLDB4MTAwMDAwLDB4MjAsLTB4N2ZlZmZmZTAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsLTB4N2ZlZjdmZTAsLTB4N2ZlZjgwMDAsLTB4ODAwMDAwMDAsLTB4N2ZmZjgwMDAsMHgxMDAwMDAsMHgyMCwtMHg3ZmVmZmZlMCwweDEwODAwMCwweDEwMDAyMCwtMHg3ZmZmN2ZlMCwwLC0weDgwMDAwMDAwLDB4ODAwMCwweDEwODAyMCwtMHg3ZmYwMDAwMCwweDEwMDAyMCwtMHg3ZmZmZmZlMCwwLDB4MTA4MDAwLDB4ODAyMCwtMHg3ZmVmODAwMCwtMHg3ZmYwMDAwMCwweDgwMjAsMCwweDEwODAyMCwtMHg3ZmVmZmZlMCwweDEwMDAwMCwtMHg3ZmZmN2ZlMCwtMHg3ZmYwMDAwMCwtMHg3ZmVmODAwMCwweDgwMDAsLTB4N2ZmMDAwMDAsLTB4N2ZmZjgwMDAsMHgyMCwtMHg3ZmVmN2ZlMCwweDEwODAyMCwweDIwLDB4ODAwMCwtMHg4MDAwMDAwMCwweDgwMjAsLTB4N2ZlZjgwMDAsMHgxMDAwMDAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsLTB4N2ZmZjdmZTAsLTB4N2ZmZmZmZTAsMHgxMDAwMjAsMHgxMDgwMDAsMCwtMHg3ZmZmODAwMCwweDgwMjAsLTB4ODAwMDAwMDAsLTB4N2ZlZmZmZTAsLTB4N2ZlZjdmZTAsMHgxMDgwMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb24zOiBuZXcgVWludDMyQXJyYXkoIFsweDIwOCwweDgwMjAyMDAsMCwweDgwMjAwMDgsMHg4MDAwMjAwLDAsMHgyMDIwOCwweDgwMDAyMDAsMHgyMDAwOCwweDgwMDAwMDgsMHg4MDAwMDA4LDB4MjAwMDAsMHg4MDIwMjA4LDB4MjAwMDgsMHg4MDIwMDAwLDB4MjA4LDB4ODAwMDAwMCwweDgsMHg4MDIwMjAwLDB4MjAwLDB4MjAyMDAsMHg4MDIwMDAwLDB4ODAyMDAwOCwweDIwMjA4LDB4ODAwMDIwOCwweDIwMjAwLDB4MjAwMDAsMHg4MDAwMjA4LDB4OCwweDgwMjAyMDgsMHgyMDAsMHg4MDAwMDAwLDB4ODAyMDIwMCwweDgwMDAwMDAsMHgyMDAwOCwweDIwOCwweDIwMDAwLDB4ODAyMDIwMCwweDgwMDAyMDAsMCwweDIwMCwweDIwMDA4LDB4ODAyMDIwOCwweDgwMDAyMDAsMHg4MDAwMDA4LDB4MjAwLDAsMHg4MDIwMDA4LDB4ODAwMDIwOCwweDIwMDAwLDB4ODAwMDAwMCwweDgwMjAyMDgsMHg4LDB4MjAyMDgsMHgyMDIwMCwweDgwMDAwMDgsMHg4MDIwMDAwLDB4ODAwMDIwOCwweDIwOCwweDgwMjAwMDAsMHgyMDIwOCwweDgsMHg4MDIwMDA4LDB4MjAyMDBdICksXG4gICAgICAgIHNwZnVuY3Rpb240OiBuZXcgVWludDMyQXJyYXkoIFsweDgwMjAwMSwweDIwODEsMHgyMDgxLDB4ODAsMHg4MDIwODAsMHg4MDAwODEsMHg4MDAwMDEsMHgyMDAxLDAsMHg4MDIwMDAsMHg4MDIwMDAsMHg4MDIwODEsMHg4MSwwLDB4ODAwMDgwLDB4ODAwMDAxLDB4MSwweDIwMDAsMHg4MDAwMDAsMHg4MDIwMDEsMHg4MCwweDgwMDAwMCwweDIwMDEsMHgyMDgwLDB4ODAwMDgxLDB4MSwweDIwODAsMHg4MDAwODAsMHgyMDAwLDB4ODAyMDgwLDB4ODAyMDgxLDB4ODEsMHg4MDAwODAsMHg4MDAwMDEsMHg4MDIwMDAsMHg4MDIwODEsMHg4MSwwLDAsMHg4MDIwMDAsMHgyMDgwLDB4ODAwMDgwLDB4ODAwMDgxLDB4MSwweDgwMjAwMSwweDIwODEsMHgyMDgxLDB4ODAsMHg4MDIwODEsMHg4MSwweDEsMHgyMDAwLDB4ODAwMDAxLDB4MjAwMSwweDgwMjA4MCwweDgwMDA4MSwweDIwMDEsMHgyMDgwLDB4ODAwMDAwLDB4ODAyMDAxLDB4ODAsMHg4MDAwMDAsMHgyMDAwLDB4ODAyMDgwXSApLFxuICAgICAgICBzcGZ1bmN0aW9uNTogbmV3IFVpbnQzMkFycmF5KCBbMHgxMDAsMHgyMDgwMTAwLDB4MjA4MDAwMCwweDQyMDAwMTAwLDB4ODAwMDAsMHgxMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MDA4MDEwMCwweDgwMDAwLDB4MjAwMDEwMCwweDQwMDgwMTAwLDB4NDIwMDAxMDAsMHg0MjA4MDAwMCwweDgwMTAwLDB4NDAwMDAwMDAsMHgyMDAwMDAwLDB4NDAwODAwMDAsMHg0MDA4MDAwMCwwLDB4NDAwMDAxMDAsMHg0MjA4MDEwMCwweDQyMDgwMTAwLDB4MjAwMDEwMCwweDQyMDgwMDAwLDB4NDAwMDAxMDAsMCwweDQyMDAwMDAwLDB4MjA4MDEwMCwweDIwMDAwMDAsMHg0MjAwMDAwMCwweDgwMTAwLDB4ODAwMDAsMHg0MjAwMDEwMCwweDEwMCwweDIwMDAwMDAsMHg0MDAwMDAwMCwweDIwODAwMDAsMHg0MjAwMDEwMCwweDQwMDgwMTAwLDB4MjAwMDEwMCwweDQwMDAwMDAwLDB4NDIwODAwMDAsMHgyMDgwMTAwLDB4NDAwODAxMDAsMHgxMDAsMHgyMDAwMDAwLDB4NDIwODAwMDAsMHg0MjA4MDEwMCwweDgwMTAwLDB4NDIwMDAwMDAsMHg0MjA4MDEwMCwweDIwODAwMDAsMCwweDQwMDgwMDAwLDB4NDIwMDAwMDAsMHg4MDEwMCwweDIwMDAxMDAsMHg0MDAwMDEwMCwweDgwMDAwLDAsMHg0MDA4MDAwMCwweDIwODAxMDAsMHg0MDAwMDEwMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjY6IG5ldyBVaW50MzJBcnJheSggWzB4MjAwMDAwMTAsMHgyMDQwMDAwMCwweDQwMDAsMHgyMDQwNDAxMCwweDIwNDAwMDAwLDB4MTAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4NDA0MDEwLDB4NDAwMDAwLDB4MjAwMDAwMTAsMHg0MDAwMTAsMHgyMDAwNDAwMCwweDIwMDAwMDAwLDB4NDAxMCwwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMHg0MDAwLDB4NDA0MDAwLDB4MjAwMDQwMTAsMHgxMCwweDIwNDAwMDEwLDB4MjA0MDAwMTAsMCwweDQwNDAxMCwweDIwNDA0MDAwLDB4NDAxMCwweDQwNDAwMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHgyMDAwNDAwMCwweDEwLDB4MjA0MDAwMTAsMHg0MDQwMDAsMHgyMDQwNDAxMCwweDQwMDAwMCwweDQwMTAsMHgyMDAwMDAxMCwweDQwMDAwMCwweDIwMDA0MDAwLDB4MjAwMDAwMDAsMHg0MDEwLDB4MjAwMDAwMTAsMHgyMDQwNDAxMCwweDQwNDAwMCwweDIwNDAwMDAwLDB4NDA0MDEwLDB4MjA0MDQwMDAsMCwweDIwNDAwMDEwLDB4MTAsMHg0MDAwLDB4MjA0MDAwMDAsMHg0MDQwMTAsMHg0MDAwLDB4NDAwMDEwLDB4MjAwMDQwMTAsMCwweDIwNDA0MDAwLDB4MjAwMDAwMDAsMHg0MDAwMTAsMHgyMDAwNDAxMF0gKSxcbiAgICAgICAgc3BmdW5jdGlvbjc6IG5ldyBVaW50MzJBcnJheSggWzB4MjAwMDAwLDB4NDIwMDAwMiwweDQwMDA4MDIsMCwweDgwMCwweDQwMDA4MDIsMHgyMDA4MDIsMHg0MjAwODAwLDB4NDIwMDgwMiwweDIwMDAwMCwwLDB4NDAwMDAwMiwweDIsMHg0MDAwMDAwLDB4NDIwMDAwMiwweDgwMiwweDQwMDA4MDAsMHgyMDA4MDIsMHgyMDAwMDIsMHg0MDAwODAwLDB4NDAwMDAwMiwweDQyMDAwMDAsMHg0MjAwODAwLDB4MjAwMDAyLDB4NDIwMDAwMCwweDgwMCwweDgwMiwweDQyMDA4MDIsMHgyMDA4MDAsMHgyLDB4NDAwMDAwMCwweDIwMDgwMCwweDQwMDAwMDAsMHgyMDA4MDAsMHgyMDAwMDAsMHg0MDAwODAyLDB4NDAwMDgwMiwweDQyMDAwMDIsMHg0MjAwMDAyLDB4MiwweDIwMDAwMiwweDQwMDAwMDAsMHg0MDAwODAwLDB4MjAwMDAwLDB4NDIwMDgwMCwweDgwMiwweDIwMDgwMiwweDQyMDA4MDAsMHg4MDIsMHg0MDAwMDAyLDB4NDIwMDgwMiwweDQyMDAwMDAsMHgyMDA4MDAsMCwweDIsMHg0MjAwODAyLDAsMHgyMDA4MDIsMHg0MjAwMDAwLDB4ODAwLDB4NDAwMDAwMiwweDQwMDA4MDAsMHg4MDAsMHgyMDAwMDJdICksXG4gICAgICAgIHNwZnVuY3Rpb244OiBuZXcgVWludDMyQXJyYXkoIFsweDEwMDAxMDQwLDB4MTAwMCwweDQwMDAwLDB4MTAwNDEwNDAsMHgxMDAwMDAwMCwweDEwMDAxMDQwLDB4NDAsMHgxMDAwMDAwMCwweDQwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4MTAwNDEwMDAsMHg0MTA0MCwweDEwMDAsMHg0MCwweDEwMDQwMDAwLDB4MTAwMDAwNDAsMHgxMDAwMTAwMCwweDEwNDAsMHg0MTAwMCwweDQwMDQwLDB4MTAwNDAwNDAsMHgxMDA0MTAwMCwweDEwNDAsMCwwLDB4MTAwNDAwNDAsMHgxMDAwMDA0MCwweDEwMDAxMDAwLDB4NDEwNDAsMHg0MDAwMCwweDQxMDQwLDB4NDAwMDAsMHgxMDA0MTAwMCwweDEwMDAsMHg0MCwweDEwMDQwMDQwLDB4MTAwMCwweDQxMDQwLDB4MTAwMDEwMDAsMHg0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDA0MDA0MCwweDEwMDAwMDAwLDB4NDAwMDAsMHgxMDAwMTA0MCwwLDB4MTAwNDEwNDAsMHg0MDA0MCwweDEwMDAwMDQwLDB4MTAwNDAwMDAsMHgxMDAwMTAwMCwweDEwMDAxMDQwLDAsMHgxMDA0MTA0MCwweDQxMDAwLDB4NDEwMDAsMHgxMDQwLDB4MTA0MCwweDQwMDQwLDB4MTAwMDAwMDAsMHgxMDA0MTAwMF0gKSxcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy9jcmVhdGUgdGhlIDE2IG9yIDQ4IHN1YmtleXMgd2Ugd2lsbCBuZWVkXG4gICAgdmFyIGtleXMgPSBkZXNfY3JlYXRlS2V5cygga2V5ICk7XG5cbiAgICB2YXIgbT0wLCBpLCBqLCB0ZW1wLCBsZWZ0LCByaWdodCwgbG9vcGluZztcbiAgICB2YXIgY2JjbGVmdCwgY2JjbGVmdDIsIGNiY3JpZ2h0LCBjYmNyaWdodDJcbiAgICB2YXIgbGVuID0gbWVzc2FnZS5sZW5ndGg7XG5cbiAgICAvL3NldCB1cCB0aGUgbG9vcHMgZm9yIHNpbmdsZSBhbmQgdHJpcGxlIGRlc1xuICAgIHZhciBpdGVyYXRpb25zID0ga2V5cy5sZW5ndGggPT0gMzIgPyAzIDogOTsgLy9zaW5nbGUgb3IgdHJpcGxlIGRlc1xuXG4gICAgaWYgKGl0ZXJhdGlvbnMgPT0gMylcbiAgICB7XG4gICAgICBsb29waW5nID0gZW5jcnlwdCA/IFsgMCwgMzIsIDIgXSA6IFsgMzAsIC0yLCAtMiBdO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbG9vcGluZyA9IGVuY3J5cHQgPyBbIDAsIDMyLCAyLCA2MiwgMzAsIC0yLCA2NCwgOTYsIDIgXSA6IFsgOTQsIDYyLCAtMiwgMzIsIDY0LCAyLCAzMCwgLTIsIC0yIF07XG4gICAgfVxuXG4gICAgLy8gcGFkIHRoZSBtZXNzYWdlIGRlcGVuZGluZyBvbiB0aGUgcGFkZGluZyBwYXJhbWV0ZXJcbiAgICBpZiAoICggcGFkZGluZyAhPSB1bmRlZmluZWQgKSAmJiAoIHBhZGRpbmcgIT0gNCApIClcbiAgICB7XG4gICAgICB2YXIgdW5wYWRkZWRNZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgIHZhciBwYWQgPSA4LShsZW4lOCk7XG5cbiAgICAgIG1lc3NhZ2UgPSBuZXcgVWludDhBcnJheSggbGVuICsgOCApO1xuICAgICAgbWVzc2FnZS5zZXQoIHVucGFkZGVkTWVzc2FnZSwgMCApO1xuXG4gICAgICBzd2l0Y2goIHBhZGRpbmcgKVxuICAgICAge1xuICAgICAgICBjYXNlIDA6IC8vIHplcm8tcGFkXG4gICAgICAgICAgbWVzc2FnZS5zZXQoIG5ldyBVaW50OEFycmF5KCBbIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAsIDB4MDAgXSApLCBsZW4gKTtcbiAgICAgICAgICBicmVhaztcblxuICAgICAgICBjYXNlIDE6IC8vIFBLQ1M3IHBhZGRpbmdcbiAgICAgICAge1xuICAgICAgICAgIG1lc3NhZ2Uuc2V0KCBuZXcgVWludDhBcnJheSggWyBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZCwgcGFkLCBwYWQsIHBhZF0gKSwgOCApO1xuXG4gICAgICAgICAgaWYgKCBwYWQ9PTggKVxuICAgICAgICAgICAgbGVuKz04O1xuXG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cblxuICAgICAgICBjYXNlIDI6ICAvLyBwYWQgdGhlIG1lc3NhZ2Ugd2l0aCBzcGFjZXNcbiAgICAgICAgICBtZXNzYWdlLnNldCggbmV3IFVpbnQ4QXJyYXkoIFsgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCwgMHgyMCBdICksIDggKTtcbiAgICAgICAgICBicmVhaztcblxuICAgICAgfVxuXG4gICAgICBsZW4gKz0gOC0obGVuJTgpXG4gICAgfVxuXG4gICAgLy8gc3RvcmUgdGhlIHJlc3VsdCBoZXJlXG4gICAgdmFyIHJlc3VsdCA9IG5ldyBVaW50OEFycmF5KCBsZW4gKTtcblxuICAgIGlmIChtb2RlID09IDEpXG4gICAgeyAvL0NCQyBtb2RlXG4gICAgICBsZXQgbW0gPSAwO1xuXG4gICAgICBjYmNsZWZ0ID0gIChpdlttbSsrXSA8PCAyNCkgfCAoaXZbbW0rK10gPDwgMTYpIHwgKGl2W21tKytdIDw8IDgpIHwgaXZbbW0rK107XG4gICAgICBjYmNyaWdodCA9IChpdlttbSsrXSA8PCAyNCkgfCAoaXZbbW0rK10gPDwgMTYpIHwgKGl2W21tKytdIDw8IDgpIHwgaXZbbW0rK107XG4gICAgfVxuXG4gICAgdmFyIHJtID0gMDtcblxuICAgIC8vbG9vcCB0aHJvdWdoIGVhY2ggNjQgYml0IGNodW5rIG9mIHRoZSBtZXNzYWdlXG4gICAgd2hpbGUgKG0gPCBsZW4pXG4gICAge1xuICAgICAgbGVmdCA9ICAobWVzc2FnZVttKytdIDw8IDI0KSB8IChtZXNzYWdlW20rK10gPDwgMTYpIHwgKG1lc3NhZ2VbbSsrXSA8PCA4KSB8IG1lc3NhZ2VbbSsrXTtcbiAgICAgIHJpZ2h0ID0gKG1lc3NhZ2VbbSsrXSA8PCAyNCkgfCAobWVzc2FnZVttKytdIDw8IDE2KSB8IChtZXNzYWdlW20rK10gPDwgOCkgfCBtZXNzYWdlW20rK107XG5cbiAgICAgIC8vZm9yIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLCB4b3IgdGhlIG1lc3NhZ2Ugd2l0aCB0aGUgcHJldmlvdXMgcmVzdWx0XG4gICAgICBpZiAobW9kZSA9PSAxKVxuICAgICAge1xuICAgICAgICBpZiAoZW5jcnlwdClcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDsgcmlnaHQgXj0gY2JjcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICB7XG4gICAgICAgICAgY2JjbGVmdDIgPSBjYmNsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0MiA9IGNiY3JpZ2h0O1xuICAgICAgICAgIGNiY2xlZnQgPSBsZWZ0O1xuICAgICAgICAgIGNiY3JpZ2h0ID0gcmlnaHQ7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy9maXJzdCBlYWNoIDY0IGJ1dCBjaHVuayBvZiB0aGUgbWVzc2FnZSBtdXN0IGJlIHBlcm11dGVkIGFjY29yZGluZyB0byBJUFxuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gMTYpIF4gcmlnaHQpICYgMHgwMDAwZmZmZjsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxNik7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gMikgXiBsZWZ0KSAmIDB4MzMzMzMzMzM7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgMik7XG4gICAgICB0ZW1wID0gKChyaWdodCA+Pj4gOCkgXiBsZWZ0KSAmIDB4MDBmZjAwZmY7IGxlZnQgXj0gdGVtcDsgcmlnaHQgXj0gKHRlbXAgPDwgOCk7XG4gICAgICB0ZW1wID0gKChsZWZ0ID4+PiAxKSBeIHJpZ2h0KSAmIDB4NTU1NTU1NTU7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMSk7XG5cbiAgICAgIGxlZnQgPSAoKGxlZnQgPDwgMSkgfCAobGVmdCA+Pj4gMzEpKTtcbiAgICAgIHJpZ2h0ID0gKChyaWdodCA8PCAxKSB8IChyaWdodCA+Pj4gMzEpKTtcblxuICAgICAgLy9kbyB0aGlzIGVpdGhlciAxIG9yIDMgdGltZXMgZm9yIGVhY2ggY2h1bmsgb2YgdGhlIG1lc3NhZ2VcbiAgICAgIGZvciAoaj0wOyBqPGl0ZXJhdGlvbnM7IGorPTMpXG4gICAgICB7XG4gICAgICAgIHZhciBlbmRsb29wID0gbG9vcGluZ1tqKzFdO1xuICAgICAgICB2YXIgbG9vcGluYyA9IGxvb3BpbmdbaisyXTtcblxuICAgICAgICAvL25vdyBnbyB0aHJvdWdoIGFuZCBwZXJmb3JtIHRoZSBlbmNyeXB0aW9uIG9yIGRlY3J5cHRpb25cbiAgICAgICAgZm9yIChpPWxvb3Bpbmdbal07IGkhPWVuZGxvb3A7IGkrPWxvb3BpbmMpXG4gICAgICAgIHsgLy9mb3IgZWZmaWNpZW5jeVxuICAgICAgICAgIHZhciByaWdodDEgPSByaWdodCBeIGtleXNbaV07XG4gICAgICAgICAgdmFyIHJpZ2h0MiA9ICgocmlnaHQgPj4+IDQpIHwgKHJpZ2h0IDw8IDI4KSkgXiBrZXlzW2krMV07XG5cbiAgICAgICAgICAvL3RoZSByZXN1bHQgaXMgYXR0YWluZWQgYnkgcGFzc2luZyB0aGVzZSBieXRlcyB0aHJvdWdoIHRoZSBTIHNlbGVjdGlvbiBmdW5jdGlvbnNcbiAgICAgICAgICB0ZW1wID0gbGVmdDtcbiAgICAgICAgICBsZWZ0ID0gcmlnaHQ7XG4gICAgICAgICAgcmlnaHQgPSB0ZW1wIF4gKGRlc1NQLnNwZnVuY3Rpb24yWyhyaWdodDEgPj4+IDI0KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjRbKHJpZ2h0MSA+Pj4gMTYpICYgMHgzZl1cbiAgICAgICAgICAgICAgICAgICAgICAgIHwgZGVzU1Auc3BmdW5jdGlvbjZbKHJpZ2h0MSA+Pj4gIDgpICYgMHgzZl0gfCBkZXNTUC5zcGZ1bmN0aW9uOFtyaWdodDEgJiAweDNmXVxuICAgICAgICAgICAgICAgICAgICAgICAgfCBkZXNTUC5zcGZ1bmN0aW9uMVsocmlnaHQyID4+PiAyNCkgJiAweDNmXSB8IGRlc1NQLnNwZnVuY3Rpb24zWyhyaWdodDIgPj4+IDE2KSAmIDB4M2ZdXG4gICAgICAgICAgICAgICAgICAgICAgICB8IGRlc1NQLnNwZnVuY3Rpb241WyhyaWdodDIgPj4+ICA4KSAmIDB4M2ZdIHwgZGVzU1Auc3BmdW5jdGlvbjdbcmlnaHQyICYgMHgzZl0pO1xuICAgICAgICB9XG5cbiAgICAgICAgdGVtcCA9IGxlZnQ7IGxlZnQgPSByaWdodDsgcmlnaHQgPSB0ZW1wOyAvL3VucmV2ZXJzZSBsZWZ0IGFuZCByaWdodFxuICAgICAgfSAvL2ZvciBlaXRoZXIgMSBvciAzIGl0ZXJhdGlvbnNcblxuICAgICAgLy9tb3ZlIHRoZW4gZWFjaCBvbmUgYml0IHRvIHRoZSByaWdodFxuICAgICAgbGVmdCA9ICgobGVmdCA+Pj4gMSkgfCAobGVmdCA8PCAzMSkpO1xuICAgICAgcmlnaHQgPSAoKHJpZ2h0ID4+PiAxKSB8IChyaWdodCA8PCAzMSkpO1xuXG4gICAgICAvL25vdyBwZXJmb3JtIElQLTEsIHdoaWNoIGlzIElQIGluIHRoZSBvcHBvc2l0ZSBkaXJlY3Rpb25cbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDEpIF4gcmlnaHQpICYgMHg1NTU1NTU1NTsgcmlnaHQgXj0gdGVtcDsgbGVmdCBePSAodGVtcCA8PCAxKTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiA4KSBeIGxlZnQpICYgMHgwMGZmMDBmZjsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCA4KTtcbiAgICAgIHRlbXAgPSAoKHJpZ2h0ID4+PiAyKSBeIGxlZnQpICYgMHgzMzMzMzMzMzsgbGVmdCBePSB0ZW1wOyByaWdodCBePSAodGVtcCA8PCAyKTtcbiAgICAgIHRlbXAgPSAoKGxlZnQgPj4+IDE2KSBeIHJpZ2h0KSAmIDB4MDAwMGZmZmY7IHJpZ2h0IF49IHRlbXA7IGxlZnQgXj0gKHRlbXAgPDwgMTYpO1xuICAgICAgdGVtcCA9ICgobGVmdCA+Pj4gNCkgXiByaWdodCkgJiAweDBmMGYwZjBmOyByaWdodCBePSB0ZW1wOyBsZWZ0IF49ICh0ZW1wIDw8IDQpO1xuXG4gICAgICAvL2ZvciBDaXBoZXIgQmxvY2sgQ2hhaW5pbmcgbW9kZSwgeG9yIHRoZSBtZXNzYWdlIHdpdGggdGhlIHByZXZpb3VzIHJlc3VsdFxuICAgICAgaWYgKG1vZGUgPT0gMSlcbiAgICAgIHtcbiAgICAgICAgaWYgKGVuY3J5cHQpXG4gICAgICAgIHtcbiAgICAgICAgICBjYmNsZWZ0ID0gbGVmdDtcbiAgICAgICAgICBjYmNyaWdodCA9IHJpZ2h0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAge1xuICAgICAgICAgIGxlZnQgXj0gY2JjbGVmdDI7XG4gICAgICAgICAgcmlnaHQgXj0gY2JjcmlnaHQyO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc3VsdC5zZXQoIG5ldyBVaW50OEFycmF5ICggWyAobGVmdD4+PjI0KSAmIDB4ZmYsIChsZWZ0Pj4+MTYpICYgMHhmZiwgKGxlZnQ+Pj44KSAmIDB4ZmYsIChsZWZ0KSAmIDB4ZmYsIChyaWdodD4+PjI0KSAmIDB4ZmYsIChyaWdodD4+PjE2KSAmIDB4ZmYsIChyaWdodD4+PjgpICYgMHhmZiwgKHJpZ2h0KSAmIDB4ZmYgXSApLCBybSApO1xuXG4gICAgICBybSArPSA4O1xuICAgIH0gLy9mb3IgZXZlcnkgOCBjaGFyYWN0ZXJzLCBvciA2NCBiaXRzIGluIHRoZSBtZXNzYWdlXG5cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9IC8vZW5kIG9mIGRlc1xuXG59XG5cbkNyeXB0b2dyYXBoaWNTZXJ2aWNlUHJvdmlkZXIucmVnaXN0ZXJTZXJ2aWNlKCAnREVTLUVDQicsXG4gIERFU0NyeXB0b2dyYXBoaWNTZXJ2aWNlLFxuICBbIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uRU5DUllQVCwgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5ERUNSWVBUIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlclNlcnZpY2UoICdERVMtQ0JDJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5FTkNSWVBULCBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLkRFQ1JZUFQsICBDcnlwdG9ncmFwaGljT3BlcmF0aW9uLlNJR04sIENyeXB0b2dyYXBoaWNPcGVyYXRpb24uVkVSSUZZIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlcktleVNlcnZpY2UoICdERVMtRUNCJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5JTVBPUlRfS0VZIF0gKTtcblxuQ3J5cHRvZ3JhcGhpY1NlcnZpY2VQcm92aWRlci5yZWdpc3RlcktleVNlcnZpY2UoICdERVMtQ0JDJyxcbiAgREVTQ3J5cHRvZ3JhcGhpY1NlcnZpY2UsXG4gIFsgQ3J5cHRvZ3JhcGhpY09wZXJhdGlvbi5JTVBPUlRfS0VZIF0gKTtcbiIsbnVsbCwiaW1wb3J0IHsgQ29udGFpbmVyLCBhdXRvaW5qZWN0IGFzIGluamVjdCB9IGZyb20gJ2F1cmVsaWEtZGVwZW5kZW5jeS1pbmplY3Rpb24nO1xuaW1wb3J0IHsgbWV0YWRhdGEgfSBmcm9tICdhdXJlbGlhLW1ldGFkYXRhJztcblxuZXhwb3J0IHsgQ29udGFpbmVyLCBpbmplY3QgfTtcbmV4cG9ydCBpbnRlcmZhY2UgSW5qZWN0YWJsZSB7XG4gIG5ldyggLi4uYXJncyApOiBPYmplY3Q7XG59XG4iLCJpbXBvcnQgeyBFdmVudEFnZ3JlZ2F0b3IsIFN1YnNjcmlwdGlvbiwgSGFuZGxlciBhcyBFdmVudEhhbmRsZXIgfSBmcm9tICdhdXJlbGlhLWV2ZW50LWFnZ3JlZ2F0b3InO1xuXG4vL2V4cG9ydCB7IEV2ZW50SGFuZGxlciB9O1xuXG5leHBvcnQgY2xhc3MgRXZlbnRIdWJcbntcbiAgX2V2ZW50QWdncmVnYXRvcjogRXZlbnRBZ2dyZWdhdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IgPSBuZXcgRXZlbnRBZ2dyZWdhdG9yKCk7XG4gIH1cblxuICBwdWJsaWMgcHVibGlzaCggZXZlbnQ6IHN0cmluZywgZGF0YT86IGFueSApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IucHVibGlzaCggZXZlbnQsIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmUoIGV2ZW50OiBzdHJpbmcsIGhhbmRsZXI6IEZ1bmN0aW9uICk6IFN1YnNjcmlwdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2V2ZW50QWdncmVnYXRvci5zdWJzY3JpYmUoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cblxuICBwdWJsaWMgc3Vic2NyaWJlT25jZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZU9uY2UoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cbn1cblxuLypmdW5jdGlvbiBldmVudEh1YigpOiBhbnkge1xuICByZXR1cm4gZnVuY3Rpb24gZXZlbnRIdWI8VEZ1bmN0aW9uIGV4dGVuZHMgRnVuY3Rpb24sIEV2ZW50SHViPih0YXJnZXQ6IFRGdW5jdGlvbik6IFRGdW5jdGlvbiB7XG5cbiAgICB0YXJnZXQucHJvdG90eXBlLnN1YnNjcmliZSA9IG5ld0NvbnN0cnVjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUodGFyZ2V0LnByb3RvdHlwZSk7XG4gICAgbmV3Q29uc3RydWN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gdGFyZ2V0O1xuXG4gICAgcmV0dXJuIDxhbnk+IG5ld0NvbnN0cnVjdG9yO1xuICB9XG59XG5cbkBldmVudEh1YigpXG5jbGFzcyBNeUNsYXNzIHt9O1xuKi9cbiIsImltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcblxuLyoqXG4qIEEgUG9ydCBpcyBhIHBsYWNlaG9sZGVyIGZvciBhbiBFbmRQb2ludCBwdWJsaXNoZWQgYnkgdGhlIHVuZGVybHlpbmdcbiogY29tcG9uZW50IG9mIGEgTm9kZS5cbiovXG5leHBvcnQgY2xhc3MgUG9ydFxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBOb2RlO1xuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2VuZFBvaW50OiBFbmRQb2ludDtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IE5vZGUsIGVuZFBvaW50OiBFbmRQb2ludCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgLy8gV2FzIGFuIEVuZFBvaW50IHN1cHBsaWVkP1xuICAgIGlmICggIWVuZFBvaW50IClcbiAgICB7XG4gICAgICBsZXQgZGlyZWN0aW9uID0gYXR0cmlidXRlcy5kaXJlY3Rpb24gfHwgRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgICBpZiAoIHR5cGVvZiBhdHRyaWJ1dGVzLmRpcmVjdGlvbiA9PSBcInN0cmluZ1wiIClcbiAgICAgICAgZGlyZWN0aW9uID0gRGlyZWN0aW9uWyBkaXJlY3Rpb24udG9VcHBlckNhc2UoKSBdO1xuXG4gICAgICAvLyBDcmVhdGUgYSBcImR1bW15XCIgZW5kUG9pbnQgd2l0aCBjb3JyZWN0IGlkICsgZGlyZWN0aW9uXG4gICAgICBlbmRQb2ludCA9IG5ldyBFbmRQb2ludCggYXR0cmlidXRlcy5pZCwgZGlyZWN0aW9uICk7XG4gICAgfVxuXG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnQoKSB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50O1xuICB9XG4gIHB1YmxpYyBzZXQgZW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApIHtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0ge1xuICAgICAgaWQ6IHRoaXMuX2VuZFBvaW50LmlkLFxuICAgICAgZGlyZWN0aW9uOiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24sXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgfTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIG93bmVyXG4gICAqL1xuICBnZXQgb3duZXIoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyXG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgcHJvdG9jb2wgSURcbiAgICovXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgRW5kUG9pbnQgSURcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5pZDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBEaXJlY3Rpb25cbiAgICovXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uO1xuICB9XG5cbn1cblxuZXhwb3J0IGNsYXNzIFB1YmxpY1BvcnQgZXh0ZW5kcyBQb3J0XG57XG4gIHByb3h5RW5kUG9pbnQ6IEVuZFBvaW50O1xuICBwcm94eUNoYW5uZWw6IENoYW5uZWw7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGVuZFBvaW50LCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsZXQgcHJveHlEaXJlY3Rpb24gPVxuICAgICAgKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLklOIClcbiAgICAgICAgPyBEaXJlY3Rpb24uT1VUXG4gICAgICAgIDogKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLk9VVCApXG4gICAgICAgICAgPyBEaXJlY3Rpb24uSU5cbiAgICAgICAgICA6IERpcmVjdGlvbi5JTk9VVDtcblxuICAgIC8vIENyZWF0ZSBhbiBFbmRQb2ludCB0byBwcm94eSBiZXR3ZWVuIHRoZSBQdWJsaWMgYW5kIFByaXZhdGUgKGludGVybmFsKVxuICAgIC8vIHNpZGVzIG9mIHRoZSBQb3J0LlxuICAgIHRoaXMucHJveHlFbmRQb2ludCA9IG5ldyBFbmRQb2ludCggdGhpcy5fZW5kUG9pbnQuaWQsIHByb3h5RGlyZWN0aW9uICk7XG5cbiAgICAvLyBXaXJlLXVwIHByb3h5IC1cblxuICAgIC8vIEZvcndhcmQgaW5jb21pbmcgcGFja2V0cyAoZnJvbSBwdWJsaWMgaW50ZXJmYWNlKSB0byBwcml2YXRlXG4gICAgdGhpcy5wcm94eUVuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5fZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgdGhpcy5wcm94eUVuZFBvaW50LCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICAgIH0pO1xuXG4gICAgLy8gRm9yd2FyZCBvdXRnb2luZyBwYWNrZXRzIChmcm9tIHByaXZhdGUgaW50ZXJmYWNlKSB0byBwdWJsaWNcbiAgICB0aGlzLl9lbmRQb2ludC5vbk1lc3NhZ2UoICggbWVzc2FnZSApID0+IHtcbiAgICAgIHRoaXMucHJveHlFbmRQb2ludC5zZW5kTWVzc2FnZSggbWVzc2FnZSApO1xuICAgIH0pO1xuXG4gICAgLy8gbm90IHlldCBjb25uZWN0ZWRcbiAgICB0aGlzLnByb3h5Q2hhbm5lbCA9IG51bGw7XG4gIH1cblxuICAvLyBDb25uZWN0IHRvIFByaXZhdGUgKGludGVybmFsKSBFbmRQb2ludC4gVG8gYmUgY2FsbGVkIGR1cmluZyBncmFwaFxuICAvLyB3aXJlVXAgcGhhc2VcbiAgcHVibGljIGNvbm5lY3RQcml2YXRlKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMucHJveHlDaGFubmVsID0gY2hhbm5lbDtcblxuICAgIHRoaXMucHJveHlFbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIHB1YmxpYyBkaXNjb25uZWN0UHJpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQuZGV0YWNoKCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgcG9ydCA9IHN1cGVyLnRvT2JqZWN0KCBvcHRzICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBOb2RlIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NvbXBvbmVudDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgX2luaXRpYWxEYXRhOiBPYmplY3Q7XG5cbiAgcHJvdGVjdGVkIF9wb3J0czogTWFwPHN0cmluZywgUG9ydD47XG5cbiAgcHVibGljIG1ldGFkYXRhOiBhbnk7XG5cbiAgLyoqXG4gICAqIFJ1bnRpbWUgYW5kIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICAqL1xuICBwcm90ZWN0ZWQgX2NvbnRleHQ6IFJ1bnRpbWVDb250ZXh0O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCAnJztcbiAgICB0aGlzLl9jb21wb25lbnQgPSBhdHRyaWJ1dGVzLmNvbXBvbmVudDtcbiAgICB0aGlzLl9pbml0aWFsRGF0YSA9IGF0dHJpYnV0ZXMuaW5pdGlhbERhdGEgfHwge307XG5cbiAgICB0aGlzLl9wb3J0cyA9IG5ldyBNYXA8c3RyaW5nLCBQb3J0PigpO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB9O1xuXG4gICAgLy8gSW5pdGlhbGx5IGNyZWF0ZSAncGxhY2Vob2xkZXInIHBvcnRzLiBPbmNlIGNvbXBvbmVudCBoYXMgYmVlblxuICAgIC8vIGxvYWRlZCBhbmQgaW5zdGFudGlhdGVkLCB0aGV5IHdpbGwgYmUgY29ubmVjdGVkIGNvbm5lY3RlZCB0b1xuICAgIC8vIHRoZSBjb21wb25lbnQncyBjb21tdW5pY2F0aW9uIGVuZC1wb2ludHNcbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5wb3J0cyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGRQbGFjZWhvbGRlclBvcnQoIGlkLCBhdHRyaWJ1dGVzLnBvcnRzWyBpZCBdICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBub2RlID0ge1xuICAgICAgaWQ6IHRoaXMuaWQsXG4gICAgICBjb21wb25lbnQ6IHRoaXMuX2NvbXBvbmVudCxcbiAgICAgIGluaXRpYWxEYXRhOiB0aGlzLl9pbml0aWFsRGF0YSxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhXG4gICAgfTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICBub2RlLnBvcnRzWyBpZCBdID0gcG9ydC50b09iamVjdCgpO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIG93bmVyXG4gICAqL1xuICBwdWJsaWMgZ2V0IG93bmVyKCk6IEdyYXBoIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXJcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIE5vZGUncyBpZFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2lkO1xuICB9XG4gIC8qKlxuICAgKiBTZXQgdGhlIE5vZGUncyBpZFxuICAgKiBAcGFyYW0gaWQgLSBuZXcgaWRlbnRpZmllclxuICAgKi9cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBwdWJsaWMgdXBkYXRlUG9ydHMoIGVuZFBvaW50czogRW5kUG9pbnRbXSApIHtcbiAgICBsZXQgY3VycmVudFBvcnRzID0gdGhpcy5fcG9ydHM7XG4gICAgbGV0IG5ld1BvcnRzOiBNYXA8c3RyaW5nLFBvcnQ+ID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICAvLyBQYXJhbSBlbmRQb2ludHMgaXMgYW4gYXJyYXkgb2YgRW5kUG9pbnRzIGV4cG9ydGVkIGJ5IGEgY29tcG9uZW50XG4gICAgLy8gdXBkYXRlIG91ciBtYXAgb2YgUG9ydHMgdG8gcmVmbGVjdCB0aGlzIGFycmF5XG4gICAgLy8gVGhpcyBtYXkgbWVhbiBpbmNsdWRpbmcgYSBuZXcgUG9ydCwgdXBkYXRpbmcgYW4gZXhpc3RpbmcgUG9ydCB0b1xuICAgIC8vIHVzZSB0aGlzIHN1cHBsaWVkIEVuZFBvaW50LCBvciBldmVuIGRlbGV0aW5nIGEgJ25vLWxvbmdlcicgdmFsaWQgUG9ydFxuICAgIGVuZFBvaW50cy5mb3JFYWNoKCAoZXA6IEVuZFBvaW50ICkgPT4ge1xuICAgICAgbGV0IGlkID0gZXAuaWQ7XG5cbiAgICAgIGlmICggY3VycmVudFBvcnRzLmhhcyggaWQgKSApIHtcbiAgICAgICAgbGV0IHBvcnQgPSBjdXJyZW50UG9ydHMuZ2V0KCBpZCApO1xuXG4gICAgICAgIHBvcnQuZW5kUG9pbnQgPSBlcDtcblxuICAgICAgICBuZXdQb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICAgICAgY3VycmVudFBvcnRzLmRlbGV0ZSggaWQgKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBlbmRQb2ludCBub3QgZm91bmQsIGNyZWF0ZSBhIHBvcnQgZm9yIGl0XG4gICAgICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIGVwLCB7IGlkOiBpZCwgZGlyZWN0aW9uOiBlcC5kaXJlY3Rpb24gfSApO1xuXG4gICAgICAgIG5ld1BvcnRzLnNldCggaWQsIHBvcnQgKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3UG9ydHM7XG4gIH1cblxuXG4gIC8qKlxuICAgKiBBZGQgYSBwbGFjZWhvbGRlciBQb3J0XG4gICAqL1xuICBwcm90ZWN0ZWQgYWRkUGxhY2Vob2xkZXJQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBwb3J0cyBhcyBhbiBhcnJheSBvZiBQb3J0c1xuICAgKlxuICAgKiBAcmV0dXJuIFBvcnRbXVxuICAgKi9cbiAgZ2V0IHBvcnRzKCk6IE1hcDxzdHJpbmcsIFBvcnQ+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHM7XG4gIH1cblxuICBnZXRQb3J0QXJyYXkoKTogUG9ydFtdIHtcbiAgICBsZXQgeHBvcnRzOiBQb3J0W10gPSBbXTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICB4cG9ydHMucHVzaCggcG9ydCApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiB4cG9ydHM7XG4gIH1cblxuICAvKipcbiAgICogTG9va3VwIGEgUG9ydCBieSBpdCdzIElEXG4gICAqIEBwYXJhbSBpZCAtIHBvcnQgaWRlbnRpZmllclxuICAgKlxuICAgKiBAcmV0dXJuIFBvcnQgb3IgdW5kZWZpbmVkXG4gICAqL1xuICBnZXRQb3J0QnlJRCggaWQ6IHN0cmluZyApOiBQb3J0XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICB9XG5cbiAgaWRlbnRpZnlQb3J0KCBpZDogc3RyaW5nLCBwcm90b2NvbElEPzogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHZhciBwb3J0OiBQb3J0O1xuXG4gICAgaWYgKCBpZCApXG4gICAgICBwb3J0ID0gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICAgIGVsc2UgaWYgKCBwcm90b2NvbElEIClcbiAgICB7XG4gICAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHAsIGlkICkgPT4ge1xuICAgICAgICBpZiAoIHAucHJvdG9jb2xJRCA9PSBwcm90b2NvbElEIClcbiAgICAgICAgICBwb3J0ID0gcDtcbiAgICAgIH0sIHRoaXMgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmUgYSBQb3J0IGZyb20gdGhpcyBOb2RlXG4gICAqIEBwYXJhbSBpZCAtIGlkZW50aWZpZXIgb2YgUG9ydCB0byBiZSByZW1vdmVkXG4gICAqIEByZXR1cm4gdHJ1ZSAtIHBvcnQgcmVtb3ZlZFxuICAgKiAgICAgICAgIGZhbHNlIC0gcG9ydCBpbmV4aXN0ZW50XG4gICAqL1xuICByZW1vdmVQb3J0KCBpZDogc3RyaW5nICk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMudW5sb2FkQ29tcG9uZW50KCk7XG5cbiAgICAvLyBHZXQgYSBDb21wb25lbnRDb250ZXh0IHJlc3BvbnNhYmxlIGZvciBDb21wb25lbnQncyBsaWZlLWN5Y2xlIGNvbnRyb2xcbiAgICBsZXQgY3R4ID0gdGhpcy5fY29udGV4dCA9IGZhY3RvcnkuY3JlYXRlQ29udGV4dCggdGhpcy5fY29tcG9uZW50LCB0aGlzLl9pbml0aWFsRGF0YSApO1xuXG4gICAgLy8gTWFrZSBvdXJzZWx2ZXMgdmlzaWJsZSB0byBjb250ZXh0IChhbmQgaW5zdGFuY2UpXG4gICAgY3R4Lm5vZGUgPSB0aGlzO1xuXG4gICAgLy9sZXQgbWUgPSB0aGlzO1xuXG4gICAgLy8gTG9hZCBjb21wb25lbnRcbiAgICByZXR1cm4gY3R4LmxvYWQoKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgY29udGV4dCgpOiBSdW50aW1lQ29udGV4dCB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbnRleHQ7XG4gIH1cblxuICB1bmxvYWRDb21wb25lbnQoKVxuICB7XG4gICAgaWYgKCB0aGlzLl9jb250ZXh0IClcbiAgICB7XG4gICAgICB0aGlzLl9jb250ZXh0LnJlbGVhc2UoKTtcblxuICAgICAgdGhpcy5fY29udGV4dCA9IG51bGw7XG4gICAgfVxuICB9XG5cbn1cbiIsImltcG9ydCB7IEtpbmQgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuaW1wb3J0IHsgRW5kUG9pbnQsIEVuZFBvaW50Q29sbGVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4uL2dyYXBoL25vZGUnO1xuaW1wb3J0IHsgUG9ydCB9IGZyb20gJy4uL2dyYXBoL3BvcnQnO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeX0gZnJvbSAnLi9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBDb21wb25lbnQgfSBmcm9tICcuLi9jb21wb25lbnQvY29tcG9uZW50JztcblxuaW1wb3J0IHsgQ29udGFpbmVyLCBJbmplY3RhYmxlIH0gZnJvbSAnLi4vZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyJztcblxuZXhwb3J0IGVudW0gUnVuU3RhdGUge1xuICBORVdCT1JOLCAgICAgIC8vIE5vdCB5ZXQgbG9hZGVkXG4gIExPQURJTkcsICAgICAgLy8gV2FpdGluZyBmb3IgYXN5bmMgbG9hZCB0byBjb21wbGV0ZVxuICBMT0FERUQsICAgICAgIC8vIENvbXBvbmVudCBsb2FkZWQsIG5vdCB5ZXQgZXhlY3V0YWJsZVxuICBSRUFEWSwgICAgICAgIC8vIFJlYWR5IGZvciBFeGVjdXRpb25cbiAgUlVOTklORywgICAgICAvLyBOZXR3b3JrIGFjdGl2ZSwgYW5kIHJ1bm5pbmdcbiAgUEFVU0VEICAgICAgICAvLyBOZXR3b3JrIHRlbXBvcmFyaWx5IHBhdXNlZFxufVxuXG4vKipcbiogVGhlIHJ1bnRpbWUgY29udGV4dCBpbmZvcm1hdGlvbiBmb3IgYSBDb21wb25lbnQgaW5zdGFuY2VcbiovXG5leHBvcnQgY2xhc3MgUnVudGltZUNvbnRleHRcbntcbiAgLyoqXG4gICogVGhlIGNvbXBvbmVudCBpZCAvIGFkZHJlc3NcbiAgKi9cbiAgcHJpdmF0ZSBfaWQ6IHN0cmluZztcblxuICAvKipcbiAgKiBUaGUgcnVudGltZSBjb21wb25lbnQgaW5zdGFuY2UgdGhhdCB0aGlzIG5vZGUgcmVwcmVzZW50c1xuICAqL1xuICBwcml2YXRlIF9pbnN0YW5jZTogQ29tcG9uZW50O1xuXG4gIC8qKlxuICAqIEluaXRpYWwgRGF0YSBmb3IgdGhlIGNvbXBvbmVudCBpbnN0YW5jZVxuICAqL1xuICBwcml2YXRlIF9jb25maWc6IHt9O1xuXG4gIC8qKlxuICAqIFRoZSBydW50aW1lIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICovXG4gIHByaXZhdGUgX2NvbnRhaW5lcjogQ29udGFpbmVyO1xuXG4gIC8qKlxuICAqIFRoZSBjb21wb25lbnQgZmFjdG9yeSB0aGF0IGNyZWF0ZWQgdXNcbiAgKi9cbiAgcHJpdmF0ZSBfZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeTtcblxuICAvKipcbiAgKiBUaGUgbm9kZVxuICAqL1xuICBwcml2YXRlIF9ub2RlOiBOb2RlO1xuXG4gIC8qKlxuICAqXG4gICpcbiAgKi9cbiAgY29uc3RydWN0b3IoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnksIGNvbnRhaW5lcjogQ29udGFpbmVyLCBpZDogc3RyaW5nLCBjb25maWc6IHt9LCBkZXBzOiBJbmplY3RhYmxlW10gPSBbXSApIHtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBmYWN0b3J5O1xuXG4gICAgdGhpcy5faWQgPSBpZDtcblxuICAgIHRoaXMuX2NvbmZpZyA9IGNvbmZpZztcblxuICAgIHRoaXMuX2NvbnRhaW5lciA9IGNvbnRhaW5lcjtcblxuICAgIC8vIFJlZ2lzdGVyIGFueSBjb250ZXh0IGRlcGVuZGVuY2llc1xuICAgIGZvciggbGV0IGkgaW4gZGVwcyApXG4gICAge1xuICAgICAgaWYgKCAhdGhpcy5fY29udGFpbmVyLmhhc1Jlc29sdmVyKCBkZXBzW2ldICkgKVxuICAgICAgICB0aGlzLl9jb250YWluZXIucmVnaXN0ZXJTaW5nbGV0b24oIGRlcHNbaV0sIGRlcHNbaV0gKTtcbiAgICB9XG4gIH1cblxuICBnZXQgbm9kZSgpOiBOb2RlIHtcbiAgICByZXR1cm4gdGhpcy5fbm9kZTtcbiAgfVxuICBzZXQgbm9kZSggbm9kZTogTm9kZSApIHtcbiAgICB0aGlzLl9ub2RlID0gbm9kZTtcblxuICAgIC8vIG1ha2Ugbm9kZSAnaW5qZWN0YWJsZScgaW4gY29udGFpbmVyXG4gICAgdGhpcy5fY29udGFpbmVyLnJlZ2lzdGVySW5zdGFuY2UoIE5vZGUsIHRoaXMgKTtcbiAgfVxuXG4gIGdldCBpbnN0YW5jZSgpOiBDb21wb25lbnQge1xuICAgIHJldHVybiB0aGlzLl9pbnN0YW5jZTtcbiAgfVxuXG4gIGdldCBjb250YWluZXIoKTogQ29udGFpbmVyIHtcbiAgICByZXR1cm4gdGhpcy5fY29udGFpbmVyO1xuICB9XG5cbiAgbG9hZCggKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gZ2V0IGFuIGluc3RhbmNlIGZyb20gdGhlIGZhY3RvcnlcbiAgICAgIG1lLl9ydW5TdGF0ZSA9IFJ1blN0YXRlLkxPQURJTkc7XG4gICAgICB0aGlzLl9mYWN0b3J5LmxvYWRDb21wb25lbnQoIHRoaXMsIHRoaXMuX2lkIClcbiAgICAgICAgLnRoZW4oIChpbnN0YW5jZSkgPT4ge1xuICAgICAgICAgIC8vIENvbXBvbmVudCAoYW5kIGFueSBkZXBlbmRlbmNpZXMpIGhhdmUgYmVlbiBsb2FkZWRcbiAgICAgICAgICBtZS5faW5zdGFuY2UgPSBpbnN0YW5jZTtcbiAgICAgICAgICBtZS5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuTE9BREVEICk7XG5cbiAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaCggKGVycikgPT4ge1xuICAgICAgICAgIC8vIFVuYWJsZSB0byBsb2FkXG4gICAgICAgICAgbWUuX3J1blN0YXRlID0gUnVuU3RhdGUuTkVXQk9STjtcblxuICAgICAgICAgIHJlamVjdCggZXJyICk7XG4gICAgICAgIH0pO1xuICAgIH0gKTtcbiAgfVxuXG4gIF9ydW5TdGF0ZTogUnVuU3RhdGUgPSBSdW5TdGF0ZS5ORVdCT1JOO1xuICBnZXQgcnVuU3RhdGUoKSB7XG4gICAgcmV0dXJuIHRoaXMuX3J1blN0YXRlO1xuICB9XG5cbiAgcHJpdmF0ZSBpblN0YXRlKCBzdGF0ZXM6IFJ1blN0YXRlW10gKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIG5ldyBTZXQ8UnVuU3RhdGU+KCBzdGF0ZXMgKS5oYXMoIHRoaXMuX3J1blN0YXRlICk7XG4gIH1cblxuICAvKipcbiAgKiBUcmFuc2l0aW9uIGNvbXBvbmVudCB0byBuZXcgc3RhdGVcbiAgKiBTdGFuZGFyZCB0cmFuc2l0aW9ucywgYW5kIHJlc3BlY3RpdmUgYWN0aW9ucywgYXJlOlxuICAqICAgTE9BREVEIC0+IFJFQURZICAgICAgaW5zdGFudGlhdGUgYW5kIGluaXRpYWxpemUgY29tcG9uZW50XG4gICogICBSRUFEWSAtPiBMT0FERUQgICAgICB0ZWFyZG93biBhbmQgZGVzdHJveSBjb21wb25lbnRcbiAgKlxuICAqICAgUkVBRFkgLT4gUlVOTklORyAgICAgc3RhcnQgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqICAgUlVOTklORyAtPiBSRUFEWSAgICAgc3RvcCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICpcbiAgKiAgIFJVTk5JTkcgLT4gUEFVU0VEICAgIHBhdXNlIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKiAgIFBBVVNFRCAtPiBSVU5OSU5HICAgIHJlc3VtZSBjb21wb25lbnQgZXhlY3V0aW9uXG4gICpcbiAgKi9cbiAgc2V0UnVuU3RhdGUoIHJ1blN0YXRlOiBSdW5TdGF0ZSApIHtcbiAgICBsZXQgaW5zdCA9IHRoaXMuaW5zdGFuY2U7XG5cbiAgICBzd2l0Y2goIHJ1blN0YXRlICkgLy8gdGFyZ2V0IHN0YXRlIC4uXG4gICAge1xuICAgICAgY2FzZSBSdW5TdGF0ZS5MT0FERUQ6IC8vIGp1c3QgbG9hZGVkLCBvciB0ZWFyZG93blxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SRUFEWSwgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyB0ZWFyZG93biBhbmQgZGVzdHJveSBjb21wb25lbnRcbiAgICAgICAgICBpZiAoIGluc3QudGVhcmRvd24gKVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGluc3QudGVhcmRvd24oKTtcblxuICAgICAgICAgICAgLy8gYW5kIGRlc3Ryb3kgaW5zdGFuY2VcbiAgICAgICAgICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUkVBRFk6ICAvLyBpbml0aWFsaXplIG9yIHN0b3Agbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5MT0FERUQgXSApICkge1xuICAgICAgICAgIC8vIGluaXRpYWxpemUgY29tcG9uZW50XG5cbiAgICAgICAgICBsZXQgZW5kUG9pbnRzOiBFbmRQb2ludFtdID0gW107XG5cbiAgICAgICAgICBpZiAoIGluc3QuaW5pdGlhbGl6ZSApXG4gICAgICAgICAgICBlbmRQb2ludHMgPSB0aGlzLmluc3RhbmNlLmluaXRpYWxpemUoIDxLaW5kPnRoaXMuX2NvbmZpZyApO1xuXG4gICAgICAgICAgaWYgKCB0aGlzLl9ub2RlIClcbiAgICAgICAgICAgIHRoaXMuX25vZGUudXBkYXRlUG9ydHMoIGVuZFBvaW50cyApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyBzdG9wIGNvbXBvbmVudFxuICAgICAgICAgIGlmICggaW5zdC5zdG9wIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2Uuc3RvcCgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIGluaXRpYWxpemVkLCBub3QgbG9hZGVkJyApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5SVU5OSU5HOiAgLy8gc3RhcnQvcmVzdW1lIG5vZGVcbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUkVBRFksIFJ1blN0YXRlLlJVTk5JTkcgXSApICkge1xuICAgICAgICAgIC8vIHN0YXJ0IGNvbXBvbmVudCBleGVjdXRpb25cbiAgICAgICAgICBpZiAoIGluc3Quc3RhcnQgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5zdGFydCgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyByZXN1bWUgY29tcG9uZW50IGV4ZWN1dGlvbiBhZnRlciBwYXVzZVxuICAgICAgICAgIGlmICggaW5zdC5yZXN1bWUgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5yZXN1bWUoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBzdGFydGVkLCBub3QgcmVhZHknICk7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlBBVVNFRDogIC8vIHBhdXNlIG5vZGVcbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklOR10gKSApIHtcbiAgICAgICAgICBpZiAoIGluc3QucGF1c2UgKVxuICAgICAgICAgICAgdGhpcy5pbnN0YW5jZS5wYXVzZSgpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyBhbHJlYWR5IHBhdXNlZFxuICAgICAgICB9XG4gICAgICAgIGVsc2VcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoICdDb21wb25lbnQgY2Fubm90IGJlIHBhdXNlZCcgKTtcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgdGhpcy5fcnVuU3RhdGUgPSBydW5TdGF0ZTtcbiAgfVxuXG4gIHJlbGVhc2UoKSB7XG4gICAgLy8gcmVsZWFzZSBpbnN0YW5jZSwgdG8gYXZvaWQgbWVtb3J5IGxlYWtzXG4gICAgdGhpcy5faW5zdGFuY2UgPSBudWxsO1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IG51bGxcbiAgfVxufVxuIiwiZXhwb3J0IGludGVyZmFjZSBNb2R1bGVMb2FkZXIge1xuICBoYXNNb2R1bGU/KCBpZDogc3RyaW5nICk6IGJvb2xlYW47XG5cbiAgbG9hZE1vZHVsZSggaWQ6IHN0cmluZyApOiBQcm9taXNlPGFueT47XG59XG5cbmRlY2xhcmUgaW50ZXJmYWNlIFN5c3RlbSB7XG4gIG5vcm1hbGl6ZVN5bmMoIGlkICk7XG4gIGltcG9ydCggaWQgKTtcbn07XG5kZWNsYXJlIHZhciBTeXN0ZW06IFN5c3RlbTtcblxuY2xhc3MgTW9kdWxlUmVnaXN0cnlFbnRyeSB7XG4gIGNvbnN0cnVjdG9yKCBhZGRyZXNzOiBzdHJpbmcgKSB7XG5cbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU3lzdGVtTW9kdWxlTG9hZGVyIGltcGxlbWVudHMgTW9kdWxlTG9hZGVyIHtcblxuICBwcml2YXRlIG1vZHVsZVJlZ2lzdHJ5OiBNYXA8c3RyaW5nLCBNb2R1bGVSZWdpc3RyeUVudHJ5PjtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLm1vZHVsZVJlZ2lzdHJ5ID0gbmV3IE1hcDxzdHJpbmcsIE1vZHVsZVJlZ2lzdHJ5RW50cnk+KCk7XG4gIH1cblxuICBwcml2YXRlIGdldE9yQ3JlYXRlTW9kdWxlUmVnaXN0cnlFbnRyeShhZGRyZXNzOiBzdHJpbmcpOiBNb2R1bGVSZWdpc3RyeUVudHJ5IHtcbiAgICByZXR1cm4gdGhpcy5tb2R1bGVSZWdpc3RyeVthZGRyZXNzXSB8fCAodGhpcy5tb2R1bGVSZWdpc3RyeVthZGRyZXNzXSA9IG5ldyBNb2R1bGVSZWdpc3RyeUVudHJ5KGFkZHJlc3MpKTtcbiAgfVxuXG4gIGxvYWRNb2R1bGUoIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxhbnk+IHtcbiAgICBsZXQgbmV3SWQgPSBTeXN0ZW0ubm9ybWFsaXplU3luYyhpZCk7XG4gICAgbGV0IGV4aXN0aW5nID0gdGhpcy5tb2R1bGVSZWdpc3RyeVtuZXdJZF07XG5cbiAgICBpZiAoZXhpc3RpbmcpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZXhpc3RpbmcpO1xuICAgIH1cblxuICAgIHJldHVybiBTeXN0ZW0uaW1wb3J0KG5ld0lkKS50aGVuKG0gPT4ge1xuICAgICAgdGhpcy5tb2R1bGVSZWdpc3RyeVtuZXdJZF0gPSBtO1xuICAgICAgcmV0dXJuIG07IC8vZW5zdXJlT3JpZ2luT25FeHBvcnRzKG0sIG5ld0lkKTtcbiAgICB9KTtcbiAgfVxuXG59XG4iLCJpbXBvcnQgeyBDb21wb25lbnQsIENvbXBvbmVudENvbnN0cnVjdG9yIH0gZnJvbSAnLi4vY29tcG9uZW50L2NvbXBvbmVudCc7XG5pbXBvcnQgeyBSdW50aW1lQ29udGV4dCB9IGZyb20gJy4vcnVudGltZS1jb250ZXh0JztcbmltcG9ydCB7IE1vZHVsZUxvYWRlciB9IGZyb20gJy4vbW9kdWxlLWxvYWRlcic7XG5cbmltcG9ydCB7IENvbnRhaW5lciwgSW5qZWN0YWJsZSB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5pbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcblxuZXhwb3J0IGNsYXNzIENvbXBvbmVudEZhY3Rvcnkge1xuICBwcml2YXRlIF9sb2FkZXI6IE1vZHVsZUxvYWRlcjtcbiAgcHJpdmF0ZSBfY29udGFpbmVyOiBDb250YWluZXI7XG4gIHByaXZhdGUgX2NvbXBvbmVudHM6IE1hcDxzdHJpbmcsIENvbXBvbmVudENvbnN0cnVjdG9yPjtcblxuICBjb25zdHJ1Y3RvciggY29udGFpbmVyPzogQ29udGFpbmVyLCBsb2FkZXI/OiBNb2R1bGVMb2FkZXIgKSB7XG4gICAgdGhpcy5fbG9hZGVyID0gbG9hZGVyO1xuICAgIHRoaXMuX2NvbnRhaW5lciA9IGNvbnRhaW5lciB8fCBuZXcgQ29udGFpbmVyKCk7XG4gICAgdGhpcy5fY29tcG9uZW50cyA9IG5ldyBNYXA8c3RyaW5nLCBDb21wb25lbnRDb25zdHJ1Y3Rvcj4oKTtcblxuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCB1bmRlZmluZWQsIE9iamVjdCApO1xuICAgIHRoaXMuX2NvbXBvbmVudHMuc2V0KCBcIlwiLCBPYmplY3QgKTtcbiAgfVxuXG4gIGNyZWF0ZUNvbnRleHQoIGlkOiBzdHJpbmcsIGNvbmZpZzoge30sIGRlcHM6IEluamVjdGFibGVbXSA9IFtdICk6IFJ1bnRpbWVDb250ZXh0XG4gIHtcbiAgICBsZXQgY2hpbGRDb250YWluZXI6IENvbnRhaW5lciA9IHRoaXMuX2NvbnRhaW5lci5jcmVhdGVDaGlsZCgpO1xuXG4gICAgcmV0dXJuIG5ldyBSdW50aW1lQ29udGV4dCggdGhpcywgY2hpbGRDb250YWluZXIsIGlkLCBjb25maWcsIGRlcHMgKTtcbiAgfVxuXG4gIGdldENoaWxkQ29udGFpbmVyKCk6IENvbnRhaW5lciB7XG4gICAgcmV0dXJuIDtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGN0eDogUnVudGltZUNvbnRleHQsIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxDb21wb25lbnQ+XG4gIHtcbiAgICBsZXQgY3JlYXRlQ29tcG9uZW50ID0gZnVuY3Rpb24oIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yICk6IENvbXBvbmVudFxuICAgIHtcbiAgICAgIGxldCBuZXdJbnN0YW5jZTogQ29tcG9uZW50ID0gY3R4LmNvbnRhaW5lci5pbnZva2UoIGN0b3IgKTtcblxuICAgICAgcmV0dXJuIG5ld0luc3RhbmNlO1xuICAgIH1cblxuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2U8Q29tcG9uZW50PiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gQ2hlY2sgY2FjaGVcbiAgICAgIGxldCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciA9IHRoaXMuZ2V0KCBpZCApO1xuXG4gICAgICBpZiAoIGN0b3IgKSB7XG4gICAgICAgIC8vIHVzZSBjYWNoZWQgY29uc3RydWN0b3JcbiAgICAgICAgcmVzb2x2ZSggY3JlYXRlQ29tcG9uZW50KCBjdG9yICkgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCB0aGlzLl9sb2FkZXIgKSB7XG4gICAgICAgIC8vIGdvdCBhIGxvYWRlZCwgc28gdHJ5IHRvIGxvYWQgdGhlIG1vZHVsZSAuLi5cbiAgICAgICAgdGhpcy5fbG9hZGVyLmxvYWRNb2R1bGUoIGlkIClcbiAgICAgICAgICAudGhlbiggKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApID0+IHtcblxuICAgICAgICAgICAgLy8gcmVnaXN0ZXIgbG9hZGVkIGNvbXBvbmVudFxuICAgICAgICAgICAgbWUuX2NvbXBvbmVudHMuc2V0KCBpZCwgY3RvciApO1xuXG4gICAgICAgICAgICAvLyBpbnN0YW50aWF0ZSBhbmQgcmVzb2x2ZVxuICAgICAgICAgICAgcmVzb2x2ZSggY3JlYXRlQ29tcG9uZW50KCBjdG9yICkgKTtcbiAgICAgICAgICB9KVxuICAgICAgICAgIC5jYXRjaCggKCBlICkgPT4ge1xuICAgICAgICAgICAgcmVqZWN0KCAnQ29tcG9uZW50RmFjdG9yeTogVW5hYmxlIHRvIGxvYWQgY29tcG9uZW50IFwiJyArIGlkICsgJ1wiIC0gJyArIGUgKTtcbiAgICAgICAgICB9ICk7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgLy8gb29wcy4gbm8gbG9hZGVyIC4uIG5vIGNvbXBvbmVudFxuICAgICAgICByZWplY3QoICdDb21wb25lbnRGYWN0b3J5OiBDb21wb25lbnQgXCInICsgaWQgKyAnXCIgbm90IHJlZ2lzdGVyZWQsIGFuZCBMb2FkZXIgbm90IGF2YWlsYWJsZScgKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIGdldCggaWQ6IHN0cmluZyApOiBDb21wb25lbnRDb25zdHJ1Y3RvciB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbXBvbmVudHMuZ2V0KCBpZCApO1xuICB9XG4gIHJlZ2lzdGVyKCBpZDogc3RyaW5nLCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApIHtcbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggaWQsIGN0b3IgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IFBvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG5leHBvcnQgdHlwZSBFbmRQb2ludFJlZiA9IHsgbm9kZUlEOiBzdHJpbmcsIHBvcnRJRDogc3RyaW5nIH07XG5cbmV4cG9ydCBjbGFzcyBMaW5rXG57XG4gIHByb3RlY3RlZCBfb3duZXI6IEdyYXBoO1xuICBwcm90ZWN0ZWQgX2lkOiBzdHJpbmc7XG5cbiAgcHJvdGVjdGVkIF9jaGFubmVsOiBDaGFubmVsO1xuICBwcm90ZWN0ZWQgX2Zyb206IEVuZFBvaW50UmVmO1xuICBwcm90ZWN0ZWQgX3RvOiBFbmRQb2ludFJlZjtcblxuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcbiAgcHJvdGVjdGVkIG1ldGFkYXRhOiBhbnk7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9pZCA9IGF0dHJpYnV0ZXMuaWQgfHwgXCJcIjtcbiAgICAvL3RoaXMuX2NoYW5uZWwgPSBudWxsO1xuICAgIHRoaXMuX2Zyb20gPSBhdHRyaWJ1dGVzWyAnZnJvbScgXTtcbiAgICB0aGlzLl90byA9IGF0dHJpYnV0ZXNbICd0bycgXTtcbiAgICB0aGlzLl9wcm90b2NvbElEID0gYXR0cmlidXRlc1sgJ3Byb3RvY29sJyBdIHx8ICdhbnknO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB4OiAxMDAsIHk6IDEwMCB9O1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICBsZXQgbGluayA9IHtcbiAgICAgIGlkOiB0aGlzLl9pZCxcbiAgICAgIHByb3RvY29sOiAoIHRoaXMuX3Byb3RvY29sSUQgIT0gJ2FueScgKSA/IHRoaXMuX3Byb3RvY29sSUQgOiB1bmRlZmluZWQsXG4gICAgICBtZXRhZGF0YTogdGhpcy5tZXRhZGF0YSxcbiAgICAgIGZyb206IHRoaXMuX2Zyb20sXG4gICAgICB0bzogdGhpcy5fdG9cbiAgICB9O1xuXG4gICAgcmV0dXJuIGxpbms7XG4gIH1cblxuICBzZXQgaWQoIGlkOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIGNvbm5lY3QoIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgLy8gaWRlbnRpZnkgZnJvbVBvcnQgaW4gZnJvbU5vZGVcbiAgICBsZXQgZnJvbVBvcnQ6IFBvcnQgPSB0aGlzLmZyb21Ob2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fZnJvbS5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKTtcblxuICAgIC8vIGlkZW50aWZ5IHRvUG9ydCBpbiB0b05vZGVcbiAgICBsZXQgdG9Qb3J0OiBQb3J0ID0gdGhpcy50b05vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl90by5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKTtcblxuICAgIHRoaXMuX2NoYW5uZWwgPSBjaGFubmVsO1xuXG4gICAgZnJvbVBvcnQuZW5kUG9pbnQuYXR0YWNoKCBjaGFubmVsICk7XG4gICAgdG9Qb3J0LmVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICB9XG5cbiAgZGlzY29ubmVjdCgpOiBDaGFubmVsXG4gIHtcbiAgICBsZXQgY2hhbiA9IHRoaXMuX2NoYW5uZWw7XG5cbiAgICBpZiAoIGNoYW4gKVxuICAgIHtcbiAgICAgIHRoaXMuX2NoYW5uZWwuZW5kUG9pbnRzLmZvckVhY2goICggZW5kUG9pbnQgKSA9PiB7XG4gICAgICAgIGVuZFBvaW50LmRldGFjaCggdGhpcy5fY2hhbm5lbCApO1xuICAgICAgfSApO1xuXG4gICAgICB0aGlzLl9jaGFubmVsID0gdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIHJldHVybiBjaGFuO1xuICB9XG5cbiAgZ2V0IGZyb21Ob2RlKCk6IE5vZGVcbiAge1xuICAgIHJldHVybiB0aGlzLl9vd25lci5nZXROb2RlQnlJRCggdGhpcy5fZnJvbS5ub2RlSUQgKTtcbiAgfVxuXG4gIGdldCBmcm9tUG9ydCgpOiBQb3J0XG4gIHtcbiAgICBsZXQgbm9kZSA9IHRoaXMuZnJvbU5vZGU7XG5cbiAgICByZXR1cm4gKG5vZGUpID8gbm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX2Zyb20ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICkgOiB1bmRlZmluZWQ7XG4gIH1cblxuICBzZXQgZnJvbVBvcnQoIHBvcnQ6IFBvcnQgKVxuICB7XG4gICAgdGhpcy5fZnJvbSA9IHtcbiAgICAgIG5vZGVJRDogcG9ydC5vd25lci5pZCxcbiAgICAgIHBvcnRJRDogcG9ydC5pZFxuICAgIH07XG5cbiAgICB0aGlzLl9wcm90b2NvbElEID0gcG9ydC5wcm90b2NvbElEO1xuICB9XG5cbiAgZ2V0IHRvTm9kZSgpOiBOb2RlXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXIuZ2V0Tm9kZUJ5SUQoIHRoaXMuX3RvLm5vZGVJRCApO1xuICB9XG5cbiAgZ2V0IHRvUG9ydCgpOiBQb3J0XG4gIHtcbiAgICBsZXQgbm9kZSA9IHRoaXMudG9Ob2RlO1xuXG4gICAgcmV0dXJuIChub2RlKSA/IG5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl90by5wb3J0SUQsIHRoaXMuX3Byb3RvY29sSUQgKSA6IHVuZGVmaW5lZDtcbiAgfVxuXG4gIHNldCB0b1BvcnQoIHBvcnQ6IFBvcnQgKVxuICB7XG4gICAgdGhpcy5fdG8gPSB7XG4gICAgICBub2RlSUQ6IHBvcnQub3duZXIuaWQsXG4gICAgICBwb3J0SUQ6IHBvcnQuaWRcbiAgICB9O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IHBvcnQucHJvdG9jb2xJRDtcbiAgfVxuXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5IH0gZnJvbSAnLi4vcnVudGltZS9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBSdW50aW1lQ29udGV4dCwgUnVuU3RhdGUgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBFbmRQb2ludCB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgQ2hhbm5lbCB9IGZyb20gJy4uL21lc3NhZ2luZy9jaGFubmVsJztcblxuaW1wb3J0IHsgR3JhcGggfSBmcm9tICcuL2dyYXBoJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgTGluayB9IGZyb20gJy4vbGluayc7XG5pbXBvcnQgeyBQb3J0LCBQdWJsaWNQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuZXhwb3J0IGNsYXNzIE5ldHdvcmsgZXh0ZW5kcyBFdmVudEh1Ylxue1xuICBzdGF0aWMgRVZFTlRfU1RBVEVfQ0hBTkdFID0gJ25ldHdvcms6c3RhdGUtY2hhbmdlJztcbiAgc3RhdGljIEVWRU5UX0dSQVBIX0NIQU5HRSA9ICduZXR3b3JrOmdyYXBoLWNoYW5nZSc7XG5cbiAgcHJpdmF0ZSBfZ3JhcGg6IEdyYXBoO1xuXG4gIHByaXZhdGUgX2ZhY3Rvcnk6IENvbXBvbmVudEZhY3Rvcnk7XG5cbiAgY29uc3RydWN0b3IoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnksIGdyYXBoPzogR3JhcGggKVxuICB7XG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBmYWN0b3J5O1xuICAgIHRoaXMuX2dyYXBoID0gZ3JhcGggfHwgbmV3IEdyYXBoKCBudWxsLCB7fSApO1xuXG4gICAgbGV0IG1lID0gdGhpcztcbiAgICB0aGlzLl9ncmFwaC5zdWJzY3JpYmUoIEdyYXBoLkVWRU5UX0FERF9OT0RFLCAoIGRhdGE6IHsgbm9kZTogTm9kZSB9ICk9PiB7XG4gICAgICBsZXQgcnVuU3RhdGU6IFJ1blN0YXRlID0gbWUuX2dyYXBoLmNvbnRleHQucnVuU3RhdGU7XG5cbiAgICAgIGlmICggcnVuU3RhdGUgIT0gUnVuU3RhdGUuTkVXQk9STiApXG4gICAgICB7XG4gICAgICAgIGxldCB7IG5vZGUgfSA9IGRhdGE7XG5cbiAgICAgICAgbm9kZS5sb2FkQ29tcG9uZW50KCBtZS5fZmFjdG9yeSApXG4gICAgICAgICAgLnRoZW4oICgpPT4ge1xuICAgICAgICAgICAgaWYgKCBOZXR3b3JrLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VELCBSdW5TdGF0ZS5SRUFEWSBdLCBydW5TdGF0ZSApIClcbiAgICAgICAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggbm9kZSwgUnVuU3RhdGUuUkVBRFkgKTtcblxuICAgICAgICAgICAgaWYgKCBOZXR3b3JrLmluU3RhdGUoIFsgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0sIHJ1blN0YXRlICkgKVxuICAgICAgICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBub2RlLCBydW5TdGF0ZSApO1xuXG4gICAgICAgICAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfR1JBUEhfQ0hBTkdFLCB7IG5vZGU6IG5vZGUgfSApO1xuICAgICAgICAgIH0pXG4gICAgICB9XG4gICAgfSApO1xuICB9XG5cbiAgZ2V0IGdyYXBoKCk6IEdyYXBoIHtcbiAgICByZXR1cm4gdGhpcy5fZ3JhcGg7XG4gIH1cblxuICAvKipcbiAgKiBMb2FkIGFsbCBjb21wb25lbnRzXG4gICovXG4gIGxvYWRDb21wb25lbnRzKCk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfU1RBVEVfQ0hBTkdFLCB7IHN0YXRlOiBSdW5TdGF0ZS5MT0FESU5HIH0gKTtcblxuICAgIHJldHVybiB0aGlzLl9ncmFwaC5sb2FkQ29tcG9uZW50KCB0aGlzLl9mYWN0b3J5ICkudGhlbiggKCk9PiB7XG4gICAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfU1RBVEVfQ0hBTkdFLCB7IHN0YXRlOiBSdW5TdGF0ZS5MT0FERUQgfSApO1xuICAgIH0pO1xuICB9XG5cbiAgaW5pdGlhbGl6ZSgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SRUFEWSApO1xuICB9XG5cbiAgdGVhcmRvd24oKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuTE9BREVEICk7XG4gIH1cblxuICBzdGF0aWMgaW5TdGF0ZSggc3RhdGVzOiBSdW5TdGF0ZVtdLCBydW5TdGF0ZTogUnVuU3RhdGUgKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIG5ldyBTZXQ8UnVuU3RhdGU+KCBzdGF0ZXMgKS5oYXMoIHJ1blN0YXRlICk7XG4gIH1cblxuICAvKipcbiAgKiBBbHRlciBydW4tc3RhdGUgb2YgYSBOb2RlIC0gTE9BREVELCBSRUFEWSwgUlVOTklORyBvciBQQVVTRUQuXG4gICogVHJpZ2dlcnMgU2V0dXAgb3IgVGVhcmRvd24gaWYgdHJhbnNpdGlvbmluZyBiZXR3ZWVuIFJFQURZIGFuZCBMT0FERURcbiAgKiBXaXJldXAgYSBncmFwaCwgY3JlYXRpbmcgQ2hhbm5lbCBiZXR3ZWVuIGxpbmtlZCBOb2Rlc1xuICAqIEFjdHMgcmVjdXJzaXZlbHksIHdpcmluZyB1cCBhbnkgc3ViLWdyYXBoc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyBzZXRSdW5TdGF0ZSggbm9kZTogTm9kZSwgcnVuU3RhdGU6IFJ1blN0YXRlIClcbiAge1xuICAgIGxldCBjdHggPSBub2RlLmNvbnRleHQ7XG4gICAgbGV0IGN1cnJlbnRTdGF0ZSA9IGN0eC5ydW5TdGF0ZTtcblxuICAgIGlmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoIClcbiAgICB7XG4gICAgICAvLyAxLiBQcmVwcm9jZXNzXG4gICAgICAvLyAgICBhLiBIYW5kbGUgdGVhcmRvd25cbiAgICAgIC8vICAgIGIuIFByb3BhZ2F0ZSBzdGF0ZSBjaGFuZ2UgdG8gc3VibmV0c1xuICAgICAgbGV0IG5vZGVzOiBNYXA8c3RyaW5nLCBOb2RlPiA9IG5vZGUubm9kZXM7XG5cbiAgICAgIGlmICggKCBydW5TdGF0ZSA9PSBSdW5TdGF0ZS5MT0FERUQgKSAmJiAoIGN1cnJlbnRTdGF0ZSA+PSBSdW5TdGF0ZS5SRUFEWSApICkge1xuICAgICAgICAvLyB0ZWFyaW5nIGRvd24gLi4gdW5saW5rIGdyYXBoIGZpcnN0XG4gICAgICAgIGxldCBsaW5rczogTWFwPHN0cmluZywgTGluaz4gPSBub2RlLmxpbmtzO1xuXG4gICAgICAgIC8vIHVud2lyZSAoZGVhY3RpdmF0ZSBhbmQgZGVzdHJveSApIENoYW5uZWxzIGJldHdlZW4gbGlua2VkIG5vZGVzXG4gICAgICAgIGxpbmtzLmZvckVhY2goICggbGluayApID0+XG4gICAgICAgIHtcbiAgICAgICAgICBOZXR3b3JrLnVud2lyZUxpbmsoIGxpbmsgKTtcbiAgICAgICAgfSApO1xuICAgICAgfVxuXG4gICAgICAvLyBQcm9wYWdhdGUgc3RhdGUgY2hhbmdlIHRvIHN1Yi1uZXRzIGZpcnN0XG4gICAgICBub2Rlcy5mb3JFYWNoKCBmdW5jdGlvbiggc3ViTm9kZSApXG4gICAgICB7XG4gICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIHN1Yk5vZGUsIHJ1blN0YXRlICk7XG4gICAgICB9ICk7XG5cbiAgICAgIC8vIDIuIENoYW5nZSBzdGF0ZSAuLi5cbiAgICAgIGN0eC5zZXRSdW5TdGF0ZSggcnVuU3RhdGUgKTtcblxuICAgICAgLy8gMy4gUG9zdHByb2Nlc3NcbiAgICAgIC8vICAgIGEuIEhhbmRsZSBzZXR1cFxuICAgICAgaWYgKCAoIHJ1blN0YXRlID09IFJ1blN0YXRlLlJFQURZICkgJiYgKCBjdXJyZW50U3RhdGUgPj0gUnVuU3RhdGUuTE9BREVEICkgKSB7XG5cbiAgICAgICAgLy8gc2V0dGluZyB1cCAuLiBsaW5rdXAgZ3JhcGggZmlyc3RcbiAgICAgICAgbGV0IGxpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPiA9IG5vZGUubGlua3M7XG4gICAgICAgIC8vIHRyZWF0IGdyYXBoIHJlY3Vyc2l2ZWx5XG5cbiAgICAgICAgLy8gMi4gd2lyZXVwIChjcmVhdGUgYW5kIGFjdGl2YXRlKSBhIENoYW5uZWwgYmV0d2VlbiBsaW5rZWQgbm9kZXNcbiAgICAgICAgbGlua3MuZm9yRWFjaCggKCBsaW5rICkgPT5cbiAgICAgICAge1xuICAgICAgICAgIE5ldHdvcmsud2lyZUxpbmsoIGxpbmsgKTtcbiAgICAgICAgfSApO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBDaGFuZ2Ugc3RhdGUgLi4uXG4gICAgICBjdHguc2V0UnVuU3RhdGUoIHJ1blN0YXRlICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogVW53aXJlIGEgbGluaywgcmVtb3ZpbmcgdGhlIENoYW5uZWwgYmV0d2VlbiB0aGUgbGlua2VkIE5vZGVzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHVud2lyZUxpbmsoIGxpbms6IExpbmsgKVxuICB7XG4gICAgLy8gZ2V0IGxpbmtlZCBub2RlcyAoTGluayBmaW5kcyBOb2RlcyBpbiBwYXJlbnQgR3JhcGgpXG4gICAgbGV0IGZyb21Ob2RlID0gbGluay5mcm9tTm9kZTtcbiAgICBsZXQgdG9Ob2RlID0gbGluay50b05vZGU7XG5cbiAgICBsZXQgY2hhbjogQ2hhbm5lbCA9IGxpbmsuZGlzY29ubmVjdCgpO1xuXG4gICAgaWYgKCBjaGFuIClcbiAgICAgIGNoYW4uZGVhY3RpdmF0ZSgpO1xuICB9XG5cbiAgLyoqXG4gICogV2lyZXVwIGEgbGluaywgY3JlYXRpbmcgQ2hhbm5lbCBiZXR3ZWVuIHRoZSBsaW5rZWQgTm9kZXNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgd2lyZUxpbmsoIGxpbms6IExpbmsgKVxuICB7XG4gICAgLy8gZ2V0IGxpbmtlZCBub2RlcyAoTGluayBmaW5kcyBOb2RlcyBpbiBwYXJlbnQgR3JhcGgpXG4gICAgbGV0IGZyb21Ob2RlID0gbGluay5mcm9tTm9kZTtcbiAgICBsZXQgdG9Ob2RlID0gbGluay50b05vZGU7XG5cbiAgICAvL2RlYnVnTWVzc2FnZSggXCJMaW5rKFwiK2xpbmsuaWQrXCIpOiBcIiArIGxpbmsuZnJvbSArIFwiIC0+IFwiICsgbGluay50byArIFwiIHByb3RvPVwiK2xpbmsucHJvdG9jb2wgKTtcblxuICAgIGxldCBjaGFubmVsID0gbmV3IENoYW5uZWwoKTtcblxuICAgIGxpbmsuY29ubmVjdCggY2hhbm5lbCApO1xuXG4gICAgY2hhbm5lbC5hY3RpdmF0ZSgpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHNldFJ1blN0YXRlKCBydW5TdGF0ZTogUnVuU3RhdGUgKVxuICB7XG4gICAgTmV0d29yay5zZXRSdW5TdGF0ZSggdGhpcy5fZ3JhcGgsIHJ1blN0YXRlICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIE5ldHdvcmsuRVZFTlRfU1RBVEVfQ0hBTkdFLCB7IHN0YXRlOiBydW5TdGF0ZSB9ICk7XG4gIH1cblxuICBzdGFydCggaW5pdGlhbGx5UGF1c2VkOiBib29sZWFuID0gZmFsc2UgKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggaW5pdGlhbGx5UGF1c2VkID8gUnVuU3RhdGUuUEFVU0VEIDogUnVuU3RhdGUuUlVOTklORyApO1xuICB9XG5cbiAgc3RlcCgpIHtcbiAgICAvLyBUT0RPOiBTaW5nbGUtc3RlcFxuICB9XG5cbiAgc3RvcCgpIHtcbiAgICB0aGlzLnNldFJ1blN0YXRlKCBSdW5TdGF0ZS5SRUFEWSApO1xuICB9XG5cbiAgcGF1c2UoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUEFVU0VEICk7XG4gIH1cblxuICByZXN1bWUoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUlVOTklORyApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IE5ldHdvcmsgfSBmcm9tICcuL25ldHdvcmsnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBMaW5rIH0gZnJvbSAnLi9saW5rJztcbmltcG9ydCB7IFBvcnQsIFB1YmxpY1BvcnQgfSBmcm9tICcuL3BvcnQnO1xuXG4vKipcbiAqIEEgR3JhcGggaXMgYSBjb2xsZWN0aW9uIG9mIE5vZGVzIGludGVyY29ubmVjdGVkIHZpYSBMaW5rcy5cbiAqIEEgR3JhcGggaXMgaXRzZWxmIGEgTm9kZSwgd2hvc2UgUG9ydHMgYWN0IGFzIHB1Ymxpc2hlZCBFbmRQb2ludHMsIHRvIHRoZSBHcmFwaC5cbiAqL1xuZXhwb3J0IGNsYXNzIEdyYXBoIGV4dGVuZHMgTm9kZVxue1xuICBzdGF0aWMgRVZFTlRfQUREX05PREUgPSAnZ3JhcGg6YWRkLW5vZGUnO1xuICBzdGF0aWMgRVZFTlRfVVBEX05PREUgPSAnZ3JhcGg6dXBkLW5vZGUnO1xuICBzdGF0aWMgRVZFTlRfREVMX05PREUgPSAnZ3JhcGg6ZGVsLW5vZGUnO1xuXG4gIHN0YXRpYyBFVkVOVF9BRERfTElOSyA9ICdncmFwaDphZGQtbGluayc7XG4gIHN0YXRpYyBFVkVOVF9VUERfTElOSyA9ICdncmFwaDp1cGQtbGluayc7XG4gIHN0YXRpYyBFVkVOVF9ERUxfTElOSyA9ICdncmFwaDpkZWwtbGluayc7XG5cbiAgLyoqXG4gICogTm9kZXMgaW4gdGhpcyBncmFwaC4gRWFjaCBub2RlIG1heSBiZTpcbiAgKiAgIDEuIEEgQ29tcG9uZW50XG4gICogICAyLiBBIHN1Yi1ncmFwaFxuICAqL1xuICBwcm90ZWN0ZWQgX25vZGVzOiBNYXA8c3RyaW5nLCBOb2RlPjtcblxuICAvLyBMaW5rcyBpbiB0aGlzIGdyYXBoLiBFYWNoIG5vZGUgbWF5IGJlOlxuICBwcm90ZWN0ZWQgX2xpbmtzOiBNYXA8c3RyaW5nLCBMaW5rPjtcblxuICAvLyBQdWJsaWMgUG9ydHMgaW4gdGhpcyBncmFwaC4gSW5oZXJpdGVkIGZyb20gTm9kZVxuICAvLyBwcml2YXRlIFBvcnRzO1xuICBjb25zdHJ1Y3Rvciggb3duZXI6IEdyYXBoLCBhdHRyaWJ1dGVzOiBhbnkgPSB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuaW5pdEZyb21PYmplY3QoIGF0dHJpYnV0ZXMgKTtcbiAgfVxuXG4gIGluaXRGcm9tU3RyaW5nKCBqc29uU3RyaW5nOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5pbml0RnJvbU9iamVjdCggSlNPTi5wYXJzZSgganNvblN0cmluZyApICk7XG4gIH1cblxuICBpbml0RnJvbU9iamVjdCggYXR0cmlidXRlczogYW55ICkge1xuXG4gICAgdGhpcy5pZCA9IGF0dHJpYnV0ZXMuaWQgfHwgXCIkZ3JhcGhcIjtcblxuICAgIHRoaXMuX25vZGVzID0gbmV3IE1hcDxzdHJpbmcsIE5vZGU+KCk7XG4gICAgdGhpcy5fbGlua3MgPSBuZXcgTWFwPHN0cmluZywgTGluaz4oKTtcblxuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLm5vZGVzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZE5vZGUoIGlkLCBhdHRyaWJ1dGVzLm5vZGVzWyBpZCBdICk7XG4gICAgfSk7XG5cbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5saW5rcyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGRMaW5rKCBpZCwgYXR0cmlidXRlcy5saW5rc1sgaWQgXSApO1xuICAgIH0pO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM6IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBncmFwaCA9IHN1cGVyLnRvT2JqZWN0KCk7XG5cbiAgICBsZXQgbm9kZXMgPSBncmFwaFsgXCJub2Rlc1wiIF0gPSB7fTtcbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuLy8gICAgICBpZiAoIG5vZGUgIT0gdGhpcyApXG4gICAgICAgIG5vZGVzWyBpZCBdID0gbm9kZS50b09iamVjdCgpO1xuICAgIH0pO1xuXG4gICAgbGV0IGxpbmtzID0gZ3JhcGhbIFwibGlua3NcIiBdID0ge307XG4gICAgdGhpcy5fbGlua3MuZm9yRWFjaCggKCBsaW5rLCBpZCApID0+IHtcbiAgICAgIGxpbmtzWyBpZCBdID0gbGluay50b09iamVjdCgpO1xuICAgIH0pO1xuXG4gICAgcmV0dXJuIGdyYXBoO1xuICB9XG5cbiAgbG9hZENvbXBvbmVudCggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSApOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCBwZW5kaW5nQ291bnQgPSAwO1xuXG4gICAgICBsZXQgbm9kZXMgPSBuZXcgTWFwPHN0cmluZywgTm9kZT4oIHRoaXMuX25vZGVzICk7XG4gICAgICBub2Rlcy5zZXQoICckZ3JhcGgnLCB0aGlzICk7XG5cbiAgICAgIG5vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICAgIGxldCBkb25lOiBQcm9taXNlPHZvaWQ+O1xuXG4gICAgICAgIHBlbmRpbmdDb3VudCsrO1xuXG4gICAgICAgIGlmICggbm9kZSA9PSB0aGlzICkge1xuICAgICAgICAgIGRvbmUgPSBzdXBlci5sb2FkQ29tcG9uZW50KCBmYWN0b3J5ICk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgZG9uZSA9IG5vZGUubG9hZENvbXBvbmVudCggZmFjdG9yeSApO1xuICAgICAgICB9XG5cbiAgICAgICAgZG9uZS50aGVuKCAoKSA9PiB7XG4gICAgICAgICAgLS1wZW5kaW5nQ291bnQ7XG4gICAgICAgICAgaWYgKCBwZW5kaW5nQ291bnQgPT0gMCApXG4gICAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaCggKCByZWFzb24gKSA9PiB7XG4gICAgICAgICAgcmVqZWN0KCByZWFzb24gKTtcbiAgICAgICAgfSApO1xuICAgICAgfSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgbm9kZXMoKTogTWFwPHN0cmluZywgTm9kZT5cbiAge1xuICAgIHJldHVybiB0aGlzLl9ub2RlcztcbiAgfVxuXG4vKiAgcHVibGljIGdldEFsbE5vZGVzKCk6IE5vZGVbXVxuICB7XG4gICAgbGV0IG5vZGVzOiBOb2RlW10gPSBbXTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICAvLyBEb24ndCByZWN1cnNlIG9uIGdyYXBoJ3MgcHNldWRvLW5vZGVcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgbm9kZXMgPSBub2Rlcy5jb25jYXQoIG5vZGUuZ2V0QWxsTm9kZXMoKSApO1xuXG4gICAgICBub2Rlcy5wdXNoKCBub2RlICk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIG5vZGVzO1xuICB9Ki9cblxuICBwdWJsaWMgZ2V0IGxpbmtzKCk6IE1hcDxzdHJpbmcsIExpbms+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fbGlua3M7XG4gIH1cblxuLyogIHB1YmxpYyBnZXRBbGxMaW5rcygpOiBMaW5rW11cbiAge1xuICAgIGxldCBsaW5rczogTGlua1tdID0gW107XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgaWYgKCAoIG5vZGUgIT0gdGhpcyApICYmICggbm9kZSBpbnN0YW5jZW9mIEdyYXBoICkgKVxuICAgICAgICBsaW5rcyA9IGxpbmtzLmNvbmNhdCggbm9kZS5nZXRBbGxMaW5rcygpICk7XG4gICAgfSApXG5cbiAgICB0aGlzLl9saW5rcy5mb3JFYWNoKCAoIGxpbmssIGlkICkgPT4ge1xuICAgICAgbGlua3MucHVzaCggbGluayApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBsaW5rcztcbiAgfSovXG5cbi8qICBwdWJsaWMgZ2V0QWxsUG9ydHMoKTogUG9ydFtdXG4gIHtcbiAgICBsZXQgcG9ydHM6IFBvcnRbXSA9IHN1cGVyLmdldFBvcnRBcnJheSgpO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgcG9ydHMgPSBwb3J0cy5jb25jYXQoIG5vZGUuZ2V0QWxsUG9ydHMoKSApO1xuICAgICAgZWxzZVxuICAgICAgICBwb3J0cyA9IHBvcnRzLmNvbmNhdCggbm9kZS5nZXRQb3J0QXJyYXkoKSApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBwb3J0cztcbiAgfSovXG5cbiAgcHVibGljIGdldE5vZGVCeUlEKCBpZDogc3RyaW5nICk6IE5vZGVcbiAge1xuICAgIGlmICggaWQgPT0gJyRncmFwaCcgKVxuICAgICAgcmV0dXJuIHRoaXM7XG5cbiAgICByZXR1cm4gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuICB9XG5cbiAgcHVibGljIGFkZE5vZGUoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM/OiB7fSApOiBOb2RlIHtcblxuICAgIGxldCBub2RlID0gbmV3IE5vZGUoIHRoaXMsIGF0dHJpYnV0ZXMgKTtcblxuICAgIG5vZGUuaWQgPSBpZDtcblxuICAgIHRoaXMuX25vZGVzLnNldCggaWQsIG5vZGUgKTtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfQUREX05PREUsIHsgbm9kZTogbm9kZSB9ICk7XG5cbiAgICByZXR1cm4gbm9kZTtcbiAgfVxuXG4gIHB1YmxpYyByZW5hbWVOb2RlKCBpZDogc3RyaW5nLCBuZXdJRDogc3RyaW5nICkge1xuXG4gICAgbGV0IG5vZGUgPSB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG5cbiAgICBpZiAoIGlkICE9IG5ld0lEIClcbiAgICB7XG4gICAgICBsZXQgZXZlbnREYXRhID0geyBub2RlOiBub2RlLCBhdHRyczogeyBpZDogbm9kZS5pZCB9IH07XG5cbiAgICAgIHRoaXMuX25vZGVzLmRlbGV0ZSggaWQgKTtcblxuICAgICAgbm9kZS5pZCA9IG5ld0lEO1xuXG4gICAgICB0aGlzLl9ub2Rlcy5zZXQoIG5ld0lELCBub2RlICk7XG5cbiAgICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfVVBEX05PREUsIGV2ZW50RGF0YSApO1xuICAgIH1cbiAgfVxuXG4gIHB1YmxpYyByZW1vdmVOb2RlKCBpZDogc3RyaW5nICk6IGJvb2xlYW4ge1xuXG4gICAgbGV0IG5vZGUgPSB0aGlzLl9ub2Rlcy5nZXQoIGlkICk7XG4gICAgaWYgKCBub2RlIClcbiAgICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfREVMX05PREUsIHsgbm9kZTogbm9kZSB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fbm9kZXMuZGVsZXRlKCBpZCApO1xuICB9XG5cbiAgcHVibGljIGdldExpbmtCeUlEKCBpZDogc3RyaW5nICk6IExpbmsge1xuXG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzWyBpZCBdO1xuICB9XG5cbiAgcHVibGljIGFkZExpbmsoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM/OiB7fSApOiBMaW5rIHtcblxuICAgIGxldCBsaW5rID0gbmV3IExpbmsoIHRoaXMsIGF0dHJpYnV0ZXMgKTtcblxuICAgIGxpbmsuaWQgPSBpZDtcblxuICAgIHRoaXMuX2xpbmtzLnNldCggaWQsIGxpbmsgKTtcblxuICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfQUREX0xJTkssIHsgbGluazogbGluayB9ICk7XG5cbiAgICByZXR1cm4gbGluaztcbiAgfVxuXG4gIHB1YmxpYyByZW5hbWVMaW5rKCBpZDogc3RyaW5nLCBuZXdJRDogc3RyaW5nICkge1xuXG4gICAgbGV0IGxpbmsgPSB0aGlzLl9saW5rcy5nZXQoIGlkICk7XG5cbiAgICB0aGlzLl9saW5rcy5kZWxldGUoIGlkICk7XG5cbiAgICBsZXQgZXZlbnREYXRhID0geyBsaW5rOiBsaW5rLCBhdHRyczogeyBpZDogbGluay5pZCB9IH07XG5cbiAgICBsaW5rLmlkID0gbmV3SUQ7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX1VQRF9OT0RFLCBldmVudERhdGEgKTtcblxuICAgIHRoaXMuX2xpbmtzLnNldCggbmV3SUQsIGxpbmsgKTtcbiAgfVxuXG4gIHB1YmxpYyByZW1vdmVMaW5rKCBpZDogc3RyaW5nICk6IGJvb2xlYW4ge1xuXG4gICAgbGV0IGxpbmsgPSB0aGlzLl9saW5rcy5nZXQoIGlkICk7XG4gICAgaWYgKCBsaW5rIClcbiAgICAgIHRoaXMucHVibGlzaCggR3JhcGguRVZFTlRfREVMX0xJTkssIHsgbGluazogbGluayB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fbGlua3MuZGVsZXRlKCBpZCApO1xuICB9XG5cbiAgcHVibGljIGFkZFB1YmxpY1BvcnQoIGlkOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IHt9ICk6IFB1YmxpY1BvcnRcbiAge1xuICAgIGF0dHJpYnV0ZXNbXCJpZFwiXSA9IGlkO1xuXG4gICAgbGV0IHBvcnQgPSBuZXcgUHVibGljUG9ydCggdGhpcywgbnVsbCwgYXR0cmlidXRlcyApO1xuXG4gICAgdGhpcy5fcG9ydHMuc2V0KCBpZCwgcG9ydCApO1xuXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZUxvYWRlciB9IGZyb20gJy4vbW9kdWxlLWxvYWRlcic7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5IH0gZnJvbSAnLi9jb21wb25lbnQtZmFjdG9yeSc7XG5cbmltcG9ydCB7IENvbnRhaW5lciB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5cblxuZXhwb3J0IGNsYXNzIFNpbXVsYXRpb25FbmdpbmVcbntcbiAgbG9hZGVyOiBNb2R1bGVMb2FkZXI7XG4gIGNvbnRhaW5lcjogQ29udGFpbmVyO1xuXG4gIC8qKlxuICAqIENyZWF0ZXMgYW4gaW5zdGFuY2Ugb2YgU2ltdWxhdGlvbkVuZ2luZS5cbiAgKiBAcGFyYW0gbG9hZGVyIFRoZSBtb2R1bGUgbG9hZGVyLlxuICAqIEBwYXJhbSBjb250YWluZXIgVGhlIHJvb3QgREkgY29udGFpbmVyIGZvciB0aGUgc2ltdWxhdGlvbi5cbiAgKi9cbiAgY29uc3RydWN0b3IoIGxvYWRlcjogTW9kdWxlTG9hZGVyLCBjb250YWluZXI6IENvbnRhaW5lciApIHtcbiAgICB0aGlzLmxvYWRlciA9IGxvYWRlcjtcbiAgICB0aGlzLmNvbnRhaW5lciA9IGNvbnRhaW5lcjtcbiAgfVxuXG5cbiAgLyoqXG4gICogUmV0dXJuIGEgQ29tcG9uZW50RmFjdG9yeSBmYWNhZGVcbiAgKi9cbiAgZ2V0Q29tcG9uZW50RmFjdG9yeSgpOiBDb21wb25lbnRGYWN0b3J5IHtcbiAgICByZXR1cm4gbmV3IENvbXBvbmVudEZhY3RvcnkoIHRoaXMuY29udGFpbmVyLCB0aGlzLmxvYWRlciApO1xuICB9XG5cbn1cbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
