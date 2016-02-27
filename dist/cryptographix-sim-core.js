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



export class ByteArray {
    constructor(bytes, format, opt) {
        if (!bytes) {
            this.byteArray = new Uint8Array(0);
        }
        else if (!format || format == ByteArray.BYTES) {
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
            if (format == ByteArray.BASE64) {
                this.byteArray = Base64Codec.decode(bytes);
            }
            else if (format == ByteArray.HEX) {
                this.byteArray = HexCodec.decode(bytes);
            }
            else if (format == ByteArray.UTF8) {
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
ByteArray.BYTES = 0;
ByteArray.HEX = 1;
ByteArray.BASE64 = 2;
ByteArray.UTF8 = 3;


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
        this.index = 0;
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
    constructor(ctor, description, category) {
        this.ctor = ctor;
        ctor.componentInfo = {
            name: ctor.name,
            description: description,
            detailLink: '',
            category: category,
            author: '',
            ports: {},
            stores: {}
        };
    }
    static init(ctor, description, category) {
        let builder = new ComponentBuilder(ctor, description, category);
        return builder;
    }
    port(id, direction, opts) {
        opts = opts || {};
        this.ctor.componentInfo.ports[id] = {
            direction: direction,
            protocol: opts.protocol,
            index: opts.index,
            required: opts.required
        };
        return this;
    }
    name(name) {
        this.ctor.componentInfo.name = name;
        return this;
    }
}
class C {
}
ComponentBuilder.init(C, 'Test Component')
    .port('p1', Direction.IN);

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

export class Key {
    constructor(id, key) {
        this.id = id;
        if (key)
            this.cryptoKey = key;
        else {
            this.cryptoKey =
                {
                    type: "",
                    algorithm: "",
                    extractable: true,
                    usages: []
                };
        }
    }
    get type() {
        return this.cryptoKey.type;
    }
    get algorithm() {
        return this.cryptoKey.algorithm;
    }
    get extractable() {
        return this.cryptoKey.extractable;
    }
    get usages() {
        return this.cryptoKey.usages;
    }
    get innerKey() {
        return this.cryptoKey;
    }
}


export class PrivateKey extends Key {
}


export class PublicKey extends Key {
}

export class KeyPair {
}


export class CryptographicService {
    constructor() {
        this.crypto = window.crypto.subtle;
        if (!this.crypto && msrcrypto)
            this.crypto = msrcrypto;
    }
    decrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            this.crypto.decrypt(algorithm, key.innerKey, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    digest(algorithm, data) {
        return new Promise((resolve, reject) => {
            this.crypto.digest(algorithm, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    encrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            this.crypto.encrypt(algorithm, key.innerKey, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    exportKey(format, key) {
        return new Promise((resolve, reject) => {
            this.crypto.exportKey(format, key.innerKey)
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
            this.crypto.importKey(format, keyData.backingArray, algorithm, extractable, keyUsages)
                .then((res) => { resolve(res); })
                .catch((err) => { reject(err); });
        });
    }
    sign(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            this.crypto.sign(algorithm, key.innerKey, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    verify(algorithm, key, signature, data) {
        return new Promise((resolve, reject) => {
            this.crypto.verify(algorithm, key.innerKey, signature.backingArray, data.backingArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
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
        let me = this;
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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJraW5kL2tpbmQudHMiLCJtZXNzYWdpbmcvbWVzc2FnZS50cyIsInJ1bnRpbWUvdGFzay1zY2hlZHVsZXIudHMiLCJtZXNzYWdpbmcvY2hhbm5lbC50cyIsIm1lc3NhZ2luZy9lbmQtcG9pbnQudHMiLCJtZXNzYWdpbmcvcHJvdG9jb2wudHMiLCJjb21wb25lbnQvcG9ydC1pbmZvLnRzIiwiY29tcG9uZW50L2NvbXBvbmVudC1pbmZvLnRzIiwiY29tcG9uZW50L3N0b3JlLWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LnRzIiwiZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyLnRzIiwiZXZlbnQtaHViL2V2ZW50LWh1Yi50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMva2V5LnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9wcml2YXRlLWtleS50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvcHVibGljLWtleS50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMva2V5LXBhaXIudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL2NyeXB0b2dyYXBoaWMtc2VydmljZS50cyIsImdyYXBoL3BvcnQudHMiLCJncmFwaC9ub2RlLnRzIiwicnVudGltZS9ydW50aW1lLWNvbnRleHQudHMiLCJydW50aW1lL21vZHVsZS1sb2FkZXIudHMiLCJydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5LnRzIiwiZ3JhcGgvbGluay50cyIsImdyYXBoL25ldHdvcmsudHMiLCJncmFwaC9ncmFwaC50cyIsInJ1bnRpbWUvc2ltdWxhdGlvbi1lbmdpbmUudHMiXSwibmFtZXMiOlsiSGV4Q29kZWMiLCJIZXhDb2RlYy5kZWNvZGUiLCJCQVNFNjRTUEVDSUFMUyIsIkJhc2U2NENvZGVjIiwiQmFzZTY0Q29kZWMuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLmRlY29kZSIsIkJhc2U2NENvZGVjLmRlY29kZS5wdXNoIiwiQmFzZTY0Q29kZWMuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLmVuY29kZSIsIkJhc2U2NENvZGVjLmVuY29kZS50cmlwbGV0VG9CYXNlNjQiLCJCeXRlQXJyYXkiLCJCeXRlQXJyYXkuY29uc3RydWN0b3IiLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJFbnVtIiwiSW50ZWdlciIsIkZpZWxkQXJyYXkiLCJLaW5kSW5mbyIsIktpbmRJbmZvLmNvbnN0cnVjdG9yIiwiS2luZEJ1aWxkZXIiLCJLaW5kQnVpbGRlci5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyLmluaXQiLCJLaW5kQnVpbGRlci5maWVsZCIsIktpbmRCdWlsZGVyLmJvb2xGaWVsZCIsIktpbmRCdWlsZGVyLm51bWJlckZpZWxkIiwiS2luZEJ1aWxkZXIuaW50ZWdlckZpZWxkIiwiS2luZEJ1aWxkZXIudWludDMyRmllbGQiLCJLaW5kQnVpbGRlci5ieXRlRmllbGQiLCJLaW5kQnVpbGRlci5zdHJpbmdGaWVsZCIsIktpbmRCdWlsZGVyLmtpbmRGaWVsZCIsIktpbmRCdWlsZGVyLmVudW1GaWVsZCIsIktpbmQiLCJLaW5kLmdldEtpbmRJbmZvIiwiS2luZC5pbml0RmllbGRzIiwiTWVzc2FnZSIsIk1lc3NhZ2UuY29uc3RydWN0b3IiLCJNZXNzYWdlLmhlYWRlciIsIk1lc3NhZ2UucGF5bG9hZCIsIktpbmRNZXNzYWdlIiwiVGFza1NjaGVkdWxlciIsIlRhc2tTY2hlZHVsZXIuY29uc3RydWN0b3IiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlciIsIlRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyLnJlcXVlc3RGbHVzaCIsIlRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lciIsIlRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoLmhhbmRsZUZsdXNoVGltZXIiLCJUYXNrU2NoZWR1bGVyLnNodXRkb3duIiwiVGFza1NjaGVkdWxlci5xdWV1ZVRhc2siLCJUYXNrU2NoZWR1bGVyLmZsdXNoVGFza1F1ZXVlIiwiVGFza1NjaGVkdWxlci5vbkVycm9yIiwiQ2hhbm5lbCIsIkNoYW5uZWwuY29uc3RydWN0b3IiLCJDaGFubmVsLnNodXRkb3duIiwiQ2hhbm5lbC5hY3RpdmUiLCJDaGFubmVsLmFjdGl2YXRlIiwiQ2hhbm5lbC5kZWFjdGl2YXRlIiwiQ2hhbm5lbC5hZGRFbmRQb2ludCIsIkNoYW5uZWwucmVtb3ZlRW5kUG9pbnQiLCJDaGFubmVsLmVuZFBvaW50cyIsIkNoYW5uZWwuc2VuZE1lc3NhZ2UiLCJEaXJlY3Rpb24iLCJFbmRQb2ludCIsIkVuZFBvaW50LmNvbnN0cnVjdG9yIiwiRW5kUG9pbnQuc2h1dGRvd24iLCJFbmRQb2ludC5pZCIsIkVuZFBvaW50LmF0dGFjaCIsIkVuZFBvaW50LmRldGFjaCIsIkVuZFBvaW50LmRldGFjaEFsbCIsIkVuZFBvaW50LmF0dGFjaGVkIiwiRW5kUG9pbnQuZGlyZWN0aW9uIiwiRW5kUG9pbnQuaGFuZGxlTWVzc2FnZSIsIkVuZFBvaW50LnNlbmRNZXNzYWdlIiwiRW5kUG9pbnQub25NZXNzYWdlIiwiUHJvdG9jb2xUeXBlQml0cyIsIlByb3RvY29sIiwiQ2xpZW50U2VydmVyUHJvdG9jb2wiLCJBUERVIiwiQVBEVU1lc3NhZ2UiLCJBUERVUHJvdG9jb2wiLCJQb3J0SW5mbyIsIlBvcnRJbmZvLmNvbnN0cnVjdG9yIiwiQ29tcG9uZW50SW5mbyIsIkNvbXBvbmVudEluZm8uY29uc3RydWN0b3IiLCJTdG9yZUluZm8iLCJDb21wb25lbnRCdWlsZGVyIiwiQ29tcG9uZW50QnVpbGRlci5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEJ1aWxkZXIuaW5pdCIsIkNvbXBvbmVudEJ1aWxkZXIucG9ydCIsIkNvbXBvbmVudEJ1aWxkZXIubmFtZSIsIkMiLCJFdmVudEh1YiIsIkV2ZW50SHViLmNvbnN0cnVjdG9yIiwiRXZlbnRIdWIucHVibGlzaCIsIkV2ZW50SHViLnN1YnNjcmliZSIsIkV2ZW50SHViLnN1YnNjcmliZU9uY2UiLCJLZXkiLCJLZXkuY29uc3RydWN0b3IiLCJLZXkudHlwZSIsIktleS5hbGdvcml0aG0iLCJLZXkuZXh0cmFjdGFibGUiLCJLZXkudXNhZ2VzIiwiS2V5LmlubmVyS2V5IiwiUHJpdmF0ZUtleSIsIlB1YmxpY0tleSIsIktleVBhaXIiLCJDcnlwdG9ncmFwaGljU2VydmljZSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlLmNvbnN0cnVjdG9yIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZGVjcnlwdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlLmRpZ2VzdCIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlLmVuY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZS5leHBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZS5nZW5lcmF0ZUtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlLmltcG9ydEtleSIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlLnNpZ24iLCJDcnlwdG9ncmFwaGljU2VydmljZS52ZXJpZnkiLCJQb3J0IiwiUG9ydC5jb25zdHJ1Y3RvciIsIlBvcnQuZW5kUG9pbnQiLCJQb3J0LnRvT2JqZWN0IiwiUG9ydC5vd25lciIsIlBvcnQucHJvdG9jb2xJRCIsIlBvcnQuaWQiLCJQb3J0LmRpcmVjdGlvbiIsIlB1YmxpY1BvcnQiLCJQdWJsaWNQb3J0LmNvbnN0cnVjdG9yIiwiUHVibGljUG9ydC5jb25uZWN0UHJpdmF0ZSIsIlB1YmxpY1BvcnQuZGlzY29ubmVjdFByaXZhdGUiLCJQdWJsaWNQb3J0LnRvT2JqZWN0IiwiTm9kZSIsIk5vZGUuY29uc3RydWN0b3IiLCJOb2RlLnRvT2JqZWN0IiwiTm9kZS5vd25lciIsIk5vZGUuaWQiLCJOb2RlLnVwZGF0ZVBvcnRzIiwiTm9kZS5hZGRQbGFjZWhvbGRlclBvcnQiLCJOb2RlLnBvcnRzIiwiTm9kZS5nZXRQb3J0QXJyYXkiLCJOb2RlLmdldFBvcnRCeUlEIiwiTm9kZS5pZGVudGlmeVBvcnQiLCJOb2RlLnJlbW92ZVBvcnQiLCJOb2RlLmxvYWRDb21wb25lbnQiLCJOb2RlLmNvbnRleHQiLCJOb2RlLnVubG9hZENvbXBvbmVudCIsIlJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQiLCJSdW50aW1lQ29udGV4dC5jb25zdHJ1Y3RvciIsIlJ1bnRpbWVDb250ZXh0Lm5vZGUiLCJSdW50aW1lQ29udGV4dC5pbnN0YW5jZSIsIlJ1bnRpbWVDb250ZXh0LmNvbnRhaW5lciIsIlJ1bnRpbWVDb250ZXh0LmxvYWQiLCJSdW50aW1lQ29udGV4dC5ydW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LmluU3RhdGUiLCJSdW50aW1lQ29udGV4dC5zZXRSdW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnJlbGVhc2UiLCJNb2R1bGVSZWdpc3RyeUVudHJ5IiwiTW9kdWxlUmVnaXN0cnlFbnRyeS5jb25zdHJ1Y3RvciIsIlN5c3RlbU1vZHVsZUxvYWRlciIsIlN5c3RlbU1vZHVsZUxvYWRlci5jb25zdHJ1Y3RvciIsIlN5c3RlbU1vZHVsZUxvYWRlci5nZXRPckNyZWF0ZU1vZHVsZVJlZ2lzdHJ5RW50cnkiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIubG9hZE1vZHVsZSIsIkNvbXBvbmVudEZhY3RvcnkiLCJDb21wb25lbnRGYWN0b3J5LmNvbnN0cnVjdG9yIiwiQ29tcG9uZW50RmFjdG9yeS5jcmVhdGVDb250ZXh0IiwiQ29tcG9uZW50RmFjdG9yeS5nZXRDaGlsZENvbnRhaW5lciIsIkNvbXBvbmVudEZhY3RvcnkubG9hZENvbXBvbmVudCIsIkNvbXBvbmVudEZhY3RvcnkuZ2V0IiwiQ29tcG9uZW50RmFjdG9yeS5yZWdpc3RlciIsIkxpbmsiLCJMaW5rLmNvbnN0cnVjdG9yIiwiTGluay50b09iamVjdCIsIkxpbmsuaWQiLCJMaW5rLmNvbm5lY3QiLCJMaW5rLmRpc2Nvbm5lY3QiLCJMaW5rLmZyb21Ob2RlIiwiTGluay5mcm9tUG9ydCIsIkxpbmsudG9Ob2RlIiwiTGluay50b1BvcnQiLCJMaW5rLnByb3RvY29sSUQiLCJOZXR3b3JrIiwiTmV0d29yay5jb25zdHJ1Y3RvciIsIk5ldHdvcmsuZ3JhcGgiLCJOZXR3b3JrLmxvYWRDb21wb25lbnRzIiwiTmV0d29yay5pbml0aWFsaXplIiwiTmV0d29yay50ZWFyZG93biIsIk5ldHdvcmsuaW5TdGF0ZSIsIk5ldHdvcmsuc2V0UnVuU3RhdGUiLCJOZXR3b3JrLnVud2lyZUxpbmsiLCJOZXR3b3JrLndpcmVMaW5rIiwiTmV0d29yay5zdGFydCIsIk5ldHdvcmsuc3RlcCIsIk5ldHdvcmsuc3RvcCIsIk5ldHdvcmsucGF1c2UiLCJOZXR3b3JrLnJlc3VtZSIsIkdyYXBoIiwiR3JhcGguY29uc3RydWN0b3IiLCJHcmFwaC5pbml0RnJvbVN0cmluZyIsIkdyYXBoLmluaXRGcm9tT2JqZWN0IiwiR3JhcGgudG9PYmplY3QiLCJHcmFwaC5sb2FkQ29tcG9uZW50IiwiR3JhcGgubm9kZXMiLCJHcmFwaC5saW5rcyIsIkdyYXBoLmdldE5vZGVCeUlEIiwiR3JhcGguYWRkTm9kZSIsIkdyYXBoLnJlbmFtZU5vZGUiLCJHcmFwaC5yZW1vdmVOb2RlIiwiR3JhcGguZ2V0TGlua0J5SUQiLCJHcmFwaC5hZGRMaW5rIiwiR3JhcGgucmVuYW1lTGluayIsIkdyYXBoLnJlbW92ZUxpbmsiLCJHcmFwaC5hZGRQdWJsaWNQb3J0IiwiU2ltdWxhdGlvbkVuZ2luZSIsIlNpbXVsYXRpb25FbmdpbmUuY29uc3RydWN0b3IiLCJTaW11bGF0aW9uRW5naW5lLmdldENvbXBvbmVudEZhY3RvcnkiXSwibWFwcGluZ3MiOiJBQUFBO0lBSUVBLE9BQU9BLE1BQU1BLENBQUVBLENBQVNBO1FBRXRCQyxFQUFFQSxDQUFDQSxDQUFFQSxRQUFRQSxDQUFDQSxZQUFZQSxJQUFJQSxTQUFVQSxDQUFDQSxDQUN6Q0EsQ0FBQ0E7WUFDQ0EsSUFBSUEsR0FBR0EsR0FBR0Esa0JBQWtCQSxDQUFDQTtZQUM3QkEsSUFBSUEsS0FBS0EsR0FBR0EsNkJBQTZCQSxDQUFDQTtZQUMxQ0EsSUFBSUEsR0FBR0EsR0FBYUEsRUFBRUEsQ0FBQ0E7WUFDdkJBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO2dCQUN2QkEsR0FBR0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7WUFDM0JBLEdBQUdBLEdBQUdBLEdBQUdBLENBQUNBLFdBQVdBLEVBQUVBLENBQUNBO1lBQ3hCQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxFQUFFQSxFQUFFQSxDQUFDQSxHQUFHQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtnQkFDeEJBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBQzNCQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQTtnQkFDakNBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBO1lBQzlCQSxRQUFRQSxDQUFDQSxZQUFZQSxHQUFHQSxHQUFHQSxDQUFDQTtRQUM5QkEsQ0FBQ0E7UUFFREEsSUFBSUEsR0FBR0EsR0FBYUEsRUFBRUEsQ0FBQ0E7UUFDdkJBLElBQUlBLElBQUlBLEdBQUdBLENBQUNBLEVBQUVBLFVBQVVBLEdBQUdBLENBQUNBLENBQUNBO1FBQzdCQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxNQUFNQSxFQUFFQSxFQUFFQSxDQUFDQSxFQUNqQ0EsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDcEJBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEdBQUdBLENBQUNBO2dCQUNUQSxLQUFLQSxDQUFDQTtZQUNWQSxJQUFJQSxDQUFDQSxHQUFHQSxRQUFRQSxDQUFDQSxZQUFZQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ1JBLFFBQVFBLENBQUNBO1lBQ2JBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLFNBQVNBLENBQUNBO2dCQUNmQSxNQUFNQSw4QkFBOEJBLEdBQUdBLENBQUNBLENBQUNBO1lBQzdDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQTtZQUNWQSxFQUFFQSxDQUFDQSxDQUFDQSxFQUFFQSxVQUFVQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFD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QSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQTtZQUM3QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDM0lBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLEdBQUdBLFFBQVFBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO1lBQzdCQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMxQkEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUNBLFlBQVlBLEtBQUtBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQ3ZCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUMxRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbkJBLENBQUNBO1FBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUNBLFlBQVlBLEtBQUtBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQzlCQSxJQUFJQSxHQUFHQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUM5R0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7WUFDeEJBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1FBQ25CQSxDQUFDQTtRQUVEQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQTtJQUNiQSxDQUFDQTtJQUVERCxPQUFPQSxNQUFNQSxDQUFFQSxLQUFpQkE7UUFFOUJJLElBQUlBLENBQVNBLENBQUNBO1FBQ2RBLElBQUlBLFVBQVVBLEdBQUdBLEtBQUtBLENBQUNBLE1BQU1BLEdBQUdBLENBQUNBLENBQUNBO1FBQ2xDQSxJQUFJQSxNQUFNQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUVoQkEsTUFBTUEsTUFBTUEsR0FBR0Esa0VBQWtFQSxDQUFDQTtRQUNsRkEsZ0JBQWlCQSxHQUFTQTtZQUN4QkMsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0E7UUFDNUJBLENBQUNBO1FBRURELHlCQUEwQkEsR0FBV0E7WUFDbkNFLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1FBQzVHQSxDQUFDQTtRQUdERixJQUFJQSxNQUFNQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxVQUFVQSxDQUFDQTtRQUN2Q0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsTUFBTUEsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7WUFDL0JBLElBQUlBLElBQUlBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQ25FQSxNQUFNQSxJQUFJQSxlQUFlQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNsQ0EsQ0FBQ0E7UUFHREEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsVUFBVUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDbkJBLEtBQUtBLENBQUNBO2dCQUNKQSxJQUFJQSxJQUFJQSxHQUFHQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDbkNBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUM1QkEsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFB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Q0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsS0FBS0EsQ0FBRUEsQ0FBQ0EsRUFBRUEsR0FBR0EsQ0FBRUEsQ0FBQ0E7UUFDbERBLENBQUNBO1FBQ0RBLElBQUlBLENBQ0pBLENBQUNBO1lBQ0NBLElBQUlBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1lBQ3pCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtZQUN2Q0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDL0JBLENBQUNBO0lBQ0hBLENBQUNBO0lBRURGLElBQUlBLFlBQVlBO1FBRWRHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO0lBQ3hCQSxDQUFDQTtJQUVESCxNQUFNQSxDQUFFQSxLQUFnQkE7UUFFdEJJLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO1FBQ3hCQSxJQUFJQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtRQUMxQkEsSUFBSUEsRUFBRUEsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBQ0EsTUFBTUEsSUFBSUEsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFFckNBLEVBQUVBLENBQUNBLENBQUVBLEVBQUdBLENBQUNBLENBQ1RBLENBQUNBO1lBQ0NBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBLE1BQU1BLEVBQUVBLEVBQUVBLENBQUNBO2dCQUNoQ0EsRUFBRUEsR0FBR0EsRUFBRUEsSUFBSUEsQ0FBRUEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDbkNBLENBQUNBO1FBRURBLE1BQU1BLENB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Q0FBR0EsQ0FBQ0E7b0JBQ3JCQSxHQUFHQSxHQUFHQSxVQUFVQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtnQkFDekJBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLEtBQUtBLENBQUNBLE9BQU9BLElBQUlBLFNBQVVBLENBQUNBO29CQUNwQ0EsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBQ3RCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxNQUFPQSxDQUFDQTtvQkFDN0JBLEdBQUdBLEdBQUdBLEVBQUVBLENBQUNBO2dCQUNYQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxNQUFPQSxDQUFDQTtvQkFDN0JBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBO2dCQUNWQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxPQUFRQSxDQUFDQTtvQkFDOUJBLEdBQUdBLEdBQUdBLEtBQUtBLENBQUNBLE9BQU9BLElBQUlBLENBQUNBLENBQUNBO2dCQUMzQkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsSUFBSUEsT0FBUUEsQ0FBQ0E7b0JBQzlCQSxHQUFHQSxHQUFHQSxLQUFLQSxDQUFDQTtnQkFDZEEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsU0FBU0EsSUFBSUEsU0FBVUEsQ0FBQ0E7b0JBQ2hDQSxHQUFHQSxHQUFHQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQTtnQkFDeEJBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLFNBQVNBLElBQUlBLElBQUtBLENBQUNBO29CQUMzQkEsR0FBR0EsR0FBR0EsS0FBS0EsQ0FBQ0EsT0FBT0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQzlCQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxTQUFTQSxJQUFJQSxJQUFLQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFDN0JB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QUFDQSxDQUFDQTtJQUNKQSxDQUFDQTtJQUVEUCxJQUFJQSxDQUFDQSxTQUE2QkEsRUFBRUEsR0FBUUEsRUFBRUEsSUFBZUE7UUFDM0RRLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxHQUFHQSxDQUFDQSxRQUFRQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFDQTtpQkFDekRBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE9BQU9BLENBQUNBLElBQUlBLFNBQVNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2lCQUMvQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDdENBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBR0RSLE1BQU1BLENBQUNBLFNBQTZCQSxFQUFFQSxHQUFRQSxFQUFFQSxTQUFvQkEsRUFBRUEsSUFBZUE7UUFDbkZTLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxTQUFTQSxFQUFFQSxHQUFHQSxDQUFDQSxRQUFRQSxFQUFFQSxTQUFTQSxDQUFDQSxZQUFZQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFDQTtpQkFDbkZBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE9BQU9BLENBQUNBLElBQUlBLFNBQVNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2lCQUMvQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FB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QUFFQSxDQUFDQTtZQUVmQSxFQUFFQSxDQUFDQSxDQUFFQSxZQUFZQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDN0JBLElBQUlBLElBQUlBLEdBQUdBLFlBQVlBLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO2dCQUVsQ0EsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsRUFBRUEsQ0FBQ0E7Z0JBRW5CQSxRQUFRQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtnQkFFekJBLFlBQVlBLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1lBQzVCQSxDQUFDQTtZQUNEQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFFSkEsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsSUFBSUEsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsRUFBRUEsU0FBU0EsRUFBRUEsRUFBRUEsQ0FBQ0EsU0FBU0EsRUFBRUEsQ0FBRUEsQ0FBQ0E7Z0JBRXJFQSxRQUFRQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtZQUMzQkEsQ0FBQ0E7UUFDSEEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFFSEEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsUUFBUUEsQ0FBQ0E7SUFDekJBLENBQUNBO0lBTVNMLGtCQUFrQkEsQ0FBRUEsRUFBVUEsRUFBRUEsVUFBY0E7UUFFdERNLFVBQVVBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLEVBQUVBLENBQUNBO1FBRXRCQSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUU5Q0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBT0ROLElBQUlBLEtBQUtBO1FBRVBPLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBO0lBQ3JCQSxDQUFDQTtJQUVEUCxZQUFZQTtRQUNWUSxJQUFJQSxNQUFNQSxHQUFXQSxFQUFFQSxDQUFDQTtRQUV4QkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUE7WUFDN0JBLE1BQU1BLENBQUNBLElBQUlBLENBQUVBLElBQUlBLENBQUVBLENBQUNBO1FBQ3RCQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUVKQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUNoQkEsQ0FBQ0E7SUFRRFIsV0FBV0EsQ0FBRUEsRUFBVUE7UUFFckJTLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQy9CQSxDQUFDQTtJQUVEVCxZQUFZQSxDQUFFQSxFQUFVQSxFQUFFQSxVQUFtQkE7UUFFM0NVLElBQUlBLElBQVVBLENBQUNBO1FBRWZBLEVBQUVBLENBQUNBLENBQUVBLEVBQUdBLENBQUNBO1lBQ1BBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBQy9CQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxVQUFXQSxDQUFDQSxDQUN0QkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsQ0FBQ0EsRUFBRUEsRUFBRUE7Z0JBQzFCQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxDQUFDQSxVQUFVQSxJQUFJQSxVQUFXQSxDQUFDQTtvQkFDL0JBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBO1lBQ2JBLENBQUNBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO1FBQ1pBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBUURWLFVBQVVBLENBQUVBLEVBQVVBO1FBRXBCVyxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUNsQ0EsQ0FBQ0E7SUFFRFgsYUFBYUEsQ0FBRUEsT0FBeUJBO1FBQ3RDWSxJQUFJQSxDQUFDQSxlQUFlQSxFQUFFQSxDQUFDQTtRQUd2QkEsSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsT0FBT0EsQ0FBQ0EsYUFBYUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsVUFBVUEsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsQ0FBQ0E7UUFHdEZBLEdBQUdBLENBQUNBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBO1FBRWhCQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUdkQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQTtJQUNwQkEsQ0FBQ0E7SUFFRFosSUFBV0EsT0FBT0E7UUFDaEJhLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBO0lBQ3ZCQSxDQUFDQTtJQUVEYixlQUFlQTtRQUViYyxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFTQSxDQUFDQSxDQUNwQkEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsT0FBT0EsRUFBRUEsQ0FBQ0E7WUFFeEJBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBO1FBQ3ZCQSxDQUFDQTtJQUNIQSxDQUFDQTtBQUVIZCxDQUFDQTtBQUFBO09DN05NLEVBQUUsSUFBSSxFQUFFLE1BQU0sZUFBZTtBQU9wQyxXQUFZLFFBT1g7QUFQRCxXQUFZLFFBQVE7SUFDbEJlLDZDQUFPQSxDQUFBQTtJQUNQQSw2Q0FBT0EsQ0FBQUE7SUFDUEEsMkNBQU1BLENBQUFBO0lBQ05BLHlDQUFLQSxDQUFBQTtJQUNMQSw2Q0FBT0EsQ0FBQUE7SUFDUEEsMkNBQU1BLENBQUFBO0FBQ1JBLENBQUNBLEVBUFcsUUFBUSxLQUFSLFFBQVEsUUFPbkI7QUFLRDtJQW9DRUMsWUFBYUEsT0FBeUJBLEVBQUVBLFNBQW9CQSxFQUFFQSxFQUFVQSxFQUFFQSxNQUFVQSxFQUFFQSxJQUFJQSxHQUFpQkEsRUFBRUE7UUE4RDdHQyxjQUFTQSxHQUFhQSxRQUFRQSxDQUFDQSxPQUFPQSxDQUFDQTtRQTVEckNBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLE9BQU9BLENBQUNBO1FBRXhCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUVkQSxJQUFJQSxDQUFDQSxPQUFPQSxHQUFHQSxNQUFNQSxDQUFDQTtRQUV0QkEsSUFBSUEsQ0FBQ0EsVUFBVUEsR0FBR0EsU0FBU0EsQ0FBQ0E7UUFHNUJBLEdBQUdBLENBQUFBLENBQUVBLEdBQUdBLENBQUNBLENBQUNBLElBQUlBLElBQUtBLENBQUNBLENBQ3BCQSxDQUFDQTtZQUNDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFHQSxDQUFDQTtnQkFDNUNBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLGlCQUFpQkEsQ0FBRUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7UUFDMURBLENBQUNBO0lBQ0hBLENBQUNBO0lBRURELElBQUlBLElBQUlBO1FBQ05FLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBO0lBQ3BCQSxDQUFDQTtJQUNERixJQUFJQSxJQUFJQSxDQUFFQSxJQUFVQTtRQUNsQkUsSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsSUFBSUEsQ0FBQ0E7UUFHbEJBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLGdCQUFnQkEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDakRBLENBQUNBO0lBRURGLElBQUlBLFFBQVFBO1FBQ1ZHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFNBQVNBLENBQUNBO0lBQ3hCQSxDQUFDQTtJQUVESCxJQUFJQSxTQUFTQTtRQUNYSSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtJQUN6QkEsQ0FBQ0E7SUFFREosSUFBSUE7UUFFRkssSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0E7UUFFZEEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsSUFBSUEsQ0FBQ0E7UUFFdEJBLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVFBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBRXhDQSxFQUFFQSxDQUFDQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQSxPQUFPQSxDQUFDQTtZQUNoQ0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsQ0FBQ0EsR0FBR0EsQ0FBRUE7aUJBQzFDQSxJQUFJQSxDQUFFQSxDQUFDQSxRQUFRQTtnQkFFZEEsRUFBRUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7Z0JBQ3hCQSxFQUFFQSxDQUFDQSxXQUFXQSxDQUFFQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtnQkFFbENBLE9BQU9BLEVBQUVBLENBQUNBO1lBQ1pBLENBQUNBLENBQUNBO2lCQUNEQSxLQUFLQSxDQUFFQSxDQUFDQSxHQUFHQTtnQkFFVkEsRUFBRUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBQ0E7Z0JBRWhDQSxNQUFNQSxDQUFFQSxHQUFHQSxDQUFFQSxDQUFDQTtZQUNoQkEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDUEEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7SUFDTkEsQ0FBQ0E7SUFHREwsSUFBSUEsUUFBUUE7UUFDVk0sTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRU9OLE9BQU9BLENBQUVBLE1BQWtCQTtRQUNqQ08sTUFBTUEsQ0FBQ0EsSUFBSUEsR0FBR0EsQ0FBWUEsTUFBTUEsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBRUEsQ0FBQ0E7SUFDM0RBLENBQUNBO0lBZURQLFdBQVdBLENBQUVBLFFBQWtCQTtRQUM3QlEsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0E7UUFFekJBLE1BQU1BLENBQUFBLENBQUVBLFFBQVNBLENBQUNBLENBQ2xCQSxDQUFDQTtZQUNDQSxLQUFLQSxRQUFRQSxDQUFDQSxNQUFNQTtnQkFDbEJBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLFFBQVFBLENBQUNBLE9BQU9BLEVBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUU1RUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsUUFBU0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO3dCQUNDQSxJQUFJQSxDQUFDQSxRQUFRQSxFQUFFQSxDQUFDQTt3QkFHaEJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBO29CQUN4QkEsQ0FBQ0E7Z0JBQ0hBLENBQUNBO2dCQUNEQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxRQUFRQSxDQUFDQSxLQUFLQTtnQkFDakJBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUcxQ0EsSUFBSUEsU0FBU0EsR0FBZUEsRUFBRUEsQ0FBQ0E7b0JBRS9CQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxVQUFXQSxDQUFDQTt3QkFDcEJBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLFVBQVVBLENBQVFBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBO29CQUU3REEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBTUEsQ0FBQ0E7d0JBQ2ZBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLFdBQVdBLENBQUVBLFNBQVNBLENBQUVBLENBQUNBO2dCQUN4Q0EsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE9BQU9BLEVBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUVqRUEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsSUFBS0EsQ0FBQ0E7d0JBQ2RBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBO2dCQUN6QkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBO29CQUNGQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSw2Q0FBNkNBLENBQUVBLENBQUNBO2dCQUNuRUEsS0FBS0EsQ0FBQ0E7WUFFUkEsS0FBS0EsUUFBUUEsQ0FBQ0EsT0FBT0E7Z0JBQ25CQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFDQSxLQUFLQSxFQUFFQSxRQUFRQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFFM0RBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLEtBQU1BLENBQUNBO3dCQUNmQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxLQUFLQSxFQUFFQSxDQUFDQTtnQkFDMUJBLENBQUNBO2dCQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtvQkFFL0NBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE1BQU9BLENBQUNBO3dCQUNoQkEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsTUFBTUEsRUFBRUEsQ0FBQ0E7Z0JBQzNCQSxDQUFDQTtnQkFDREEsSUFBSUE7b0JBQ0ZBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLHdDQUF3Q0EsQ0FBRUEsQ0FBQ0E7Z0JBQzlEQSxLQUFLQSxDQUFDQTtZQUVSQSxLQUFLQSxRQUFRQSxDQUFDQSxNQUFNQTtnQkFDbEJBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE9BQU9BLENBQUNBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUMxQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBTUEsQ0FBQ0E7d0JBQ2ZBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLENBQUNBO2dCQUMxQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO2dCQUVqREEsQ0FBQ0E7Z0JBQ0RBLElBQUlBO29CQUNGQSxNQUFNQSxJQUFJQSxLQUFLQSxDQUFFQSw0QkFBNEJBLENBQUVBLENBQUNBO2dCQUNsREEsS0FBS0EsQ0FBQ0E7UUFDVkEsQ0FBQ0E7UUFFREEsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBRURSLE9BQU9BO1FBRUxTLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLENBQUNBO1FBRXRCQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFBQTtJQUN0QkEsQ0FBQ0E7QUFDSFQsQ0FBQ0E7QUFBQTtBQ2hOQSxDQUFDO0FBR0Y7SUFDRVUsWUFBYUEsT0FBZUE7SUFFNUJDLENBQUNBO0FBQ0hELENBQUNBO0FBRUQ7SUFJRUU7UUFDRUMsSUFBSUEsQ0FBQ0EsY0FBY0EsR0FBR0EsSUFBSUEsR0FBR0EsRUFBK0JBLENBQUNBO0lBQy9EQSxDQUFDQTtJQUVPRCw4QkFBOEJBLENBQUNBLE9BQWVBO1FBQ3BERSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxjQUFjQSxDQUFDQSxPQUFPQSxDQUFDQSxJQUFJQSxDQUFDQSxJQUFJQSxDQUFDQSxjQUFjQSxDQUFDQSxPQUFPQSxDQUFDQSxHQUFHQSxJQUFJQSxtQkFBbUJBLENBQUNBLE9BQU9BLENBQUNBLENBQUNBLENBQUNBO0lBQzNHQSxDQUFDQTtJQUVERixVQUFVQSxDQUFFQSxFQUFVQTtRQUNwQkcsSUFBSUEsS0FBS0EsR0FBR0EsTUFBTUEsQ0FBQ0EsYUFBYUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBQ0E7UUFDckNBLElBQUlBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLGNBQWNBLENBQUNBLEtBQUtBLENBQUNBLENBQUNBO1FBRTFDQSxFQUFFQSxDQUFDQSxDQUFDQSxRQUFRQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNiQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFDQSxRQUFRQSxDQUFDQSxDQUFDQTtRQUNuQ0EsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7WUFDaENBLElBQUlBLENBQUNBLGNBQWNBLENBQUNBLEtBQUtBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBQy9CQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUNYQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtBQUVISCxDQUFDQTtBQUFBO09DM0NNLEVBQUUsY0FBYyxFQUFFLE1BQU0sbUJBQW1CO09BRzNDLEVBQUUsU0FBUyxFQUFjLE1BQU0sbUNBQW1DO0FBR3pFO0lBS0VJLFlBQWFBLFNBQXFCQSxFQUFFQSxNQUFxQkE7UUFDdkRDLElBQUlBLENBQUNBLE9BQU9BLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3RCQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxTQUFTQSxJQUFJQSxJQUFJQSxTQUFTQSxFQUFFQSxDQUFDQTtRQUMvQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsSUFBSUEsR0FBR0EsRUFBZ0NBLENBQUNBO1FBRTNEQSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFDQSxHQUFHQSxDQUFFQSxTQUFTQSxFQUFFQSxNQUFNQSxDQUFFQSxDQUFDQTtRQUMxQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDckNBLENBQUNBO0lBRURELGFBQWFBLENBQUVBLEVBQVVBLEVBQUVBLE1BQVVBLEVBQUVBLElBQUlBLEdBQWlCQSxFQUFFQTtRQUU1REUsSUFBSUEsY0FBY0EsR0FBY0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsV0FBV0EsRUFBRUEsQ0FBQ0E7UUFFOURBLE1BQU1BLENBQUNBLElBQUlBLGNBQWNBLENBQUVBLElBQUlBLEVBQUVBLGNBQWNBLEVBQUVBLEVBQUVBLEVBQUVBLE1BQU1BLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO0lBQ3RFQSxDQUFDQTtJQUVERixpQkFBaUJBO1FBQ2ZHLE1BQU1BLENBQUVBO0lBQ1ZBLENBQUNBO0lBRURILGFBQWFBLENBQUVBLEdBQW1CQSxFQUFFQSxFQUFVQTtRQUU1Q0ksSUFBSUEsZUFBZUEsR0FBR0EsVUFBVUEsSUFBMEJBO1lBRXhELElBQUksV0FBVyxHQUFjLEdBQUcsQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFFLElBQUksQ0FBRSxDQUFDO1lBRTFELE1BQU0sQ0FBQyxXQUFXLENBQUM7UUFDckIsQ0FBQyxDQUFBQTtRQUVEQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUVkQSxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFhQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUU3Q0EsSUFBSUEsSUFBSUEsR0FBeUJBLElBQUlBLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1lBRWhEQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFFWEEsT0FBT0EsQ0FBRUEsZUFBZUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7WUFDckNBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQVFBLENBQUNBLENBQUNBLENBQUNBO2dCQUV4QkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsRUFBRUEsQ0FBRUE7cUJBQzFCQSxJQUFJQSxDQUFFQSxDQUFFQSxJQUEwQkE7b0JBR2pDQSxFQUFFQSxDQUFDQSxXQUFXQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtvQkFHL0JBLE9BQU9BLENBQUVBLGVBQWVBLENBQUVBLElBQUlBLENBQUVBLENBQUVBLENBQUNBO2dCQUNyQ0EsQ0FBQ0EsQ0FBQ0E7cUJBQ0RBLEtBQUtBLENBQUVBLENBQUVBLENBQUNBO29CQUNUQSxNQUFNQSxDQUFFQSw4Q0FBOENBLEdBQUdBLEVBQUVBLEdBQUdBLE1BQU1BLEdBQUdBLENBQUNBLENBQUVBLENBQUNBO2dCQUM3RUEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDUkEsQ0FBQ0E7WUFDREEsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBRUpBLE1BQU1BLENBQUVBLCtCQUErQkEsR0FBR0EsRUFBRUEsR0FBR0EsNENBQTRDQSxDQUFFQSxDQUFDQTtZQUNoR0EsQ0FBQ0E7UUFDSEEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFFREosR0FBR0EsQ0FBRUEsRUFBVUE7UUFDYkssTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDcENBLENBQUNBO0lBQ0RMLFFBQVFBLENBQUVBLEVBQVVBLEVBQUVBLElBQTBCQTtRQUM5Q00sSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDbkNBLENBQUNBO0FBQ0hOLENBQUNBO0FBQUE7QUN0RUQ7SUFZRU8sWUFBYUEsS0FBWUEsRUFBRUEsVUFBVUEsR0FBUUEsRUFBRUE7UUFFN0NDLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBO1FBQ3BCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxVQUFVQSxDQUFDQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFDQTtRQUUvQkEsSUFBSUEsQ0FBQ0EsS0FBS0EsR0FBR0EsVUFBVUEsQ0FBRUEsTUFBTUEsQ0FBRUEsQ0FBQ0E7UUFDbENBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLFVBQVVBLENBQUVBLElBQUlBLENBQUVBLENBQUNBO1FBQzlCQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxVQUFVQSxDQUFFQSxVQUFVQSxDQUFFQSxJQUFJQSxLQUFLQSxDQUFDQTtRQUVyREEsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsVUFBVUEsQ0FBQ0EsUUFBUUEsSUFBSUEsRUFBRUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7SUFDNURBLENBQUNBO0lBRURELFFBQVFBLENBQUVBLElBQVVBO1FBRWxCRSxJQUFJQSxJQUFJQSxHQUFHQTtZQUNUQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxHQUFHQTtZQUNaQSxRQUFRQSxFQUFFQSxDQUFFQSxJQUFJQSxDQUFDQSxXQUFXQSxJQUFJQSxLQUFLQSxDQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxTQUFTQTtZQUN0RUEsUUFBUUEsRUFBRUEsSUFBSUEsQ0FBQ0EsUUFBUUE7WUFDdkJBLElBQUlBLEVBQUVBLElBQUlBLENBQUNBLEtBQUtBO1lBQ2hCQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxHQUFHQTtTQUNiQSxDQUFDQTtRQUVGQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVERixJQUFJQSxFQUFFQSxDQUFFQSxFQUFVQTtRQUVoQkcsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0EsRUFBRUEsQ0FBQ0E7SUFDaEJBLENBQUNBO0lBRURILE9BQU9BLENBQUVBLE9BQWdCQTtRQUd2QkksSUFBSUEsUUFBUUEsR0FBU0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsQ0FBQ0E7UUFHdkZBLElBQUlBLE1BQU1BLEdBQVNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLENBQUNBO1FBRWpGQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtRQUV4QkEsUUFBUUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsT0FBT0EsQ0FBRUEsQ0FBQ0E7UUFDcENBLE1BQU1BLENBQUNBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLE9BQU9BLENBQUVBLENBQUNBO0lBQ3BDQSxDQUFDQTtJQUVESixVQUFVQTtRQUVSSyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQTtRQUV6QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBS0EsQ0FBQ0EsQ0FDWEEsQ0FBQ0E7WUFDQ0EsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUE7Z0JBQ3pDQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFFQSxDQUFDQTtZQUNuQ0EsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFFSkEsSUFBSUEsQ0FBQ0EsUUFBUUEsR0FBR0EsU0FBU0EsQ0FBQ0E7UUFDNUJBLENBQUNBO1FBRURBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRURMLElBQUlBLFFBQVFBO1FBRVZNLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLFdBQVdBLENBQUVBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBO0lBQ3REQSxDQUFDQTtJQUVETixJQUFJQSxRQUFRQTtRQUVWTyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQTtRQUV6QkEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsR0FBR0EsU0FBU0EsQ0FBQ0E7SUFDdkZBLENBQUNBO0lBRURQLElBQUlBLFFBQVFBLENBQUVBLElBQVVBO1FBRXRCTyxJQUFJQSxDQUFDQSxLQUFLQSxHQUFHQTtZQUNYQSxNQUFNQSxFQUFFQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQSxFQUFFQTtZQUNyQkEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsRUFBRUE7U0FDaEJBLENBQUNBO1FBRUZBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO0lBQ3JDQSxDQUFDQTtJQUVEUCxJQUFJQSxNQUFNQTtRQUVSUSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUNwREEsQ0FBQ0E7SUFFRFIsSUFBSUEsTUFBTUE7UUFFUlMsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7UUFFdkJBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLFlBQVlBLENBQUVBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLEdBQUdBLFNBQVNBLENBQUNBO0lBQ3JGQSxDQUFDQTtJQUVEVCxJQUFJQSxNQUFNQSxDQUFFQSxJQUFVQTtRQUVwQlMsSUFBSUEsQ0FBQ0EsR0FBR0EsR0FBR0E7WUFDVEEsTUFBTUEsRUFBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0EsRUFBRUE7WUFDckJBLE1BQU1BLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBO1NBQ2hCQSxDQUFDQTtRQUVGQSxJQUFJQSxDQUFDQSxXQUFXQSxHQUFHQSxJQUFJQSxDQUFDQSxVQUFVQSxDQUFDQTtJQUNyQ0EsQ0FBQ0E7SUFFRFQsSUFBSUEsVUFBVUE7UUFFWlUsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBQ0E7SUFDMUJBLENBQUNBO0FBQ0hWLENBQUNBO0FBQUE7T0NqSU0sRUFBRSxRQUFRLEVBQUUsTUFBTSx3QkFBd0I7T0FFMUMsRUFBa0IsUUFBUSxFQUFFLE1BQU0sNEJBQTRCO09BRTlELEVBQUUsT0FBTyxFQUFFLE1BQU0sc0JBQXNCO09BRXZDLEVBQUUsS0FBSyxFQUFFLE1BQU0sU0FBUztBQUsvQiw2QkFBNkIsUUFBUTtJQVNuQ1csWUFBYUEsT0FBeUJBLEVBQUVBLEtBQWFBO1FBRW5EQyxPQUFPQSxDQUFDQTtRQUVSQSxJQUFJQSxDQUFDQSxRQUFRQSxHQUFHQSxPQUFPQSxDQUFDQTtRQUN4QkEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsS0FBS0EsSUFBSUEsSUFBSUEsS0FBS0EsQ0FBRUEsSUFBSUEsRUFBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFN0NBLElBQUlBLEVBQUVBLEdBQUdBLElBQUlBLENBQUNBO1FBQ2RBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLFNBQVNBLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLENBQUVBLElBQW9CQTtZQUNqRUEsSUFBSUEsUUFBUUEsR0FBYUEsRUFBRUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsUUFBUUEsQ0FBQ0E7WUFFcERBLEVBQUVBLENBQUNBLENBQUVBLFFBQVFBLElBQUlBLFFBQVFBLENBQUNBLE9BQVFBLENBQUNBLENBQ25DQSxDQUFDQTtnQkFDQ0EsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0E7Z0JBRXBCQSxJQUFJQSxDQUFDQSxhQUFhQSxDQUFFQSxFQUFFQSxDQUFDQSxRQUFRQSxDQUFFQTtxQkFDOUJBLElBQUlBLENBQUVBO29CQUNMQSxFQUFFQSxDQUFDQSxDQUFFQSxPQUFPQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxRQUFRQSxDQUFDQSxPQUFPQSxFQUFFQSxRQUFRQSxDQUFDQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFDQSxLQUFLQSxDQUFFQSxFQUFFQSxRQUFRQSxDQUFHQSxDQUFDQTt3QkFDdkZBLE9BQU9BLENBQUNBLFdBQVdBLENBQUVBLElBQUlBLEVBQUVBLFFBQVFBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBO29CQUU5Q0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsRUFBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsUUFBUUEsQ0FBR0EsQ0FBQ0E7d0JBQ3ZFQSxPQUFPQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQTtvQkFFeENBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLE9BQU9BLENBQUNBLGtCQUFrQkEsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7Z0JBQzdEQSxDQUFDQSxDQUFDQSxDQUFBQTtZQUNOQSxDQUFDQTtRQUNIQSxDQUFDQSxDQUFFQSxDQUFDQTtJQUNOQSxDQUFDQTtJQUVERCxJQUFJQSxLQUFLQTtRQUNQRSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQTtJQUNyQkEsQ0FBQ0E7SUFLREYsY0FBY0E7UUFFWkcsSUFBSUEsRUFBRUEsR0FBR0EsSUFBSUEsQ0FBQ0E7UUFFZEEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsT0FBT0EsQ0FBQ0Esa0JBQWtCQSxFQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxRQUFRQSxDQUFDQSxPQUFPQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV4RUEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsYUFBYUEsQ0FBRUEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBRUEsQ0FBQ0EsSUFBSUEsQ0FBRUE7WUFDdERBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLE9BQU9BLENBQUNBLGtCQUFrQkEsRUFBRUEsRUFBRUEsS0FBS0EsRUFBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDekVBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBRURILFVBQVVBO1FBQ1JJLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLFFBQVFBLENBQUNBLEtBQUtBLENBQUVBLENBQUNBO0lBQ3JDQSxDQUFDQTtJQUVESixRQUFRQTtRQUNOSyxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUN0Q0EsQ0FBQ0E7SUFFREwsT0FBT0EsT0FBT0EsQ0FBRUEsTUFBa0JBLEVBQUVBLFFBQWtCQTtRQUNwRE0sTUFBTUEsQ0FBQ0EsSUFBSUEsR0FBR0EsQ0FBWUEsTUFBTUEsQ0FBRUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0E7SUFDckRBLENBQUNBO0lBUUROLE9BQWVBLFdBQVdBLENBQUVBLElBQVVBLEVBQUVBLFFBQWtCQTtRQUV4RE8sSUFBSUEsR0FBR0EsR0FBR0EsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBQ0E7UUFDdkJBLElBQUlBLFlBQVlBLEdBQUdBLEdBQUdBLENBQUNBLFFBQVFBLENBQUNBO1FBRWhDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxZQUFZQSxLQUFNQSxDQUFDQSxDQUM1QkEsQ0FBQ0E7WUFJQ0EsSUFBSUEsS0FBS0EsR0FBc0JBLElBQUlBLENBQUNBLEtBQUtBLENBQUNBO1lBRTFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFFQSxRQUFRQSxJQUFJQSxRQUFRQSxDQUFDQSxNQUFNQSxDQUFFQSxJQUFJQSxDQUFFQSxZQUFZQSxJQUFJQSxRQUFRQSxDQUFDQSxLQUFLQSxDQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFFNUVBLElBQUlBLEtBQUtBLEdBQXNCQSxJQUFJQSxDQUFDQSxLQUFLQSxDQUFDQTtnQkFHMUNBLEtBQUtBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLElBQUlBO29CQUVuQkEsT0FBT0EsQ0FBQ0EsVUFBVUEsQ0FBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7Z0JBQzdCQSxDQUFDQSxDQUFFQSxDQUFDQTtZQUNOQSxDQUFDQTtZQUdEQSxLQUFLQSxDQUFDQSxPQUFPQSxDQUFFQSxVQUFVQSxPQUFPQTtnQkFFOUIsT0FBTyxDQUFDLFdBQVcsQ0FBRSxPQUFPLEVBQUUsUUFBUSxDQUFFLENBQUM7WUFDM0MsQ0FBQyxDQUFFQSxDQUFDQTtZQUdKQSxHQUFHQSxDQUFDQSxXQUFXQSxDQUFFQSxRQUFRQSxDQUFFQSxDQUFDQTtZQUk1QkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsQ0FBRUEsUUFBUUEsSUFBSUEsUUFBUUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsSUFBSUEsQ0FBRUEsWUFBWUEsSUFBSUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRzVFQSxJQUFJQSxLQUFLQSxHQUFzQkEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBQ0E7Z0JBSTFDQSxLQUFLQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxJQUFJQTtvQkFFbkJBLE9BQU9BLENBQUNBLFFBQVFBLENBQUVBLElBQUlBLENBQUVBLENBQUNBO2dCQUMzQkEsQ0FBQ0EsQ0FBRUEsQ0FBQ0E7WUFDTkEsQ0FBQ0E7UUFDSEEsQ0FBQ0E7UUFBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7WUFFTkEsR0FBR0EsQ0FBQ0EsV0FBV0EsQ0FBRUEsUUFBUUEsQ0FBRUEsQ0FBQ0E7UUFDOUJBLENBQUNBO0lBQ0hBLENBQUNBO0lBS0RQLE9BQWVBLFVBQVVBLENBQUVBLElBQVVBO1FBR25DUSxJQUFJQSxRQUFRQSxHQUFHQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQTtRQUM3QkEsSUFBSUEsTUFBTUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7UUFFekJBLElBQUlBLElBQUlBLEdBQVlBLElBQUlBLENBQUNBLFVBQVVBLEVBQUVBLENBQUNBO1FBRXRDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQTtZQUNUQSxJQUFJQSxDQUFDQSxVQUFVQSxFQUFFQSxDQUFDQTtJQUN0QkEsQ0FBQ0E7SUFLRFIsT0FBZUEsUUFBUUEsQ0FBRUEsSUFBVUE7UUFHakNTLElBQUlBLFFBQVFBLEdBQUdBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBO1FBQzdCQSxJQUFJQSxNQUFNQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQTtRQUl6QkEsSUFBSUEsT0FBT0EsR0FBR0EsSUFBSUEsT0FBT0EsRUFBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLE9BQU9BLENBQUVBLENBQUNBO1FBRXhCQSxPQUFPQSxDQUFDQSxRQUFRQSxFQUFFQSxDQUFDQTtJQUNyQkEsQ0FBQ0E7SUFFU1QsV0FBV0EsQ0FBRUEsUUFBa0JBO1FBRXZDTyxPQUFPQSxDQUFDQSxXQUFXQSxDQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxFQUFFQSxRQUFRQSxDQUFFQSxDQUFDQTtRQUU3Q0EsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsT0FBT0EsQ0FBQ0Esa0JBQWtCQSxFQUFFQSxFQUFFQSxLQUFLQSxFQUFFQSxRQUFRQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUNsRUEsQ0FBQ0E7SUFFRFAsS0FBS0EsQ0FBRUEsZUFBZUEsR0FBWUEsS0FBS0E7UUFDckNVLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLGVBQWVBLEdBQUdBLFFBQVFBLENBQUNBLE1BQU1BLEdBQUdBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBO0lBQzNFQSxDQUFDQTtJQUVEVixJQUFJQTtJQUVKVyxDQUFDQTtJQUVEWCxJQUFJQTtRQUNGWSxJQUFJQSxDQUFDQSxXQUFXQSxDQUFFQSxRQUFRQSxDQUFDQSxLQUFLQSxDQUFFQSxDQUFDQTtJQUNyQ0EsQ0FBQ0E7SUFFRFosS0FBS0E7UUFDSGEsSUFBSUEsQ0FBQ0EsV0FBV0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBQ0E7SUFDdENBLENBQUNBO0lBRURiLE1BQU1BO1FBQ0pjLElBQUlBLENBQUNBLFdBQVdBLENBQUVBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBO0lBQ3ZDQSxDQUFDQTtBQUNIZCxDQUFDQTtBQXZMUSwwQkFBa0IsR0FBRyxzQkFBc0IsQ0FBQztBQUM1QywwQkFBa0IsR0FBRyxzQkFBc0IsQ0FzTG5EOztPQ2hNTSxFQUFFLElBQUksRUFBRSxNQUFNLFFBQVE7T0FDdEIsRUFBRSxJQUFJLEVBQUUsTUFBTSxRQUFRO09BQ3RCLEVBQVEsVUFBVSxFQUFFLE1BQU0sUUFBUTtBQU16QywyQkFBMkIsSUFBSTtJQXNCN0JlLFlBQWFBLEtBQVlBLEVBQUVBLFVBQVVBLEdBQVFBLEVBQUVBO1FBRTdDQyxNQUFPQSxLQUFLQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUUzQkEsSUFBSUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7SUFDcENBLENBQUNBO0lBRURELGNBQWNBLENBQUVBLFVBQWtCQTtRQUVoQ0UsSUFBSUEsQ0FBQ0EsY0FBY0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBS0EsQ0FBRUEsVUFBVUEsQ0FBRUEsQ0FBRUEsQ0FBQ0E7SUFDbERBLENBQUNBO0lBRURGLGNBQWNBLENBQUVBLFVBQWVBO1FBRTdCRyxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxVQUFVQSxDQUFDQSxFQUFFQSxJQUFJQSxRQUFRQSxDQUFDQTtRQUVwQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsSUFBSUEsR0FBR0EsRUFBZ0JBLENBQUNBO1FBQ3RDQSxJQUFJQSxDQUFDQSxNQUFNQSxHQUFHQSxJQUFJQSxHQUFHQSxFQUFnQkEsQ0FBQ0E7UUFFdENBLE1BQU1BLENBQUNBLElBQUlBLENBQUVBLFVBQVVBLENBQUNBLEtBQUtBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBLE9BQU9BLENBQUVBLENBQUNBLEVBQUVBO1lBQ2hEQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxFQUFFQSxFQUFFQSxVQUFVQSxDQUFDQSxLQUFLQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFFQSxDQUFDQTtRQUM3Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFFSEEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBRUEsVUFBVUEsQ0FBQ0EsS0FBS0EsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBQ0EsRUFBRUE7WUFDaERBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEVBQUVBLEVBQUVBLFVBQVVBLENBQUNBLEtBQUtBLENBQUVBLEVBQUVBLENBQUVBLENBQUVBLENBQUNBO1FBQzdDQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtJQUVESCxRQUFRQSxDQUFFQSxJQUFTQTtRQUVqQkksSUFBSUEsS0FBS0EsR0FBR0EsS0FBS0EsQ0FBQ0EsUUFBUUEsRUFBRUEsQ0FBQ0E7UUFFN0JBLElBQUlBLEtBQUtBLEdBQUdBLEtBQUtBLENBQUVBLE9BQU9BLENBQUVBLEdBQUdBLEVBQUVBLENBQUNBO1FBQ2xDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFFQSxDQUFFQSxJQUFJQSxFQUFFQSxFQUFFQTtZQUUzQkEsS0FBS0EsQ0FBRUEsRUFBRUEsQ0FBRUEsR0FBR0EsSUFBSUEsQ0FBQ0EsUUFBUUEsRUFBRUEsQ0FBQ0E7UUFDbENBLENBQUNBLENBQUNBLENBQUNBO1FBRUhBLElBQUlBLEtBQUtBLEdBQUdBLEtBQUtBLENBQUVBLE9BQU9BLENBQUVBLEdBQUdBLEVBQUVBLENBQUNBO1FBQ2xDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFFQSxD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O1FBRTFDVSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUVqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsRUFBRUEsSUFBSUEsS0FBTUEsQ0FBQ0EsQ0FDbEJBLENBQUNBO1lBQ0NBLElBQUlBLFNBQVNBLEdBQUdBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLEtBQUtBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO1lBRXZEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUV6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsS0FBS0EsQ0FBQ0E7WUFFaEJBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEtBQUtBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO1lBRS9CQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxTQUFTQSxDQUFFQSxDQUFDQTtRQUNsREEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFTVYsVUFBVUEsQ0FBRUEsRUFBVUE7UUFFM0JXLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBQ2pDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQTtZQUNUQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV2REEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDbENBLENBQUNBO0lBRU1YLFdBQVdBLENBQUVBLEVBQVVBO1FBRTVCWSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUMzQkEsQ0FBQ0E7SUFFTVosT0FBT0EsQ0FBRUEsRUFBVUEsRUFBRUEsVUFBZUE7UUFFekNhLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLElBQUlBLENBQUVBLElBQUlBLEVBQUVBLFVBQVVBLENBQUVBLENBQUNBO1FBRXhDQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUViQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUU1QkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFckRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBO0lBQ2RBLENBQUNBO0lBRU1iLFVBQVVBLENBQUVBLEVBQVVBLEVBQUVBLEtBQWFBO1FBRTFDYyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUVqQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFekJBLElBQUlBLFNBQVNBLEdBQUdBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLEtBQUtBLEVBQUVBLEVBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUNBLEVBQUVBLEVBQUVBLEVBQUVBLENBQUNBO1FBRXZEQSxJQUFJQSxDQUFDQSxFQUFFQSxHQUFHQSxLQUFLQSxDQUFDQTtRQUVoQkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFFaERBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEtBQUtBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO0lBQ2pDQSxDQUFDQTtJQUVNZCxVQUFVQSxDQUFFQSxFQUFVQTtRQUUzQmUsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFDakNBLEVBQUVBLENBQUNBLENBQUVBLElBQUtBLENBQUNBO1lBQ1RBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXZEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtJQUNsQ0EsQ0FBQ0E7SUFFTWYsYUFBYUEsQ0FBRUEsRUFBVUEsRUFBRUEsVUFBY0E7UUFFOUNnQixVQUFVQSxDQUFDQSxJQUFJQSxDQUFDQSxHQUFHQSxFQUFFQSxDQUFDQTtRQUV0QkEsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsVUFBVUEsQ0FBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsVUFBVUEsQ0FBRUEsQ0FBQ0E7UUFFcERBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLEVBQUVBLElBQUlBLENBQUVBLENBQUNBO1FBRTVCQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtBQUNIaEIsQ0FBQ0E7QUE3UFEsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBQ2xDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFFbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBQ2xDLG9CQUFjLEdBQUcsZ0JBQWdCLENBdVB6Qzs7T0MxUU0sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLHFCQUFxQjtBQUt0RDtJQVVFaUIsWUFBYUEsTUFBb0JBLEVBQUVBLFNBQW9CQTtRQUNyREMsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsTUFBTUEsQ0FBQ0E7UUFDckJBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLFNBQVNBLENBQUNBO0lBQzdCQSxDQUFDQTtJQU1ERCxtQkFBbUJBO1FBQ2pCRSxNQUFNQSxDQUFDQSxJQUFJQSxnQkFBZ0JBLENBQUVBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLElBQUlBLENBQUNBLE1BQU1BLENBQUVBLENBQUNBO0lBQzdEQSxDQUFDQTtBQUVIRixDQUFDQTtBQUFBIiwiZmlsZSI6ImNyeXB0b2dyYXBoaXgtc2ltLWNvcmUuanMiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgY2xhc3MgSGV4Q29kZWNcbntcbiAgcHJpdmF0ZSBzdGF0aWMgaGV4RGVjb2RlTWFwOiBudW1iZXJbXTtcblxuICBzdGF0aWMgZGVjb2RlKCBhOiBzdHJpbmcgKTogVWludDhBcnJheVxuICB7XG4gICAgaWYgKCBIZXhDb2RlYy5oZXhEZWNvZGVNYXAgPT0gdW5kZWZpbmVkIClcbiAgICB7XG4gICAgICB2YXIgaGV4ID0gXCIwMTIzNDU2Nzg5QUJDREVGXCI7XG4gICAgICB2YXIgYWxsb3cgPSBcIiBcXGZcXG5cXHJcXHRcXHUwMEEwXFx1MjAyOFxcdTIwMjlcIjtcbiAgICAgIHZhciBkZWM6IG51bWJlcltdID0gW107XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgZGVjW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgIGhleCA9IGhleC50b0xvd2VyQ2FzZSgpO1xuICAgICAgZm9yICh2YXIgaSA9IDEwOyBpIDwgMTY7ICsraSlcbiAgICAgICAgICBkZWNbaGV4LmNoYXJBdChpKV0gPSBpO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhbGxvdy5sZW5ndGg7ICsraSlcbiAgICAgICAgICBkZWNbYWxsb3cuY2hhckF0KGkpXSA9IC0xO1xuICAgICAgSGV4Q29kZWMuaGV4RGVjb2RlTWFwID0gZGVjO1xuICAgIH1cblxuICAgIHZhciBvdXQ6IG51bWJlcltdID0gW107XG4gICAgdmFyIGJpdHMgPSAwLCBjaGFyX2NvdW50ID0gMDtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGEubGVuZ3RoOyArK2kpXG4gICAge1xuICAgICAgdmFyIGMgPSBhLmNoYXJBdChpKTtcbiAgICAgIGlmIChjID09ICc9JylcbiAgICAgICAgICBicmVhaztcbiAgICAgIHZhciBiID0gSGV4Q29kZWMuaGV4RGVjb2RlTWFwW2NdO1xuICAgICAgaWYgKGIgPT0gLTEpXG4gICAgICAgICAgY29udGludWU7XG4gICAgICBpZiAoYiA9PSB1bmRlZmluZWQpXG4gICAgICAgICAgdGhyb3cgJ0lsbGVnYWwgY2hhcmFjdGVyIGF0IG9mZnNldCAnICsgaTtcbiAgICAgIGJpdHMgfD0gYjtcbiAgICAgIGlmICgrK2NoYXJfY291bnQgPj0gMikge1xuICAgICAgICAgIG91dC5wdXNoKCBiaXRzICk7XG4gICAgICAgICAgYml0cyA9IDA7XG4gICAgICAgICAgY2hhcl9jb3VudCA9IDA7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAgIGJpdHMgPDw9IDQ7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGNoYXJfY291bnQpXG4gICAgICB0aHJvdyBcIkhleCBlbmNvZGluZyBpbmNvbXBsZXRlOiA0IGJpdHMgbWlzc2luZ1wiO1xuXG4gICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbSggb3V0ICk7XG4gIH1cbn1cbiIsInR5cGUgYnl0ZSA9IG51bWJlcjtcblxuZW51bSBCQVNFNjRTUEVDSUFMUyB7XG4gIFBMVVMgPSAnKycuY2hhckNvZGVBdCgwKSxcbiAgU0xBU0ggPSAnLycuY2hhckNvZGVBdCgwKSxcbiAgTlVNQkVSID0gJzAnLmNoYXJDb2RlQXQoMCksXG4gIExPV0VSID0gJ2EnLmNoYXJDb2RlQXQoMCksXG4gIFVQUEVSID0gJ0EnLmNoYXJDb2RlQXQoMCksXG4gIFBMVVNfVVJMX1NBRkUgPSAnLScuY2hhckNvZGVBdCgwKSxcbiAgU0xBU0hfVVJMX1NBRkUgPSAnXycuY2hhckNvZGVBdCgwKVxufVxuXG5leHBvcnQgY2xhc3MgQmFzZTY0Q29kZWNcbntcbiAgc3RhdGljIGRlY29kZSggYjY0OiBzdHJpbmcgKTogVWludDhBcnJheVxuICB7XG4gICAgaWYgKGI2NC5sZW5ndGggJSA0ID4gMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGJhc2U2NCBzdHJpbmcuIExlbmd0aCBtdXN0IGJlIGEgbXVsdGlwbGUgb2YgNCcpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIGRlY29kZSggZWx0OiBTdHJpbmcgKTogbnVtYmVyXG4gICAge1xuICAgICAgdmFyIGNvZGUgPSBlbHQuY2hhckNvZGVBdCgwKTtcblxuICAgICAgaWYgKGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlBMVVMgfHwgY29kZSA9PT0gQkFTRTY0U1BFQ0lBTFMuUExVU19VUkxfU0FGRSlcbiAgICAgICAgcmV0dXJuIDYyOyAvLyAnKydcblxuICAgICAgaWYgKGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlNMQVNIIHx8IGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlNMQVNIX1VSTF9TQUZFKVxuICAgICAgICByZXR1cm4gNjM7IC8vICcvJ1xuXG4gICAgICBpZiAoY29kZSA+PSBCQVNFNjRTUEVDSUFMUy5OVU1CRVIpXG4gICAgICB7XG4gICAgICAgIGlmIChjb2RlIDwgQkFTRTY0U1BFQ0lBTFMuTlVNQkVSICsgMTApXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5OVU1CRVIgKyAyNiArIDI2O1xuXG4gICAgICAgIGlmIChjb2RlIDwgQkFTRTY0U1BFQ0lBTFMuVVBQRVIgKyAyNilcbiAgICAgICAgICByZXR1cm4gY29kZSAtIEJBU0U2NFNQRUNJQUxTLlVQUEVSO1xuXG4gICAgICAgIGlmIChjb2RlIDwgQkFTRTY0U1BFQ0lBTFMuTE9XRVIgKyAyNilcbiAgICAgICAgICByZXR1cm4gY29kZSAtIEJBU0U2NFNQRUNJQUxTLkxPV0VSICsgMjY7XG4gICAgICB9XG5cbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBiYXNlNjQgc3RyaW5nLiBDaGFyYWN0ZXIgbm90IHZhbGlkJyk7XG4gICAgfVxuXG4gICAgLy8gdGhlIG51bWJlciBvZiBlcXVhbCBzaWducyAocGxhY2UgaG9sZGVycylcbiAgICAvLyBpZiB0aGVyZSBhcmUgdHdvIHBsYWNlaG9sZGVycywgdGhhbiB0aGUgdHdvIGNoYXJhY3RlcnMgYmVmb3JlIGl0XG4gICAgLy8gcmVwcmVzZW50IG9uZSBieXRlXG4gICAgLy8gaWYgdGhlcmUgaXMgb25seSBvbmUsIHRoZW4gdGhlIHRocmVlIGNoYXJhY3RlcnMgYmVmb3JlIGl0IHJlcHJlc2VudCAyIGJ5dGVzXG4gICAgLy8gdGhpcyBpcyBqdXN0IGEgY2hlYXAgaGFjayB0byBub3QgZG8gaW5kZXhPZiB0d2ljZVxuICAgIGxldCBsZW4gPSBiNjQubGVuZ3RoO1xuICAgIGxldCBwbGFjZUhvbGRlcnMgPSBiNjQuY2hhckF0KGxlbiAtIDIpID09PSAnPScgPyAyIDogYjY0LmNoYXJBdChsZW4gLSAxKSA9PT0gJz0nID8gMSA6IDA7XG5cbiAgICAvLyBiYXNlNjQgaXMgNC8zICsgdXAgdG8gdHdvIGNoYXJhY3RlcnMgb2YgdGhlIG9yaWdpbmFsIGRhdGFcbiAgICBsZXQgYXJyID0gbmV3IFVpbnQ4QXJyYXkoIGI2NC5sZW5ndGggKiAzIC8gNCAtIHBsYWNlSG9sZGVycyApO1xuXG4gICAgLy8gaWYgdGhlcmUgYXJlIHBsYWNlaG9sZGVycywgb25seSBnZXQgdXAgdG8gdGhlIGxhc3QgY29tcGxldGUgNCBjaGFyc1xuICAgIGxldCBsID0gcGxhY2VIb2xkZXJzID4gMCA/IGI2NC5sZW5ndGggLSA0IDogYjY0Lmxlbmd0aDtcblxuICAgIHZhciBMID0gMDtcblxuICAgIGZ1bmN0aW9uIHB1c2ggKHY6IGJ5dGUpIHtcbiAgICAgIGFycltMKytdID0gdjtcbiAgICB9XG5cbiAgICBsZXQgaSA9IDAsIGogPSAwO1xuXG4gICAgZm9yICg7IGkgPCBsOyBpICs9IDQsIGogKz0gMykge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMTgpIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPDwgMTIpIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAyKSkgPDwgNikgfCBkZWNvZGUoYjY0LmNoYXJBdChpICsgMykpO1xuICAgICAgcHVzaCgodG1wICYgMHhGRjAwMDApID4+IDE2KTtcbiAgICAgIHB1c2goKHRtcCAmIDB4RkYwMCkgPj4gOCk7XG4gICAgICBwdXNoKHRtcCAmIDB4RkYpO1xuICAgIH1cblxuICAgIGlmIChwbGFjZUhvbGRlcnMgPT09IDIpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDIpIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPj4gNCk7XG4gICAgICBwdXNoKHRtcCAmIDB4RkYpO1xuICAgIH0gZWxzZSBpZiAocGxhY2VIb2xkZXJzID09PSAxKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAxMCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDEpKSA8PCA0KSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMikpID4+IDIpO1xuICAgICAgcHVzaCgodG1wID4+IDgpICYgMHhGRik7XG4gICAgICBwdXNoKHRtcCAmIDB4RkYpO1xuICAgIH1cblxuICAgIHJldHVybiBhcnI7XG4gIH1cblxuICBzdGF0aWMgZW5jb2RlKCB1aW50ODogVWludDhBcnJheSApOiBzdHJpbmdcbiAge1xuICAgIHZhciBpOiBudW1iZXI7XG4gICAgdmFyIGV4dHJhQnl0ZXMgPSB1aW50OC5sZW5ndGggJSAzOyAvLyBpZiB3ZSBoYXZlIDEgYnl0ZSBsZWZ0LCBwYWQgMiBieXRlc1xuICAgIHZhciBvdXRwdXQgPSAnJztcblxuICAgIGNvbnN0IGxvb2t1cCA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvJztcbiAgICBmdW5jdGlvbiBlbmNvZGUoIG51bTogYnl0ZSApIHtcbiAgICAgIHJldHVybiBsb29rdXAuY2hhckF0KG51bSk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdHJpcGxldFRvQmFzZTY0KCBudW06IG51bWJlciApIHtcbiAgICAgIHJldHVybiBlbmNvZGUobnVtID4+IDE4ICYgMHgzRikgKyBlbmNvZGUobnVtID4+IDEyICYgMHgzRikgKyBlbmNvZGUobnVtID4+IDYgJiAweDNGKSArIGVuY29kZShudW0gJiAweDNGKTtcbiAgICB9XG5cbiAgICAvLyBnbyB0aHJvdWdoIHRoZSBhcnJheSBldmVyeSB0aHJlZSBieXRlcywgd2UnbGwgZGVhbCB3aXRoIHRyYWlsaW5nIHN0dWZmIGxhdGVyXG4gICAgbGV0IGxlbmd0aCA9IHVpbnQ4Lmxlbmd0aCAtIGV4dHJhQnl0ZXM7XG4gICAgZm9yIChpID0gMDsgaSA8IGxlbmd0aDsgaSArPSAzKSB7XG4gICAgICBsZXQgdGVtcCA9ICh1aW50OFtpXSA8PCAxNikgKyAodWludDhbaSArIDFdIDw8IDgpICsgKHVpbnQ4W2kgKyAyXSk7XG4gICAgICBvdXRwdXQgKz0gdHJpcGxldFRvQmFzZTY0KHRlbXApO1xuICAgIH1cblxuICAgIC8vIHBhZCB0aGUgZW5kIHdpdGggemVyb3MsIGJ1dCBtYWtlIHN1cmUgdG8gbm90IGZvcmdldCB0aGUgZXh0cmEgYnl0ZXNcbiAgICBzd2l0Y2ggKGV4dHJhQnl0ZXMpIHtcbiAgICAgIGNhc2UgMTpcbiAgICAgICAgbGV0IHRlbXAgPSB1aW50OFt1aW50OC5sZW5ndGggLSAxXTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSh0ZW1wID4+IDIpO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKCh0ZW1wIDw8IDQpICYgMHgzRik7XG4gICAgICAgIG91dHB1dCArPSAnPT0nO1xuICAgICAgICBicmVha1xuICAgICAgY2FzZSAyOlxuICAgICAgICB0ZW1wID0gKHVpbnQ4W3VpbnQ4Lmxlbmd0aCAtIDJdIDw8IDgpICsgKHVpbnQ4W3VpbnQ4Lmxlbmd0aCAtIDFdKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSh0ZW1wID4+IDEwKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA+PiA0KSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gZW5jb2RlKCh0ZW1wIDw8IDIpICYgMHgzRik7XG4gICAgICAgIG91dHB1dCArPSAnPSc7XG4gICAgICAgIGJyZWFrXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBicmVhaztcbiAgICB9XG5cbiAgICByZXR1cm4gb3V0cHV0O1xuICB9XG59XG4iLCJpbXBvcnQgeyBIZXhDb2RlYyB9IGZyb20gJy4vaGV4LWNvZGVjJztcbmltcG9ydCB7IEJhc2U2NENvZGVjIH0gZnJvbSAnLi9iYXNlNjQtY29kZWMnO1xuXG5leHBvcnQgY2xhc3MgQnl0ZUFycmF5IC8vZXh0ZW5kcyBVaW50OEFycmF5XG57XG4gIHB1YmxpYyBzdGF0aWMgQllURVMgPSAwO1xuICBwdWJsaWMgc3RhdGljIEhFWCA9IDE7XG4gIHB1YmxpYyBzdGF0aWMgQkFTRTY0ID0gMjtcbiAgcHVibGljIHN0YXRpYyBVVEY4ID0gMztcblxuICBwcml2YXRlIGJ5dGVBcnJheTogVWludDhBcnJheTtcbiAgLyoqXG4gICAqIENyZWF0ZSBhIEJ5dGVBcnJheVxuICAgKiBAcGFyYW0gYnl0ZXMgLSBpbml0aWFsIGNvbnRlbnRzLCBvcHRpb25hbFxuICAgKiAgIG1heSBiZTpcbiAgICogICAgIGFuIGV4aXN0aW5nIEJ5dGVBcnJheVxuICAgKiAgICAgYW4gQXJyYXkgb2YgbnVtYmVycyAoMC4uMjU1KVxuICAgKiAgICAgYSBzdHJpbmcsIHRvIGJlIGNvbnZlcnRlZFxuICAgKiAgICAgYW4gQXJyYXlCdWZmZXJcbiAgICogICAgIGEgVWludDhBcnJheVxuICAgKi9cbiAgY29uc3RydWN0b3IoIGJ5dGVzPzogQnl0ZUFycmF5IHwgQXJyYXk8bnVtYmVyPiB8IFN0cmluZyB8IEFycmF5QnVmZmVyIHwgVWludDhBcnJheSwgZm9ybWF0PzogbnVtYmVyLCBvcHQ/OiBhbnkgKVxuICB7XG4gICAgaWYgKCAhYnl0ZXMgKVxuICAgIHtcbiAgICAgIC8vIHplcm8tbGVuZ3RoIGFycmF5XG4gICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCAwICk7XG4gICAgfVxuICAgIGVsc2UgaWYgKCAhZm9ybWF0IHx8IGZvcm1hdCA9PSBCeXRlQXJyYXkuQllURVMgKVxuICAgIHtcbiAgICAgIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlciApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxBcnJheUJ1ZmZlcj5ieXRlcyApO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgVWludDhBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYnl0ZXM7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBCeXRlQXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzLmJ5dGVBcnJheTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIEFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggYnl0ZXMgKTtcbiAgICAgIC8vZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICAgIC8ve1xuLy8gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIC8vfVxuICAgIH1cbiAgICBlbHNlIGlmICggdHlwZW9mIGJ5dGVzID09IFwic3RyaW5nXCIgKVxuICAgIHtcbiAgICAgIGlmICggZm9ybWF0ID09IEJ5dGVBcnJheS5CQVNFNjQgKVxuICAgICAge1xuICAgICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gQmFzZTY0Q29kZWMuZGVjb2RlKCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggZm9ybWF0ID09IEJ5dGVBcnJheS5IRVggKVxuICAgICAge1xuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IEhleENvZGVjLmRlY29kZSggPHN0cmluZz5ieXRlcyApO1xuICAgICAgfVxuICAgICAgZWxzZSBpZiAoIGZvcm1hdCA9PSBCeXRlQXJyYXkuVVRGOCApXG4gICAgICB7XG4gICAgICAgIGxldCBsID0gKCA8c3RyaW5nPmJ5dGVzICkubGVuZ3RoO1xuICAgICAgICBsZXQgYmEgPSBuZXcgVWludDhBcnJheSggbCApO1xuICAgICAgICBmb3IoIGxldCBpID0gMDsgaSA8IGw7ICsraSApXG4gICAgICAgICAgYmFbaV0gPSAoIDxzdHJpbmc+Ynl0ZXMgKS5jaGFyQ29kZUF0KCBpICk7XG5cbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBiYTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBNdXN0IGhhdmUgZXhlYyBvbmUgb2YgYWJvdmUgYWxsb2NhdG9yc1xuICAgIGlmICggIXRoaXMuYnl0ZUFycmF5IClcbiAgICB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoIFwiSW52YWxpZCBQYXJhbXMgZm9yIEJ5dGVBcnJheSgpXCIpXG4gICAgfVxuICB9XG5cbiAgZ2V0IGxlbmd0aCgpOiBudW1iZXJcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheS5sZW5ndGg7XG4gIH1cblxuICBzZXQgbGVuZ3RoKCBsZW46IG51bWJlciApXG4gIHtcbiAgICBpZiAoIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCA+PSBsZW4gKVxuICAgIHtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gdGhpcy5ieXRlQXJyYXkuc2xpY2UoIDAsIGxlbiApO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgbGV0IG9sZCA9IHRoaXMuYnl0ZUFycmF5O1xuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggbGVuICk7XG4gICAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIG9sZCwgMCApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBiYWNraW5nQXJyYXkoKTogVWludDhBcnJheVxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5O1xuICB9XG5cbiAgZXF1YWxzKCB2YWx1ZTogQnl0ZUFycmF5ICk6IGJvb2xlYW5cbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG4gICAgdmFyIG9rID0gKCBiYS5sZW5ndGggPT0gdmJhLmxlbmd0aCApO1xuXG4gICAgaWYgKCBvayApXG4gICAge1xuICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICAgIG9rID0gb2sgJiYgKCBiYVtpXSA9PSB2YmFbaV0gKTtcbiAgICB9XG5cbiAgICByZXR1cm4gb2s7XG4gIH1cblxuICAvKipcbiAgICAqIGdldCBieXRlIGF0IG9mZnNldFxuICAgICovXG4gIGJ5dGVBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdO1xuICB9XG5cbiAgd29yZEF0KCBvZmZzZXQ6IG51bWJlciApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gPDwgIDggKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gICAgICAgKTtcbiAgfVxuXG4gIGxpdHRsZUVuZGlhbldvcmRBdCggb2Zmc2V0ICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAgOCApO1xuICB9XG5cbiAgZHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8IDI0IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdIDw8IDE2IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMiBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMyBdICAgICAgICk7XG4gIH1cblxuICAvKipcbiAgICAqIHNldCBieXRlIGF0IG9mZnNldFxuICAgICogQGZsdWVudFxuICAgICovXG4gIHNldEJ5dGVBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0IF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0Qnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIHZhbHVlLmJ5dGVBcnJheSwgb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGNsb25lKCk6IEJ5dGVBcnJheVxuICB7XG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEV4dHJhY3QgYSBzZWN0aW9uIChvZmZzZXQsIGNvdW50KSBmcm9tIHRoZSBCeXRlQXJyYXlcbiAgKiBAZmx1ZW50XG4gICogQHJldHVybnMgYSBuZXcgQnl0ZUFycmF5IGNvbnRhaW5pbmcgYSBzZWN0aW9uLlxuICAqL1xuICBieXRlc0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnNsaWNlKCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIENyZWF0ZSBhIHZpZXcgaW50byB0aGUgQnl0ZUFycmF5XG4gICpcbiAgKiBAcmV0dXJucyBhIEJ5dGVBcnJheSByZWZlcmVuY2luZyBhIHNlY3Rpb24gb2Ygb3JpZ2luYWwgQnl0ZUFycmF5LlxuICAqL1xuICB2aWV3QXQoIG9mZnNldDogbnVtYmVyLCBjb3VudD86IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIGlmICggIU51bWJlci5pc0ludGVnZXIoIGNvdW50ICkgKVxuICAgICAgY291bnQgPSAoIHRoaXMubGVuZ3RoIC0gb2Zmc2V0ICk7XG5cbiAgICByZXR1cm4gbmV3IEJ5dGVBcnJheSggdGhpcy5ieXRlQXJyYXkuc3ViYXJyYXkoIG9mZnNldCwgb2Zmc2V0ICsgY291bnQgKSApO1xuICB9XG5cbiAgLyoqXG4gICogQXBwZW5kIGJ5dGVcbiAgKiBAZmx1ZW50XG4gICovXG4gIGFkZEJ5dGUoIHZhbHVlOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmJ5dGVBcnJheVsgdGhpcy5ieXRlQXJyYXkubGVuZ3RoIF0gPSB2YWx1ZTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgc2V0TGVuZ3RoKCBsZW46IG51bWJlciApOiBCeXRlQXJyYXlcbiAge1xuICAgIHRoaXMubGVuZ3RoID0gbGVuO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjb25jYXQoIGJ5dGVzOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJhLmxlbmd0aCArIGJ5dGVzLmxlbmd0aCApO1xuXG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBiYSApO1xuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYnl0ZXMuYnl0ZUFycmF5LCBiYS5sZW5ndGggKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgbm90KCApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4weEZGO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBhbmQoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldICYgdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSB8IHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB4b3IoIHZhbHVlOiBCeXRlQXJyYXkgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuXG4gICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBiYS5sZW5ndGg7ICsraSApXG4gICAgICBiYVtpXSA9IGJhW2ldIF4gdmJhWyBpIF07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHRvU3RyaW5nKCBmb3JtYXQ/OiBudW1iZXIsIG9wdD86IGFueSApXG4gIHtcbiAgICBsZXQgcyA9IFwiXCI7XG4gICAgZm9yKCB2YXIgaSA9IDA7IGkgPCB0aGlzLmxlbmd0aDsgKytpIClcbiAgICAgIHMgKz0gKCBcIjBcIiArIHRoaXMuYnl0ZUFycmF5WyBpIF0udG9TdHJpbmcoIDE2ICkpLnNsaWNlKCAtMiApO1xuXG4gICAgcmV0dXJuIHM7XG4gIH1cbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJy4vYnl0ZS1hcnJheSc7XG5cbmV4cG9ydCBjbGFzcyBFbnVtIHtcbn1cblxuZXhwb3J0IGNsYXNzIEludGVnZXIgZXh0ZW5kcyBOdW1iZXIge1xufVxuXG4vKipcbiAqIFNldCBvZiBkYXRhIHR5cGVzIHRoYXQgYXJlIHZhbGlkIGFzIEtpbmQgZmllbGRzXG4gKiBpbmNsdWRlcyBGaWVsZFR5cGVBcnJheSBrbHVkZ2UgcmVxdWlyZWQgZm9yIFRTIHRvIHBhcnNlIHJlY3Vyc2l2ZVxuICogdHlwZSBkZWZpbml0aW9uc1xuICovXG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRBcnJheSBleHRlbmRzIEFycmF5PEZpZWxkVHlwZT4ge31cbmV4cG9ydCB0eXBlIEZpZWxkVHlwZSA9IFN0cmluZyB8IE51bWJlciB8IEludGVnZXIgfCBFbnVtIHwgQnl0ZUFycmF5IHwgS2luZCB8IEZpZWxkQXJyYXk7XG5cbmV4cG9ydCBjbGFzcyBGaWVsZEFycmF5IGltcGxlbWVudHMgRmllbGRBcnJheSB7fVxuXG5leHBvcnQgdmFyIEZpZWxkVHlwZXMgPSB7XG4gIEJvb2xlYW46IEJvb2xlYW4sXG5cbiAgTnVtYmVyOiBOdW1iZXIsXG5cbiAgSW50ZWdlcjogSW50ZWdlcixcblxuICBCeXRlQXJyYXk6IEJ5dGVBcnJheSxcblxuICBFbnVtOiBFbnVtLFxuXG4gIEFycmF5OiBGaWVsZEFycmF5LFxuXG4gIFN0cmluZzogU3RyaW5nLFxuXG4gIEtpbmQ6IEtpbmRcbn1cblxuZXhwb3J0IGludGVyZmFjZSBGaWVsZE9wdGlvbnMge1xuICAvKipcbiAgKiBtaW5pbXVtIGxlbmd0aCBmb3IgU3RyaW5nLCBtaW5pbXVtIHZhbHVlIGZvciBOdW1iZXIvSW50ZWdlclxuICAqL1xuICBtaW5pbXVtPzogbnVtYmVyO1xuXG4gIC8qKlxuICAqIG1heGltdW0gbGVuZ3RoIGZvciBTdHJpbmcsIG1heGltdW0gdmFsdWUgZm9yIE51bWJlci9JbnRlZ2VyXG4gICovXG4gIG1heGltdW0/OiBudW1iZXI7XG5cbiAgLyoqXG4gICogZGVmYXVsdCB2YWx1ZSBkdXJpbmcgaW5pdGlhbGl6YXRpb25cbiAgKi9cbiAgXCJkZWZhdWx0XCI/OiBhbnk7XG5cbiAgLyoqXG4gICogZG9lcyBub3QgZXhpc3QgYXMgYW4gb3duUHJvcGVydHlcbiAgKi9cbiAgY2FsY3VsYXRlZD86IGJvb2xlYW47XG5cbiAgLyoqXG4gICogc3ViLWtpbmQsIHdoZW4gZmllbGQgaXMgdHlwZSBLaW5kXG4gICovXG4gIGtpbmQ/OiBLaW5kO1xuXG4gIC8qKlxuICAqIHN1Yi1maWVsZCBpbmZvLCB3aGVuIGZpZWxkIGlzIHR5cGUgRmllbGRBcnJheVxuICAqL1xuICBhcnJheUluZm8/OiBGaWVsZEluZm87XG5cbiAgLyoqXG4gICogaW5kZXgvdmFsdWUgbWFwLCB3aGVuIGZpZWxkIGlmIHR5cGUgRW51bVxuICAqL1xuICBlbnVtTWFwPzogTWFwPG51bWJlciwgc3RyaW5nPjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBGaWVsZEluZm8gZXh0ZW5kcyBGaWVsZE9wdGlvbnMge1xuICAvKipcbiAgKiBEZXNjcmlwdGlvbiBmb3IgZmllbGRcbiAgKi9cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICAvKipcbiAgKiBUeXBlIG9mIGZpZWxkLCBvbmUgb2YgRmllbGRUeXBlc1xuICAqL1xuICBmaWVsZFR5cGU6IEZpZWxkVHlwZTtcbn1cblxuXG4vKipcbiogTWV0YWRhdGEgYWJvdXQgYSBLaW5kLiBDb250YWlucyBuYW1lLCBkZXNjcmlwdGlvbiBhbmQgYSBtYXAgb2ZcbiogcHJvcGVydHktZGVzY3JpcHRvcnMgdGhhdCBkZXNjcmliZSB0aGUgc2VyaWFsaXphYmxlIGZpZWxkcyBvZlxuKiBhbiBvYmplY3Qgb2YgdGhhdCBLaW5kLlxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kSW5mb1xue1xuICBuYW1lOiBzdHJpbmc7XG5cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICBmaWVsZHM6IHsgW2lkOiBzdHJpbmddOiBGaWVsZEluZm8gfSA9IHt9O1xufVxuXG4vKipcbiogQnVpbGRlciBmb3IgJ0tpbmQnIG1ldGFkYXRhXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRCdWlsZGVyXG57XG4gIHByaXZhdGUgY3RvcjogS2luZENvbnN0cnVjdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKSB7XG4gICAgdGhpcy5jdG9yID0gY3RvcjtcblxuICAgIGN0b3Iua2luZEluZm8gPSB7XG4gICAgICBuYW1lOiBjdG9yLm5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24sXG4gICAgICBmaWVsZHM6IHt9XG4gICAgfVxuICB9XG5cblxuICBwcml2YXRlIGtpbmRJbmZvOiBLaW5kSW5mbztcblxuICBwdWJsaWMgc3RhdGljIGluaXQoIGN0b3I6IEtpbmRDb25zdHJ1Y3RvciwgZGVzY3JpcHRpb246IHN0cmluZyApOiBLaW5kQnVpbGRlclxuICB7XG4gICAgbGV0IGJ1aWxkZXIgPSBuZXcgS2luZEJ1aWxkZXIoIGN0b3IsIGRlc2NyaXB0aW9uICk7XG5cbiAgICByZXR1cm4gYnVpbGRlcjtcbiAgfVxuXG4gIHB1YmxpYyBmaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBmaWVsZFR5cGU6IEZpZWxkVHlwZSwgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBmaWVsZDogRmllbGRJbmZvID0gPEZpZWxkSW5mbz5vcHRzO1xuXG4gICAgZmllbGQuZGVzY3JpcHRpb24gPSBkZXNjcmlwdGlvbjtcbiAgICBmaWVsZC5maWVsZFR5cGUgPSBmaWVsZFR5cGU7XG5cbiAgICB0aGlzLmN0b3Iua2luZEluZm8uZmllbGRzWyBuYW1lIF0gPSBmaWVsZDtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgcHVibGljIGJvb2xGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBCb29sZWFuLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgbnVtYmVyRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgTnVtYmVyLCBvcHRzICk7XG4gIH1cblxuICBwdWJsaWMgaW50ZWdlckZpZWxkKCBuYW1lOiBzdHJpbmcsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIG9wdHM6IEZpZWxkT3B0aW9ucyA9IHt9ICk6IEtpbmRCdWlsZGVyIHtcbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyB1aW50MzJGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgb3B0cy5taW5pbXVtID0gb3B0cy5taW5pbXVtIHx8IDA7XG4gICAgb3B0cy5tYXhpbXVtID0gb3B0cy5tYXhpbXVtIHx8IDB4RkZGRkZGRkY7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBieXRlRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMubWluaW11bSA9IG9wdHMubWluaW11bSB8fCAwO1xuICAgIG9wdHMubWF4aW11bSA9IG9wdHMubWF4aW11bSB8fCAyNTU7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEludGVnZXIsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdHJpbmdGaWVsZCggbmFtZTogc3RyaW5nLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBvcHRzOiBGaWVsZE9wdGlvbnMgPSB7fSApOiBLaW5kQnVpbGRlciB7XG4gICAgcmV0dXJuIHRoaXMuZmllbGQoIG5hbWUsIGRlc2NyaXB0aW9uLCBTdHJpbmcsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBraW5kRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywga2luZDogS2luZCwgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuICAgIG9wdHMua2luZCA9IGtpbmQ7XG5cbiAgICByZXR1cm4gdGhpcy5maWVsZCggbmFtZSwgZGVzY3JpcHRpb24sIEtpbmQsIG9wdHMgKTtcbiAgfVxuXG4gIHB1YmxpYyBlbnVtRmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZW51bW06IHsgWyBpZHg6IG51bWJlciBdOiBzdHJpbmcgfSwgb3B0czogRmllbGRPcHRpb25zID0ge30gKTogS2luZEJ1aWxkZXIge1xuXG4gICAgb3B0cy5lbnVtTWFwID0gbmV3IE1hcDxudW1iZXIsc3RyaW5nPiggKTtcblxuICAgIGZvciggbGV0IGlkeCBpbiBlbnVtbSApIHtcbiAgICAgIGlmICggMSAqIGlkeCA9PSBpZHggKVxuICAgICAgICBvcHRzLmVudW1NYXAuc2V0KCBpZHgsIGVudW1tWyBpZHggXSApO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmZpZWxkKCBuYW1lLCBkZXNjcmlwdGlvbiwgRW51bSwgb3B0cyApO1xuICB9XG59XG5cbi8qICBtYWtlS2luZCgga2luZENvbnN0cnVjdG9yLCBraW5kT3B0aW9ucyApXG4gIHtcbiAgICB2YXIgJGtpbmRJbmZvID0ga2luZE9wdGlvbnMua2luZEluZm87XG5cbiAgICBraW5kQ29uc3RydWN0b3IuJGtpbmROYW1lID0gJGtpbmRJbmZvLnRpdGxlO1xuXG4gICAgdmFyIGtleXMgPSBPYmplY3Qua2V5cygga2luZE9wdGlvbnMua2luZE1ldGhvZHMgKTtcblxuICAgIGZvciAoIHZhciBqID0gMCwgamogPSBrZXlzLmxlbmd0aDsgaiA8IGpqOyBqKysgKSB7XG4gICAgICB2YXIga2V5ID0ga2V5c1tqXTtcbiAgICAgIGtpbmRDb25zdHJ1Y3RvcltrZXldID0ga2luZE9wdGlvbnMua2luZE1ldGhvZHNba2V5XTtcbiAgICB9XG5cbiAgICBraW5kQ29uc3RydWN0b3IuZ2V0S2luZEluZm8gPSBraW5kQ29uc3RydWN0b3IucHJvdG90eXBlLmdldEtpbmRJbmZvID0gZnVuY3Rpb24gZ2V0S2luZEluZm8oKSB7XG4gICAgICByZXR1cm4gJGtpbmRJbmZvO1xuICAgIH1cblxuICAgIHJldHVybiBraW5kQ29uc3RydWN0b3I7XG4gIH1cbiovXG5cbi8qKlxuKiBSZXByZXNlbnRzIGEgc2VyaWFsaXphYmxlIGFuZCBpbnNwZWN0YWJsZSBkYXRhLXR5cGVcbiogaW1wbGVtZW50ZWQgYXMgYSBoYXNoLW1hcCBjb250YWluaW5nIGtleS12YWx1ZSBwYWlycyxcbiogYWxvbmcgd2l0aCBtZXRhZGF0YSB0aGF0IGRlc2NyaWJlcyBlYWNoIGZpZWxkIHVzaW5nIGEganNvbi1zY2hlbWUgbGlrZVxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgS2luZFxue1xufVxuXG5leHBvcnQgY2xhc3MgS2luZCBpbXBsZW1lbnRzIEtpbmQge1xuICBzdGF0aWMgZ2V0S2luZEluZm8oIGtpbmQ6IEtpbmQgKTogS2luZEluZm8ge1xuICAgIHJldHVybiAoPEtpbmRDb25zdHJ1Y3Rvcj4oa2luZC5jb25zdHJ1Y3RvcikpLmtpbmRJbmZvO1xuICB9XG5cbiAgc3RhdGljIGluaXRGaWVsZHMoIGtpbmQ6IEtpbmQsIGF0dHJpYnV0ZXM6IHt9ID0ge30gICkge1xuICAgIGxldCBraW5kSW5mbyA9IEtpbmQuZ2V0S2luZEluZm8oIGtpbmQgKTtcblxuICAgIGZvciggbGV0IGlkIGluIGtpbmRJbmZvLmZpZWxkcyApIHtcbiAgICAgIGxldCBmaWVsZCA9IGtpbmRJbmZvLmZpZWxkc1sgaWQgXTtcbiAgICAgIGxldCBmaWVsZFR5cGUgPSBmaWVsZC5maWVsZFR5cGU7XG5cbi8vICAgICAgY29uc29sZS5sb2coIGlkICsgJzonICsgZmllbGRUeXBlICk7XG4vLyAgICAgIGNvbnNvbGUubG9nKCBraW5kLmhhc093blByb3BlcnR5KGlkKSAgKTtcblxuICAgICAgbGV0IHZhbDogYW55O1xuXG4gICAgICBpZiAoICFmaWVsZC5jYWxjdWxhdGVkICkge1xuICAgICAgICAvLyB3ZSBvbmx5IHNldCAnbm9uJy1jYWxjdWxhdGVkIGZpZWxkLCBzaW5jZSBjYWxjdWxhdGVkIGZpZWxkIGhhdmVcbiAgICAgICAgLy8gbm8gc2V0dGVyXG5cbiAgICAgICAgLy8gZ290IGEgdmFsdWUgZm9yIHRoaXMgZmllbGQgP1xuICAgICAgICBpZiAoIGF0dHJpYnV0ZXNbIGlkIF0gKVxuICAgICAgICAgIHZhbCA9IGF0dHJpYnV0ZXNbIGlkIF07XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZC5kZWZhdWx0ICE9IHVuZGVmaW5lZCApXG4gICAgICAgICAgdmFsID0gZmllbGQuZGVmYXVsdDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBTdHJpbmcgKVxuICAgICAgICAgIHZhbCA9ICcnO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IE51bWJlciApXG4gICAgICAgICAgdmFsID0gMDtcbiAgICAgICAgZWxzZSBpZiAoIGZpZWxkVHlwZSA9PSBJbnRlZ2VyIClcbiAgICAgICAgICB2YWwgPSBmaWVsZC5taW5pbXVtIHx8IDA7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gQm9vbGVhbiApXG4gICAgICAgICAgdmFsID0gZmFsc2U7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gQnl0ZUFycmF5IClcbiAgICAgICAgICB2YWwgPSBuZXcgQnl0ZUFycmF5KCk7XG4gICAgICAgIGVsc2UgaWYgKCBmaWVsZFR5cGUgPT0gRW51bSApXG4gICAgICAgICAgdmFsID0gZmllbGQuZW51bU1hcC5rZXlzWzBdO1xuICAgICAgICBlbHNlIGlmICggZmllbGRUeXBlID09IEtpbmQgKSB7XG4gICAgICAgICAgbGV0IHh4ID0gKDxLaW5kPmZpZWxkVHlwZSkuY29uc3RydWN0b3I7XG4gICAgICAgICAgdmFsID0gT2JqZWN0LmNyZWF0ZSggeHggKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGtpbmRbIGlkIF0gPSB2YWw7XG5cbi8vICAgICAgICBjb25zb2xlLmxvZygga2luZFtpZF0gKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuZXhwb3J0IGludGVyZmFjZSBLaW5kQ29uc3RydWN0b3JcbntcbiAgbmV3ICggLi4uYXJncyApOiBLaW5kO1xuXG4gIGtpbmRJbmZvPzogS2luZEluZm87XG59XG4iLCJpbXBvcnQgeyBLaW5kIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuXG4vKlxuKiBNZXNzYWdlIEhlYWRlclxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgTWVzc2FnZUhlYWRlclxue1xuICAvKlxuICAqIE1lc3NhZ2UgTmFtZSwgaW5kaWNhdGVzIGEgY29tbWFuZCAvIG1ldGhvZCAvIHJlc3BvbnNlIHRvIGV4ZWN1dGVcbiAgKi9cbiAgbWV0aG9kPzogc3RyaW5nO1xuXG4gIC8qXG4gICogTWVzc2FnZSBJZGVudGlmaWVyICh1bmlxdWUpIGZvciBlYWNoIHNlbnQgbWVzc2FnZSAob3IgQ01ELVJFU1AgcGFpcilcbiAgKi9cbiAgaWQ/OiBudW1iZXI7XG5cblxuICAvKlxuICAqIERlc2NyaXB0aW9uLCB1c2VmdWwgZm9yIHRyYWNpbmcgYW5kIGxvZ2dpbmdcbiAgKi9cbiAgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG5cbiAgLypcbiAgKiBGb3IgQ01EL1JFU1Agc3R5bGUgcHJvdG9jb2xzLCBpbmRpY2F0ZXMgdGhhdCBtZXNzYWdlIGRpc3BhdGNoZWRcbiAgKiBpbiByZXNwb25zZSB0byBhIHByZXZpb3VzIGNvbW1hbmRcbiAgKi9cbiAgaXNSZXNwb25zZT86IGJvb2xlYW47XG5cbiAgLypcbiAgKiBFbmRQb2ludCB0aGF0IG9yaWdpbmF0ZWQgdGhlIG1lc3NhZ2VcbiAgKi9cbiAgb3JpZ2luPzogRW5kUG9pbnQ7XG5cblxuICAvKlxuICAqIEluZGljYXRlcyB0aGUgS2luZCBvZiBkYXRhICh3aGVuIHNlcmlhbGl6ZWQpXG4gICovXG4gIGtpbmROYW1lPzogc3RyaW5nO1xufVxuXG4vKlxuKiBBIFR5cGVkIE1lc3NhZ2UsIHdpdGggaGVhZGVyIGFuZCBwYXlsb2FkXG4qL1xuZXhwb3J0IGNsYXNzIE1lc3NhZ2U8VD5cbntcbiAgcHJpdmF0ZSBfaGVhZGVyOiBNZXNzYWdlSGVhZGVyO1xuICBwcml2YXRlIF9wYXlsb2FkOiBUO1xuXG4gIGNvbnN0cnVjdG9yKCBoZWFkZXI6IE1lc3NhZ2VIZWFkZXIsIHBheWxvYWQ6IFQgKVxuICB7XG4gICAgdGhpcy5faGVhZGVyID0gaGVhZGVyIHx8IHt9O1xuICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICB9XG5cbiAgZ2V0IGhlYWRlcigpOiBNZXNzYWdlSGVhZGVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faGVhZGVyO1xuICB9XG5cbiAgZ2V0IHBheWxvYWQoKTogVFxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BheWxvYWQ7XG4gIH1cbn1cblxuLypcbiogQSB0eXBlZCBNZXNzYWdlIHdob3NlIHBheWxvYWQgaXMgYSBLaW5kXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRNZXNzYWdlPEsgZXh0ZW5kcyBLaW5kPiBleHRlbmRzIE1lc3NhZ2U8Sz5cbntcbn1cbiIsImV4cG9ydCB0eXBlIFRhc2sgPSAoKSA9PiB2b2lkO1xuZXhwb3J0IHR5cGUgRmx1c2hGdW5jID0gKCkgPT4gdm9pZDtcbnZhciB3aW5kb3cgPSB3aW5kb3cgfHwge307XG5cbmV4cG9ydCBjbGFzcyBUYXNrU2NoZWR1bGVyXG57XG4gIHN0YXRpYyBtYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpOiBGbHVzaEZ1bmNcbiAge1xuICAgIHZhciB0b2dnbGUgPSAxO1xuXG4gICAgdmFyIG9ic2VydmVyID0gbmV3IFRhc2tTY2hlZHVsZXIuQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpO1xuXG4gICAgdmFyIG5vZGU6IE9iamVjdCA9IGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKCcnKTtcblxuICAgIG9ic2VydmVyLm9ic2VydmUobm9kZSwgeyBjaGFyYWN0ZXJEYXRhOiB0cnVlIH0pO1xuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpXG4gICAge1xuICAgICAgdG9nZ2xlID0gLXRvZ2dsZTtcbiAgICAgIG5vZGVbXCJkYXRhXCJdID0gdG9nZ2xlO1xuICAgIH07XG4gIH1cblxuICBzdGF0aWMgbWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lcihmbHVzaCk6IEZsdXNoRnVuY1xuICB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpIHtcbiAgICAgIHZhciB0aW1lb3V0SGFuZGxlID0gc2V0VGltZW91dChoYW5kbGVGbHVzaFRpbWVyLCAwKTtcblxuICAgICAgdmFyIGludGVydmFsSGFuZGxlID0gc2V0SW50ZXJ2YWwoaGFuZGxlRmx1c2hUaW1lciwgNTApO1xuICAgICAgZnVuY3Rpb24gaGFuZGxlRmx1c2hUaW1lcigpXG4gICAgICB7XG4gICAgICAgIGNsZWFyVGltZW91dCh0aW1lb3V0SGFuZGxlKTtcbiAgICAgICAgY2xlYXJJbnRlcnZhbChpbnRlcnZhbEhhbmRsZSk7XG4gICAgICAgIGZsdXNoKCk7XG4gICAgICB9XG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBCcm93c2VyTXV0YXRpb25PYnNlcnZlciA9IHdpbmRvd1sgXCJNdXRhdGlvbk9ic2VydmVyXCIgXSB8fCB3aW5kb3dbIFwiV2ViS2l0TXV0YXRpb25PYnNlcnZlclwiXTtcbiAgc3RhdGljIGhhc1NldEltbWVkaWF0ZSA9IHR5cGVvZiBzZXRJbW1lZGlhdGUgPT09ICdmdW5jdGlvbic7XG5cbiAgc3RhdGljIHRhc2tRdWV1ZUNhcGFjaXR5ID0gMTAyNDtcbiAgdGFza1F1ZXVlOiBUYXNrW107XG5cbiAgcmVxdWVzdEZsdXNoVGFza1F1ZXVlOiBGbHVzaEZ1bmM7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy50YXNrUXVldWUgPSBbXTtcblxuICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgIGlmICh0eXBlb2YgVGFza1NjaGVkdWxlci5Ccm93c2VyTXV0YXRpb25PYnNlcnZlciA9PT0gJ2Z1bmN0aW9uJylcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSA9IFRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHNlbGYuZmx1c2hUYXNrUXVldWUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUgPSBUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIoZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gc2VsZi5mbHVzaFRhc2tRdWV1ZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgVGFza1NjaGVkdWxlciwgY2FuY2VsbGluZyBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgc2h1dGRvd24oKVxuICB7XG4gIH1cblxuICBxdWV1ZVRhc2soIHRhc2spXG4gIHtcbiAgICBpZiAoIHRoaXMudGFza1F1ZXVlLmxlbmd0aCA8IDEgKVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlKCk7XG4gICAgfVxuXG4gICAgdGhpcy50YXNrUXVldWUucHVzaCh0YXNrKTtcbiAgfVxuXG4gIGZsdXNoVGFza1F1ZXVlKClcbiAge1xuICAgIHZhciBxdWV1ZSA9IHRoaXMudGFza1F1ZXVlLFxuICAgICAgICBjYXBhY2l0eSA9IFRhc2tTY2hlZHVsZXIudGFza1F1ZXVlQ2FwYWNpdHksXG4gICAgICAgIGluZGV4ID0gMCxcbiAgICAgICAgdGFzaztcblxuICAgIHdoaWxlIChpbmRleCA8IHF1ZXVlLmxlbmd0aClcbiAgICB7XG4gICAgICB0YXNrID0gcXVldWVbaW5kZXhdO1xuXG4gICAgICB0cnlcbiAgICAgIHtcbiAgICAgICAgdGFzay5jYWxsKCk7XG4gICAgICB9XG4gICAgICBjYXRjaCAoZXJyb3IpXG4gICAgICB7XG4gICAgICAgIHRoaXMub25FcnJvcihlcnJvciwgdGFzayk7XG4gICAgICB9XG5cbiAgICAgIGluZGV4Kys7XG5cbiAgICAgIGlmIChpbmRleCA+IGNhcGFjaXR5KVxuICAgICAge1xuICAgICAgICBmb3IgKHZhciBzY2FuID0gMDsgc2NhbiA8IGluZGV4OyBzY2FuKyspXG4gICAgICAgIHtcbiAgICAgICAgICBxdWV1ZVtzY2FuXSA9IHF1ZXVlW3NjYW4gKyBpbmRleF07XG4gICAgICAgIH1cblxuICAgICAgICBxdWV1ZS5sZW5ndGggLT0gaW5kZXg7XG4gICAgICAgIGluZGV4ID0gMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBxdWV1ZS5sZW5ndGggPSAwO1xuICB9XG5cbiAgb25FcnJvcihlcnJvciwgdGFzaylcbiAge1xuICAgIGlmICgnb25FcnJvcicgaW4gdGFzaykge1xuICAgICAgdGFzay5vbkVycm9yKGVycm9yKTtcbiAgICB9XG4gICAgZWxzZSBpZiAoIFRhc2tTY2hlZHVsZXIuaGFzU2V0SW1tZWRpYXRlIClcbiAgICB7XG4gICAgICBzZXRJbW1lZGlhdGUoZnVuY3Rpb24gKCkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgc2V0VGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSwgMCk7XG4gICAgfVxuICB9XG59XG4iLCJpbXBvcnQgeyBUYXNrU2NoZWR1bGVyIH0gZnJvbSAnLi4vcnVudGltZS90YXNrLXNjaGVkdWxlcic7XG5pbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5cbi8qKlxuKiBBIG1lc3NhZ2UtcGFzc2luZyBjaGFubmVsIGJldHdlZW4gbXVsdGlwbGUgRW5kUG9pbnRzXG4qXG4qIEVuZFBvaW50cyBtdXN0IGZpcnN0IHJlZ2lzdGVyIHdpdGggdGhlIENoYW5uZWwuIFdoZW5ldmVyIHRoZSBDaGFubmVsIGlzIGluXG4qIGFuIGFjdGl2ZSBzdGF0ZSwgY2FsbHMgdG8gc2VuZE1lc3NhZ2Ugd2lsbCBmb3J3YXJkIHRoZSBtZXNzYWdlIHRvIGFsbFxuKiByZWdpc3RlcmVkIEVuZFBvaW50cyAoZXhjZXB0IHRoZSBvcmlnaW5hdG9yIEVuZFBvaW50KS5cbiovXG5leHBvcnQgY2xhc3MgQ2hhbm5lbFxue1xuICAvKipcbiAgKiBUcnVlIGlmIENoYW5uZWwgaXMgYWN0aXZlXG4gICovXG4gIHByaXZhdGUgX2FjdGl2ZTogYm9vbGVhbjtcblxuICAvKipcbiAgKiBBcnJheSBvZiBFbmRQb2ludHMgYXR0YWNoZWQgdG8gdGhpcyBDaGFubmVsXG4gICovXG4gIHByaXZhdGUgX2VuZFBvaW50czogRW5kUG9pbnRbXTtcblxuICAvKipcbiAgKiBQcml2YXRlIFRhc2tTY2hlZHVsZXIgdXNlZCB0byBtYWtlIG1lc3NhZ2Utc2VuZHMgYXN5bmNocm9ub3VzLlxuICAqL1xuICBwcml2YXRlIF90YXNrU2NoZWR1bGVyOiBUYXNrU2NoZWR1bGVyO1xuXG4gIC8qKlxuICAqIENyZWF0ZSBhIG5ldyBDaGFubmVsLCBpbml0aWFsbHkgaW5hY3RpdmVcbiAgKi9cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBDaGFubmVsLCBkZWFjdGl2YXRlLCByZW1vdmUgYWxsIEVuZFBvaW50cyBhbmRcbiAgKiBhYm9ydCBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG5cbiAgICBpZiAoIHRoaXMuX3Rhc2tTY2hlZHVsZXIgKVxuICAgIHtcbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIuc2h1dGRvd24oKTtcblxuICAgICAgdGhpcy5fdGFza1NjaGVkdWxlciA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBJcyBDaGFubmVsIGFjdGl2ZT9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgY2hhbm5lbCBpcyBhY3RpdmUsIGZhbHNlIG90aGVyd2lzZVxuICAqL1xuICBwdWJsaWMgZ2V0IGFjdGl2ZSgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fYWN0aXZlO1xuICB9XG5cbiAgLyoqXG4gICogQWN0aXZhdGUgdGhlIENoYW5uZWwsIGVuYWJsaW5nIGNvbW11bmljYXRpb25cbiAgKi9cbiAgcHVibGljIGFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSBuZXcgVGFza1NjaGVkdWxlcigpO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gdHJ1ZTtcbiAgfVxuXG4gIC8qKlxuICAqIERlYWN0aXZhdGUgdGhlIENoYW5uZWwsIGRpc2FibGluZyBhbnkgZnVydGhlciBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBkZWFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG5cbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGFuIEVuZFBvaW50IHRvIHNlbmQgYW5kIHJlY2VpdmUgbWVzc2FnZXMgdmlhIHRoaXMgQ2hhbm5lbC5cbiAgKlxuICAqIEBwYXJhbSBlbmRQb2ludCAtIHRoZSBFbmRQb2ludCB0byByZWdpc3RlclxuICAqL1xuICBwdWJsaWMgYWRkRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICB0aGlzLl9lbmRQb2ludHMucHVzaCggZW5kUG9pbnQgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFVucmVnaXN0ZXIgYW4gRW5kUG9pbnQuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gdW5yZWdpc3RlclxuICAqL1xuICBwdWJsaWMgcmVtb3ZlRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fZW5kUG9pbnRzLmluZGV4T2YoIGVuZFBvaW50ICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICB0aGlzLl9lbmRQb2ludHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBHZXQgRW5kUG9pbnRzIHJlZ2lzdGVyZWQgd2l0aCB0aGlzIENoYW5uZWxcbiAgKlxuICAqIEByZXR1cm4gQXJyYXkgb2YgRW5kUG9pbnRzXG4gICovXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnRzKCk6IEVuZFBvaW50W11cbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludHM7XG4gIH1cblxuICAvKipcbiAgKiBTZW5kIGEgbWVzc2FnZSB0byBhbGwgbGlzdGVuZXJzIChleGNlcHQgb3JpZ2luKVxuICAqXG4gICogQHBhcmFtIG9yaWdpbiAtIEVuZFBvaW50IHRoYXQgaXMgc2VuZGluZyB0aGUgbWVzc2FnZVxuICAqIEBwYXJhbSBtZXNzYWdlIC0gTWVzc2FnZSB0byBiZSBzZW50XG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggb3JpZ2luOiBFbmRQb2ludCwgbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIGxldCBpc1Jlc3BvbnNlID0gKCBtZXNzYWdlLmhlYWRlciAmJiBtZXNzYWdlLmhlYWRlci5pc1Jlc3BvbnNlICk7XG5cbiAgICBpZiAoICF0aGlzLl9hY3RpdmUgKVxuICAgICAgcmV0dXJuO1xuXG4gICAgaWYgKCBvcmlnaW4uZGlyZWN0aW9uID09IERpcmVjdGlvbi5JTiAmJiAhaXNSZXNwb25zZSApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdVbmFibGUgdG8gc2VuZCBvbiBJTiBwb3J0Jyk7XG5cbiAgICB0aGlzLl9lbmRQb2ludHMuZm9yRWFjaCggZW5kUG9pbnQgPT4ge1xuICAgICAgLy8gU2VuZCB0byBhbGwgbGlzdGVuZXJzLCBleGNlcHQgZm9yIG9yaWdpbmF0b3IgLi4uXG4gICAgICBpZiAoIG9yaWdpbiAhPSBlbmRQb2ludCApXG4gICAgICB7XG4gICAgICAgIC8vIE9ubHkgc2VuZCB0byBJTiBvciBJTk9VVCBsaXN0ZW5lcnMsIFVOTEVTUyBtZXNzYWdlIGlzIGFcbiAgICAgICAgLy8gcmVwbHkgKGluIGEgY2xpZW50LXNlcnZlcikgY29uZmlndXJhdGlvblxuICAgICAgICBpZiAoIGVuZFBvaW50LmRpcmVjdGlvbiAhPSBEaXJlY3Rpb24uT1VUIHx8IGlzUmVzcG9uc2UgKVxuICAgICAgICB7XG4gICAgICAgICAgdGhpcy5fdGFza1NjaGVkdWxlci5xdWV1ZVRhc2soICgpID0+IHtcbiAgICAgICAgICAgIGVuZFBvaW50LmhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2UsIG9yaWdpbiwgdGhpcyApO1xuICAgICAgICAgIH0gKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuL2NoYW5uZWwnO1xuXG5leHBvcnQgZW51bSBEaXJlY3Rpb24ge1xuICBJTiA9IDEsXG4gIE9VVCA9IDIsXG4gIElOT1VUID0gM1xufTtcblxuZXhwb3J0IHR5cGUgSGFuZGxlTWVzc2FnZURlbGVnYXRlID0gKCBtZXNzYWdlOiBNZXNzYWdlPGFueT4sIHJlY2VpdmluZ0VuZFBvaW50PzogRW5kUG9pbnQsIHJlY2VpdmluZ0NoYW5uZWw/OiBDaGFubmVsICkgPT4gdm9pZDtcblxuLyoqXG4qIEFuIEVuZFBvaW50IGlzIGEgc2VuZGVyL3JlY2VpdmVyIGZvciBtZXNzYWdlLXBhc3NpbmcuIEl0IGhhcyBhbiBpZGVudGlmaWVyXG4qIGFuZCBhbiBvcHRpb25hbCBkaXJlY3Rpb24sIHdoaWNoIG1heSBiZSBJTiwgT1VUIG9yIElOL09VVCAoZGVmYXVsdCkuXG4qXG4qIEVuZFBvaW50cyBtYXkgaGF2ZSBtdWx0aXBsZSBjaGFubmVscyBhdHRhY2hlZCwgYW5kIHdpbGwgZm9yd2FyZCBtZXNzYWdlc1xuKiB0byBhbGwgb2YgdGhlbS5cbiovXG5leHBvcnQgY2xhc3MgRW5kUG9pbnRcbntcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX2NoYW5uZWxzOiBDaGFubmVsW107XG5cbiAgLyoqXG4gICogQSBsaXN0IG9mIGF0dGFjaGVkIENoYW5uZWxzXG4gICovXG4gIHByb3RlY3RlZCBfbWVzc2FnZUxpc3RlbmVyczogSGFuZGxlTWVzc2FnZURlbGVnYXRlW107XG5cbiAgcHJpdmF0ZSBfZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgY29uc3RydWN0b3IoIGlkOiBzdHJpbmcsIGRpcmVjdGlvbjogRGlyZWN0aW9uID0gRGlyZWN0aW9uLklOT1VUIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG5cbiAgICB0aGlzLl9kaXJlY3Rpb24gPSBkaXJlY3Rpb247XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuXG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgRW5kUG9pbnQsIGRldGFjaGluZyBhbnkgYXR0YWNoZWQgQ2hhbm5lbHMgYW5kIHJlbW92aW5nIGFueVxuICAqIG1lc3NhZ2UtbGlzdGVuZXJzLiBDYWxsaW5nIHNodXRkb3duKCkgaXMgbWFuZGF0b3J5IHRvIGF2b2lkIG1lbW9yeS1sZWFrc1xuICAqIGR1ZSB0byB0aGUgY2lyY3VsYXIgcmVmZXJlbmNlcyB0aGF0IGV4aXN0IGJldHdlZW4gQ2hhbm5lbHMgYW5kIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgc2h1dGRvd24oKVxuICB7XG4gICAgdGhpcy5kZXRhY2hBbGwoKTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIEVuZFBvaW50J3MgaWRcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9pZDtcbiAgfVxuXG4gIC8qKlxuICAqIEF0dGFjaCBhIENoYW5uZWwgdG8gdGhpcyBFbmRQb2ludC4gT25jZSBhdHRhY2hlZCwgdGhlIENoYW5uZWwgd2lsbCBmb3J3YXJkXG4gICogbWVzc2FnZXMgdG8gdGhpcyBFbmRQb2ludCwgYW5kIHdpbGwgYWNjZXB0IG1lc3NhZ2VzIG9yaWdpbmF0ZWQgaGVyZS5cbiAgKiBBbiBFbmRQb2ludCBjYW4gaGF2ZSBtdWx0aXBsZSBDaGFubmVscyBhdHRhY2hlZCwgaW4gd2hpY2ggY2FzZSBpdCB3aWxsXG4gICogYnJvYWRjYXN0IHRvIHRoZW0gYWxsIHdoZW4gc2VuZGluZywgYW5kIHdpbGwgcmVjZWl2ZSBtZXNzYWdlcyBpblxuICAqIGFycml2YWwtb3JkZXIuXG4gICovXG4gIHB1YmxpYyBhdHRhY2goIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMucHVzaCggY2hhbm5lbCApO1xuXG4gICAgY2hhbm5lbC5hZGRFbmRQb2ludCggdGhpcyApO1xuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGEgc3BlY2lmaWMgQ2hhbm5lbCBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2goIGNoYW5uZWxUb0RldGFjaDogQ2hhbm5lbCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fY2hhbm5lbHMuaW5kZXhPZiggY2hhbm5lbFRvRGV0YWNoICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICBjaGFubmVsVG9EZXRhY2gucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBEZXRhY2ggYWxsIENoYW5uZWxzIGZyb20gdGhpcyBFbmRQb2ludC5cbiAgKi9cbiAgcHVibGljIGRldGFjaEFsbCgpXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcbiAgICB9ICk7XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQXJlIGFueSBjaGFubmVscyBhdHRhY2hlZCB0byB0aGlzIEVuZFBvaW50P1xuICAqXG4gICogQHJldHVybnMgdHJ1ZSBpZiBFbmRwb2ludCBpcyBhdHRhY2hlZCB0byBhdC1sZWFzdC1vbmUgQ2hhbm5lbFxuICAqL1xuICBnZXQgYXR0YWNoZWQoKVxuICB7XG4gICAgcmV0dXJuICggdGhpcy5fY2hhbm5lbHMubGVuZ3RoID4gMCApO1xuICB9XG5cbiAgZ2V0IGRpcmVjdGlvbigpOiBEaXJlY3Rpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9kaXJlY3Rpb247XG4gIH1cblxuICAvKipcbiAgKiBIYW5kbGUgYW4gaW5jb21pbmcgTWVzc2FnZSwgbWV0aG9kIGNhbGxlZCBieSBDaGFubmVsLlxuICAqL1xuICBwdWJsaWMgaGFuZGxlTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCBmcm9tRW5kUG9pbnQ6IEVuZFBvaW50LCBmcm9tQ2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzLmZvckVhY2goIG1lc3NhZ2VMaXN0ZW5lciA9PiB7XG4gICAgICBtZXNzYWdlTGlzdGVuZXIoIG1lc3NhZ2UsIHRoaXMsIGZyb21DaGFubmVsICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIE1lc3NhZ2UuXG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLmZvckVhY2goIGNoYW5uZWwgPT4ge1xuICAgICAgY2hhbm5lbC5zZW5kTWVzc2FnZSggdGhpcywgbWVzc2FnZSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGEgZGVsZWdhdGUgdG8gcmVjZWl2ZSBpbmNvbWluZyBNZXNzYWdlc1xuICAqXG4gICogQHBhcmFtIG1lc3NhZ2VMaXN0ZW5lciAtIGRlbGVnYXRlIHRvIGJlIGNhbGxlZCB3aXRoIHJlY2VpdmVkIE1lc3NhZ2VcbiAgKi9cbiAgcHVibGljIG9uTWVzc2FnZSggbWVzc2FnZUxpc3RlbmVyOiBIYW5kbGVNZXNzYWdlRGVsZWdhdGUgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5wdXNoKCBtZXNzYWdlTGlzdGVuZXIgKTtcbiAgfVxufVxuXG4vKipcbiogQW4gaW5kZXhlZCBjb2xsZWN0aW9uIG9mIEVuZFBvaW50IG9iamVjdHMsIG5vcm1hbGx5IGluZGV4ZWQgdmlhIEVuZFBvaW50J3NcbiogdW5pcXVlIGlkZW50aWZpZXJcbiovXG5leHBvcnQgdHlwZSBFbmRQb2ludENvbGxlY3Rpb24gPSB7IFtpZDogc3RyaW5nXTogRW5kUG9pbnQ7IH07XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IEtpbmQsIEtpbmRJbmZvIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuZXhwb3J0IGVudW0gUHJvdG9jb2xUeXBlQml0c1xue1xuICBQQUNLRVQgPSAwLCAgICAgICAgIC8qKiBEYXRhZ3JhbS1vcmllbnRlZCAoYWx3YXlzIGNvbm5lY3RlZC4uLikgKi9cbiAgU1RSRUFNID0gMSwgICAgICAgICAvKiogQ29ubmVjdGlvbi1vcmllbnRlZCAqL1xuXG4gIE9ORVdBWSA9IDAsICAgICAgICAgLyoqIFVuaWRpcmVjdGlvbmFsIE9VVCAoc291cmNlKSAtPiBJTiAoc2luaykgKi9cbiAgQ0xJRU5UU0VSVkVSID0gNCwgICAvKiogQ29tbWFuZCBPVVQtPklOLCBSZXNwb25zZSBJTi0+T1VUICovXG4gIFBFRVIyUEVFUiA9IDYsICAgICAgLyoqIEJpZGlyZWN0aW9uYWw6IElOT1VUIDwtPiBJTk9VVCAqL1xuXG4gIFVOVFlQRUQgPSAwLCAgICAgICAgLyoqIFVudHlwZWQgZGF0YSAqL1xuICBUWVBFRCA9IDgsICAgICAgICAgIC8qKiBUeXBlZCBkYXRhICoqL1xufVxuXG5leHBvcnQgdHlwZSBQcm90b2NvbFR5cGUgPSBudW1iZXI7XG5cbmV4cG9ydCBjbGFzcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSAwO1xufVxuXG4vKipcbiogQSBDbGllbnQtU2VydmVyIFByb3RvY29sLCB0byBiZSB1c2VkIGJldHdlZW5cbiovXG5jbGFzcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxUPiBleHRlbmRzIFByb3RvY29sPFQ+XG57XG4gIHN0YXRpYyBwcm90b2NvbFR5cGU6IFByb3RvY29sVHlwZSA9IFByb3RvY29sVHlwZUJpdHMuQ0xJRU5UU0VSVkVSIHwgUHJvdG9jb2xUeXBlQml0cy5UWVBFRDtcbn1cblxuY2xhc3MgQVBEVSBpbXBsZW1lbnRzIEtpbmQge1xuICBraW5kSW5mbzogS2luZEluZm87XG4gIHByb3BlcnRpZXM7XG59XG5cbmNsYXNzIEFQRFVNZXNzYWdlIGV4dGVuZHMgTWVzc2FnZTxBUERVPlxue1xufVxuXG5jbGFzcyBBUERVUHJvdG9jb2wgZXh0ZW5kcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxBUERVTWVzc2FnZT5cbntcblxufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuLyoqXG4qIEBjbGFzcyBQb3J0SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIGNvbXBvbmVudCdzIFBvcnRcbiovXG5leHBvcnQgY2xhc3MgUG9ydEluZm9cbntcbiAgLyoqXG4gICogRGlyZWN0aW9uOiBJTiwgT1VULCBvciBJTk9VVFxuICAqICAgZm9yIGNsaWVudC1zZXJ2ZXIsIE9VVD1DbGllbnQsIElOPVNlcnZlclxuICAqICAgZm9yIHNvY2tldFxuICAqL1xuICBkaXJlY3Rpb246IERpcmVjdGlvbjtcblxuICAvKipcbiAgKiBQcm90b2NvbCBpbXBsZW1lbnRlZCBieSB0aGUgcG9ydFxuICAqL1xuICBwcm90b2NvbDogUHJvdG9jb2w8YW55PjtcblxuICAvKipcbiAgKiBSRlUgLSBpbmRleGFibGUgcG9ydHNcbiAgKi9cbiAgaW5kZXg6IG51bWJlciA9IDA7XG5cbiAgLyoqXG4gICogdHJ1ZSBpcyBwb3J0IG11c3QgYmUgY29ubmVjdGVkIGZvciBjb21wb25lbnQgdG8gZXhlY3V0ZVxuICAqL1xuICByZXF1aXJlZDogYm9vbGVhbiA9IGZhbHNlO1xufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5cbi8qKlxuKiBAY2xhc3MgQ29tcG9uZW50SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIENvbXBvbmVudFxuKi9cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRJbmZvXG57XG4gIC8qKlxuICAqIENvbXBvbmVudCBOYW1lXG4gICovXG4gIG5hbWU6IHN0cmluZztcblxuICAvKipcbiAgKiBCcmllZiBkZXNjcmlwdGlvbiBmb3IgdGhlIGNvbXBvbmVudCwgdG8gYXBwZWFyIGluICdoaW50J1xuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIExpbmsgdG8gZGV0YWlsZWQgaW5mb3JtYXRpb24gZm9yIHRoZSBjb21wb25lbnRcbiAgKi9cbiAgZGV0YWlsTGluazogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQ2F0ZWdvcnkgbmFtZSBmb3IgdGhlIGNvbXBvbmVudCwgZ3JvdXBzIHNhbWUgY2F0ZWdvcmllcyB0b2dldGhlclxuICAqL1xuICBjYXRlZ29yeTogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQXV0aG9yJ3MgbmFtZVxuICAqL1xuICBhdXRob3I6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIEFycmF5IG9mIFBvcnQgZGVzY3JpcHRvcnMuIFdoZW4gYWN0aXZlLCB0aGUgY29tcG9uZW50IHdpbGwgY29tbXVuaWNhdGVcbiAgKiB0aHJvdWdoIGNvcnJlc3BvbmRpbmcgRW5kUG9pbnRzXG4gICovXG4gIHBvcnRzOiB7IFtpZDogc3RyaW5nXTogUG9ydEluZm8gfSA9IHt9O1xuICBzdG9yZXM6IHsgW2lkOiBzdHJpbmddOiBQb3J0SW5mbyB9ID0ge307XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cbn1cbiIsIlxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgY29tcG9uZW50J3MgU3RvcmVcbiogVE9ETzogXG4qL1xuZXhwb3J0IGNsYXNzIFN0b3JlSW5mb1xue1xufVxuIiwiaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5pbXBvcnQgeyBTdG9yZUluZm8gfSBmcm9tICcuL3N0b3JlLWluZm8nO1xuaW1wb3J0IHsgQ29tcG9uZW50SW5mbyB9IGZyb20gJy4vY29tcG9uZW50LWluZm8nO1xuaW1wb3J0IHsgRW5kUG9pbnQsIERpcmVjdGlvbiB9IGZyb20gJy4uL21lc3NhZ2luZy9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgUHJvdG9jb2wgfSBmcm9tICcuLi9tZXNzYWdpbmcvcHJvdG9jb2wnO1xuaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5cbi8qKlxuKiBCdWlsZGVyIGZvciAnQ29tcG9uZW50JyBtZXRhZGF0YSAoc3RhdGljIGNvbXBvbmVudEluZm8pXG4qL1xuZXhwb3J0IGNsYXNzIENvbXBvbmVudEJ1aWxkZXJcbntcbiAgcHJpdmF0ZSBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvcjtcblxuICBjb25zdHJ1Y3RvciggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGNhdGVnb3J5Pzogc3RyaW5nICkge1xuXG4gICAgdGhpcy5jdG9yID0gY3RvcjtcblxuICAgIGN0b3IuY29tcG9uZW50SW5mbyA9IHtcbiAgICAgIG5hbWU6IGN0b3IubmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBkZXNjcmlwdGlvbixcbiAgICAgIGRldGFpbExpbms6ICcnLFxuICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5LFxuICAgICAgYXV0aG9yOiAnJyxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIHN0b3Jlczoge31cbiAgICB9O1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciwgZGVzY3JpcHRpb246IHN0cmluZywgY2F0ZWdvcnk/OiBzdHJpbmcgKTogQ29tcG9uZW50QnVpbGRlclxuICB7XG4gICAgbGV0IGJ1aWxkZXIgPSBuZXcgQ29tcG9uZW50QnVpbGRlciggY3RvciwgZGVzY3JpcHRpb24sIGNhdGVnb3J5ICk7XG5cbiAgICByZXR1cm4gYnVpbGRlcjtcbiAgfVxuXG4gIHB1YmxpYyBwb3J0KCBpZDogc3RyaW5nLCBkaXJlY3Rpb246IERpcmVjdGlvbiwgb3B0cz86IHsgcHJvdG9jb2w/OiBQcm90b2NvbDxhbnk+OyBpbmRleD86IG51bWJlcjsgcmVxdWlyZWQ/OiBib29sZWFuIH0gKTogQ29tcG9uZW50QnVpbGRlclxuICB7XG4gICAgb3B0cyA9IG9wdHMgfHwge307XG5cbiAgICB0aGlzLmN0b3IuY29tcG9uZW50SW5mby5wb3J0c1sgaWQgXSA9IHtcbiAgICAgIGRpcmVjdGlvbjogZGlyZWN0aW9uLFxuICAgICAgcHJvdG9jb2w6IG9wdHMucHJvdG9jb2wsXG4gICAgICBpbmRleDogb3B0cy5pbmRleCxcbiAgICAgIHJlcXVpcmVkOiBvcHRzLnJlcXVpcmVkXG4gICAgfTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgcHVibGljIG5hbWUoIG5hbWU6IHN0cmluZyApIHtcbiAgICB0aGlzLmN0b3IuY29tcG9uZW50SW5mby5uYW1lID0gbmFtZTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxufVxuXG4vKipcbiogQ29tcG9uZW50cyBhcmUgcnVudGltZSBvYmplY3RzIHRoYXQgZXhlY3V0ZSB3aXRoaW4gYSBHcmFwaC5cbiogQSBncmFwaCBOb2RlIGlzIGEgcGxhY2Vob2xkZXIgZm9yIHRoZSBhY3R1YWwgQ29tcG9uZW50IHRoYXRcbiogd2lsbCBleGVjdXRlLlxuKiBUaGlzIGludGVyZmFjZSBkZWZpbmVzIHRoZSBzdGFuZGFyZCBtZXRob2RzIGFuZCBwcm9wZXJ0aWVzIHRoYXQgYSBDb21wb25lbnRcbiogY2FuIG9wdGlvbmFsbHkgaW1wbGVtZW50LlxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ29tcG9uZW50XG57XG4gIGluaXRpYWxpemU/KCBjb25maWc6IEtpbmQgKTogRW5kUG9pbnRbXTtcbiAgdGVhcmRvd24/KCk7XG5cbiAgc3RhcnQ/KCk7XG4gIHN0b3A/KCk7XG5cbiAgcGF1c2U/KCk7XG4gIHJlc3VtZT8oKTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDb21wb25lbnRDb25zdHJ1Y3Rvclxue1xuICBuZXcgKCAuLi5hcmdzICk6IENvbXBvbmVudDtcblxuICBjb21wb25lbnRJbmZvPzogQ29tcG9uZW50SW5mbztcbn1cblxuLyoqXG4qIEV4YW1wbGUgdXNhZ2UgLi4uLlxuKi9cbmNsYXNzIEMgaW1wbGVtZW50cyBDb21wb25lbnQge1xuXG59XG5cbkNvbXBvbmVudEJ1aWxkZXIuaW5pdCggQywgJ1Rlc3QgQ29tcG9uZW50JyApXG4gICAgICAgICAgICAgICAgLnBvcnQoICdwMScsIERpcmVjdGlvbi5JTiApXG4gICAgICAgICAgICAgICAgO1xuIiwiaW1wb3J0IHsgQ29udGFpbmVyLCBhdXRvaW5qZWN0IGFzIGluamVjdCB9IGZyb20gJ2F1cmVsaWEtZGVwZW5kZW5jeS1pbmplY3Rpb24nO1xuaW1wb3J0IHsgbWV0YWRhdGEgfSBmcm9tICdhdXJlbGlhLW1ldGFkYXRhJztcblxuZXhwb3J0IHsgQ29udGFpbmVyLCBpbmplY3QgfTtcbmV4cG9ydCBpbnRlcmZhY2UgSW5qZWN0YWJsZSB7XG4gIG5ldyggLi4uYXJncyApOiBPYmplY3Q7XG59XG4iLCJpbXBvcnQgeyBFdmVudEFnZ3JlZ2F0b3IsIFN1YnNjcmlwdGlvbiwgSGFuZGxlciBhcyBFdmVudEhhbmRsZXIgfSBmcm9tICdhdXJlbGlhLWV2ZW50LWFnZ3JlZ2F0b3InO1xuXG4vL2V4cG9ydCB7IEV2ZW50SGFuZGxlciB9O1xuXG5leHBvcnQgY2xhc3MgRXZlbnRIdWJcbntcbiAgX2V2ZW50QWdncmVnYXRvcjogRXZlbnRBZ2dyZWdhdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IgPSBuZXcgRXZlbnRBZ2dyZWdhdG9yKCk7XG4gIH1cblxuICBwdWJsaWMgcHVibGlzaCggZXZlbnQ6IHN0cmluZywgZGF0YT86IGFueSApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IucHVibGlzaCggZXZlbnQsIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmUoIGV2ZW50OiBzdHJpbmcsIGhhbmRsZXI6IEZ1bmN0aW9uICk6IFN1YnNjcmlwdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2V2ZW50QWdncmVnYXRvci5zdWJzY3JpYmUoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cblxuICBwdWJsaWMgc3Vic2NyaWJlT25jZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZU9uY2UoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cbn1cblxuLypmdW5jdGlvbiBldmVudEh1YigpOiBhbnkge1xuICByZXR1cm4gZnVuY3Rpb24gZXZlbnRIdWI8VEZ1bmN0aW9uIGV4dGVuZHMgRnVuY3Rpb24sIEV2ZW50SHViPih0YXJnZXQ6IFRGdW5jdGlvbik6IFRGdW5jdGlvbiB7XG5cbiAgICB0YXJnZXQucHJvdG90eXBlLnN1YnNjcmliZSA9IG5ld0NvbnN0cnVjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUodGFyZ2V0LnByb3RvdHlwZSk7XG4gICAgbmV3Q29uc3RydWN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gdGFyZ2V0O1xuXG4gICAgcmV0dXJuIDxhbnk+IG5ld0NvbnN0cnVjdG9yO1xuICB9XG59XG5cbkBldmVudEh1YigpXG5jbGFzcyBNeUNsYXNzIHt9O1xuKi9cbiIsIi8vZW51bSBLZXlUeXBlIHsgXCJwdWJsaWNcIiwgXCJwcml2YXRlXCIsIFwic2VjcmV0XCIgfTtcblxuLy9lbnVtIEtleVVzYWdlIHsgXCJlbmNyeXB0XCIsIFwiZGVjcnlwdFwiLCBcInNpZ25cIiwgXCJ2ZXJpZnlcIiwgXCJkZXJpdmVLZXlcIiwgXCJkZXJpdmVCaXRzXCIsIFwid3JhcEtleVwiLCBcInVud3JhcEtleVwiIH07XG5cbmV4cG9ydCBjbGFzcyBLZXkgLy9pbXBsZW1lbnRzIENyeXB0b0tleVxue1xuICBwcm90ZWN0ZWQgaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgY3J5cHRvS2V5OiBDcnlwdG9LZXk7XG5cbiAgY29uc3RydWN0b3IoIGlkOiBzdHJpbmcsIGtleT86IENyeXB0b0tleSApXG4gIHtcbiAgICB0aGlzLmlkID0gaWQ7XG5cbiAgICBpZiAoIGtleSApXG4gICAgICB0aGlzLmNyeXB0b0tleSA9IGtleTtcbiAgICBlbHNlXG4gICAge1xuICAgICAgdGhpcy5jcnlwdG9LZXkgPVxuICAgICAge1xuICAgICAgICB0eXBlOiBcIlwiLFxuICAgICAgICBhbGdvcml0aG06IFwiXCIsXG4gICAgICAgIGV4dHJhY3RhYmxlOiB0cnVlLFxuICAgICAgICB1c2FnZXM6IFtdXG4gICAgICB9O1xuICAgIH1cblxuICB9XG5cbiAgcHVibGljIGdldCB0eXBlKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuY3J5cHRvS2V5LnR5cGU7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGFsZ29yaXRobSgpOiBLZXlBbGdvcml0aG1cbiAge1xuICAgIHJldHVybiB0aGlzLmNyeXB0b0tleS5hbGdvcml0aG07XG4gIH1cblxuICBwdWJsaWMgZ2V0IGV4dHJhY3RhYmxlKCk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLmNyeXB0b0tleS5leHRyYWN0YWJsZTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgdXNhZ2VzKCk6IHN0cmluZ1tdXG4gIHtcbiAgICByZXR1cm4gdGhpcy5jcnlwdG9LZXkudXNhZ2VzO1xuICB9XG5cbiAgcHVibGljIGdldCBpbm5lcktleSgpOiBDcnlwdG9LZXlcbiAge1xuICAgIHJldHVybiB0aGlzLmNyeXB0b0tleTtcbiAgfVxuLyogIGdldENvbXBvbmVudCggY29tcG9uZW50SUQ6IHN0cmluZyApOiBhbnlcbiAge1xuICAgIHJldHVybiB0aGlzLmtleUNvbXBvbmVudHNbIGNvbXBvbmVudElEIF07XG4gIH1cblxuICBzZXRDb21wb25lbnQoIGNvbXBvbmVudElEOiBzdHJpbmcsIHZhbHVlOiBhbnkgKVxuICB7XG4gICAgdGhpcy5rZXlDb21wb25lbnRzWyBjb21wb25lbnRJRCBdID0gdmFsdWU7XG4gIH0qL1xufVxuIiwiaW1wb3J0IHsgS2V5IH0gZnJvbSAnLi9rZXknO1xuXG5leHBvcnQgY2xhc3MgUHJpdmF0ZUtleSBleHRlbmRzIEtleVxue1xuXG59XG4iLCJpbXBvcnQgeyBLZXkgfSBmcm9tICcuL2tleSc7XG5cbmV4cG9ydCBjbGFzcyBQdWJsaWNLZXkgZXh0ZW5kcyBLZXlcbntcblxufVxuIiwiaW1wb3J0IHsgUHJpdmF0ZUtleSB9IGZyb20gJy4vcHJpdmF0ZS1rZXknO1xuaW1wb3J0IHsgUHVibGljS2V5IH0gZnJvbSAnLi9wdWJsaWMta2V5JztcblxuZXhwb3J0IGNsYXNzIEtleVBhaXJcbntcbiAgcHJpdmF0ZUtleTogUHJpdmF0ZUtleTtcbiAgcHVibGljS2V5OiBQdWJsaWNLZXk7XG59XG4iLCJpbXBvcnQgeyBCeXRlQXJyYXkgfSBmcm9tICcuLi9raW5kL2J5dGUtYXJyYXknO1xuaW1wb3J0IHsgS2V5IH0gZnJvbSAnLi9rZXknO1xuaW1wb3J0IHsgUHJpdmF0ZUtleSB9IGZyb20gJy4vcHJpdmF0ZS1rZXknO1xuaW1wb3J0IHsgUHVibGljS2V5IH0gZnJvbSAnLi9wdWJsaWMta2V5JztcbmltcG9ydCB7IEtleVBhaXIgfSBmcm9tICcuL2tleS1wYWlyJztcblxuZGVjbGFyZSB2YXIgbXNyY3J5cHRvO1xuXG5leHBvcnQgY2xhc3MgQ3J5cHRvZ3JhcGhpY1NlcnZpY2Uge1xuICBwcm90ZWN0ZWQgY3J5cHRvOiBTdWJ0bGVDcnlwdG87XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5jcnlwdG8gPSB3aW5kb3cuY3J5cHRvLnN1YnRsZTtcblxuICAgIGlmICggIXRoaXMuY3J5cHRvICYmIG1zcmNyeXB0byApXG4gICAgICAgdGhpcy5jcnlwdG8gPSBtc3JjcnlwdG87XG4gIH1cblxuICBkZWNyeXB0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IEtleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB0aGlzLmNyeXB0by5kZWNyeXB0KGFsZ29yaXRobSwga2V5LmlubmVyS2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4vL2Rlcml2ZUJpdHMoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGJhc2VLZXk6IENyeXB0b0tleSwgbGVuZ3RoOiBudW1iZXIpOiBhbnk7XG4vL2Rlcml2ZUtleShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBkZXJpdmVkS2V5VHlwZTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IGFueTtcbiAgZGlnZXN0KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBkYXRhOiBCeXRlQXJyYXkpOiBhbnkge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHRoaXMuY3J5cHRvLmRpZ2VzdChhbGdvcml0aG0sIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGVuY3J5cHQoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IEtleSwgZGF0YTogQnl0ZUFycmF5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5jcnlwdG8uZW5jcnlwdChhbGdvcml0aG0sIGtleS5pbm5lcktleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuICBleHBvcnRLZXkoIGZvcm1hdDogc3RyaW5nLCBrZXk6IEtleSApOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHRoaXMuY3J5cHRvLmV4cG9ydEtleShmb3JtYXQsIGtleS5pbm5lcktleSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGdlbmVyYXRlS2V5KCBhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10gKTogUHJvbWlzZTxLZXkgfCBLZXlQYWlyPiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEtleSB8IEtleVBhaXI+KChyZXNvbHZlLCByZWplY3QpID0+IHtcblxuICAgfSk7XG4gIH1cblxuICBpbXBvcnRLZXkoZm9ybWF0OiBzdHJpbmcsIGtleURhdGE6IEJ5dGVBcnJheSAsIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEtleT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5jcnlwdG8uaW1wb3J0S2V5KGZvcm1hdCwga2V5RGF0YS5iYWNraW5nQXJyYXksIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIGtleVVzYWdlcylcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKHJlcyk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgIH0pO1xuICB9XG5cbiAgc2lnbihhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBLZXksIGRhdGE6IEJ5dGVBcnJheSk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5jcnlwdG8uc2lnbihhbGdvcml0aG0sIGtleS5pbm5lcktleSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuLy91bndyYXBLZXkoZm9ybWF0OiBzdHJpbmcsIHdyYXBwZWRLZXk6IEFycmF5QnVmZmVyVmlldywgdW53cmFwcGluZ0tleTogQ3J5cHRvS2V5LCB1bndyYXBBbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgdW53cmFwcGVkS2V5QWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogYW55O1xuICB2ZXJpZnkoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogS2V5LCBzaWduYXR1cmU6IEJ5dGVBcnJheSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB0aGlzLmNyeXB0by52ZXJpZnkoYWxnb3JpdGhtLCBrZXkuaW5uZXJLZXksIHNpZ25hdHVyZS5iYWNraW5nQXJyYXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbi8vd3JhcEtleShmb3JtYXQ6IHN0cmluZywga2V5OiBDcnlwdG9LZXksIHdyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHdyYXBBbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSk6IGFueTtcbn1cbiIsImltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcblxuLyoqXG4qIEEgUG9ydCBpcyBhIHBsYWNlaG9sZGVyIGZvciBhbiBFbmRQb2ludCBwdWJsaXNoZWQgYnkgdGhlIHVuZGVybHlpbmdcbiogY29tcG9uZW50IG9mIGEgTm9kZS5cbiovXG5leHBvcnQgY2xhc3MgUG9ydFxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBOb2RlO1xuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2VuZFBvaW50OiBFbmRQb2ludDtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IE5vZGUsIGVuZFBvaW50OiBFbmRQb2ludCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgLy8gV2FzIGFuIEVuZFBvaW50IHN1cHBsaWVkP1xuICAgIGlmICggIWVuZFBvaW50IClcbiAgICB7XG4gICAgICBsZXQgZGlyZWN0aW9uID0gYXR0cmlidXRlcy5kaXJlY3Rpb24gfHwgRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgICBpZiAoIHR5cGVvZiBhdHRyaWJ1dGVzLmRpcmVjdGlvbiA9PSBcInN0cmluZ1wiIClcbiAgICAgICAgZGlyZWN0aW9uID0gRGlyZWN0aW9uWyBkaXJlY3Rpb24udG9VcHBlckNhc2UoKSBdO1xuXG4gICAgICAvLyBDcmVhdGUgYSBcImR1bW15XCIgZW5kUG9pbnQgd2l0aCBjb3JyZWN0IGlkICsgZGlyZWN0aW9uXG4gICAgICBlbmRQb2ludCA9IG5ldyBFbmRQb2ludCggYXR0cmlidXRlcy5pZCwgZGlyZWN0aW9uICk7XG4gICAgfVxuXG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnQoKSB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50O1xuICB9XG4gIHB1YmxpYyBzZXQgZW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApIHtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0ge1xuICAgICAgaWQ6IHRoaXMuX2VuZFBvaW50LmlkLFxuICAgICAgZGlyZWN0aW9uOiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24sXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgfTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIG93bmVyXG4gICAqL1xuICBnZXQgb3duZXIoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyXG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgcHJvdG9jb2wgSURcbiAgICovXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgRW5kUG9pbnQgSURcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5pZDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBEaXJlY3Rpb25cbiAgICovXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uO1xuICB9XG5cbn1cblxuZXhwb3J0IGNsYXNzIFB1YmxpY1BvcnQgZXh0ZW5kcyBQb3J0XG57XG4gIHByb3h5RW5kUG9pbnQ6IEVuZFBvaW50O1xuICBwcm94eUNoYW5uZWw6IENoYW5uZWw7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGVuZFBvaW50LCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsZXQgcHJveHlEaXJlY3Rpb24gPVxuICAgICAgKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLklOIClcbiAgICAgICAgPyBEaXJlY3Rpb24uT1VUXG4gICAgICAgIDogKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLk9VVCApXG4gICAgICAgICAgPyBEaXJlY3Rpb24uSU5cbiAgICAgICAgICA6IERpcmVjdGlvbi5JTk9VVDtcblxuICAgIC8vIENyZWF0ZSBhbiBFbmRQb2ludCB0byBwcm94eSBiZXR3ZWVuIHRoZSBQdWJsaWMgYW5kIFByaXZhdGUgKGludGVybmFsKVxuICAgIC8vIHNpZGVzIG9mIHRoZSBQb3J0LlxuICAgIHRoaXMucHJveHlFbmRQb2ludCA9IG5ldyBFbmRQb2ludCggdGhpcy5fZW5kUG9pbnQuaWQsIHByb3h5RGlyZWN0aW9uICk7XG5cbiAgICAvLyBXaXJlLXVwIHByb3h5IC1cblxuICAgIC8vIEZvcndhcmQgaW5jb21pbmcgcGFja2V0cyAoZnJvbSBwdWJsaWMgaW50ZXJmYWNlKSB0byBwcml2YXRlXG4gICAgdGhpcy5wcm94eUVuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5fZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgdGhpcy5wcm94eUVuZFBvaW50LCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICAgIH0pO1xuXG4gICAgLy8gRm9yd2FyZCBvdXRnb2luZyBwYWNrZXRzIChmcm9tIHByaXZhdGUgaW50ZXJmYWNlKSB0byBwdWJsaWNcbiAgICB0aGlzLl9lbmRQb2ludC5vbk1lc3NhZ2UoICggbWVzc2FnZSApID0+IHtcbiAgICAgIHRoaXMucHJveHlFbmRQb2ludC5zZW5kTWVzc2FnZSggbWVzc2FnZSApO1xuICAgIH0pO1xuXG4gICAgLy8gbm90IHlldCBjb25uZWN0ZWRcbiAgICB0aGlzLnByb3h5Q2hhbm5lbCA9IG51bGw7XG4gIH1cblxuICAvLyBDb25uZWN0IHRvIFByaXZhdGUgKGludGVybmFsKSBFbmRQb2ludC4gVG8gYmUgY2FsbGVkIGR1cmluZyBncmFwaFxuICAvLyB3aXJlVXAgcGhhc2VcbiAgcHVibGljIGNvbm5lY3RQcml2YXRlKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMucHJveHlDaGFubmVsID0gY2hhbm5lbDtcblxuICAgIHRoaXMucHJveHlFbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIHB1YmxpYyBkaXNjb25uZWN0UHJpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQuZGV0YWNoKCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgcG9ydCA9IHN1cGVyLnRvT2JqZWN0KCBvcHRzICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBOb2RlIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgcHJvdGVjdGVkIF9vd25lcjogR3JhcGg7XG4gIHByb3RlY3RlZCBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2NvbXBvbmVudDogc3RyaW5nO1xuICBwcm90ZWN0ZWQgX2luaXRpYWxEYXRhOiBPYmplY3Q7XG5cbiAgcHJvdGVjdGVkIF9wb3J0czogTWFwPHN0cmluZywgUG9ydD47XG5cbiAgcHVibGljIG1ldGFkYXRhOiBhbnk7XG5cbiAgLyoqXG4gICAqIFJ1bnRpbWUgYW5kIGNvbXBvbmVudCBpbnN0YW5jZSB0aGF0IHRoaXMgbm9kZSByZXByZXNlbnRzXG4gICAqL1xuICBwcm90ZWN0ZWQgX2NvbnRleHQ6IFJ1bnRpbWVDb250ZXh0O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9vd25lciA9IG93bmVyO1xuICAgIHRoaXMuX2lkID0gYXR0cmlidXRlcy5pZCB8fCAnJztcbiAgICB0aGlzLl9jb21wb25lbnQgPSBhdHRyaWJ1dGVzLmNvbXBvbmVudDtcbiAgICB0aGlzLl9pbml0aWFsRGF0YSA9IGF0dHJpYnV0ZXMuaW5pdGlhbERhdGEgfHwge307XG5cbiAgICB0aGlzLl9wb3J0cyA9IG5ldyBNYXA8c3RyaW5nLCBQb3J0PigpO1xuXG4gICAgdGhpcy5tZXRhZGF0YSA9IGF0dHJpYnV0ZXMubWV0YWRhdGEgfHwgeyB9O1xuXG4gICAgLy8gSW5pdGlhbGx5IGNyZWF0ZSAncGxhY2Vob2xkZXInIHBvcnRzLiBPbmNlIGNvbXBvbmVudCBoYXMgYmVlblxuICAgIC8vIGxvYWRlZCBhbmQgaW5zdGFudGlhdGVkLCB0aGV5IHdpbGwgYmUgY29ubmVjdGVkIGNvbm5lY3RlZCB0b1xuICAgIC8vIHRoZSBjb21wb25lbnQncyBjb21tdW5pY2F0aW9uIGVuZC1wb2ludHNcbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5wb3J0cyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGRQbGFjZWhvbGRlclBvcnQoIGlkLCBhdHRyaWJ1dGVzLnBvcnRzWyBpZCBdICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBub2RlID0ge1xuICAgICAgaWQ6IHRoaXMuaWQsXG4gICAgICBjb21wb25lbnQ6IHRoaXMuX2NvbXBvbmVudCxcbiAgICAgIGluaXRpYWxEYXRhOiB0aGlzLl9pbml0aWFsRGF0YSxcbiAgICAgIHBvcnRzOiB7fSxcbiAgICAgIG1ldGFkYXRhOiB0aGlzLm1ldGFkYXRhXG4gICAgfTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICBub2RlLnBvcnRzWyBpZCBdID0gcG9ydC50b09iamVjdCgpO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIG93bmVyXG4gICAqL1xuICBwdWJsaWMgZ2V0IG93bmVyKCk6IEdyYXBoIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXJcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIE5vZGUncyBpZFxuICAgKi9cbiAgZ2V0IGlkKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX2lkO1xuICB9XG4gIC8qKlxuICAgKiBTZXQgdGhlIE5vZGUncyBpZFxuICAgKiBAcGFyYW0gaWQgLSBuZXcgaWRlbnRpZmllclxuICAgKi9cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBwdWJsaWMgdXBkYXRlUG9ydHMoIGVuZFBvaW50czogRW5kUG9pbnRbXSApIHtcbiAgICBsZXQgY3VycmVudFBvcnRzID0gdGhpcy5fcG9ydHM7XG4gICAgbGV0IG5ld1BvcnRzOiBNYXA8c3RyaW5nLFBvcnQ+ID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICAvLyBQYXJhbSBlbmRQb2ludHMgaXMgYW4gYXJyYXkgb2YgRW5kUG9pbnRzIGV4cG9ydGVkIGJ5IGEgY29tcG9uZW50XG4gICAgLy8gdXBkYXRlIG91ciBtYXAgb2YgUG9ydHMgdG8gcmVmbGVjdCB0aGlzIGFycmF5XG4gICAgLy8gVGhpcyBtYXkgbWVhbiBpbmNsdWRpbmcgYSBuZXcgUG9ydCwgdXBkYXRpbmcgYW4gZXhpc3RpbmcgUG9ydCB0b1xuICAgIC8vIHVzZSB0aGlzIHN1cHBsaWVkIEVuZFBvaW50LCBvciBldmVuIGRlbGV0aW5nIGEgJ25vLWxvbmdlcicgdmFsaWQgUG9ydFxuICAgIGVuZFBvaW50cy5mb3JFYWNoKCAoZXA6IEVuZFBvaW50ICkgPT4ge1xuICAgICAgbGV0IGlkID0gZXAuaWQ7XG5cbiAgICAgIGlmICggY3VycmVudFBvcnRzLmhhcyggaWQgKSApIHtcbiAgICAgICAgbGV0IHBvcnQgPSBjdXJyZW50UG9ydHMuZ2V0KCBpZCApO1xuXG4gICAgICAgIHBvcnQuZW5kUG9pbnQgPSBlcDtcblxuICAgICAgICBuZXdQb3J0cy5zZXQoIGlkLCBwb3J0ICk7XG5cbiAgICAgICAgY3VycmVudFBvcnRzLmRlbGV0ZSggaWQgKTtcbiAgICAgIH1cbiAgICAgIGVsc2Uge1xuICAgICAgICAvLyBlbmRQb2ludCBub3QgZm91bmQsIGNyZWF0ZSBhIHBvcnQgZm9yIGl0XG4gICAgICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIGVwLCB7IGlkOiBpZCwgZGlyZWN0aW9uOiBlcC5kaXJlY3Rpb24gfSApO1xuXG4gICAgICAgIG5ld1BvcnRzLnNldCggaWQsIHBvcnQgKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3UG9ydHM7XG4gIH1cblxuXG4gIC8qKlxuICAgKiBBZGQgYSBwbGFjZWhvbGRlciBQb3J0XG4gICAqL1xuICBwcm90ZWN0ZWQgYWRkUGxhY2Vob2xkZXJQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBwb3J0cyBhcyBhbiBhcnJheSBvZiBQb3J0c1xuICAgKlxuICAgKiBAcmV0dXJuIFBvcnRbXVxuICAgKi9cbiAgZ2V0IHBvcnRzKCk6IE1hcDxzdHJpbmcsIFBvcnQ+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHM7XG4gIH1cblxuICBnZXRQb3J0QXJyYXkoKTogUG9ydFtdIHtcbiAgICBsZXQgeHBvcnRzOiBQb3J0W10gPSBbXTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICB4cG9ydHMucHVzaCggcG9ydCApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiB4cG9ydHM7XG4gIH1cblxuICAvKipcbiAgICogTG9va3VwIGEgUG9ydCBieSBpdCdzIElEXG4gICAqIEBwYXJhbSBpZCAtIHBvcnQgaWRlbnRpZmllclxuICAgKlxuICAgKiBAcmV0dXJuIFBvcnQgb3IgdW5kZWZpbmVkXG4gICAqL1xuICBnZXRQb3J0QnlJRCggaWQ6IHN0cmluZyApOiBQb3J0XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICB9XG5cbiAgaWRlbnRpZnlQb3J0KCBpZDogc3RyaW5nLCBwcm90b2NvbElEPzogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHZhciBwb3J0OiBQb3J0O1xuXG4gICAgaWYgKCBpZCApXG4gICAgICBwb3J0ID0gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICAgIGVsc2UgaWYgKCBwcm90b2NvbElEIClcbiAgICB7XG4gICAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHAsIGlkICkgPT4ge1xuICAgICAgICBpZiAoIHAucHJvdG9jb2xJRCA9PSBwcm90b2NvbElEIClcbiAgICAgICAgICBwb3J0ID0gcDtcbiAgICAgIH0sIHRoaXMgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmUgYSBQb3J0IGZyb20gdGhpcyBOb2RlXG4gICAqIEBwYXJhbSBpZCAtIGlkZW50aWZpZXIgb2YgUG9ydCB0byBiZSByZW1vdmVkXG4gICAqIEByZXR1cm4gdHJ1ZSAtIHBvcnQgcmVtb3ZlZFxuICAgKiAgICAgICAgIGZhbHNlIC0gcG9ydCBpbmV4aXN0ZW50XG4gICAqL1xuICByZW1vdmVQb3J0KCBpZDogc3RyaW5nICk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMudW5sb2FkQ29tcG9uZW50KCk7XG5cbiAgICAvLyBHZXQgYSBDb21wb25lbnRDb250ZXh0IHJlc3BvbnNhYmxlIGZvciBDb21wb25lbnQncyBsaWZlLWN5Y2xlIGNvbnRyb2xcbiAgICBsZXQgY3R4ID0gdGhpcy5fY29udGV4dCA9IGZhY3RvcnkuY3JlYXRlQ29udGV4dCggdGhpcy5fY29tcG9uZW50LCB0aGlzLl9pbml0aWFsRGF0YSApO1xuXG4gICAgLy8gTWFrZSBvdXJzZWx2ZXMgdmlzaWJsZSB0byBjb250ZXh0IChhbmQgaW5zdGFuY2UpXG4gICAgY3R4Lm5vZGUgPSB0aGlzO1xuXG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIC8vIExvYWQgY29tcG9uZW50XG4gICAgcmV0dXJuIGN0eC5sb2FkKCk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGNvbnRleHQoKTogUnVudGltZUNvbnRleHQge1xuICAgIHJldHVybiB0aGlzLl9jb250ZXh0O1xuICB9XG5cbiAgdW5sb2FkQ29tcG9uZW50KClcbiAge1xuICAgIGlmICggdGhpcy5fY29udGV4dCApXG4gICAge1xuICAgICAgdGhpcy5fY29udGV4dC5yZWxlYXNlKCk7XG5cbiAgICAgIHRoaXMuX2NvbnRleHQgPSBudWxsO1xuICAgIH1cbiAgfVxuXG59XG4iLCJpbXBvcnQgeyBLaW5kIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50LCBFbmRQb2ludENvbGxlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuLi9ncmFwaC9ub2RlJztcbmltcG9ydCB7IFBvcnQgfSBmcm9tICcuLi9ncmFwaC9wb3J0JztcbmltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4vY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgQ29tcG9uZW50IH0gZnJvbSAnLi4vY29tcG9uZW50L2NvbXBvbmVudCc7XG5cbmltcG9ydCB7IENvbnRhaW5lciwgSW5qZWN0YWJsZSB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5cbmV4cG9ydCBlbnVtIFJ1blN0YXRlIHtcbiAgTkVXQk9STiwgICAgICAvLyBOb3QgeWV0IGxvYWRlZFxuICBMT0FESU5HLCAgICAgIC8vIFdhaXRpbmcgZm9yIGFzeW5jIGxvYWQgdG8gY29tcGxldGVcbiAgTE9BREVELCAgICAgICAvLyBDb21wb25lbnQgbG9hZGVkLCBub3QgeWV0IGV4ZWN1dGFibGVcbiAgUkVBRFksICAgICAgICAvLyBSZWFkeSBmb3IgRXhlY3V0aW9uXG4gIFJVTk5JTkcsICAgICAgLy8gTmV0d29yayBhY3RpdmUsIGFuZCBydW5uaW5nXG4gIFBBVVNFRCAgICAgICAgLy8gTmV0d29yayB0ZW1wb3JhcmlseSBwYXVzZWRcbn1cblxuLyoqXG4qIFRoZSBydW50aW1lIGNvbnRleHQgaW5mb3JtYXRpb24gZm9yIGEgQ29tcG9uZW50IGluc3RhbmNlXG4qL1xuZXhwb3J0IGNsYXNzIFJ1bnRpbWVDb250ZXh0XG57XG4gIC8qKlxuICAqIFRoZSBjb21wb25lbnQgaWQgLyBhZGRyZXNzXG4gICovXG4gIHByaXZhdGUgX2lkOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogVGhlIHJ1bnRpbWUgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgKi9cbiAgcHJpdmF0ZSBfaW5zdGFuY2U6IENvbXBvbmVudDtcblxuICAvKipcbiAgKiBJbml0aWFsIERhdGEgZm9yIHRoZSBjb21wb25lbnQgaW5zdGFuY2VcbiAgKi9cbiAgcHJpdmF0ZSBfY29uZmlnOiB7fTtcblxuICAvKipcbiAgKiBUaGUgcnVudGltZSBjb21wb25lbnQgaW5zdGFuY2UgdGhhdCB0aGlzIG5vZGUgcmVwcmVzZW50c1xuICAqL1xuICBwcml2YXRlIF9jb250YWluZXI6IENvbnRhaW5lcjtcblxuICAvKipcbiAgKiBUaGUgY29tcG9uZW50IGZhY3RvcnkgdGhhdCBjcmVhdGVkIHVzXG4gICovXG4gIHByaXZhdGUgX2ZhY3Rvcnk6IENvbXBvbmVudEZhY3Rvcnk7XG5cbiAgLyoqXG4gICogVGhlIG5vZGVcbiAgKi9cbiAgcHJpdmF0ZSBfbm9kZTogTm9kZTtcblxuICAvKipcbiAgKlxuICAqXG4gICovXG4gIGNvbnN0cnVjdG9yKCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5LCBjb250YWluZXI6IENvbnRhaW5lciwgaWQ6IHN0cmluZywgY29uZmlnOiB7fSwgZGVwczogSW5qZWN0YWJsZVtdID0gW10gKSB7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gZmFjdG9yeTtcblxuICAgIHRoaXMuX2lkID0gaWQ7XG5cbiAgICB0aGlzLl9jb25maWcgPSBjb25maWc7XG5cbiAgICB0aGlzLl9jb250YWluZXIgPSBjb250YWluZXI7XG5cbiAgICAvLyBSZWdpc3RlciBhbnkgY29udGV4dCBkZXBlbmRlbmNpZXNcbiAgICBmb3IoIGxldCBpIGluIGRlcHMgKVxuICAgIHtcbiAgICAgIGlmICggIXRoaXMuX2NvbnRhaW5lci5oYXNSZXNvbHZlciggZGVwc1tpXSApIClcbiAgICAgICAgdGhpcy5fY29udGFpbmVyLnJlZ2lzdGVyU2luZ2xldG9uKCBkZXBzW2ldLCBkZXBzW2ldICk7XG4gICAgfVxuICB9XG5cbiAgZ2V0IG5vZGUoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX25vZGU7XG4gIH1cbiAgc2V0IG5vZGUoIG5vZGU6IE5vZGUgKSB7XG4gICAgdGhpcy5fbm9kZSA9IG5vZGU7XG5cbiAgICAvLyBtYWtlIG5vZGUgJ2luamVjdGFibGUnIGluIGNvbnRhaW5lclxuICAgIHRoaXMuX2NvbnRhaW5lci5yZWdpc3Rlckluc3RhbmNlKCBOb2RlLCB0aGlzICk7XG4gIH1cblxuICBnZXQgaW5zdGFuY2UoKTogQ29tcG9uZW50IHtcbiAgICByZXR1cm4gdGhpcy5faW5zdGFuY2U7XG4gIH1cblxuICBnZXQgY29udGFpbmVyKCk6IENvbnRhaW5lciB7XG4gICAgcmV0dXJuIHRoaXMuX2NvbnRhaW5lcjtcbiAgfVxuXG4gIGxvYWQoICk6IFByb21pc2U8dm9pZD5cbiAge1xuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG5cbiAgICByZXR1cm4gbmV3IFByb21pc2U8dm9pZD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIGdldCBhbiBpbnN0YW5jZSBmcm9tIHRoZSBmYWN0b3J5XG4gICAgICBtZS5fcnVuU3RhdGUgPSBSdW5TdGF0ZS5MT0FESU5HO1xuICAgICAgdGhpcy5fZmFjdG9yeS5sb2FkQ29tcG9uZW50KCB0aGlzLCB0aGlzLl9pZCApXG4gICAgICAgIC50aGVuKCAoaW5zdGFuY2UpID0+IHtcbiAgICAgICAgICAvLyBDb21wb25lbnQgKGFuZCBhbnkgZGVwZW5kZW5jaWVzKSBoYXZlIGJlZW4gbG9hZGVkXG4gICAgICAgICAgbWUuX2luc3RhbmNlID0gaW5zdGFuY2U7XG4gICAgICAgICAgbWUuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLkxPQURFRCApO1xuXG4gICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goIChlcnIpID0+IHtcbiAgICAgICAgICAvLyBVbmFibGUgdG8gbG9hZFxuICAgICAgICAgIG1lLl9ydW5TdGF0ZSA9IFJ1blN0YXRlLk5FV0JPUk47XG5cbiAgICAgICAgICByZWplY3QoIGVyciApO1xuICAgICAgICB9KTtcbiAgICB9ICk7XG4gIH1cblxuICBfcnVuU3RhdGU6IFJ1blN0YXRlID0gUnVuU3RhdGUuTkVXQk9STjtcbiAgZ2V0IHJ1blN0YXRlKCkge1xuICAgIHJldHVybiB0aGlzLl9ydW5TdGF0ZTtcbiAgfVxuXG4gIHByaXZhdGUgaW5TdGF0ZSggc3RhdGVzOiBSdW5TdGF0ZVtdICk6IGJvb2xlYW4ge1xuICAgIHJldHVybiBuZXcgU2V0PFJ1blN0YXRlPiggc3RhdGVzICkuaGFzKCB0aGlzLl9ydW5TdGF0ZSApO1xuICB9XG5cbiAgLyoqXG4gICogVHJhbnNpdGlvbiBjb21wb25lbnQgdG8gbmV3IHN0YXRlXG4gICogU3RhbmRhcmQgdHJhbnNpdGlvbnMsIGFuZCByZXNwZWN0aXZlIGFjdGlvbnMsIGFyZTpcbiAgKiAgIExPQURFRCAtPiBSRUFEWSAgICAgIGluc3RhbnRpYXRlIGFuZCBpbml0aWFsaXplIGNvbXBvbmVudFxuICAqICAgUkVBRFkgLT4gTE9BREVEICAgICAgdGVhcmRvd24gYW5kIGRlc3Ryb3kgY29tcG9uZW50XG4gICpcbiAgKiAgIFJFQURZIC0+IFJVTk5JTkcgICAgIHN0YXJ0IGNvbXBvbmVudCBleGVjdXRpb25cbiAgKiAgIFJVTk5JTkcgLT4gUkVBRFkgICAgIHN0b3AgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqXG4gICogICBSVU5OSU5HIC0+IFBBVVNFRCAgICBwYXVzZSBjb21wb25lbnQgZXhlY3V0aW9uXG4gICogICBQQVVTRUQgLT4gUlVOTklORyAgICByZXN1bWUgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqXG4gICovXG4gIHNldFJ1blN0YXRlKCBydW5TdGF0ZTogUnVuU3RhdGUgKSB7XG4gICAgbGV0IGluc3QgPSB0aGlzLmluc3RhbmNlO1xuXG4gICAgc3dpdGNoKCBydW5TdGF0ZSApIC8vIHRhcmdldCBzdGF0ZSAuLlxuICAgIHtcbiAgICAgIGNhc2UgUnVuU3RhdGUuTE9BREVEOiAvLyBqdXN0IGxvYWRlZCwgb3IgdGVhcmRvd25cbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuUkVBRFksIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gdGVhcmRvd24gYW5kIGRlc3Ryb3kgY29tcG9uZW50XG4gICAgICAgICAgaWYgKCBpbnN0LnRlYXJkb3duIClcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpbnN0LnRlYXJkb3duKCk7XG5cbiAgICAgICAgICAgIC8vIGFuZCBkZXN0cm95IGluc3RhbmNlXG4gICAgICAgICAgICB0aGlzLl9pbnN0YW5jZSA9IG51bGw7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlIFJ1blN0YXRlLlJFQURZOiAgLy8gaW5pdGlhbGl6ZSBvciBzdG9wIG5vZGVcbiAgICAgICAgaWYgKCB0aGlzLmluU3RhdGUoIFsgUnVuU3RhdGUuTE9BREVEIF0gKSApIHtcbiAgICAgICAgICAvLyBpbml0aWFsaXplIGNvbXBvbmVudFxuXG4gICAgICAgICAgbGV0IGVuZFBvaW50czogRW5kUG9pbnRbXSA9IFtdO1xuXG4gICAgICAgICAgaWYgKCBpbnN0LmluaXRpYWxpemUgKVxuICAgICAgICAgICAgZW5kUG9pbnRzID0gdGhpcy5pbnN0YW5jZS5pbml0aWFsaXplKCA8S2luZD50aGlzLl9jb25maWcgKTtcblxuICAgICAgICAgIGlmICggdGhpcy5fbm9kZSApXG4gICAgICAgICAgICB0aGlzLl9ub2RlLnVwZGF0ZVBvcnRzKCBlbmRQb2ludHMgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gc3RvcCBjb21wb25lbnRcbiAgICAgICAgICBpZiAoIGluc3Quc3RvcCApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnN0b3AoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBpbml0aWFsaXplZCwgbm90IGxvYWRlZCcgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUlVOTklORzogIC8vIHN0YXJ0L3Jlc3VtZSBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJFQURZLCBSdW5TdGF0ZS5SVU5OSU5HIF0gKSApIHtcbiAgICAgICAgICAvLyBzdGFydCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICAgICAgICAgaWYgKCBpbnN0LnN0YXJ0IClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2Uuc3RhcnQoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gcmVzdW1lIGNvbXBvbmVudCBleGVjdXRpb24gYWZ0ZXIgcGF1c2VcbiAgICAgICAgICBpZiAoIGluc3QucmVzdW1lIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UucmVzdW1lKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgc3RhcnRlZCwgbm90IHJlYWR5JyApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5QQVVTRUQ6ICAvLyBwYXVzZSBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkddICkgKSB7XG4gICAgICAgICAgaWYgKCBpbnN0LnBhdXNlIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UucGF1c2UoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gYWxyZWFkeSBwYXVzZWRcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBwYXVzZWQnICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHRoaXMuX3J1blN0YXRlID0gcnVuU3RhdGU7XG4gIH1cblxuICByZWxlYXNlKCkge1xuICAgIC8vIHJlbGVhc2UgaW5zdGFuY2UsIHRvIGF2b2lkIG1lbW9yeSBsZWFrc1xuICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBudWxsXG4gIH1cbn1cbiIsImV4cG9ydCBpbnRlcmZhY2UgTW9kdWxlTG9hZGVyIHtcbiAgaGFzTW9kdWxlPyggaWQ6IHN0cmluZyApOiBib29sZWFuO1xuXG4gIGxvYWRNb2R1bGUoIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxhbnk+O1xufVxuXG5kZWNsYXJlIGludGVyZmFjZSBTeXN0ZW0ge1xuICBub3JtYWxpemVTeW5jKCBpZCApO1xuICBpbXBvcnQoIGlkICk7XG59O1xuZGVjbGFyZSB2YXIgU3lzdGVtOiBTeXN0ZW07XG5cbmNsYXNzIE1vZHVsZVJlZ2lzdHJ5RW50cnkge1xuICBjb25zdHJ1Y3RvciggYWRkcmVzczogc3RyaW5nICkge1xuXG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFN5c3RlbU1vZHVsZUxvYWRlciBpbXBsZW1lbnRzIE1vZHVsZUxvYWRlciB7XG5cbiAgcHJpdmF0ZSBtb2R1bGVSZWdpc3RyeTogTWFwPHN0cmluZywgTW9kdWxlUmVnaXN0cnlFbnRyeT47XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5tb2R1bGVSZWdpc3RyeSA9IG5ldyBNYXA8c3RyaW5nLCBNb2R1bGVSZWdpc3RyeUVudHJ5PigpO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRPckNyZWF0ZU1vZHVsZVJlZ2lzdHJ5RW50cnkoYWRkcmVzczogc3RyaW5nKTogTW9kdWxlUmVnaXN0cnlFbnRyeSB7XG4gICAgcmV0dXJuIHRoaXMubW9kdWxlUmVnaXN0cnlbYWRkcmVzc10gfHwgKHRoaXMubW9kdWxlUmVnaXN0cnlbYWRkcmVzc10gPSBuZXcgTW9kdWxlUmVnaXN0cnlFbnRyeShhZGRyZXNzKSk7XG4gIH1cblxuICBsb2FkTW9kdWxlKCBpZDogc3RyaW5nICk6IFByb21pc2U8YW55PiB7XG4gICAgbGV0IG5ld0lkID0gU3lzdGVtLm5vcm1hbGl6ZVN5bmMoaWQpO1xuICAgIGxldCBleGlzdGluZyA9IHRoaXMubW9kdWxlUmVnaXN0cnlbbmV3SWRdO1xuXG4gICAgaWYgKGV4aXN0aW5nKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGV4aXN0aW5nKTtcbiAgICB9XG5cbiAgICByZXR1cm4gU3lzdGVtLmltcG9ydChuZXdJZCkudGhlbihtID0+IHtcbiAgICAgIHRoaXMubW9kdWxlUmVnaXN0cnlbbmV3SWRdID0gbTtcbiAgICAgIHJldHVybiBtOyAvL2Vuc3VyZU9yaWdpbk9uRXhwb3J0cyhtLCBuZXdJZCk7XG4gICAgfSk7XG4gIH1cblxufVxuIiwiaW1wb3J0IHsgQ29tcG9uZW50LCBDb21wb25lbnRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2NvbXBvbmVudC9jb21wb25lbnQnO1xuaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBNb2R1bGVMb2FkZXIgfSBmcm9tICcuL21vZHVsZS1sb2FkZXInO1xuXG5pbXBvcnQgeyBDb250YWluZXIsIEluamVjdGFibGUgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRGYWN0b3J5IHtcbiAgcHJpdmF0ZSBfbG9hZGVyOiBNb2R1bGVMb2FkZXI7XG4gIHByaXZhdGUgX2NvbnRhaW5lcjogQ29udGFpbmVyO1xuICBwcml2YXRlIF9jb21wb25lbnRzOiBNYXA8c3RyaW5nLCBDb21wb25lbnRDb25zdHJ1Y3Rvcj47XG5cbiAgY29uc3RydWN0b3IoIGNvbnRhaW5lcj86IENvbnRhaW5lciwgbG9hZGVyPzogTW9kdWxlTG9hZGVyICkge1xuICAgIHRoaXMuX2xvYWRlciA9IGxvYWRlcjtcbiAgICB0aGlzLl9jb250YWluZXIgPSBjb250YWluZXIgfHwgbmV3IENvbnRhaW5lcigpO1xuICAgIHRoaXMuX2NvbXBvbmVudHMgPSBuZXcgTWFwPHN0cmluZywgQ29tcG9uZW50Q29uc3RydWN0b3I+KCk7XG5cbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggdW5kZWZpbmVkLCBPYmplY3QgKTtcbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggXCJcIiwgT2JqZWN0ICk7XG4gIH1cblxuICBjcmVhdGVDb250ZXh0KCBpZDogc3RyaW5nLCBjb25maWc6IHt9LCBkZXBzOiBJbmplY3RhYmxlW10gPSBbXSApOiBSdW50aW1lQ29udGV4dFxuICB7XG4gICAgbGV0IGNoaWxkQ29udGFpbmVyOiBDb250YWluZXIgPSB0aGlzLl9jb250YWluZXIuY3JlYXRlQ2hpbGQoKTtcblxuICAgIHJldHVybiBuZXcgUnVudGltZUNvbnRleHQoIHRoaXMsIGNoaWxkQ29udGFpbmVyLCBpZCwgY29uZmlnLCBkZXBzICk7XG4gIH1cblxuICBnZXRDaGlsZENvbnRhaW5lcigpOiBDb250YWluZXIge1xuICAgIHJldHVybiA7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBjdHg6IFJ1bnRpbWVDb250ZXh0LCBpZDogc3RyaW5nICk6IFByb21pc2U8Q29tcG9uZW50PlxuICB7XG4gICAgbGV0IGNyZWF0ZUNvbXBvbmVudCA9IGZ1bmN0aW9uKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApOiBDb21wb25lbnRcbiAgICB7XG4gICAgICBsZXQgbmV3SW5zdGFuY2U6IENvbXBvbmVudCA9IGN0eC5jb250YWluZXIuaW52b2tlKCBjdG9yICk7XG5cbiAgICAgIHJldHVybiBuZXdJbnN0YW5jZTtcbiAgICB9XG5cbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENvbXBvbmVudD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIENoZWNrIGNhY2hlXG4gICAgICBsZXQgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgPSB0aGlzLmdldCggaWQgKTtcblxuICAgICAgaWYgKCBjdG9yICkge1xuICAgICAgICAvLyB1c2UgY2FjaGVkIGNvbnN0cnVjdG9yXG4gICAgICAgIHJlc29sdmUoIGNyZWF0ZUNvbXBvbmVudCggY3RvciApICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggdGhpcy5fbG9hZGVyICkge1xuICAgICAgICAvLyBnb3QgYSBsb2FkZWQsIHNvIHRyeSB0byBsb2FkIHRoZSBtb2R1bGUgLi4uXG4gICAgICAgIHRoaXMuX2xvYWRlci5sb2FkTW9kdWxlKCBpZCApXG4gICAgICAgICAgLnRoZW4oICggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKSA9PiB7XG5cbiAgICAgICAgICAgIC8vIHJlZ2lzdGVyIGxvYWRlZCBjb21wb25lbnRcbiAgICAgICAgICAgIG1lLl9jb21wb25lbnRzLnNldCggaWQsIGN0b3IgKTtcblxuICAgICAgICAgICAgLy8gaW5zdGFudGlhdGUgYW5kIHJlc29sdmVcbiAgICAgICAgICAgIHJlc29sdmUoIGNyZWF0ZUNvbXBvbmVudCggY3RvciApICk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAuY2F0Y2goICggZSApID0+IHtcbiAgICAgICAgICAgIHJlamVjdCggJ0NvbXBvbmVudEZhY3Rvcnk6IFVuYWJsZSB0byBsb2FkIGNvbXBvbmVudCBcIicgKyBpZCArICdcIiAtICcgKyBlICk7XG4gICAgICAgICAgfSApO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIC8vIG9vcHMuIG5vIGxvYWRlciAuLiBubyBjb21wb25lbnRcbiAgICAgICAgcmVqZWN0KCAnQ29tcG9uZW50RmFjdG9yeTogQ29tcG9uZW50IFwiJyArIGlkICsgJ1wiIG5vdCByZWdpc3RlcmVkLCBhbmQgTG9hZGVyIG5vdCBhdmFpbGFibGUnICk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICBnZXQoIGlkOiBzdHJpbmcgKTogQ29tcG9uZW50Q29uc3RydWN0b3Ige1xuICAgIHJldHVybiB0aGlzLl9jb21wb25lbnRzLmdldCggaWQgKTtcbiAgfVxuICByZWdpc3RlciggaWQ6IHN0cmluZywgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKSB7XG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIGlkLCBjdG9yICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuZXhwb3J0IHR5cGUgRW5kUG9pbnRSZWYgPSB7IG5vZGVJRDogc3RyaW5nLCBwb3J0SUQ6IHN0cmluZyB9O1xuXG5leHBvcnQgY2xhc3MgTGlua1xue1xuICBwcm90ZWN0ZWQgX293bmVyOiBHcmFwaDtcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfY2hhbm5lbDogQ2hhbm5lbDtcbiAgcHJvdGVjdGVkIF9mcm9tOiBFbmRQb2ludFJlZjtcbiAgcHJvdGVjdGVkIF90bzogRW5kUG9pbnRSZWY7XG5cbiAgcHJvdGVjdGVkIF9wcm90b2NvbElEOiBzdHJpbmc7XG4gIHByb3RlY3RlZCBtZXRhZGF0YTogYW55O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5faWQgPSBhdHRyaWJ1dGVzLmlkIHx8IFwiXCI7XG4gICAgLy90aGlzLl9jaGFubmVsID0gbnVsbDtcbiAgICB0aGlzLl9mcm9tID0gYXR0cmlidXRlc1sgJ2Zyb20nIF07XG4gICAgdGhpcy5fdG8gPSBhdHRyaWJ1dGVzWyAndG8nIF07XG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgbGV0IGxpbmsgPSB7XG4gICAgICBpZDogdGhpcy5faWQsXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgICBmcm9tOiB0aGlzLl9mcm9tLFxuICAgICAgdG86IHRoaXMuX3RvXG4gICAgfTtcblxuICAgIHJldHVybiBsaW5rO1xuICB9XG5cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBjb25uZWN0KCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIC8vIGlkZW50aWZ5IGZyb21Qb3J0IGluIGZyb21Ob2RlXG4gICAgbGV0IGZyb21Qb3J0OiBQb3J0ID0gdGhpcy5mcm9tTm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX2Zyb20ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICk7XG5cbiAgICAvLyBpZGVudGlmeSB0b1BvcnQgaW4gdG9Ob2RlXG4gICAgbGV0IHRvUG9ydDogUG9ydCA9IHRoaXMudG9Ob2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fdG8ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICk7XG5cbiAgICB0aGlzLl9jaGFubmVsID0gY2hhbm5lbDtcblxuICAgIGZyb21Qb3J0LmVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICAgIHRvUG9ydC5lbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogQ2hhbm5lbFxuICB7XG4gICAgbGV0IGNoYW4gPSB0aGlzLl9jaGFubmVsO1xuXG4gICAgaWYgKCBjaGFuIClcbiAgICB7XG4gICAgICB0aGlzLl9jaGFubmVsLmVuZFBvaW50cy5mb3JFYWNoKCAoIGVuZFBvaW50ICkgPT4ge1xuICAgICAgICBlbmRQb2ludC5kZXRhY2goIHRoaXMuX2NoYW5uZWwgKTtcbiAgICAgIH0gKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbCA9IHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICByZXR1cm4gY2hhbjtcbiAgfVxuXG4gIGdldCBmcm9tTm9kZSgpOiBOb2RlXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXIuZ2V0Tm9kZUJ5SUQoIHRoaXMuX2Zyb20ubm9kZUlEICk7XG4gIH1cblxuICBnZXQgZnJvbVBvcnQoKTogUG9ydFxuICB7XG4gICAgbGV0IG5vZGUgPSB0aGlzLmZyb21Ob2RlO1xuXG4gICAgcmV0dXJuIChub2RlKSA/IG5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl9mcm9tLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApIDogdW5kZWZpbmVkO1xuICB9XG5cbiAgc2V0IGZyb21Qb3J0KCBwb3J0OiBQb3J0IClcbiAge1xuICAgIHRoaXMuX2Zyb20gPSB7XG4gICAgICBub2RlSUQ6IHBvcnQub3duZXIuaWQsXG4gICAgICBwb3J0SUQ6IHBvcnQuaWRcbiAgICB9O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IHBvcnQucHJvdG9jb2xJRDtcbiAgfVxuXG4gIGdldCB0b05vZGUoKTogTm9kZVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyLmdldE5vZGVCeUlEKCB0aGlzLl90by5ub2RlSUQgKTtcbiAgfVxuXG4gIGdldCB0b1BvcnQoKTogUG9ydFxuICB7XG4gICAgbGV0IG5vZGUgPSB0aGlzLnRvTm9kZTtcblxuICAgIHJldHVybiAobm9kZSkgPyBub2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fdG8ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICkgOiB1bmRlZmluZWQ7XG4gIH1cblxuICBzZXQgdG9Qb3J0KCBwb3J0OiBQb3J0IClcbiAge1xuICAgIHRoaXMuX3RvID0ge1xuICAgICAgbm9kZUlEOiBwb3J0Lm93bmVyLmlkLFxuICAgICAgcG9ydElEOiBwb3J0LmlkXG4gICAgfTtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBwb3J0LnByb3RvY29sSUQ7XG4gIH1cblxuICBnZXQgcHJvdG9jb2xJRCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9wcm90b2NvbElEO1xuICB9XG59XG4iLCJpbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeSB9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgUnVudGltZUNvbnRleHQsIFJ1blN0YXRlIH0gZnJvbSAnLi4vcnVudGltZS9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IExpbmsgfSBmcm9tICcuL2xpbmsnO1xuaW1wb3J0IHsgUG9ydCwgUHVibGljUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbmV4cG9ydCBjbGFzcyBOZXR3b3JrIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgc3RhdGljIEVWRU5UX1NUQVRFX0NIQU5HRSA9ICduZXR3b3JrOnN0YXRlLWNoYW5nZSc7XG4gIHN0YXRpYyBFVkVOVF9HUkFQSF9DSEFOR0UgPSAnbmV0d29yazpncmFwaC1jaGFuZ2UnO1xuXG4gIHByaXZhdGUgX2dyYXBoOiBHcmFwaDtcblxuICBwcml2YXRlIF9mYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5O1xuXG4gIGNvbnN0cnVjdG9yKCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5LCBncmFwaD86IEdyYXBoIClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gZmFjdG9yeTtcbiAgICB0aGlzLl9ncmFwaCA9IGdyYXBoIHx8IG5ldyBHcmFwaCggbnVsbCwge30gKTtcblxuICAgIGxldCBtZSA9IHRoaXM7XG4gICAgdGhpcy5fZ3JhcGguc3Vic2NyaWJlKCBHcmFwaC5FVkVOVF9BRERfTk9ERSwgKCBkYXRhOiB7IG5vZGU6IE5vZGUgfSApPT4ge1xuICAgICAgbGV0IHJ1blN0YXRlOiBSdW5TdGF0ZSA9IG1lLl9ncmFwaC5jb250ZXh0LnJ1blN0YXRlO1xuXG4gICAgICBpZiAoIHJ1blN0YXRlICE9IFJ1blN0YXRlLk5FV0JPUk4gKVxuICAgICAge1xuICAgICAgICBsZXQgeyBub2RlIH0gPSBkYXRhO1xuXG4gICAgICAgIG5vZGUubG9hZENvbXBvbmVudCggbWUuX2ZhY3RvcnkgKVxuICAgICAgICAgIC50aGVuKCAoKT0+IHtcbiAgICAgICAgICAgIGlmICggTmV0d29yay5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCwgUnVuU3RhdGUuUkVBRFkgXSwgcnVuU3RhdGUgKSApXG4gICAgICAgICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIG5vZGUsIFJ1blN0YXRlLlJFQURZICk7XG5cbiAgICAgICAgICAgIGlmICggTmV0d29yay5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdLCBydW5TdGF0ZSApIClcbiAgICAgICAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggbm9kZSwgcnVuU3RhdGUgKTtcblxuICAgICAgICAgICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX0dSQVBIX0NIQU5HRSwgeyBub2RlOiBub2RlIH0gKTtcbiAgICAgICAgICB9KVxuICAgICAgfVxuICAgIH0gKTtcbiAgfVxuXG4gIGdldCBncmFwaCgpOiBHcmFwaCB7XG4gICAgcmV0dXJuIHRoaXMuX2dyYXBoO1xuICB9XG5cbiAgLyoqXG4gICogTG9hZCBhbGwgY29tcG9uZW50c1xuICAqL1xuICBsb2FkQ29tcG9uZW50cygpOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogUnVuU3RhdGUuTE9BRElORyB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fZ3JhcGgubG9hZENvbXBvbmVudCggdGhpcy5fZmFjdG9yeSApLnRoZW4oICgpPT4ge1xuICAgICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogUnVuU3RhdGUuTE9BREVEIH0gKTtcbiAgICB9KTtcbiAgfVxuXG4gIGluaXRpYWxpemUoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUkVBRFkgKTtcbiAgfVxuXG4gIHRlYXJkb3duKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLkxPQURFRCApO1xuICB9XG5cbiAgc3RhdGljIGluU3RhdGUoIHN0YXRlczogUnVuU3RhdGVbXSwgcnVuU3RhdGU6IFJ1blN0YXRlICk6IGJvb2xlYW4ge1xuICAgIHJldHVybiBuZXcgU2V0PFJ1blN0YXRlPiggc3RhdGVzICkuaGFzKCBydW5TdGF0ZSApO1xuICB9XG5cbiAgLyoqXG4gICogQWx0ZXIgcnVuLXN0YXRlIG9mIGEgTm9kZSAtIExPQURFRCwgUkVBRFksIFJVTk5JTkcgb3IgUEFVU0VELlxuICAqIFRyaWdnZXJzIFNldHVwIG9yIFRlYXJkb3duIGlmIHRyYW5zaXRpb25pbmcgYmV0d2VlbiBSRUFEWSBhbmQgTE9BREVEXG4gICogV2lyZXVwIGEgZ3JhcGgsIGNyZWF0aW5nIENoYW5uZWwgYmV0d2VlbiBsaW5rZWQgTm9kZXNcbiAgKiBBY3RzIHJlY3Vyc2l2ZWx5LCB3aXJpbmcgdXAgYW55IHN1Yi1ncmFwaHNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgc2V0UnVuU3RhdGUoIG5vZGU6IE5vZGUsIHJ1blN0YXRlOiBSdW5TdGF0ZSApXG4gIHtcbiAgICBsZXQgY3R4ID0gbm9kZS5jb250ZXh0O1xuICAgIGxldCBjdXJyZW50U3RhdGUgPSBjdHgucnVuU3RhdGU7XG5cbiAgICBpZiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApXG4gICAge1xuICAgICAgLy8gMS4gUHJlcHJvY2Vzc1xuICAgICAgLy8gICAgYS4gSGFuZGxlIHRlYXJkb3duXG4gICAgICAvLyAgICBiLiBQcm9wYWdhdGUgc3RhdGUgY2hhbmdlIHRvIHN1Ym5ldHNcbiAgICAgIGxldCBub2RlczogTWFwPHN0cmluZywgTm9kZT4gPSBub2RlLm5vZGVzO1xuXG4gICAgICBpZiAoICggcnVuU3RhdGUgPT0gUnVuU3RhdGUuTE9BREVEICkgJiYgKCBjdXJyZW50U3RhdGUgPj0gUnVuU3RhdGUuUkVBRFkgKSApIHtcbiAgICAgICAgLy8gdGVhcmluZyBkb3duIC4uIHVubGluayBncmFwaCBmaXJzdFxuICAgICAgICBsZXQgbGlua3M6IE1hcDxzdHJpbmcsIExpbms+ID0gbm9kZS5saW5rcztcblxuICAgICAgICAvLyB1bndpcmUgKGRlYWN0aXZhdGUgYW5kIGRlc3Ryb3kgKSBDaGFubmVscyBiZXR3ZWVuIGxpbmtlZCBub2Rlc1xuICAgICAgICBsaW5rcy5mb3JFYWNoKCAoIGxpbmsgKSA9PlxuICAgICAgICB7XG4gICAgICAgICAgTmV0d29yay51bndpcmVMaW5rKCBsaW5rICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH1cblxuICAgICAgLy8gUHJvcGFnYXRlIHN0YXRlIGNoYW5nZSB0byBzdWItbmV0cyBmaXJzdFxuICAgICAgbm9kZXMuZm9yRWFjaCggZnVuY3Rpb24oIHN1Yk5vZGUgKVxuICAgICAge1xuICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBzdWJOb2RlLCBydW5TdGF0ZSApO1xuICAgICAgfSApO1xuXG4gICAgICAvLyAyLiBDaGFuZ2Ugc3RhdGUgLi4uXG4gICAgICBjdHguc2V0UnVuU3RhdGUoIHJ1blN0YXRlICk7XG5cbiAgICAgIC8vIDMuIFBvc3Rwcm9jZXNzXG4gICAgICAvLyAgICBhLiBIYW5kbGUgc2V0dXBcbiAgICAgIGlmICggKCBydW5TdGF0ZSA9PSBSdW5TdGF0ZS5SRUFEWSApICYmICggY3VycmVudFN0YXRlID49IFJ1blN0YXRlLkxPQURFRCApICkge1xuXG4gICAgICAgIC8vIHNldHRpbmcgdXAgLi4gbGlua3VwIGdyYXBoIGZpcnN0XG4gICAgICAgIGxldCBsaW5rczogTWFwPHN0cmluZywgTGluaz4gPSBub2RlLmxpbmtzO1xuICAgICAgICAvLyB0cmVhdCBncmFwaCByZWN1cnNpdmVseVxuXG4gICAgICAgIC8vIDIuIHdpcmV1cCAoY3JlYXRlIGFuZCBhY3RpdmF0ZSkgYSBDaGFubmVsIGJldHdlZW4gbGlua2VkIG5vZGVzXG4gICAgICAgIGxpbmtzLmZvckVhY2goICggbGluayApID0+XG4gICAgICAgIHtcbiAgICAgICAgICBOZXR3b3JrLndpcmVMaW5rKCBsaW5rICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgLy8gQ2hhbmdlIHN0YXRlIC4uLlxuICAgICAgY3R4LnNldFJ1blN0YXRlKCBydW5TdGF0ZSApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIFVud2lyZSBhIGxpbmssIHJlbW92aW5nIHRoZSBDaGFubmVsIGJldHdlZW4gdGhlIGxpbmtlZCBOb2Rlc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyB1bndpcmVMaW5rKCBsaW5rOiBMaW5rIClcbiAge1xuICAgIC8vIGdldCBsaW5rZWQgbm9kZXMgKExpbmsgZmluZHMgTm9kZXMgaW4gcGFyZW50IEdyYXBoKVxuICAgIGxldCBmcm9tTm9kZSA9IGxpbmsuZnJvbU5vZGU7XG4gICAgbGV0IHRvTm9kZSA9IGxpbmsudG9Ob2RlO1xuXG4gICAgbGV0IGNoYW46IENoYW5uZWwgPSBsaW5rLmRpc2Nvbm5lY3QoKTtcblxuICAgIGlmICggY2hhbiApXG4gICAgICBjaGFuLmRlYWN0aXZhdGUoKTtcbiAgfVxuXG4gIC8qKlxuICAqIFdpcmV1cCBhIGxpbmssIGNyZWF0aW5nIENoYW5uZWwgYmV0d2VlbiB0aGUgbGlua2VkIE5vZGVzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHdpcmVMaW5rKCBsaW5rOiBMaW5rIClcbiAge1xuICAgIC8vIGdldCBsaW5rZWQgbm9kZXMgKExpbmsgZmluZHMgTm9kZXMgaW4gcGFyZW50IEdyYXBoKVxuICAgIGxldCBmcm9tTm9kZSA9IGxpbmsuZnJvbU5vZGU7XG4gICAgbGV0IHRvTm9kZSA9IGxpbmsudG9Ob2RlO1xuXG4gICAgLy9kZWJ1Z01lc3NhZ2UoIFwiTGluayhcIitsaW5rLmlkK1wiKTogXCIgKyBsaW5rLmZyb20gKyBcIiAtPiBcIiArIGxpbmsudG8gKyBcIiBwcm90bz1cIitsaW5rLnByb3RvY29sICk7XG5cbiAgICBsZXQgY2hhbm5lbCA9IG5ldyBDaGFubmVsKCk7XG5cbiAgICBsaW5rLmNvbm5lY3QoIGNoYW5uZWwgKTtcblxuICAgIGNoYW5uZWwuYWN0aXZhdGUoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXRSdW5TdGF0ZSggcnVuU3RhdGU6IFJ1blN0YXRlIClcbiAge1xuICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIHRoaXMuX2dyYXBoLCBydW5TdGF0ZSApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogcnVuU3RhdGUgfSApO1xuICB9XG5cbiAgc3RhcnQoIGluaXRpYWxseVBhdXNlZDogYm9vbGVhbiA9IGZhbHNlICkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIGluaXRpYWxseVBhdXNlZCA/IFJ1blN0YXRlLlBBVVNFRCA6IFJ1blN0YXRlLlJVTk5JTkcgKTtcbiAgfVxuXG4gIHN0ZXAoKSB7XG4gICAgLy8gVE9ETzogU2luZ2xlLXN0ZXBcbiAgfVxuXG4gIHN0b3AoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUkVBRFkgKTtcbiAgfVxuXG4gIHBhdXNlKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlBBVVNFRCApO1xuICB9XG5cbiAgcmVzdW1lKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJVTk5JTkcgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeX0gZnJvbSAnLi4vcnVudGltZS9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuXG5pbXBvcnQgeyBOZXR3b3JrIH0gZnJvbSAnLi9uZXR3b3JrJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgTGluayB9IGZyb20gJy4vbGluayc7XG5pbXBvcnQgeyBQb3J0LCBQdWJsaWNQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuLyoqXG4gKiBBIEdyYXBoIGlzIGEgY29sbGVjdGlvbiBvZiBOb2RlcyBpbnRlcmNvbm5lY3RlZCB2aWEgTGlua3MuXG4gKiBBIEdyYXBoIGlzIGl0c2VsZiBhIE5vZGUsIHdob3NlIFBvcnRzIGFjdCBhcyBwdWJsaXNoZWQgRW5kUG9pbnRzLCB0byB0aGUgR3JhcGguXG4gKi9cbmV4cG9ydCBjbGFzcyBHcmFwaCBleHRlbmRzIE5vZGVcbntcbiAgc3RhdGljIEVWRU5UX0FERF9OT0RFID0gJ2dyYXBoOmFkZC1ub2RlJztcbiAgc3RhdGljIEVWRU5UX1VQRF9OT0RFID0gJ2dyYXBoOnVwZC1ub2RlJztcbiAgc3RhdGljIEVWRU5UX0RFTF9OT0RFID0gJ2dyYXBoOmRlbC1ub2RlJztcblxuICBzdGF0aWMgRVZFTlRfQUREX0xJTksgPSAnZ3JhcGg6YWRkLWxpbmsnO1xuICBzdGF0aWMgRVZFTlRfVVBEX0xJTksgPSAnZ3JhcGg6dXBkLWxpbmsnO1xuICBzdGF0aWMgRVZFTlRfREVMX0xJTksgPSAnZ3JhcGg6ZGVsLWxpbmsnO1xuXG4gIC8qKlxuICAqIE5vZGVzIGluIHRoaXMgZ3JhcGguIEVhY2ggbm9kZSBtYXkgYmU6XG4gICogICAxLiBBIENvbXBvbmVudFxuICAqICAgMi4gQSBzdWItZ3JhcGhcbiAgKi9cbiAgcHJvdGVjdGVkIF9ub2RlczogTWFwPHN0cmluZywgTm9kZT47XG5cbiAgLy8gTGlua3MgaW4gdGhpcyBncmFwaC4gRWFjaCBub2RlIG1heSBiZTpcbiAgcHJvdGVjdGVkIF9saW5rczogTWFwPHN0cmluZywgTGluaz47XG5cbiAgLy8gUHVibGljIFBvcnRzIGluIHRoaXMgZ3JhcGguIEluaGVyaXRlZCBmcm9tIE5vZGVcbiAgLy8gcHJpdmF0ZSBQb3J0cztcbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgc3VwZXIoIG93bmVyLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLmluaXRGcm9tT2JqZWN0KCBhdHRyaWJ1dGVzICk7XG4gIH1cblxuICBpbml0RnJvbVN0cmluZygganNvblN0cmluZzogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuaW5pdEZyb21PYmplY3QoIEpTT04ucGFyc2UoIGpzb25TdHJpbmcgKSApO1xuICB9XG5cbiAgaW5pdEZyb21PYmplY3QoIGF0dHJpYnV0ZXM6IGFueSApIHtcblxuICAgIHRoaXMuaWQgPSBhdHRyaWJ1dGVzLmlkIHx8IFwiJGdyYXBoXCI7XG5cbiAgICB0aGlzLl9ub2RlcyA9IG5ldyBNYXA8c3RyaW5nLCBOb2RlPigpO1xuICAgIHRoaXMuX2xpbmtzID0gbmV3IE1hcDxzdHJpbmcsIExpbms+KCk7XG5cbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5ub2RlcyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGROb2RlKCBpZCwgYXR0cmlidXRlcy5ub2Rlc1sgaWQgXSApO1xuICAgIH0pO1xuXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMubGlua3MgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkTGluayggaWQsIGF0dHJpYnV0ZXMubGlua3NbIGlkIF0gKTtcbiAgICB9KTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzOiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgZ3JhcGggPSBzdXBlci50b09iamVjdCgpO1xuXG4gICAgbGV0IG5vZGVzID0gZ3JhcGhbIFwibm9kZXNcIiBdID0ge307XG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbi8vICAgICAgaWYgKCBub2RlICE9IHRoaXMgKVxuICAgICAgICBub2Rlc1sgaWQgXSA9IG5vZGUudG9PYmplY3QoKTtcbiAgICB9KTtcblxuICAgIGxldCBsaW5rcyA9IGdyYXBoWyBcImxpbmtzXCIgXSA9IHt9O1xuICAgIHRoaXMuX2xpbmtzLmZvckVhY2goICggbGluaywgaWQgKSA9PiB7XG4gICAgICBsaW5rc1sgaWQgXSA9IGxpbmsudG9PYmplY3QoKTtcbiAgICB9KTtcblxuICAgIHJldHVybiBncmFwaDtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnkgKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgcGVuZGluZ0NvdW50ID0gMDtcblxuICAgICAgbGV0IG5vZGVzID0gbmV3IE1hcDxzdHJpbmcsIE5vZGU+KCB0aGlzLl9ub2RlcyApO1xuICAgICAgbm9kZXMuc2V0KCAnJGdyYXBoJywgdGhpcyApO1xuXG4gICAgICBub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgICBsZXQgZG9uZTogUHJvbWlzZTx2b2lkPjtcblxuICAgICAgICBwZW5kaW5nQ291bnQrKztcblxuICAgICAgICBpZiAoIG5vZGUgPT0gdGhpcyApIHtcbiAgICAgICAgICBkb25lID0gc3VwZXIubG9hZENvbXBvbmVudCggZmFjdG9yeSApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIGRvbmUgPSBub2RlLmxvYWRDb21wb25lbnQoIGZhY3RvcnkgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGRvbmUudGhlbiggKCkgPT4ge1xuICAgICAgICAgIC0tcGVuZGluZ0NvdW50O1xuICAgICAgICAgIGlmICggcGVuZGluZ0NvdW50ID09IDAgKVxuICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goICggcmVhc29uICkgPT4ge1xuICAgICAgICAgIHJlamVjdCggcmVhc29uICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH0gKTtcbiAgICB9ICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IG5vZGVzKCk6IE1hcDxzdHJpbmcsIE5vZGU+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fbm9kZXM7XG4gIH1cblxuLyogIHB1YmxpYyBnZXRBbGxOb2RlcygpOiBOb2RlW11cbiAge1xuICAgIGxldCBub2RlczogTm9kZVtdID0gW107XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgLy8gRG9uJ3QgcmVjdXJzZSBvbiBncmFwaCdzIHBzZXVkby1ub2RlXG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIG5vZGVzID0gbm9kZXMuY29uY2F0KCBub2RlLmdldEFsbE5vZGVzKCkgKTtcblxuICAgICAgbm9kZXMucHVzaCggbm9kZSApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlcztcbiAgfSovXG5cbiAgcHVibGljIGdldCBsaW5rcygpOiBNYXA8c3RyaW5nLCBMaW5rPlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzO1xuICB9XG5cbi8qICBwdWJsaWMgZ2V0QWxsTGlua3MoKTogTGlua1tdXG4gIHtcbiAgICBsZXQgbGlua3M6IExpbmtbXSA9IFtdO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgbGlua3MgPSBsaW5rcy5jb25jYXQoIG5vZGUuZ2V0QWxsTGlua3MoKSApO1xuICAgIH0gKVxuXG4gICAgdGhpcy5fbGlua3MuZm9yRWFjaCggKCBsaW5rLCBpZCApID0+IHtcbiAgICAgIGxpbmtzLnB1c2goIGxpbmsgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbGlua3M7XG4gIH0qL1xuXG4vKiAgcHVibGljIGdldEFsbFBvcnRzKCk6IFBvcnRbXVxuICB7XG4gICAgbGV0IHBvcnRzOiBQb3J0W10gPSBzdXBlci5nZXRQb3J0QXJyYXkoKTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIHBvcnRzID0gcG9ydHMuY29uY2F0KCBub2RlLmdldEFsbFBvcnRzKCkgKTtcbiAgICAgIGVsc2VcbiAgICAgICAgcG9ydHMgPSBwb3J0cy5jb25jYXQoIG5vZGUuZ2V0UG9ydEFycmF5KCkgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gcG9ydHM7XG4gIH0qL1xuXG4gIHB1YmxpYyBnZXROb2RlQnlJRCggaWQ6IHN0cmluZyApOiBOb2RlXG4gIHtcbiAgICBpZiAoIGlkID09ICckZ3JhcGgnIClcbiAgICAgIHJldHVybiB0aGlzO1xuXG4gICAgcmV0dXJuIHRoaXMuX25vZGVzLmdldCggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBhZGROb2RlKCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzPzoge30gKTogTm9kZSB7XG5cbiAgICBsZXQgbm9kZSA9IG5ldyBOb2RlKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG5cbiAgICBub2RlLmlkID0gaWQ7XG5cbiAgICB0aGlzLl9ub2Rlcy5zZXQoIGlkLCBub2RlICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0FERF9OT0RFLCB7IG5vZGU6IG5vZGUgfSApO1xuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICBwdWJsaWMgcmVuYW1lTm9kZSggaWQ6IHN0cmluZywgbmV3SUQ6IHN0cmluZyApIHtcblxuICAgIGxldCBub2RlID0gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuXG4gICAgaWYgKCBpZCAhPSBuZXdJRCApXG4gICAge1xuICAgICAgbGV0IGV2ZW50RGF0YSA9IHsgbm9kZTogbm9kZSwgYXR0cnM6IHsgaWQ6IG5vZGUuaWQgfSB9O1xuXG4gICAgICB0aGlzLl9ub2Rlcy5kZWxldGUoIGlkICk7XG5cbiAgICAgIG5vZGUuaWQgPSBuZXdJRDtcblxuICAgICAgdGhpcy5fbm9kZXMuc2V0KCBuZXdJRCwgbm9kZSApO1xuXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX1VQRF9OT0RFLCBldmVudERhdGEgKTtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgcmVtb3ZlTm9kZSggaWQ6IHN0cmluZyApOiBib29sZWFuIHtcblxuICAgIGxldCBub2RlID0gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuICAgIGlmICggbm9kZSApXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0RFTF9OT0RFLCB7IG5vZGU6IG5vZGUgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX25vZGVzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXRMaW5rQnlJRCggaWQ6IHN0cmluZyApOiBMaW5rIHtcblxuICAgIHJldHVybiB0aGlzLl9saW5rc1sgaWQgXTtcbiAgfVxuXG4gIHB1YmxpYyBhZGRMaW5rKCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzPzoge30gKTogTGluayB7XG5cbiAgICBsZXQgbGluayA9IG5ldyBMaW5rKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsaW5rLmlkID0gaWQ7XG5cbiAgICB0aGlzLl9saW5rcy5zZXQoIGlkLCBsaW5rICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0FERF9MSU5LLCB7IGxpbms6IGxpbmsgfSApO1xuXG4gICAgcmV0dXJuIGxpbms7XG4gIH1cblxuICBwdWJsaWMgcmVuYW1lTGluayggaWQ6IHN0cmluZywgbmV3SUQ6IHN0cmluZyApIHtcblxuICAgIGxldCBsaW5rID0gdGhpcy5fbGlua3MuZ2V0KCBpZCApO1xuXG4gICAgdGhpcy5fbGlua3MuZGVsZXRlKCBpZCApO1xuXG4gICAgbGV0IGV2ZW50RGF0YSA9IHsgbGluazogbGluaywgYXR0cnM6IHsgaWQ6IGxpbmsuaWQgfSB9O1xuXG4gICAgbGluay5pZCA9IG5ld0lEO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9VUERfTk9ERSwgZXZlbnREYXRhICk7XG5cbiAgICB0aGlzLl9saW5rcy5zZXQoIG5ld0lELCBsaW5rICk7XG4gIH1cblxuICBwdWJsaWMgcmVtb3ZlTGluayggaWQ6IHN0cmluZyApOiBib29sZWFuIHtcblxuICAgIGxldCBsaW5rID0gdGhpcy5fbGlua3MuZ2V0KCBpZCApO1xuICAgIGlmICggbGluayApXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0RFTF9MSU5LLCB7IGxpbms6IGxpbmsgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBhZGRQdWJsaWNQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQdWJsaWNQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFB1YmxpY1BvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG59XG4iLCJpbXBvcnQgeyBNb2R1bGVMb2FkZXIgfSBmcm9tICcuL21vZHVsZS1sb2FkZXInO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeSB9IGZyb20gJy4vY29tcG9uZW50LWZhY3RvcnknO1xuXG5pbXBvcnQgeyBDb250YWluZXIgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuXG5cbmV4cG9ydCBjbGFzcyBTaW11bGF0aW9uRW5naW5lXG57XG4gIGxvYWRlcjogTW9kdWxlTG9hZGVyO1xuICBjb250YWluZXI6IENvbnRhaW5lcjtcblxuICAvKipcbiAgKiBDcmVhdGVzIGFuIGluc3RhbmNlIG9mIFNpbXVsYXRpb25FbmdpbmUuXG4gICogQHBhcmFtIGxvYWRlciBUaGUgbW9kdWxlIGxvYWRlci5cbiAgKiBAcGFyYW0gY29udGFpbmVyIFRoZSByb290IERJIGNvbnRhaW5lciBmb3IgdGhlIHNpbXVsYXRpb24uXG4gICovXG4gIGNvbnN0cnVjdG9yKCBsb2FkZXI6IE1vZHVsZUxvYWRlciwgY29udGFpbmVyOiBDb250YWluZXIgKSB7XG4gICAgdGhpcy5sb2FkZXIgPSBsb2FkZXI7XG4gICAgdGhpcy5jb250YWluZXIgPSBjb250YWluZXI7XG4gIH1cblxuXG4gIC8qKlxuICAqIFJldHVybiBhIENvbXBvbmVudEZhY3RvcnkgZmFjYWRlXG4gICovXG4gIGdldENvbXBvbmVudEZhY3RvcnkoKTogQ29tcG9uZW50RmFjdG9yeSB7XG4gICAgcmV0dXJuIG5ldyBDb21wb25lbnRGYWN0b3J5KCB0aGlzLmNvbnRhaW5lciwgdGhpcy5sb2FkZXIgKTtcbiAgfVxuXG59XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
