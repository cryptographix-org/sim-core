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
            s += ("0" + this.byteArray[i].toString(16)).substring(-2);
        return s;
    }
}
ByteArray.BYTES = 0;
ByteArray.HEX = 1;
ByteArray.BASE64 = 2;
ByteArray.UTF8 = 3;

export class Enum {
}
;
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
    field(name, description, dataType, opts) {
        this.ctor.kindInfo.fields[name] = {
            description: description,
            dataType: dataType
        };
        return this;
    }
}
var Oranges;
(function (Oranges) {
    Oranges[Oranges["BLOOD"] = 0] = "BLOOD";
    Oranges[Oranges["SEVILLE"] = 1] = "SEVILLE";
    Oranges[Oranges["SATSUMA"] = 2] = "SATSUMA";
    Oranges[Oranges["NAVEL"] = 3] = "NAVEL";
})(Oranges || (Oranges = {}));
class FruityKind {
}
KindBuilder.init(FruityKind, 'a Collection of fruit')
    .field('banana', 'a banana', String)
    .field('apple', 'an apple or pear', Number)
    .field('orange', 'some sort of orange', Enum);

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
        ctx.container.registerInstance(Node, this);
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
                    let endPoints = {};
                    if (inst.initialize)
                        endPoints = this.instance.initialize(this._config);
                    this.reconcilePorts(endPoints);
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
    reconcilePorts(endPoints) {
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

//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImtpbmQvaGV4LWNvZGVjLnRzIiwia2luZC9iYXNlNjQtY29kZWMudHMiLCJraW5kL2J5dGUtYXJyYXkudHMiLCJraW5kL2tpbmQudHMiLCJtZXNzYWdpbmcvbWVzc2FnZS50cyIsInJ1bnRpbWUvdGFzay1zY2hlZHVsZXIudHMiLCJtZXNzYWdpbmcvY2hhbm5lbC50cyIsIm1lc3NhZ2luZy9lbmQtcG9pbnQudHMiLCJtZXNzYWdpbmcvcHJvdG9jb2wudHMiLCJjb21wb25lbnQvcG9ydC1pbmZvLnRzIiwiY29tcG9uZW50L2NvbXBvbmVudC1pbmZvLnRzIiwiY29tcG9uZW50L3N0b3JlLWluZm8udHMiLCJjb21wb25lbnQvY29tcG9uZW50LnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9rZXkudHMiLCJjcnlwdG9ncmFwaGljLXNlcnZpY2VzL3ByaXZhdGUta2V5LnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9wdWJsaWMta2V5LnRzIiwiY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlcy9rZXktcGFpci50cyIsImNyeXB0b2dyYXBoaWMtc2VydmljZXMvY3J5cHRvZ3JhcGhpYy1zZXJ2aWNlLnRzIiwiZGVwZW5kZW5jeS1pbmplY3Rpb24vY29udGFpbmVyLnRzIiwiZXZlbnQtaHViL2V2ZW50LWh1Yi50cyIsImdyYXBoL3BvcnQudHMiLCJncmFwaC9ub2RlLnRzIiwicnVudGltZS9ydW50aW1lLWNvbnRleHQudHMiLCJydW50aW1lL21vZHVsZS1sb2FkZXIudHMiLCJydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5LnRzIiwiZ3JhcGgvbGluay50cyIsImdyYXBoL25ldHdvcmsudHMiLCJncmFwaC9ncmFwaC50cyIsInJ1bnRpbWUvc2ltdWxhdGlvbi1lbmdpbmUudHMiXSwibmFtZXMiOlsiSGV4Q29kZWMiLCJIZXhDb2RlYy5kZWNvZGUiLCJCQVNFNjRTUEVDSUFMUyIsIkJhc2U2NENvZGVjIiwiQmFzZTY0Q29kZWMuZGVjb2RlIiwiQmFzZTY0Q29kZWMuZGVjb2RlLmRlY29kZSIsIkJhc2U2NENvZGVjLmRlY29kZS5wdXNoIiwiQmFzZTY0Q29kZWMuZW5jb2RlIiwiQmFzZTY0Q29kZWMuZW5jb2RlLmVuY29kZSIsIkJhc2U2NENvZGVjLmVuY29kZS50cmlwbGV0VG9CYXNlNjQiLCJCeXRlQXJyYXkiLCJCeXRlQXJyYXkuY29uc3RydWN0b3IiLCJCeXRlQXJyYXkubGVuZ3RoIiwiQnl0ZUFycmF5LmJhY2tpbmdBcnJheSIsIkJ5dGVBcnJheS5lcXVhbHMiLCJCeXRlQXJyYXkuYnl0ZUF0IiwiQnl0ZUFycmF5LndvcmRBdCIsIkJ5dGVBcnJheS5saXR0bGVFbmRpYW5Xb3JkQXQiLCJCeXRlQXJyYXkuZHdvcmRBdCIsIkJ5dGVBcnJheS5zZXRCeXRlQXQiLCJCeXRlQXJyYXkuc2V0Qnl0ZXNBdCIsIkJ5dGVBcnJheS5jbG9uZSIsIkJ5dGVBcnJheS5ieXRlc0F0IiwiQnl0ZUFycmF5LnZpZXdBdCIsIkJ5dGVBcnJheS5hZGRCeXRlIiwiQnl0ZUFycmF5LnNldExlbmd0aCIsIkJ5dGVBcnJheS5jb25jYXQiLCJCeXRlQXJyYXkubm90IiwiQnl0ZUFycmF5LmFuZCIsIkJ5dGVBcnJheS5vciIsIkJ5dGVBcnJheS54b3IiLCJCeXRlQXJyYXkudG9TdHJpbmciLCJFbnVtIiwiS2luZEluZm8iLCJLaW5kSW5mby5jb25zdHJ1Y3RvciIsIktpbmRCdWlsZGVyIiwiS2luZEJ1aWxkZXIuY29uc3RydWN0b3IiLCJLaW5kQnVpbGRlci5pbml0IiwiS2luZEJ1aWxkZXIuZmllbGQiLCJPcmFuZ2VzIiwiRnJ1aXR5S2luZCIsIk1lc3NhZ2UiLCJNZXNzYWdlLmNvbnN0cnVjdG9yIiwiTWVzc2FnZS5oZWFkZXIiLCJNZXNzYWdlLnBheWxvYWQiLCJLaW5kTWVzc2FnZSIsIlRhc2tTY2hlZHVsZXIiLCJUYXNrU2NoZWR1bGVyLmNvbnN0cnVjdG9yIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tTXV0YXRpb25PYnNlcnZlci5yZXF1ZXN0Rmx1c2giLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIiLCJUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIucmVxdWVzdEZsdXNoIiwiVGFza1NjaGVkdWxlci5tYWtlUmVxdWVzdEZsdXNoRnJvbVRpbWVyLnJlcXVlc3RGbHVzaC5oYW5kbGVGbHVzaFRpbWVyIiwiVGFza1NjaGVkdWxlci5zaHV0ZG93biIsIlRhc2tTY2hlZHVsZXIucXVldWVUYXNrIiwiVGFza1NjaGVkdWxlci5mbHVzaFRhc2tRdWV1ZSIsIlRhc2tTY2hlZHVsZXIub25FcnJvciIsIkNoYW5uZWwiLCJDaGFubmVsLmNvbnN0cnVjdG9yIiwiQ2hhbm5lbC5zaHV0ZG93biIsIkNoYW5uZWwuYWN0aXZlIiwiQ2hhbm5lbC5hY3RpdmF0ZSIsIkNoYW5uZWwuZGVhY3RpdmF0ZSIsIkNoYW5uZWwuYWRkRW5kUG9pbnQiLCJDaGFubmVsLnJlbW92ZUVuZFBvaW50IiwiQ2hhbm5lbC5lbmRQb2ludHMiLCJDaGFubmVsLnNlbmRNZXNzYWdlIiwiRGlyZWN0aW9uIiwiRW5kUG9pbnQiLCJFbmRQb2ludC5jb25zdHJ1Y3RvciIsIkVuZFBvaW50LnNodXRkb3duIiwiRW5kUG9pbnQuaWQiLCJFbmRQb2ludC5hdHRhY2giLCJFbmRQb2ludC5kZXRhY2giLCJFbmRQb2ludC5kZXRhY2hBbGwiLCJFbmRQb2ludC5hdHRhY2hlZCIsIkVuZFBvaW50LmRpcmVjdGlvbiIsIkVuZFBvaW50LmhhbmRsZU1lc3NhZ2UiLCJFbmRQb2ludC5zZW5kTWVzc2FnZSIsIkVuZFBvaW50Lm9uTWVzc2FnZSIsIlByb3RvY29sVHlwZUJpdHMiLCJQcm90b2NvbCIsIkNsaWVudFNlcnZlclByb3RvY29sIiwiQVBEVSIsIkFQRFVNZXNzYWdlIiwiQVBEVVByb3RvY29sIiwiUG9ydEluZm8iLCJQb3J0SW5mby5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEluZm8iLCJDb21wb25lbnRJbmZvLmNvbnN0cnVjdG9yIiwiU3RvcmVJbmZvIiwiQ29tcG9uZW50QnVpbGRlciIsIkNvbXBvbmVudEJ1aWxkZXIuY29uc3RydWN0b3IiLCJDb21wb25lbnRCdWlsZGVyLmluaXQiLCJDb21wb25lbnRCdWlsZGVyLnBvcnQiLCJDb21wb25lbnRCdWlsZGVyLm5hbWUiLCJDIiwiS2V5IiwiS2V5LmNvbnN0cnVjdG9yIiwiS2V5LnR5cGUiLCJLZXkuYWxnb3JpdGhtIiwiS2V5LmV4dHJhY3RhYmxlIiwiS2V5LnVzYWdlcyIsIktleS5pbm5lcktleSIsIlByaXZhdGVLZXkiLCJQdWJsaWNLZXkiLCJLZXlQYWlyIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2UiLCJDcnlwdG9ncmFwaGljU2VydmljZS5jb25zdHJ1Y3RvciIsIkNyeXB0b2dyYXBoaWNTZXJ2aWNlLmRlY3J5cHQiLCJDcnlwdG9ncmFwaGljU2VydmljZS5kaWdlc3QiLCJDcnlwdG9ncmFwaGljU2VydmljZS5lbmNyeXB0IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZXhwb3J0S2V5IiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2UuZ2VuZXJhdGVLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZS5pbXBvcnRLZXkiLCJDcnlwdG9ncmFwaGljU2VydmljZS5zaWduIiwiQ3J5cHRvZ3JhcGhpY1NlcnZpY2UudmVyaWZ5IiwiRXZlbnRIdWIiLCJFdmVudEh1Yi5jb25zdHJ1Y3RvciIsIkV2ZW50SHViLnB1Ymxpc2giLCJFdmVudEh1Yi5zdWJzY3JpYmUiLCJFdmVudEh1Yi5zdWJzY3JpYmVPbmNlIiwiUG9ydCIsIlBvcnQuY29uc3RydWN0b3IiLCJQb3J0LmVuZFBvaW50IiwiUG9ydC50b09iamVjdCIsIlBvcnQub3duZXIiLCJQb3J0LnByb3RvY29sSUQiLCJQb3J0LmlkIiwiUG9ydC5kaXJlY3Rpb24iLCJQdWJsaWNQb3J0IiwiUHVibGljUG9ydC5jb25zdHJ1Y3RvciIsIlB1YmxpY1BvcnQuY29ubmVjdFByaXZhdGUiLCJQdWJsaWNQb3J0LmRpc2Nvbm5lY3RQcml2YXRlIiwiUHVibGljUG9ydC50b09iamVjdCIsIk5vZGUiLCJOb2RlLmNvbnN0cnVjdG9yIiwiTm9kZS50b09iamVjdCIsIk5vZGUub3duZXIiLCJOb2RlLmlkIiwiTm9kZS5hZGRQbGFjZWhvbGRlclBvcnQiLCJOb2RlLnBvcnRzIiwiTm9kZS5nZXRQb3J0QXJyYXkiLCJOb2RlLmdldFBvcnRCeUlEIiwiTm9kZS5pZGVudGlmeVBvcnQiLCJOb2RlLnJlbW92ZVBvcnQiLCJOb2RlLmxvYWRDb21wb25lbnQiLCJOb2RlLmNvbnRleHQiLCJOb2RlLnVubG9hZENvbXBvbmVudCIsIlJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQiLCJSdW50aW1lQ29udGV4dC5jb25zdHJ1Y3RvciIsIlJ1bnRpbWVDb250ZXh0Lmluc3RhbmNlIiwiUnVudGltZUNvbnRleHQuY29udGFpbmVyIiwiUnVudGltZUNvbnRleHQubG9hZCIsIlJ1bnRpbWVDb250ZXh0LnJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQuaW5TdGF0ZSIsIlJ1bnRpbWVDb250ZXh0LnNldFJ1blN0YXRlIiwiUnVudGltZUNvbnRleHQucmVjb25jaWxlUG9ydHMiLCJSdW50aW1lQ29udGV4dC5yZWxlYXNlIiwiTW9kdWxlUmVnaXN0cnlFbnRyeSIsIk1vZHVsZVJlZ2lzdHJ5RW50cnkuY29uc3RydWN0b3IiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIuY29uc3RydWN0b3IiLCJTeXN0ZW1Nb2R1bGVMb2FkZXIuZ2V0T3JDcmVhdGVNb2R1bGVSZWdpc3RyeUVudHJ5IiwiU3lzdGVtTW9kdWxlTG9hZGVyLmxvYWRNb2R1bGUiLCJDb21wb25lbnRGYWN0b3J5IiwiQ29tcG9uZW50RmFjdG9yeS5jb25zdHJ1Y3RvciIsIkNvbXBvbmVudEZhY3RvcnkuY3JlYXRlQ29udGV4dCIsIkNvbXBvbmVudEZhY3RvcnkuZ2V0Q2hpbGRDb250YWluZXIiLCJDb21wb25lbnRGYWN0b3J5LmxvYWRDb21wb25lbnQiLCJDb21wb25lbnRGYWN0b3J5LmdldCIsIkNvbXBvbmVudEZhY3RvcnkucmVnaXN0ZXIiLCJMaW5rIiwiTGluay5jb25zdHJ1Y3RvciIsIkxpbmsudG9PYmplY3QiLCJMaW5rLmlkIiwiTGluay5jb25uZWN0IiwiTGluay5kaXNjb25uZWN0IiwiTGluay5mcm9tTm9kZSIsIkxpbmsuZnJvbVBvcnQiLCJMaW5rLnRvTm9kZSIsIkxpbmsudG9Qb3J0IiwiTGluay5wcm90b2NvbElEIiwiTmV0d29yayIsIk5ldHdvcmsuY29uc3RydWN0b3IiLCJOZXR3b3JrLmdyYXBoIiwiTmV0d29yay5sb2FkQ29tcG9uZW50cyIsIk5ldHdvcmsuaW5pdGlhbGl6ZSIsIk5ldHdvcmsudGVhcmRvd24iLCJOZXR3b3JrLmluU3RhdGUiLCJOZXR3b3JrLnNldFJ1blN0YXRlIiwiTmV0d29yay51bndpcmVMaW5rIiwiTmV0d29yay53aXJlTGluayIsIk5ldHdvcmsuc3RhcnQiLCJOZXR3b3JrLnN0ZXAiLCJOZXR3b3JrLnN0b3AiLCJOZXR3b3JrLnBhdXNlIiwiTmV0d29yay5yZXN1bWUiLCJHcmFwaCIsIkdyYXBoLmNvbnN0cnVjdG9yIiwiR3JhcGguaW5pdEZyb21TdHJpbmciLCJHcmFwaC5pbml0RnJvbU9iamVjdCIsIkdyYXBoLnRvT2JqZWN0IiwiR3JhcGgubG9hZENvbXBvbmVudCIsIkdyYXBoLm5vZGVzIiwiR3JhcGgubGlua3MiLCJHcmFwaC5nZXROb2RlQnlJRCIsIkdyYXBoLmFkZE5vZGUiLCJHcmFwaC5yZW5hbWVOb2RlIiwiR3JhcGgucmVtb3ZlTm9kZSIsIkdyYXBoLmdldExpbmtCeUlEIiwiR3JhcGguYWRkTGluayIsIkdyYXBoLnJlbmFtZUxpbmsiLCJHcmFwaC5yZW1vdmVMaW5rIiwiR3JhcGguYWRkUHVibGljUG9ydCIsIlNpbXVsYXRpb25FbmdpbmUiLCJTaW11bGF0aW9uRW5naW5lLmNvbnN0cnVjdG9yIiwiU2ltdWxhdGlvbkVuZ2luZS5nZXRDb21wb25lbnRGYWN0b3J5Il0sIm1hcHBpbmdzIjoiQUFBQTtJQUlFQSxPQUFPQSxNQUFNQSxDQUFFQSxDQUFTQTtRQUV0QkMsRUFBRUEsQ0FBQ0EsQ0FBRUEsUUFBUUEsQ0FBQ0EsWUFBWUEsSUFBSUEsU0FBVUEsQ0FBQ0EsQ0FDekNBLENBQUNBO1lBQ0NBLElBQUlBLEdBQUdBLEdBQUdBLGtCQUFrQkEsQ0FBQ0E7WUFDN0JBLElBQUlBLEtBQUtBLEdBQUdBLDZCQUE2QkEsQ0FBQ0E7WUFDMUNBLElBQUlBLEdBQUdBLEdBQWFBLEVBQUVBLENBQUNBO1lBQ3ZCQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtnQkFDdkJBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1lBQzNCQSxHQUFHQSxHQUFHQSxHQUFHQSxDQUFDQSxXQUFXQSxFQUFFQSxDQUFDQTtZQUN4QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsQ0FBQ0EsR0FBR0EsRUFBRUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ3hCQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUMzQkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0E7Z0JBQ2pDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUM5QkEsUUFBUUEsQ0FBQ0EsWUFBWUEsR0FBR0EsR0FBR0EsQ0FBQ0E7UUFDOUJBLENBQUNBO1FBRURBLElBQUlBLEdBQUdBLEdBQWFBLEVBQUVBLENBQUNBO1FBQ3ZCQSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFDQSxFQUFFQSxVQUFVQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUM3QkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsTUFBTUEsRUFBRUEsRUFBRUEsQ0FBQ0EsRUFDakNBLENBQUNBO1lBQ0NBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQ3BCQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxHQUFHQSxDQUFDQTtnQkFDVEEsS0FBS0EsQ0FBQ0E7WUFDVkEsSUFBSUEsQ0FBQ0EsR0FBR0EsUUFBUUEsQ0FBQ0EsWUFBWUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDakNBLEVBQUVBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLENBQUNBO2dCQUNSQSxRQUFRQSxDQUFDQTtZQUNiQSxFQUFFQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFDQTtnQkFDZkEsTUFBTUEsOEJBQThCQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUM3Q0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0E7WUFDVkEsRUFBRUEsQ0FBQ0EsQ0FBQ0EsRUFBRUEsVUFBVUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ3BCQSxHQUFHQSxDQUFDQSxJQUFJQSxDQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtnQkFDakJBLElBQUlBLEdBQUdBLENBQUNBLENBQUNBO2dCQUNUQSxVQUFVQSxHQUFHQSxDQUFDQSxDQUFDQTtZQUNuQkEsQ0FBQ0E7WUFBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ0pBLElBQUlBLEtBQUtBLENBQUNBLENBQUNBO1lBQ2ZBLENBQUNBO1FBQ0hBLENBQUNBO1FBRURBLEVBQUVBLENBQUNBLENBQUNBLFVBQVVBLENBQUNBO1lBQ2JB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LENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLEdBQUdBLENBQUNBLENBQUNBLEtBQUtBLEdBQUdBLEdBQUdBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBR3pGQSxJQUFJQSxHQUFHQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxHQUFHQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxHQUFHQSxDQUFDQSxHQUFHQSxZQUFZQSxDQUFFQSxDQUFDQTtRQUc5REEsSUFBSUEsQ0FBQ0EsR0FBR0EsWUFBWUEsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7UUFFdkRBLElBQUlBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBRVZBLGNBQWVBLENBQU9BO1lBQ3BCRSxHQUFHQSxDQUFDQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNmQSxDQUFDQTtRQUVERixJQUFJQSxDQUFDQSxHQUFHQSxDQUFDQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUVqQkEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0E7WUFDN0JBLElBQUlBLEdBQUdBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLEVBQUVBLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLE1BQU1BLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1lBQzNJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxHQUFHQSxRQUFRQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxDQUFDQTtZQUM3QkEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsR0FBR0EsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDMUJBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1FBQ25CQSxDQUFDQTtRQUVEQSxFQUFFQSxDQUFDQSxDQUFDQSxZQUFZQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUN2QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDMUVBLElBQUlBLENBQUNBLEdBQUdBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1FBQ25CQSxDQUFDQTtRQUFDQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFDQSxZQUFZQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUM5QkEsSUFBSUEsR0FBR0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsRUFBRUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsTUFBTUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7WUFDOUdBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO1lBQ3hCQSxJQUFJQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUNuQkEsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0E7SUFDYkEsQ0FBQ0E7SUFFREQsT0FBT0EsTUFBTUEsQ0FBRUEsS0FBaUJBO1FBRTlCSSxJQUFJQSxDQUFTQSxDQUFDQTtRQUNkQSxJQUFJQSxVQUFVQSxHQUFHQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQTtRQUNsQ0EsSUFBSUEsTUFBTUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFaEJBLE1BQU1BLE1BQU1BLEdBQUdBLGtFQUFrRUEsQ0FBQ0E7UUFDbEZBLGdCQUFpQkEsR0FBU0E7WUFDeEJDLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBO1FBQzVCQSxDQUFDQTtRQUVERCx5QkFBMEJBLEdBQVdBO1lBQ25DRSxNQUFNQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxHQUFHQSxNQUFNQSxDQUFDQSxHQUFHQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtRQUM1R0EsQ0FBQ0E7UUFHREYsSUFBSUEsTUFBTUEsR0FBR0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsVUFBVUEsQ0FBQ0E7UUFDdkNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLEdBQUdBLENBQUNBLEVBQUVBLENBQUNBLEdBQUdBLE1BQU1BLEVBQUVBLENBQUNBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBO1lBQy9CQSxJQUFJQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxDQUFDQSxJQUFJQSxFQUFFQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtZQUNuRUEsTUFBTUEsSUFBSUEsZUFBZUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7UUFDbENBLENBQUNBO1FBR0RBLE1BQU1BLENBQUNBLENBQUNBLFVBQVVBLENBQUNBLENBQUNBLENBQUNBO1lBQ25CQSxLQUFLQSxDQUFDQTtnQkFDSkEsSUFBSUEsSUFBSUEsR0FBR0EsS0FBS0EsQ0FBQ0EsS0FBS0EsQ0FBQ0EsTUFBTUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBQ25DQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDNUJBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLENBQUNBLElBQUlBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLElBQUlBLENBQUNBLENBQUNBO2dCQUNyQ0EsTUFBTUEsSUFBSUEsSUFBSUEsQ0FBQ0E7Z0JBQ2ZBLEtBQUtBLENBQUFBO1lBQ1BBLEtBQUtBLENBQUNBO2dCQUNKQSxJQUFJQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxDQUFDQSxLQUFLQSxDQUFDQSxLQUFLQSxDQUFDQSxNQUFNQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtnQkFDbEVBLE1BQU1BLElBQUlBLE1BQU1BLENBQUNBLElBQUlBLElBQUlBLEVBQUVBLENBQUNBLENBQUNBO2dCQUM3QkEsTUFBTUEsSUFBSUEsTUFBTUEsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsSUFBSUEsQ0FBQ0EsQ0FBQ0E7Z0JBQ3JDQSxNQUFNQSxJQUFJQSxNQUFNQSxDQUFDQSxDQUFDQSxJQUFJQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxJQUFJQSxDQUFDQSxDQUFDQTtnQkFDckNBLE1BQU1BLElBQUlBLEdBQUdBLENBQUNBO2dCQUNkQSxLQUFLQSxDQUFBQTtZQUNQQTtnQkFDRUEsS0FBS0EsQ0FBQ0E7UUFDVkEsQ0FBQ0E7UUFFREEsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0E7SUFDaEJBLENBQUNBO0FBQ0hKLENBQUNBO0FBQUE7T0NqSU0sRUFBRSxRQUFRLEVBQUUsTUFBTSxhQUFhO09BQy9CLEVBQUUsV0FBVyxFQUFFLE1BQU0sZ0JBQWdCO0FBRTVDO0lBa0JFTyxZQUFhQSxLQUFxRUEsRUFBRUEsTUFBZUEsRUFBRUEsR0FBU0E7UUFFNUdDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLEtBQU1BLENBQUNBLENBQ2JBLENBQUNBO1lBRUNBLElBQUlBLENBQUNBLFNBQVNBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLENBQUNBLENBQUVBLENBQUNBO1FBQ3ZDQSxDQUFDQTtRQUNEQSxJQUFJQSxDQUFDQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxNQUFNQSxJQUFJQSxNQUFNQSxJQUFJQSxTQUFTQSxDQUFDQSxLQUFNQSxDQUFDQSxDQUNoREEsQ0FBQ0E7WUFDQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsV0FBWUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFlQSxLQUFLQSxDQUFFQSxDQUFDQTtZQUN4REEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsVUFBV0EsQ0FBQ0E7Z0JBQ3JDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQTtZQUN6QkEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsU0FBVUEsQ0FBQ0E7Z0JBQ3BDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxLQUFLQSxDQUFDQSxTQUFTQSxDQUFDQTtZQUNuQ0EsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsS0FBS0EsWUFBWUEsS0FBTUEsQ0FBQ0E7Z0JBQ2hDQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxVQUFVQSxDQUFFQSxLQUFLQSxDQUFFQSxDQUFDQTtRQUs3Q0EsQ0FBQ0E7UUFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsS0FBS0EsSUFBSUEsUUFBU0EsQ0FBQ0EsQ0FDcENBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLElBQUlBLFNBQVNBLENBQUNBLE1BQU9BLENBQUNBLENBQ2pDQSxDQUFDQTtnQkFDR0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsV0FBV0EsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDekRBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLElBQUlBLFNBQVNBLENBQUNBLEdBQUlBLENBQUNBLENBQ25DQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBVUEsS0FBS0EsQ0FBRUEsQ0FBQ0E7WUFDcERBLENBQUNBO1lBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLE1BQU1BLElBQUlBLFNBQVNBLENBQUNBLElBQUtBLENBQUNBLENBQ3BDQSxDQUFDQTtnQkFDQ0EsSUFBSUEsQ0FBQ0EsR0FBYUEsS0FBT0EsQ0FBQ0EsTUFBTUEsQ0FBQ0E7Z0JBQ2pDQSxJQUFJQSxFQUFFQSxH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QUFHLEVBQUUsTUFBTSxPQUFPO0FBRTNCLCtCQUErQixHQUFHO0FBR2xDQyxDQUFDQTtBQUFBO0FDRkQ7QUFJQUMsQ0FBQ0E7QUFBQTtPQ1BNLEVBQUUsU0FBUyxFQUFFLE1BQU0sb0JBQW9CO0FBUTlDO0lBR0VDO1FBQ0VDLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBO1FBRW5DQSxFQUFFQSxDQUFDQSxDQUFFQSxDQUFDQSxJQUFJQSxDQUFDQSxNQUFNQSxJQUFJQSxTQUFVQSxDQUFDQTtZQUM3QkEsSUFBSUEsQ0FBQ0EsTUFBTUEsR0FBR0EsU0FBU0EsQ0FBQ0E7SUFDN0JBLENBQUNBO0lBRURELE9BQU9BLENBQUNBLFNBQTZCQSxFQUFFQSxHQUFRQSxFQUFFQSxJQUFlQTtRQUM5REUsTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE9BQU9BLENBQUNBLFNBQVNBLEVBQUVBLEdBQUdBLENBQUNBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBLENBQUNBO2lCQUM1REEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsT0FBT0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7aUJBQy9DQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUN0Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFJREYsTUFBTUEsQ0FBQ0EsU0FBNkJBLEVBQUVBLElBQWVBO1FBQ25ERyxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsWUFBWUEsQ0FBQ0E7aUJBQzlDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxPQUFPQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtpQkFDL0NBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1FBQ3JDQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtJQUVESCxPQUFPQSxDQUFFQSxTQUE2QkEsRUFBRUEsR0FBUUEsRUFBRUEsSUFBZUE7UUFDL0RJLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQVlBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQzVDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxPQUFPQSxDQUFDQSxTQUFTQSxFQUFFQSxHQUFHQSxDQUFDQSxRQUFRQSxFQUFFQSxJQUFJQSxDQUFDQSxZQUFZQSxDQUFDQTtpQkFDNURBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE9BQU9BLENBQUNBLElBQUlBLFNBQVNBLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2lCQUMvQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDdENBLENBQUNBLENBQUNBLENBQUNBO0lBQ0xBLENBQUNBO0lBRURKLFNBQVNBLENBQUVBLE1BQWNBLEVBQUVBLEdBQVFBO1FBQ2pDSyxNQUFNQSxDQUFDQSxJQUFJQSxPQUFPQSxDQUFZQSxDQUFDQSxPQUFPQSxFQUFFQSxNQUFNQTtZQUM1Q0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsTUFBTUEsRUFBRUEsR0FBR0EsQ0FBQ0EsUUFBUUEsQ0FBQ0E7aUJBQ3hDQSxJQUFJQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxPQUFPQSxDQUFDQSxJQUFJQSxTQUFTQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtpQkFDL0NBLEtBQUtBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE1BQU1BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO1FBQ3RDQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNMQSxDQUFDQTtJQUVETCxXQUFXQSxDQUFFQSxTQUE2QkEsRUFBRUEsV0FBb0JBLEVBQUVBLFNBQW1CQTtRQUNuRk0sTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBZ0JBLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1FBRW5EQSxDQUFDQSxDQUFDQSxDQUFDQTtJQUNKQSxDQUFDQTtJQUVETixTQUFTQSxDQUFDQSxNQUFjQSxFQUFFQSxPQUFrQkEsRUFBR0EsU0FBNkJBLEVBQUVBLFdBQW9CQSxFQUFFQSxTQUFtQkE7UUFDckhPLE1BQU1BLENBQUNBLElBQUlBLE9BQU9BLENBQU1BLENBQUNBLE9BQU9BLEVBQUVBLE1BQU1BO1lBQ3RDQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxTQUFTQSxDQUFDQSxNQUFNQSxFQUFFQSxPQUFPQSxDQUFDQSxZQUFZQSxFQUFFQSxTQUFTQSxFQUFFQSxXQUFXQSxFQUFFQSxTQUFTQSxDQUFDQTtpQkFDbkZBLElBQUlBLENBQUNBLENBQUNBLEdBQUdBLE9BQU9BLE9BQU9BLENBQUNBLEdBQUdBLENBQUNBLENBQUNBLENBQUNBLENBQUNBLENBQUNBO2lCQUNoQ0EsS0FBS0EsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7UUFDdkNBLENBQUNBLENBQUNBLENBQUNBO0lBQ0pBLENBQUNBO0lBRURQLElBQUlBLENBQUNBLFNBQTZCQSxFQUFFQSxHQUFRQSxFQUFFQSxJQUFlQTtRQUMzRFEsTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFNBQVNBLEVBQUVBLEdBQUdBLENBQUNBLFFBQVFBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBLENBQUNBO2lCQUN6REEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsT0FBT0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7aUJBQy9DQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUN0Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7SUFHRFIsTUFBTUEsQ0FBQ0EsU0FBNkJBLEVBQUVBLEdBQVFBLEVBQUVBLFNBQW9CQSxFQUFFQSxJQUFlQTtRQUNuRlMsTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBWUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFDNUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUNBLFNBQVNBLEVBQUVBLEdBQUdBLENBQUNBLFFBQVFBLEVBQUVBLFNBQVNBLENBQUNBLFlBQVlBLEVBQUVBLElBQUlBLENBQUNBLFlBQVlBLENBQUNBO2lCQUNuRkEsSUFBSUEsQ0FBQ0EsQ0FBQ0EsR0FBR0EsT0FBT0EsT0FBT0EsQ0FBQ0EsSUFBSUEsU0FBU0EsQ0FBQ0EsR0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7aUJBQy9DQSxLQUFLQSxDQUFDQSxDQUFDQSxHQUFHQSxPQUFPQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFDQTtRQUN0Q0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7SUFDTEEsQ0FBQ0E7QUFHSFQsQ0FBQ0E7QUFBQTtPQ3BGTSxFQUFFLFNBQVMsRUFBRSxVQUFVLElBQUksTUFBTSxFQUFFLE1BQU0sOEJBQThCO0FBRzlFLFNBQVMsU0FBUyxFQUFFLE1BQU0sR0FBRztPQ0h0QixFQUFFLGVBQWUsRUFBeUMsTUFBTSwwQkFBMEI7QUFJakc7SUFJRVU7UUFFRUMsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxHQUFHQSxJQUFJQSxlQUFlQSxFQUFFQSxDQUFDQTtJQUNoREEsQ0FBQ0E7SUFFTUQsT0FBT0EsQ0FBRUEsS0FBYUEsRUFBRUEsSUFBVUE7UUFFdkNFLElBQUlBLENBQUNBLGdCQUFnQkEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7SUFDL0NBLENBQUNBO0lBRU1GLFNBQVNBLENBQUVBLEtBQWFBLEVBQUVBLE9BQWlCQTtRQUVoREcsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsZ0JBQWdCQSxDQUFDQSxTQUFTQSxDQUFFQSxLQUFLQSxFQUFFQSxPQUFPQSxDQUFFQSxDQUFDQTtJQUMzREEsQ0FBQ0E7SUFFTUgsYUFBYUEsQ0FBRUEsS0FBYUEsRUFBRUEsT0FBaUJBO1FBRXBESSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQSxnQkFBZ0JBLENBQUNBLGFBQWFBLENBQUVBLEtBQUtBLEVBQUVBLE9BQU9BLENBQUVBLENBQUNBO0lBQy9EQSxDQUFDQTtBQUNISixDQUFDQTtBQUFBLE9DM0JNLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxNQUFNLHdCQUF3QjtBQVU1RDtJQVNFSyxZQUFhQSxLQUFXQSxFQUFFQSxRQUFrQkEsRUFBRUEsVUFBVUEsR0FBUUEsRUFBRUE7UUFHaEVDLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLFFBQVNBLENBQUNBLENBQ2hCQSxDQUFDQTtZQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxVQUFVQSxDQUFDQSxTQUFTQSxJQUFJQSxTQUFTQSxDQUFDQSxLQUFLQSxDQUFDQTtZQUV4REEsRUFBRUEsQ0FBQ0EsQ0FBRUEsT0FBT0EsVUFBVUEsQ0FBQ0EsU0FBU0EsSUFBSUEsUUFBU0EsQ0FBQ0E7Z0JBQzVDQSxTQUFTQSxHQUFHQSxTQUFTQSxDQUFFQSxTQUFTQSxDQUFDQSxXQUFXQSxFQUFFQSxDQUFFQSxDQUFDQTtZQUduREEsUUFBUUEsR0FBR0EsSUFBSUEsUUFBUUEsQ0FBRUEsVUFBVUEsQ0FBQ0EsRUFBRUEsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFDdERBLENBQUNBO1FBRURBLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLEtBQUtBLENBQUNBO1FBQ3BCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtRQUUxQkEsSUFBSUEsQ0FBQ0EsV0FBV0EsR0FBR0EsVUFBVUEsQ0FBRUEsVUFBVUEsQ0FBRUEsSUFBSUEsS0FBS0EsQ0FBQ0E7UUFFckRBLElBQUlBLENBQUNBLFFBQVFBLEdBQUdBLFVBQVVBLENBQUNBLFFBQVFBLElBQUlBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBLEVBQUVBLEdBQUdBLEVBQUVBLENBQUNBO0lBQzVEQSxDQUFDQTtJQUVERCxJQUFXQSxRQUFRQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBQ0RGLElBQVdBLFFBQVFBLENBQUVBLFFBQWtCQTtRQUNyQ0UsSUFBSUEsQ0FBQ0EsU0FBU0EsR0FBR0EsUUFBUUEsQ0FBQ0E7SUFDNUJBLENBQUNBO0lBS0RGLFFBQVFBLENBQUVBLElBQVVBO1FBRWxCRyxJQUFJQSxJQUFJQSxHQUFHQTtZQUNUQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxDQUFDQSxFQUFFQTtZQUNyQkEsU0FBU0EsRUFBRUEsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0EsU0FBU0E7WUFDbkNBLFFBQVFBLEVBQUVBLENBQUVBLElBQUlBLENBQUNBLFdBQVdBLElBQUlBLEtBQUtBLENBQUVBLEdBQUdBLElBQUlBLENBQUNBLFdBQVdBLEdBQUdBLFNBQVNBO1lBQ3RFQSxRQUFRQSxFQUFF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QUNBLE9BQU9BLEdBQUdBLE1BQU1BLENBQUNBO1FBRXRCQSxJQUFJQSxDQUFDQSxVQUFVQSxHQUFHQSxTQUFTQSxDQUFDQTtRQUc1QkEsR0FBR0EsQ0FBQUEsQ0FBRUEsR0FBR0EsQ0FBQ0EsQ0FBQ0EsSUFBSUEsSUFBS0EsQ0FBQ0EsQ0FDcEJBLENBQUNBO1lBQ0NBLEVBQUVBLENBQUNBLENBQUVBLENBQUNBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBLFdBQVdBLENBQUVBLElBQUlBLENBQUNBLENBQUNBLENBQUNBLENBQUdBLENBQUNBO2dCQUM1Q0EsSUFBSUEsQ0FBQ0EsVUFBVUEsQ0FBQ0EsaUJBQWlCQSxDQUFFQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQSxFQUFFQSxJQUFJQSxDQUFDQSxDQUFDQSxDQUFDQSxDQUFFQSxDQUFDQTtRQUMxREEsQ0FBQ0E7SUFDSEEsQ0FBQ0E7SUFFREQsSUFBSUEsUUFBUUE7UUFDVkUsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsU0FBU0EsQ0FBQ0E7SUFDeEJBLENBQUNBO0lBRURGLElBQUlBLFNBQVNBO1FBQ1hHLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLFVBQVVBLENBQUNBO0lBQ3pCQSxDQUFDQTtJQUVESCxJQUFJQTtRQUVGSSxJQUFJQSxFQUFFQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUVkQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxJQUFJQSxDQUFDQTtRQUV0QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsT0FBT0EsQ0FBUUEsQ0FBQ0EsT0FBT0EsRUFBRUEsTUFBTUE7WUFFeENBLEVBQUVBLENBQUNBLFNBQVNBLEdBQUdBLFFBQVFBLENBQUNBLE9BQU9BLENBQUNBO1lBQ2hDQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxhQUFhQSxDQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxDQUFDQSxHQUFHQSxDQUFFQTtpQkFDMUNBLElBQUlBLENBQUVBLENBQUNBLFFBQVFBO2dCQUVkQSxFQUFFQSxDQUFDQSxTQUFTQSxHQUFHQSxRQUFRQSxDQUFDQTtnQkFDeEJBLEVB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QUVBLFFBQVFBLENBQUNBLE9BQU9BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUUzREEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsS0FBTUEsQ0FBQ0E7d0JBQ2ZBLElBQUlBLENBQUNBLFFBQVFBLENBQUNBLEtBQUtBLEVBQUVBLENBQUNBO2dCQUMxQkEsQ0FBQ0E7Z0JBQ0RBLElBQUlBLENBQUNBLEVBQUVBLENBQUNBLENBQUVBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLENBQUVBLFFBQVFBLENBQUNBLE1BQU1BLENBQUVBLENBQUdBLENBQUNBLENBQUNBLENBQUNBO29CQUUvQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsTUFBT0EsQ0FBQ0E7d0JBQ2hCQSxJQUFJQSxDQUFDQSxRQUFRQSxDQUFDQSxNQUFNQSxFQUFFQSxDQUFDQTtnQkFDM0JBLENBQUNBO2dCQUNEQSxJQUFJQTtvQkFDRkEsTUFBTUEsSUFBSUEsS0FBS0EsQ0FBRUEsd0NBQXdDQSxDQUFFQSxDQUFDQTtnQkFDOURBLEtBQUtBLENBQUNBO1lBRVJBLEtBQUtBLFFBQVFBLENBQUNBLE1BQU1BO2dCQUNsQkEsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsT0FBT0EsQ0FBQ0EsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7b0JBQzFDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFJQSxDQUFDQSxLQUFNQSxDQUFDQTt3QkFDZkEsSUFBSUEsQ0FBQ0EsUUFBUUEsQ0FBQ0EsS0FBS0EsRUFBRUEsQ0FBQ0E7Z0JBQzFCQSxDQUFDQTtnQkFDREEsSUFBSUEsQ0FBQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsQ0FBRUEsUUFBUUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsQ0FBR0EsQ0FBQ0EsQ0FBQ0EsQ0FBQ0E7Z0JBRWpEQSxDQUFDQTtnQkFDREEsSUFBSUE7b0JBQ0ZBLE1BQU1BLElBQUlBLEtBQUtBLENBQUVBLDRC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QUFHQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUV4Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFYkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNVCxVQUFVQSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ1UsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLEVBQUVBLENBQUNBLENBQUVBLEVBQUVBLElBQUlBLEtBQU1BLENBQUNBLENBQ2xCQSxDQUFDQTtZQUNDQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtZQUV2REEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7WUFFekJBLElBQUlBLENBQUNBLEVBQUVBLEdBQUdBLEtBQUtBLENBQUNBO1lBRWhCQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtZQUUvQkEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsU0FBU0EsQ0FBRUEsQ0FBQ0E7UUFDbERBLENBQUNBO0lBQ0hBLENBQUNBO0lBRU1WLFVBQVVBLENBQUVBLEVBQVVBO1FBRTNCVyxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUNqQ0EsRUFBRUEsQ0FBQ0EsQ0FBRUEsSUFBS0EsQ0FBQ0E7WUFDVEEsSUFBSUEsQ0FBQ0EsT0FBT0EsQ0FBRUEsS0FBS0EsQ0FBQ0EsY0FBY0EsRUFBRUEsRUFBRUEsSUFBSUEsRUFBRUEsSUFBSUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFdkRBLE1BQU1BLENBQUNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO0lBQ2xDQSxDQUFDQTtJQUVNWCxXQUFXQSxDQUFFQSxFQUFVQTtRQUU1QlksTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDM0JBLENBQUNBO0lBRU1aLE9BQU9BLENBQUVBLEVBQVVBLEVBQUVBLFVBQWVBO1FBRXpDYSxJQUFJQSxJQUFJQSxHQUFHQSxJQUFJQSxJQUFJQSxDQUFFQSxJQUFJQSxFQUFFQSxVQUFVQSxDQUFFQSxDQUFDQTtRQUV4Q0EsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFYkEsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsRUFBRUEsSUFBSUEsQ0FBRUEsQ0FBQ0E7UUFFNUJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLEVBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLENBQUVBLENBQUNBO1FBRXJEQSxNQUFNQSxDQUFDQSxJQUFJQSxDQUFDQTtJQUNkQSxDQUFDQTtJQUVNYixVQUFVQSxDQUFFQSxFQUFVQSxFQUFFQSxLQUFhQTtRQUUxQ2MsSUFBSUEsSUFBSUEsR0FBR0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsR0FBR0EsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7UUFFakNBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLE1BQU1BLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBRXpCQSxJQUFJQSxTQUFTQSxHQUFHQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxLQUFLQSxFQUFFQSxFQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFDQSxFQUFFQSxFQUFFQSxFQUFFQSxDQUFDQTtRQUV2REEsSUFBSUEsQ0FBQ0EsRUFBRUEsR0FBR0EsS0FBS0EsQ0FBQ0E7UUFFaEJBLElBQUlBLENBQUNBLE9BQU9BLENBQUVBLEtBQUtBLENBQUNBLGNBQWNBLEVBQUVBLFNBQVNBLENBQUVBLENBQUNBO1FBRWhEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxLQUFLQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtJQUNqQ0EsQ0FBQ0E7SUFFTWQsVUFBVUEsQ0FBRUEsRUFBVUE7UUFFM0JlLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLENBQUNBLE1BQU1BLENBQUNBLEdBQUdBLENBQUVBLEVBQUVBLENBQUVBLENBQUNBO1FBQ2pDQSxFQUFFQSxDQUFDQSxDQUFFQSxJQUFLQSxDQUFDQTtZQUNUQSxJQUFJQSxDQUFDQSxPQUFPQSxDQUFFQSxLQUFLQSxDQUFDQSxjQUFjQSxFQUFFQSxFQUFFQSxJQUFJQSxFQUFFQSxJQUFJQSxFQUFFQSxDQUFFQSxDQUFDQTtRQUV2REEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsTUFBTUEsQ0FBQ0EsTUFBTUEsQ0FBRUEsRUFBRUEsQ0FBRUEsQ0FBQ0E7SUFDbENBLENBQUNBO0lBRU1mLGFBQWFBLENBQUVBLEVBQVVBLEVBQUVBLFVBQWNBO1FBRTlDZ0IsVUFBVUEsQ0FBQ0EsSUFBSUEsQ0FBQ0EsR0FBR0EsRUFBRUEsQ0FBQ0E7UUFFdEJBLElBQUlBLElBQUlBLEdBQUdBLElBQUlBLFVBQVVBLENBQUVBLElBQUlBLEVBQUVBLElBQUlBLEVBQUVBLFVBQVVBLENBQUVBLENBQUNBO1FBRXBEQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFDQSxHQUFHQSxDQUFFQSxFQUFFQSxFQUFFQSxJQUFJQSxDQUFFQSxDQUFDQTtRQUU1QkEsTUFBTUEsQ0FBQ0EsSUFBSUEsQ0FBQ0E7SUFDZEEsQ0FBQ0E7QUFDSGhCLENBQUNBO0FBN1BRLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQUFDO0FBRWxDLG9CQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFDbEMsb0JBQWMsR0FBRyxnQkFBZ0IsQ0FBQztBQUNsQyxvQkFBYyxHQUFHLGdCQUFnQixDQXVQekM7O09DMVFNLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxxQkFBcUI7QUFLdEQ7SUFVRWlCLFlBQWFBLE1BQW9CQSxFQUFFQSxTQUFvQkE7UUFDckRDLElBQUlBLENBQUNBLE1BQU1BLEdBQUdBLE1BQU1BLENBQUNBO1FBQ3JCQSxJQUFJQSxDQUFDQSxTQUFTQSxHQUFHQSxTQUFTQSxDQUFDQTtJQUM3QkEsQ0FBQ0E7SUFNREQsbUJBQW1CQTtRQUNqQkUsTUFBTUEsQ0FBQ0EsSUFBSUEsZ0JBQWdCQSxDQUFFQSxJQUFJQSxDQUFDQSxTQUFTQSxFQUFFQSxJQUFJQSxDQUFDQSxNQUFNQSxDQUFFQSxDQUFDQTtJQUM3REEsQ0FBQ0E7QUFFSEYsQ0FBQ0E7QUFBQSIsImZpbGUiOiJjcnlwdG9ncmFwaGl4LXNpbS1jb3JlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNsYXNzIEhleENvZGVjXG57XG4gIHByaXZhdGUgc3RhdGljIGhleERlY29kZU1hcDogbnVtYmVyW107XG5cbiAgc3RhdGljIGRlY29kZSggYTogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmICggSGV4Q29kZWMuaGV4RGVjb2RlTWFwID09IHVuZGVmaW5lZCApXG4gICAge1xuICAgICAgdmFyIGhleCA9IFwiMDEyMzQ1Njc4OUFCQ0RFRlwiO1xuICAgICAgdmFyIGFsbG93ID0gXCIgXFxmXFxuXFxyXFx0XFx1MDBBMFxcdTIwMjhcXHUyMDI5XCI7XG4gICAgICB2YXIgZGVjOiBudW1iZXJbXSA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgKytpKVxuICAgICAgICAgIGRlY1toZXguY2hhckF0KGkpXSA9IGk7XG4gICAgICBoZXggPSBoZXgudG9Mb3dlckNhc2UoKTtcbiAgICAgIGZvciAodmFyIGkgPSAxMDsgaSA8IDE2OyArK2kpXG4gICAgICAgICAgZGVjW2hleC5jaGFyQXQoaSldID0gaTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYWxsb3cubGVuZ3RoOyArK2kpXG4gICAgICAgICAgZGVjW2FsbG93LmNoYXJBdChpKV0gPSAtMTtcbiAgICAgIEhleENvZGVjLmhleERlY29kZU1hcCA9IGRlYztcbiAgICB9XG5cbiAgICB2YXIgb3V0OiBudW1iZXJbXSA9IFtdO1xuICAgIHZhciBiaXRzID0gMCwgY2hhcl9jb3VudCA9IDA7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhLmxlbmd0aDsgKytpKVxuICAgIHtcbiAgICAgIHZhciBjID0gYS5jaGFyQXQoaSk7XG4gICAgICBpZiAoYyA9PSAnPScpXG4gICAgICAgICAgYnJlYWs7XG4gICAgICB2YXIgYiA9IEhleENvZGVjLmhleERlY29kZU1hcFtjXTtcbiAgICAgIGlmIChiID09IC0xKVxuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgaWYgKGIgPT0gdW5kZWZpbmVkKVxuICAgICAgICAgIHRocm93ICdJbGxlZ2FsIGNoYXJhY3RlciBhdCBvZmZzZXQgJyArIGk7XG4gICAgICBiaXRzIHw9IGI7XG4gICAgICBpZiAoKytjaGFyX2NvdW50ID49IDIpIHtcbiAgICAgICAgICBvdXQucHVzaCggYml0cyApO1xuICAgICAgICAgIGJpdHMgPSAwO1xuICAgICAgICAgIGNoYXJfY291bnQgPSAwO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBiaXRzIDw8PSA0O1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChjaGFyX2NvdW50KVxuICAgICAgdGhyb3cgXCJIZXggZW5jb2RpbmcgaW5jb21wbGV0ZTogNCBiaXRzIG1pc3NpbmdcIjtcblxuICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oIG91dCApO1xuICB9XG59XG4iLCJ0eXBlIGJ5dGUgPSBudW1iZXI7XG5cbmVudW0gQkFTRTY0U1BFQ0lBTFMge1xuICBQTFVTID0gJysnLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIID0gJy8nLmNoYXJDb2RlQXQoMCksXG4gIE5VTUJFUiA9ICcwJy5jaGFyQ29kZUF0KDApLFxuICBMT1dFUiA9ICdhJy5jaGFyQ29kZUF0KDApLFxuICBVUFBFUiA9ICdBJy5jaGFyQ29kZUF0KDApLFxuICBQTFVTX1VSTF9TQUZFID0gJy0nLmNoYXJDb2RlQXQoMCksXG4gIFNMQVNIX1VSTF9TQUZFID0gJ18nLmNoYXJDb2RlQXQoMClcbn1cblxuZXhwb3J0IGNsYXNzIEJhc2U2NENvZGVjXG57XG4gIHN0YXRpYyBkZWNvZGUoIGI2NDogc3RyaW5nICk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIGlmIChiNjQubGVuZ3RoICUgNCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBiYXNlNjQgc3RyaW5nLiBMZW5ndGggbXVzdCBiZSBhIG11bHRpcGxlIG9mIDQnKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBkZWNvZGUoIGVsdDogU3RyaW5nICk6IG51bWJlclxuICAgIHtcbiAgICAgIHZhciBjb2RlID0gZWx0LmNoYXJDb2RlQXQoMCk7XG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5QTFVTIHx8IGNvZGUgPT09IEJBU0U2NFNQRUNJQUxTLlBMVVNfVVJMX1NBRkUpXG4gICAgICAgIHJldHVybiA2MjsgLy8gJysnXG5cbiAgICAgIGlmIChjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSCB8fCBjb2RlID09PSBCQVNFNjRTUEVDSUFMUy5TTEFTSF9VUkxfU0FGRSlcbiAgICAgICAgcmV0dXJuIDYzOyAvLyAnLydcblxuICAgICAgaWYgKGNvZGUgPj0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSKVxuICAgICAge1xuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLk5VTUJFUiArIDEwKVxuICAgICAgICAgIHJldHVybiBjb2RlIC0gQkFTRTY0U1BFQ0lBTFMuTlVNQkVSICsgMjYgKyAyNjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLlVQUEVSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5VUFBFUjtcblxuICAgICAgICBpZiAoY29kZSA8IEJBU0U2NFNQRUNJQUxTLkxPV0VSICsgMjYpXG4gICAgICAgICAgcmV0dXJuIGNvZGUgLSBCQVNFNjRTUEVDSUFMUy5MT1dFUiArIDI2O1xuICAgICAgfVxuXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ludmFsaWQgYmFzZTY0IHN0cmluZy4gQ2hhcmFjdGVyIG5vdCB2YWxpZCcpO1xuICAgIH1cblxuICAgIC8vIHRoZSBudW1iZXIgb2YgZXF1YWwgc2lnbnMgKHBsYWNlIGhvbGRlcnMpXG4gICAgLy8gaWYgdGhlcmUgYXJlIHR3byBwbGFjZWhvbGRlcnMsIHRoYW4gdGhlIHR3byBjaGFyYWN0ZXJzIGJlZm9yZSBpdFxuICAgIC8vIHJlcHJlc2VudCBvbmUgYnl0ZVxuICAgIC8vIGlmIHRoZXJlIGlzIG9ubHkgb25lLCB0aGVuIHRoZSB0aHJlZSBjaGFyYWN0ZXJzIGJlZm9yZSBpdCByZXByZXNlbnQgMiBieXRlc1xuICAgIC8vIHRoaXMgaXMganVzdCBhIGNoZWFwIGhhY2sgdG8gbm90IGRvIGluZGV4T2YgdHdpY2VcbiAgICBsZXQgbGVuID0gYjY0Lmxlbmd0aDtcbiAgICBsZXQgcGxhY2VIb2xkZXJzID0gYjY0LmNoYXJBdChsZW4gLSAyKSA9PT0gJz0nID8gMiA6IGI2NC5jaGFyQXQobGVuIC0gMSkgPT09ICc9JyA/IDEgOiAwO1xuXG4gICAgLy8gYmFzZTY0IGlzIDQvMyArIHVwIHRvIHR3byBjaGFyYWN0ZXJzIG9mIHRoZSBvcmlnaW5hbCBkYXRhXG4gICAgbGV0IGFyciA9IG5ldyBVaW50OEFycmF5KCBiNjQubGVuZ3RoICogMyAvIDQgLSBwbGFjZUhvbGRlcnMgKTtcblxuICAgIC8vIGlmIHRoZXJlIGFyZSBwbGFjZWhvbGRlcnMsIG9ubHkgZ2V0IHVwIHRvIHRoZSBsYXN0IGNvbXBsZXRlIDQgY2hhcnNcbiAgICBsZXQgbCA9IHBsYWNlSG9sZGVycyA+IDAgPyBiNjQubGVuZ3RoIC0gNCA6IGI2NC5sZW5ndGg7XG5cbiAgICB2YXIgTCA9IDA7XG5cbiAgICBmdW5jdGlvbiBwdXNoICh2OiBieXRlKSB7XG4gICAgICBhcnJbTCsrXSA9IHY7XG4gICAgfVxuXG4gICAgbGV0IGkgPSAwLCBqID0gMDtcblxuICAgIGZvciAoOyBpIDwgbDsgaSArPSA0LCBqICs9IDMpIHtcbiAgICAgIGxldCB0bXAgPSAoZGVjb2RlKGI2NC5jaGFyQXQoaSkpIDw8IDE4KSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpIDw8IDEyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMikpIDw8IDYpIHwgZGVjb2RlKGI2NC5jaGFyQXQoaSArIDMpKTtcbiAgICAgIHB1c2goKHRtcCAmIDB4RkYwMDAwKSA+PiAxNik7XG4gICAgICBwdXNoKCh0bXAgJiAweEZGMDApID4+IDgpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICBpZiAocGxhY2VIb2xkZXJzID09PSAyKSB7XG4gICAgICBsZXQgdG1wID0gKGRlY29kZShiNjQuY2hhckF0KGkpKSA8PCAyKSB8IChkZWNvZGUoYjY0LmNoYXJBdChpICsgMSkpID4+IDQpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9IGVsc2UgaWYgKHBsYWNlSG9sZGVycyA9PT0gMSkge1xuICAgICAgbGV0IHRtcCA9IChkZWNvZGUoYjY0LmNoYXJBdChpKSkgPDwgMTApIHwgKGRlY29kZShiNjQuY2hhckF0KGkgKyAxKSkgPDwgNCkgfCAoZGVjb2RlKGI2NC5jaGFyQXQoaSArIDIpKSA+PiAyKTtcbiAgICAgIHB1c2goKHRtcCA+PiA4KSAmIDB4RkYpO1xuICAgICAgcHVzaCh0bXAgJiAweEZGKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXJyO1xuICB9XG5cbiAgc3RhdGljIGVuY29kZSggdWludDg6IFVpbnQ4QXJyYXkgKTogc3RyaW5nXG4gIHtcbiAgICB2YXIgaTogbnVtYmVyO1xuICAgIHZhciBleHRyYUJ5dGVzID0gdWludDgubGVuZ3RoICUgMzsgLy8gaWYgd2UgaGF2ZSAxIGJ5dGUgbGVmdCwgcGFkIDIgYnl0ZXNcbiAgICB2YXIgb3V0cHV0ID0gJyc7XG5cbiAgICBjb25zdCBsb29rdXAgPSAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLyc7XG4gICAgZnVuY3Rpb24gZW5jb2RlKCBudW06IGJ5dGUgKSB7XG4gICAgICByZXR1cm4gbG9va3VwLmNoYXJBdChudW0pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHRyaXBsZXRUb0Jhc2U2NCggbnVtOiBudW1iZXIgKSB7XG4gICAgICByZXR1cm4gZW5jb2RlKG51bSA+PiAxOCAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiAxMiAmIDB4M0YpICsgZW5jb2RlKG51bSA+PiA2ICYgMHgzRikgKyBlbmNvZGUobnVtICYgMHgzRik7XG4gICAgfVxuXG4gICAgLy8gZ28gdGhyb3VnaCB0aGUgYXJyYXkgZXZlcnkgdGhyZWUgYnl0ZXMsIHdlJ2xsIGRlYWwgd2l0aCB0cmFpbGluZyBzdHVmZiBsYXRlclxuICAgIGxldCBsZW5ndGggPSB1aW50OC5sZW5ndGggLSBleHRyYUJ5dGVzO1xuICAgIGZvciAoaSA9IDA7IGkgPCBsZW5ndGg7IGkgKz0gMykge1xuICAgICAgbGV0IHRlbXAgPSAodWludDhbaV0gPDwgMTYpICsgKHVpbnQ4W2kgKyAxXSA8PCA4KSArICh1aW50OFtpICsgMl0pO1xuICAgICAgb3V0cHV0ICs9IHRyaXBsZXRUb0Jhc2U2NCh0ZW1wKTtcbiAgICB9XG5cbiAgICAvLyBwYWQgdGhlIGVuZCB3aXRoIHplcm9zLCBidXQgbWFrZSBzdXJlIHRvIG5vdCBmb3JnZXQgdGhlIGV4dHJhIGJ5dGVzXG4gICAgc3dpdGNoIChleHRyYUJ5dGVzKSB7XG4gICAgICBjYXNlIDE6XG4gICAgICAgIGxldCB0ZW1wID0gdWludDhbdWludDgubGVuZ3RoIC0gMV07XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAyKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCA0KSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz09JztcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgdGVtcCA9ICh1aW50OFt1aW50OC5sZW5ndGggLSAyXSA8PCA4KSArICh1aW50OFt1aW50OC5sZW5ndGggLSAxXSk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUodGVtcCA+PiAxMCk7XG4gICAgICAgIG91dHB1dCArPSBlbmNvZGUoKHRlbXAgPj4gNCkgJiAweDNGKTtcbiAgICAgICAgb3V0cHV0ICs9IGVuY29kZSgodGVtcCA8PCAyKSAmIDB4M0YpO1xuICAgICAgICBvdXRwdXQgKz0gJz0nO1xuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgSGV4Q29kZWMgfSBmcm9tICcuL2hleC1jb2RlYyc7XG5pbXBvcnQgeyBCYXNlNjRDb2RlYyB9IGZyb20gJy4vYmFzZTY0LWNvZGVjJztcblxuZXhwb3J0IGNsYXNzIEJ5dGVBcnJheSAvL2V4dGVuZHMgVWludDhBcnJheVxue1xuICBwdWJsaWMgc3RhdGljIEJZVEVTID0gMDtcbiAgcHVibGljIHN0YXRpYyBIRVggPSAxO1xuICBwdWJsaWMgc3RhdGljIEJBU0U2NCA9IDI7XG4gIHB1YmxpYyBzdGF0aWMgVVRGOCA9IDM7XG5cbiAgcHJpdmF0ZSBieXRlQXJyYXk6IFVpbnQ4QXJyYXk7XG4gIC8qKlxuICAgKiBDcmVhdGUgYSBCeXRlQXJyYXlcbiAgICogQHBhcmFtIGJ5dGVzIC0gaW5pdGlhbCBjb250ZW50cywgb3B0aW9uYWxcbiAgICogICBtYXkgYmU6XG4gICAqICAgICBhbiBleGlzdGluZyBCeXRlQXJyYXlcbiAgICogICAgIGFuIEFycmF5IG9mIG51bWJlcnMgKDAuLjI1NSlcbiAgICogICAgIGEgc3RyaW5nLCB0byBiZSBjb252ZXJ0ZWRcbiAgICogICAgIGFuIEFycmF5QnVmZmVyXG4gICAqICAgICBhIFVpbnQ4QXJyYXlcbiAgICovXG4gIGNvbnN0cnVjdG9yKCBieXRlcz86IEJ5dGVBcnJheSB8IEFycmF5PG51bWJlcj4gfCBTdHJpbmcgfCBBcnJheUJ1ZmZlciB8IFVpbnQ4QXJyYXksIGZvcm1hdD86IG51bWJlciwgb3B0PzogYW55IClcbiAge1xuICAgIGlmICggIWJ5dGVzIClcbiAgICB7XG4gICAgICAvLyB6ZXJvLWxlbmd0aCBhcnJheVxuICAgICAgdGhpcy5ieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheSggMCApO1xuICAgIH1cbiAgICBlbHNlIGlmICggIWZvcm1hdCB8fCBmb3JtYXQgPT0gQnl0ZUFycmF5LkJZVEVTIClcbiAgICB7XG4gICAgICBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCA8QXJyYXlCdWZmZXI+Ynl0ZXMgKTtcbiAgICAgIGVsc2UgaWYgKCBieXRlcyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkgKVxuICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IGJ5dGVzO1xuICAgICAgZWxzZSBpZiAoIGJ5dGVzIGluc3RhbmNlb2YgQnl0ZUFycmF5IClcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBieXRlcy5ieXRlQXJyYXk7XG4gICAgICBlbHNlIGlmICggYnl0ZXMgaW5zdGFuY2VvZiBBcnJheSApXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGJ5dGVzICk7XG4gICAgICAvL2Vsc2UgaWYgKCB0eXBlb2YgYnl0ZXMgPT0gXCJzdHJpbmdcIiApXG4gICAgICAvL3tcbi8vICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCA8c3RyaW5nPmJ5dGVzICk7XG4gICAgICAvL31cbiAgICB9XG4gICAgZWxzZSBpZiAoIHR5cGVvZiBieXRlcyA9PSBcInN0cmluZ1wiIClcbiAgICB7XG4gICAgICBpZiAoIGZvcm1hdCA9PSBCeXRlQXJyYXkuQkFTRTY0IClcbiAgICAgIHtcbiAgICAgICAgICB0aGlzLmJ5dGVBcnJheSA9IEJhc2U2NENvZGVjLmRlY29kZSggPHN0cmluZz5ieXRlcyApO1xuICAgICAgfVxuICAgICAgZWxzZSBpZiAoIGZvcm1hdCA9PSBCeXRlQXJyYXkuSEVYIClcbiAgICAgIHtcbiAgICAgICAgdGhpcy5ieXRlQXJyYXkgPSBIZXhDb2RlYy5kZWNvZGUoIDxzdHJpbmc+Ynl0ZXMgKTtcbiAgICAgIH1cbiAgICAgIGVsc2UgaWYgKCBmb3JtYXQgPT0gQnl0ZUFycmF5LlVURjggKVxuICAgICAge1xuICAgICAgICBsZXQgbCA9ICggPHN0cmluZz5ieXRlcyApLmxlbmd0aDtcbiAgICAgICAgbGV0IGJhID0gbmV3IFVpbnQ4QXJyYXkoIGwgKTtcbiAgICAgICAgZm9yKCBsZXQgaSA9IDA7IGkgPCBsOyArK2kgKVxuICAgICAgICAgIGJhW2ldID0gKCA8c3RyaW5nPmJ5dGVzICkuY2hhckNvZGVBdCggaSApO1xuXG4gICAgICAgIHRoaXMuYnl0ZUFycmF5ID0gYmE7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gTXVzdCBoYXZlIGV4ZWMgb25lIG9mIGFib3ZlIGFsbG9jYXRvcnNcbiAgICBpZiAoICF0aGlzLmJ5dGVBcnJheSApXG4gICAge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCBcIkludmFsaWQgUGFyYW1zIGZvciBCeXRlQXJyYXkoKVwiKVxuICAgIH1cbiAgfVxuXG4gIGdldCBsZW5ndGgoKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5ieXRlQXJyYXkubGVuZ3RoO1xuICB9XG5cbiAgc2V0IGxlbmd0aCggbGVuOiBudW1iZXIgKVxuICB7XG4gICAgaWYgKCB0aGlzLmJ5dGVBcnJheS5sZW5ndGggPj0gbGVuIClcbiAgICB7XG4gICAgICB0aGlzLmJ5dGVBcnJheSA9IHRoaXMuYnl0ZUFycmF5LnNsaWNlKCAwLCBsZW4gKTtcbiAgICB9XG4gICAgZWxzZVxuICAgIHtcbiAgICAgIGxldCBvbGQgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICAgIHRoaXMuYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoIGxlbiApO1xuICAgICAgdGhpcy5ieXRlQXJyYXkuc2V0KCBvbGQsIDAgKTtcbiAgICB9XG4gIH1cblxuICBnZXQgYmFja2luZ0FycmF5KCk6IFVpbnQ4QXJyYXlcbiAge1xuICAgIHJldHVybiB0aGlzLmJ5dGVBcnJheTtcbiAgfVxuXG4gIGVxdWFscyggdmFsdWU6IEJ5dGVBcnJheSApOiBib29sZWFuXG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcbiAgICBsZXQgdmJhID0gdmFsdWUuYnl0ZUFycmF5O1xuICAgIHZhciBvayA9ICggYmEubGVuZ3RoID09IHZiYS5sZW5ndGggKTtcblxuICAgIGlmICggb2sgKVxuICAgIHtcbiAgICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgICBvayA9IG9rICYmICggYmFbaV0gPT0gdmJhW2ldICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG9rO1xuICB9XG5cbiAgLyoqXG4gICAgKiBnZXQgYnl0ZSBhdCBvZmZzZXRcbiAgICAqL1xuICBieXRlQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgXTtcbiAgfVxuXG4gIHdvcmRBdCggb2Zmc2V0OiBudW1iZXIgKTogbnVtYmVyXG4gIHtcbiAgICByZXR1cm4gKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICAgICBdIDw8ICA4IClcbiAgICAgICAgICsgKCB0aGlzLmJ5dGVBcnJheVsgb2Zmc2V0ICsgMSBdICAgICAgICk7XG4gIH1cblxuICBsaXR0bGVFbmRpYW5Xb3JkQXQoIG9mZnNldCApOiBudW1iZXJcbiAge1xuICAgIHJldHVybiAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgICAgIF0gKVxuICAgICAgICAgKyAoIHRoaXMuYnl0ZUFycmF5WyBvZmZzZXQgKyAxIF0gPDwgIDggKTtcbiAgfVxuXG4gIGR3b3JkQXQoIG9mZnNldDogbnVtYmVyICk6IG51bWJlclxuICB7XG4gICAgcmV0dXJuICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCAgICAgXSA8PCAyNCApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDEgXSA8PCAxNiApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDIgXSA8PCAgOCApXG4gICAgICAgICArICggdGhpcy5ieXRlQXJyYXlbIG9mZnNldCArIDMgXSAgICAgICApO1xuICB9XG5cbiAgLyoqXG4gICAgKiBzZXQgYnl0ZSBhdCBvZmZzZXRcbiAgICAqIEBmbHVlbnRcbiAgICAqL1xuICBzZXRCeXRlQXQoIG9mZnNldDogbnVtYmVyLCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXlbIG9mZnNldCBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldEJ5dGVzQXQoIG9mZnNldDogbnVtYmVyLCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXkuc2V0KCB2YWx1ZS5ieXRlQXJyYXksIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBjbG9uZSgpOiBCeXRlQXJyYXlcbiAge1xuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSgpICk7XG4gIH1cblxuICAvKipcbiAgKiBFeHRyYWN0IGEgc2VjdGlvbiAob2Zmc2V0LCBjb3VudCkgZnJvbSB0aGUgQnl0ZUFycmF5XG4gICogQGZsdWVudFxuICAqIEByZXR1cm5zIGEgbmV3IEJ5dGVBcnJheSBjb250YWluaW5nIGEgc2VjdGlvbi5cbiAgKi9cbiAgYnl0ZXNBdCggb2Zmc2V0OiBudW1iZXIsIGNvdW50PzogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgaWYgKCAhTnVtYmVyLmlzSW50ZWdlciggY291bnQgKSApXG4gICAgICBjb3VudCA9ICggdGhpcy5sZW5ndGggLSBvZmZzZXQgKTtcblxuICAgIHJldHVybiBuZXcgQnl0ZUFycmF5KCB0aGlzLmJ5dGVBcnJheS5zbGljZSggb2Zmc2V0LCBvZmZzZXQgKyBjb3VudCApICk7XG4gIH1cblxuICAvKipcbiAgKiBDcmVhdGUgYSB2aWV3IGludG8gdGhlIEJ5dGVBcnJheVxuICAqXG4gICogQHJldHVybnMgYSBCeXRlQXJyYXkgcmVmZXJlbmNpbmcgYSBzZWN0aW9uIG9mIG9yaWdpbmFsIEJ5dGVBcnJheS5cbiAgKi9cbiAgdmlld0F0KCBvZmZzZXQ6IG51bWJlciwgY291bnQ/OiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICBpZiAoICFOdW1iZXIuaXNJbnRlZ2VyKCBjb3VudCApIClcbiAgICAgIGNvdW50ID0gKCB0aGlzLmxlbmd0aCAtIG9mZnNldCApO1xuXG4gICAgcmV0dXJuIG5ldyBCeXRlQXJyYXkoIHRoaXMuYnl0ZUFycmF5LnN1YmFycmF5KCBvZmZzZXQsIG9mZnNldCArIGNvdW50ICkgKTtcbiAgfVxuXG4gIC8qKlxuICAqIEFwcGVuZCBieXRlXG4gICogQGZsdWVudFxuICAqL1xuICBhZGRCeXRlKCB2YWx1ZTogbnVtYmVyICk6IEJ5dGVBcnJheVxuICB7XG4gICAgdGhpcy5ieXRlQXJyYXlbIHRoaXMuYnl0ZUFycmF5Lmxlbmd0aCBdID0gdmFsdWU7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNldExlbmd0aCggbGVuOiBudW1iZXIgKTogQnl0ZUFycmF5XG4gIHtcbiAgICB0aGlzLmxlbmd0aCA9IGxlbjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgY29uY2F0KCBieXRlczogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG5cbiAgICB0aGlzLmJ5dGVBcnJheSA9IG5ldyBVaW50OEFycmF5KCBiYS5sZW5ndGggKyBieXRlcy5sZW5ndGggKTtcblxuICAgIHRoaXMuYnl0ZUFycmF5LnNldCggYmEgKTtcbiAgICB0aGlzLmJ5dGVBcnJheS5zZXQoIGJ5dGVzLmJ5dGVBcnJheSwgYmEubGVuZ3RoICk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIG5vdCggKTogQnl0ZUFycmF5XG4gIHtcbiAgICBsZXQgYmEgPSB0aGlzLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeMHhGRjtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgYW5kKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSAmIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBvciggdmFsdWU6IEJ5dGVBcnJheSApOiBCeXRlQXJyYXlcbiAge1xuICAgIGxldCBiYSA9IHRoaXMuYnl0ZUFycmF5O1xuICAgIGxldCB2YmEgPSB2YWx1ZS5ieXRlQXJyYXk7XG5cbiAgICBmb3IoIGxldCBpID0gMDsgaSA8IGJhLmxlbmd0aDsgKytpIClcbiAgICAgIGJhW2ldID0gYmFbaV0gfCB2YmFbIGkgXTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgeG9yKCB2YWx1ZTogQnl0ZUFycmF5ICk6IEJ5dGVBcnJheVxuICB7XG4gICAgbGV0IGJhID0gdGhpcy5ieXRlQXJyYXk7XG4gICAgbGV0IHZiYSA9IHZhbHVlLmJ5dGVBcnJheTtcblxuICAgIGZvciggbGV0IGkgPSAwOyBpIDwgYmEubGVuZ3RoOyArK2kgKVxuICAgICAgYmFbaV0gPSBiYVtpXSBeIHZiYVsgaSBdO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICB0b1N0cmluZyggZm9ybWF0PzogbnVtYmVyLCBvcHQ/OiBhbnkgKVxuICB7XG4gICAgbGV0IHMgPSBcIlwiO1xuICAgIGZvciggdmFyIGkgPSAwOyBpIDwgdGhpcy5sZW5ndGg7ICsraSApXG4gICAgICBzICs9ICggXCIwXCIgKyB0aGlzLmJ5dGVBcnJheVsgaSBdLnRvU3RyaW5nKCAxNiApKS5zdWJzdHJpbmcoIC0yICk7XG5cbiAgICByZXR1cm4gcztcbiAgfVxufVxuIiwiaW1wb3J0IHsgQnl0ZUFycmF5IH0gZnJvbSAnLi9ieXRlLWFycmF5JztcblxuZXhwb3J0IGNsYXNzIEVudW0ge307XG5cbmV4cG9ydCB0eXBlIERhdGFUeXBlID0gU3RyaW5nIHwgTnVtYmVyIHwgRW51bSB8IEJ5dGVBcnJheSB8IEtpbmQ7XG5cbmV4cG9ydCBpbnRlcmZhY2UgRmllbGRJbmZvIHtcbiAgaWQ/OiBzdHJpbmc7XG5cbiAgZGVzY3JpcHRpb246IHN0cmluZztcblxuICBkYXRhVHlwZTogRGF0YVR5cGU7XG5cbiAgZW51bUluZm8/OiBNYXA8bnVtYmVyLCBzdHJpbmc+O1xuXG4gIG1pbkxlbmd0aD86IG51bWJlcjtcblxuICBtYXhMZW5ndGg/OiBudW1iZXI7XG59XG5cbi8qKlxuKiBNZXRhZGF0YSBhYm91dCBhIEtpbmQuIENvbnRhaW5zIG5hbWUsIGRlc2NyaXB0aW9uIGFuZCBhIG1hcCBvZlxuKiBwcm9wZXJ0eS1kZXNjcmlwdG9ycyB0aGF0IGRlc2NyaWJlIHRoZSBzZXJpYWxpemFibGUgZmllbGRzIG9mXG4qIGFuIG9iamVjdCBvZiB0aGF0IEtpbmQuXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRJbmZvXG57XG4gIG5hbWU6IHN0cmluZztcblxuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIGZpZWxkczogeyBbaWQ6IHN0cmluZ106IEZpZWxkSW5mbyB9ID0ge307XG59XG5cblxuLyoqXG4qIEJ1aWxkZXIgZm9yICdLaW5kJyBtZXRhZGF0YVxuKi9cbmV4cG9ydCBjbGFzcyBLaW5kQnVpbGRlclxue1xuICBwcml2YXRlIGN0b3I6IEtpbmRDb25zdHJ1Y3RvcjtcblxuICBjb25zdHJ1Y3RvciggY3RvcjogS2luZENvbnN0cnVjdG9yLCBkZXNjcmlwdGlvbjogc3RyaW5nICkge1xuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmtpbmRJbmZvID0ge1xuICAgICAgbmFtZTogY3Rvci5uYW1lLFxuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZmllbGRzOiB7fVxuICAgIH1cbiAgfVxuXG5cbiAgcHJpdmF0ZSBraW5kSW5mbzogS2luZEluZm87XG5cbiAgcHVibGljIHN0YXRpYyBpbml0KCBjdG9yOiBLaW5kQ29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcgKTogS2luZEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IEtpbmRCdWlsZGVyKCBjdG9yLCBkZXNjcmlwdGlvbiApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgZmllbGQoIG5hbWU6IHN0cmluZywgZGVzY3JpcHRpb246IHN0cmluZywgZGF0YVR5cGU6IERhdGFUeXBlLCBvcHRzPyApOiBLaW5kQnVpbGRlclxuICB7XG4gICAgdGhpcy5jdG9yLmtpbmRJbmZvLmZpZWxkc1sgbmFtZSBdID0ge1xuICAgICAgZGVzY3JpcHRpb246IGRlc2NyaXB0aW9uLFxuICAgICAgZGF0YVR5cGU6IGRhdGFUeXBlXG4gICAgfTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbn1cblxuLyogIG1ha2VLaW5kKCBraW5kQ29uc3RydWN0b3IsIGtpbmRPcHRpb25zIClcbiAge1xuICAgIHZhciAka2luZEluZm8gPSBraW5kT3B0aW9ucy5raW5kSW5mbztcblxuICAgIGtpbmRDb25zdHJ1Y3Rvci4ka2luZE5hbWUgPSAka2luZEluZm8udGl0bGU7XG5cbiAgICB2YXIga2V5cyA9IE9iamVjdC5rZXlzKCBraW5kT3B0aW9ucy5raW5kTWV0aG9kcyApO1xuXG4gICAgZm9yICggdmFyIGogPSAwLCBqaiA9IGtleXMubGVuZ3RoOyBqIDwgamo7IGorKyApIHtcbiAgICAgIHZhciBrZXkgPSBrZXlzW2pdO1xuICAgICAga2luZENvbnN0cnVjdG9yW2tleV0gPSBraW5kT3B0aW9ucy5raW5kTWV0aG9kc1trZXldO1xuICAgIH1cblxuICAgIGtpbmRDb25zdHJ1Y3Rvci5nZXRLaW5kSW5mbyA9IGtpbmRDb25zdHJ1Y3Rvci5wcm90b3R5cGUuZ2V0S2luZEluZm8gPSBmdW5jdGlvbiBnZXRLaW5kSW5mbygpIHtcbiAgICAgIHJldHVybiAka2luZEluZm87XG4gICAgfVxuXG4gICAgcmV0dXJuIGtpbmRDb25zdHJ1Y3RvcjtcbiAgfVxuKi9cblxuLyoqXG4qIFJlcHJlc2VudHMgYSBzZXJpYWxpemFibGUgYW5kIGluc3BlY3RhYmxlIGRhdGEtdHlwZVxuKiBpbXBsZW1lbnRlZCBhcyBhIGhhc2gtbWFwIGNvbnRhaW5pbmcga2V5LXZhbHVlIHBhaXJzLFxuKiBhbG9uZyB3aXRoIG1ldGFkYXRhIHRoYXQgZGVzY3JpYmVzIGVhY2ggZmllbGQgdXNpbmcgYSBqc29uLXNjaGVtZSBsaWtlXG4qL1xuZXhwb3J0IGludGVyZmFjZSBLaW5kXG57XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgS2luZENvbnN0cnVjdG9yXG57XG4gIG5ldyAoIC4uLmFyZ3MgKTogS2luZDtcblxuICBraW5kSW5mbz86IEtpbmRJbmZvO1xufVxuXG5lbnVtIE9yYW5nZXMge1xuICBCTE9PRCxcbiAgU0VWSUxMRSxcbiAgU0FUU1VNQSxcbiAgTkFWRUxcbn1cblxuLyoqXG4qIEV4YW1wbGVcbiovXG5jbGFzcyBGcnVpdHlLaW5kIGltcGxlbWVudHMgS2luZFxue1xuICBiYW5hbmE6IFN0cmluZztcbiAgYXBwbGU6IE51bWJlcjtcbiAgb3JhbmdlOiBPcmFuZ2VzO1xufVxuXG5LaW5kQnVpbGRlci5pbml0KCBGcnVpdHlLaW5kLCAnYSBDb2xsZWN0aW9uIG9mIGZydWl0JyApXG4gIC5maWVsZCgnYmFuYW5hJywgJ2EgYmFuYW5hJywgU3RyaW5nIClcbiAgLmZpZWxkKCdhcHBsZScsICdhbiBhcHBsZSBvciBwZWFyJywgTnVtYmVyIClcbiAgLmZpZWxkKCdvcmFuZ2UnLCAnc29tZSBzb3J0IG9mIG9yYW5nZScsIEVudW0gKVxuICA7XG4iLCJpbXBvcnQgeyBLaW5kIH0gZnJvbSAnLi4va2luZC9raW5kJztcbmltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuXG4vKlxuKiBNZXNzYWdlIEhlYWRlclxuKi9cbmV4cG9ydCBpbnRlcmZhY2UgTWVzc2FnZUhlYWRlclxue1xuICAvKlxuICAqIE1lc3NhZ2UgTmFtZSwgaW5kaWNhdGVzIGEgY29tbWFuZCAvIG1ldGhvZCAvIHJlc3BvbnNlIHRvIGV4ZWN1dGVcbiAgKi9cbiAgbWV0aG9kPzogc3RyaW5nO1xuXG4gIC8qXG4gICogTWVzc2FnZSBJZGVudGlmaWVyICh1bmlxdWUpIGZvciBlYWNoIHNlbnQgbWVzc2FnZSAob3IgQ01ELVJFU1AgcGFpcilcbiAgKi9cbiAgaWQ/OiBudW1iZXI7XG5cblxuICAvKlxuICAqIERlc2NyaXB0aW9uLCB1c2VmdWwgZm9yIHRyYWNpbmcgYW5kIGxvZ2dpbmdcbiAgKi9cbiAgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG5cbiAgLypcbiAgKiBGb3IgQ01EL1JFU1Agc3R5bGUgcHJvdG9jb2xzLCBpbmRpY2F0ZXMgdGhhdCBtZXNzYWdlIGRpc3BhdGNoZWRcbiAgKiBpbiByZXNwb25zZSB0byBhIHByZXZpb3VzIGNvbW1hbmRcbiAgKi9cbiAgaXNSZXNwb25zZT86IGJvb2xlYW47XG5cbiAgLypcbiAgKiBFbmRQb2ludCB0aGF0IG9yaWdpbmF0ZWQgdGhlIG1lc3NhZ2VcbiAgKi9cbiAgb3JpZ2luPzogRW5kUG9pbnQ7XG5cblxuICAvKlxuICAqIEluZGljYXRlcyB0aGUgS2luZCBvZiBkYXRhICh3aGVuIHNlcmlhbGl6ZWQpXG4gICovXG4gIGtpbmROYW1lPzogc3RyaW5nO1xufVxuXG4vKlxuKiBBIFR5cGVkIE1lc3NhZ2UsIHdpdGggaGVhZGVyIGFuZCBwYXlsb2FkXG4qL1xuZXhwb3J0IGNsYXNzIE1lc3NhZ2U8VD5cbntcbiAgcHJpdmF0ZSBfaGVhZGVyOiBNZXNzYWdlSGVhZGVyO1xuICBwcml2YXRlIF9wYXlsb2FkOiBUO1xuXG4gIGNvbnN0cnVjdG9yKCBoZWFkZXI6IE1lc3NhZ2VIZWFkZXIsIHBheWxvYWQ6IFQgKVxuICB7XG4gICAgdGhpcy5faGVhZGVyID0gaGVhZGVyIHx8IHt9O1xuICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICB9XG5cbiAgZ2V0IGhlYWRlcigpOiBNZXNzYWdlSGVhZGVyXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faGVhZGVyO1xuICB9XG5cbiAgZ2V0IHBheWxvYWQoKTogVFxuICB7XG4gICAgcmV0dXJuIHRoaXMuX3BheWxvYWQ7XG4gIH1cbn1cblxuLypcbiogQSB0eXBlZCBNZXNzYWdlIHdob3NlIHBheWxvYWQgaXMgYSBLaW5kXG4qL1xuZXhwb3J0IGNsYXNzIEtpbmRNZXNzYWdlPEsgZXh0ZW5kcyBLaW5kPiBleHRlbmRzIE1lc3NhZ2U8Sz5cbntcbn1cbiIsImV4cG9ydCB0eXBlIFRhc2sgPSAoKSA9PiB2b2lkO1xuZXhwb3J0IHR5cGUgRmx1c2hGdW5jID0gKCkgPT4gdm9pZDtcbnZhciB3aW5kb3cgPSB3aW5kb3cgfHwge307XG5cbmV4cG9ydCBjbGFzcyBUYXNrU2NoZWR1bGVyXG57XG4gIHN0YXRpYyBtYWtlUmVxdWVzdEZsdXNoRnJvbU11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpOiBGbHVzaEZ1bmNcbiAge1xuICAgIHZhciB0b2dnbGUgPSAxO1xuXG4gICAgdmFyIG9ic2VydmVyID0gbmV3IFRhc2tTY2hlZHVsZXIuQnJvd3Nlck11dGF0aW9uT2JzZXJ2ZXIoZmx1c2gpO1xuXG4gICAgdmFyIG5vZGU6IE9iamVjdCA9IGRvY3VtZW50LmNyZWF0ZVRleHROb2RlKCcnKTtcblxuICAgIG9ic2VydmVyLm9ic2VydmUobm9kZSwgeyBjaGFyYWN0ZXJEYXRhOiB0cnVlIH0pO1xuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpXG4gICAge1xuICAgICAgdG9nZ2xlID0gLXRvZ2dsZTtcbiAgICAgIG5vZGVbXCJkYXRhXCJdID0gdG9nZ2xlO1xuICAgIH07XG4gIH1cblxuICBzdGF0aWMgbWFrZVJlcXVlc3RGbHVzaEZyb21UaW1lcihmbHVzaCk6IEZsdXNoRnVuY1xuICB7XG4gICAgcmV0dXJuIGZ1bmN0aW9uIHJlcXVlc3RGbHVzaCgpIHtcbiAgICAgIHZhciB0aW1lb3V0SGFuZGxlID0gc2V0VGltZW91dChoYW5kbGVGbHVzaFRpbWVyLCAwKTtcblxuICAgICAgdmFyIGludGVydmFsSGFuZGxlID0gc2V0SW50ZXJ2YWwoaGFuZGxlRmx1c2hUaW1lciwgNTApO1xuICAgICAgZnVuY3Rpb24gaGFuZGxlRmx1c2hUaW1lcigpXG4gICAgICB7XG4gICAgICAgIGNsZWFyVGltZW91dCh0aW1lb3V0SGFuZGxlKTtcbiAgICAgICAgY2xlYXJJbnRlcnZhbChpbnRlcnZhbEhhbmRsZSk7XG4gICAgICAgIGZsdXNoKCk7XG4gICAgICB9XG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBCcm93c2VyTXV0YXRpb25PYnNlcnZlciA9IHdpbmRvd1sgXCJNdXRhdGlvbk9ic2VydmVyXCIgXSB8fCB3aW5kb3dbIFwiV2ViS2l0TXV0YXRpb25PYnNlcnZlclwiXTtcbiAgc3RhdGljIGhhc1NldEltbWVkaWF0ZSA9IHR5cGVvZiBzZXRJbW1lZGlhdGUgPT09ICdmdW5jdGlvbic7XG5cbiAgc3RhdGljIHRhc2tRdWV1ZUNhcGFjaXR5ID0gMTAyNDtcbiAgdGFza1F1ZXVlOiBUYXNrW107XG5cbiAgcmVxdWVzdEZsdXNoVGFza1F1ZXVlOiBGbHVzaEZ1bmM7XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy50YXNrUXVldWUgPSBbXTtcblxuICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgIGlmICh0eXBlb2YgVGFza1NjaGVkdWxlci5Ccm93c2VyTXV0YXRpb25PYnNlcnZlciA9PT0gJ2Z1bmN0aW9uJylcbiAgICB7XG4gICAgICB0aGlzLnJlcXVlc3RGbHVzaFRhc2tRdWV1ZSA9IFRhc2tTY2hlZHVsZXIubWFrZVJlcXVlc3RGbHVzaEZyb21NdXRhdGlvbk9ic2VydmVyKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHNlbGYuZmx1c2hUYXNrUXVldWUoKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgdGhpcy5yZXF1ZXN0Rmx1c2hUYXNrUXVldWUgPSBUYXNrU2NoZWR1bGVyLm1ha2VSZXF1ZXN0Rmx1c2hGcm9tVGltZXIoZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gc2VsZi5mbHVzaFRhc2tRdWV1ZSgpO1xuICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgVGFza1NjaGVkdWxlciwgY2FuY2VsbGluZyBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgc2h1dGRvd24oKVxuICB7XG4gIH1cblxuICBxdWV1ZVRhc2soIHRhc2spXG4gIHtcbiAgICBpZiAoIHRoaXMudGFza1F1ZXVlLmxlbmd0aCA8IDEgKVxuICAgIHtcbiAgICAgIHRoaXMucmVxdWVzdEZsdXNoVGFza1F1ZXVlKCk7XG4gICAgfVxuXG4gICAgdGhpcy50YXNrUXVldWUucHVzaCh0YXNrKTtcbiAgfVxuXG4gIGZsdXNoVGFza1F1ZXVlKClcbiAge1xuICAgIHZhciBxdWV1ZSA9IHRoaXMudGFza1F1ZXVlLFxuICAgICAgICBjYXBhY2l0eSA9IFRhc2tTY2hlZHVsZXIudGFza1F1ZXVlQ2FwYWNpdHksXG4gICAgICAgIGluZGV4ID0gMCxcbiAgICAgICAgdGFzaztcblxuICAgIHdoaWxlIChpbmRleCA8IHF1ZXVlLmxlbmd0aClcbiAgICB7XG4gICAgICB0YXNrID0gcXVldWVbaW5kZXhdO1xuXG4gICAgICB0cnlcbiAgICAgIHtcbiAgICAgICAgdGFzay5jYWxsKCk7XG4gICAgICB9XG4gICAgICBjYXRjaCAoZXJyb3IpXG4gICAgICB7XG4gICAgICAgIHRoaXMub25FcnJvcihlcnJvciwgdGFzayk7XG4gICAgICB9XG5cbiAgICAgIGluZGV4Kys7XG5cbiAgICAgIGlmIChpbmRleCA+IGNhcGFjaXR5KVxuICAgICAge1xuICAgICAgICBmb3IgKHZhciBzY2FuID0gMDsgc2NhbiA8IGluZGV4OyBzY2FuKyspXG4gICAgICAgIHtcbiAgICAgICAgICBxdWV1ZVtzY2FuXSA9IHF1ZXVlW3NjYW4gKyBpbmRleF07XG4gICAgICAgIH1cblxuICAgICAgICBxdWV1ZS5sZW5ndGggLT0gaW5kZXg7XG4gICAgICAgIGluZGV4ID0gMDtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBxdWV1ZS5sZW5ndGggPSAwO1xuICB9XG5cbiAgb25FcnJvcihlcnJvciwgdGFzaylcbiAge1xuICAgIGlmICgnb25FcnJvcicgaW4gdGFzaykge1xuICAgICAgdGFzay5vbkVycm9yKGVycm9yKTtcbiAgICB9XG4gICAgZWxzZSBpZiAoIFRhc2tTY2hlZHVsZXIuaGFzU2V0SW1tZWRpYXRlIClcbiAgICB7XG4gICAgICBzZXRJbW1lZGlhdGUoZnVuY3Rpb24gKCkge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBlbHNlXG4gICAge1xuICAgICAgc2V0VGltZW91dChmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSwgMCk7XG4gICAgfVxuICB9XG59XG4iLCJpbXBvcnQgeyBUYXNrU2NoZWR1bGVyIH0gZnJvbSAnLi4vcnVudGltZS90YXNrLXNjaGVkdWxlcic7XG5pbXBvcnQgeyBFbmRQb2ludCwgRGlyZWN0aW9uIH0gZnJvbSAnLi9lbmQtcG9pbnQnO1xuaW1wb3J0IHsgTWVzc2FnZSB9IGZyb20gJy4vbWVzc2FnZSc7XG5cbi8qKlxuKiBBIG1lc3NhZ2UtcGFzc2luZyBjaGFubmVsIGJldHdlZW4gbXVsdGlwbGUgRW5kUG9pbnRzXG4qXG4qIEVuZFBvaW50cyBtdXN0IGZpcnN0IHJlZ2lzdGVyIHdpdGggdGhlIENoYW5uZWwuIFdoZW5ldmVyIHRoZSBDaGFubmVsIGlzIGluXG4qIGFuIGFjdGl2ZSBzdGF0ZSwgY2FsbHMgdG8gc2VuZE1lc3NhZ2Ugd2lsbCBmb3J3YXJkIHRoZSBtZXNzYWdlIHRvIGFsbFxuKiByZWdpc3RlcmVkIEVuZFBvaW50cyAoZXhjZXB0IHRoZSBvcmlnaW5hdG9yIEVuZFBvaW50KS5cbiovXG5leHBvcnQgY2xhc3MgQ2hhbm5lbFxue1xuICAvKipcbiAgKiBUcnVlIGlmIENoYW5uZWwgaXMgYWN0aXZlXG4gICovXG4gIHByaXZhdGUgX2FjdGl2ZTogYm9vbGVhbjtcblxuICAvKipcbiAgKiBBcnJheSBvZiBFbmRQb2ludHMgYXR0YWNoZWQgdG8gdGhpcyBDaGFubmVsXG4gICovXG4gIHByaXZhdGUgX2VuZFBvaW50czogRW5kUG9pbnRbXTtcblxuICAvKipcbiAgKiBQcml2YXRlIFRhc2tTY2hlZHVsZXIgdXNlZCB0byBtYWtlIG1lc3NhZ2Utc2VuZHMgYXN5bmNocm9ub3VzLlxuICAqL1xuICBwcml2YXRlIF90YXNrU2NoZWR1bGVyOiBUYXNrU2NoZWR1bGVyO1xuXG4gIC8qKlxuICAqIENyZWF0ZSBhIG5ldyBDaGFubmVsLCBpbml0aWFsbHkgaW5hY3RpdmVcbiAgKi9cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gICAgdGhpcy5fYWN0aXZlID0gZmFsc2U7XG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG4gIH1cblxuICAvKipcbiAgKiBDbGVhbnVwIHRoZSBDaGFubmVsLCBkZWFjdGl2YXRlLCByZW1vdmUgYWxsIEVuZFBvaW50cyBhbmRcbiAgKiBhYm9ydCBhbnkgcGVuZGluZyBjb21tdW5pY2F0aW9ucy5cbiAgKi9cbiAgcHVibGljIHNodXRkb3duKClcbiAge1xuICAgIHRoaXMuX2FjdGl2ZSA9IGZhbHNlO1xuXG4gICAgdGhpcy5fZW5kUG9pbnRzID0gW107XG5cbiAgICBpZiAoIHRoaXMuX3Rhc2tTY2hlZHVsZXIgKVxuICAgIHtcbiAgICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIuc2h1dGRvd24oKTtcblxuICAgICAgdGhpcy5fdGFza1NjaGVkdWxlciA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBJcyBDaGFubmVsIGFjdGl2ZT9cbiAgKlxuICAqIEByZXR1cm5zIHRydWUgaWYgY2hhbm5lbCBpcyBhY3RpdmUsIGZhbHNlIG90aGVyd2lzZVxuICAqL1xuICBwdWJsaWMgZ2V0IGFjdGl2ZSgpOiBib29sZWFuXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fYWN0aXZlO1xuICB9XG5cbiAgLyoqXG4gICogQWN0aXZhdGUgdGhlIENoYW5uZWwsIGVuYWJsaW5nIGNvbW11bmljYXRpb25cbiAgKi9cbiAgcHVibGljIGFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSBuZXcgVGFza1NjaGVkdWxlcigpO1xuXG4gICAgdGhpcy5fYWN0aXZlID0gdHJ1ZTtcbiAgfVxuXG4gIC8qKlxuICAqIERlYWN0aXZhdGUgdGhlIENoYW5uZWwsIGRpc2FibGluZyBhbnkgZnVydGhlciBjb21tdW5pY2F0aW9uXG4gICovXG4gIHB1YmxpYyBkZWFjdGl2YXRlKClcbiAge1xuICAgIHRoaXMuX3Rhc2tTY2hlZHVsZXIgPSB1bmRlZmluZWQ7XG5cbiAgICB0aGlzLl9hY3RpdmUgPSBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGFuIEVuZFBvaW50IHRvIHNlbmQgYW5kIHJlY2VpdmUgbWVzc2FnZXMgdmlhIHRoaXMgQ2hhbm5lbC5cbiAgKlxuICAqIEBwYXJhbSBlbmRQb2ludCAtIHRoZSBFbmRQb2ludCB0byByZWdpc3RlclxuICAqL1xuICBwdWJsaWMgYWRkRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICB0aGlzLl9lbmRQb2ludHMucHVzaCggZW5kUG9pbnQgKTtcbiAgfVxuXG4gIC8qKlxuICAqIFVucmVnaXN0ZXIgYW4gRW5kUG9pbnQuXG4gICpcbiAgKiBAcGFyYW0gZW5kUG9pbnQgLSB0aGUgRW5kUG9pbnQgdG8gdW5yZWdpc3RlclxuICAqL1xuICBwdWJsaWMgcmVtb3ZlRW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fZW5kUG9pbnRzLmluZGV4T2YoIGVuZFBvaW50ICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICB0aGlzLl9lbmRQb2ludHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBHZXQgRW5kUG9pbnRzIHJlZ2lzdGVyZWQgd2l0aCB0aGlzIENoYW5uZWxcbiAgKlxuICAqIEByZXR1cm4gQXJyYXkgb2YgRW5kUG9pbnRzXG4gICovXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnRzKCk6IEVuZFBvaW50W11cbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludHM7XG4gIH1cblxuICAvKipcbiAgKiBTZW5kIGEgbWVzc2FnZSB0byBhbGwgbGlzdGVuZXJzIChleGNlcHQgb3JpZ2luKVxuICAqXG4gICogQHBhcmFtIG9yaWdpbiAtIEVuZFBvaW50IHRoYXQgaXMgc2VuZGluZyB0aGUgbWVzc2FnZVxuICAqIEBwYXJhbSBtZXNzYWdlIC0gTWVzc2FnZSB0byBiZSBzZW50XG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggb3JpZ2luOiBFbmRQb2ludCwgbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIGxldCBpc1Jlc3BvbnNlID0gKCBtZXNzYWdlLmhlYWRlciAmJiBtZXNzYWdlLmhlYWRlci5pc1Jlc3BvbnNlICk7XG5cbiAgICBpZiAoICF0aGlzLl9hY3RpdmUgKVxuICAgICAgcmV0dXJuO1xuXG4gICAgaWYgKCBvcmlnaW4uZGlyZWN0aW9uID09IERpcmVjdGlvbi5JTiAmJiAhaXNSZXNwb25zZSApXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoICdVbmFibGUgdG8gc2VuZCBvbiBJTiBwb3J0Jyk7XG5cbiAgICB0aGlzLl9lbmRQb2ludHMuZm9yRWFjaCggZW5kUG9pbnQgPT4ge1xuICAgICAgLy8gU2VuZCB0byBhbGwgbGlzdGVuZXJzLCBleGNlcHQgZm9yIG9yaWdpbmF0b3IgLi4uXG4gICAgICBpZiAoIG9yaWdpbiAhPSBlbmRQb2ludCApXG4gICAgICB7XG4gICAgICAgIC8vIE9ubHkgc2VuZCB0byBJTiBvciBJTk9VVCBsaXN0ZW5lcnMsIFVOTEVTUyBtZXNzYWdlIGlzIGFcbiAgICAgICAgLy8gcmVwbHkgKGluIGEgY2xpZW50LXNlcnZlcikgY29uZmlndXJhdGlvblxuICAgICAgICBpZiAoIGVuZFBvaW50LmRpcmVjdGlvbiAhPSBEaXJlY3Rpb24uT1VUIHx8IGlzUmVzcG9uc2UgKVxuICAgICAgICB7XG4gICAgICAgICAgdGhpcy5fdGFza1NjaGVkdWxlci5xdWV1ZVRhc2soICgpID0+IHtcbiAgICAgICAgICAgIGVuZFBvaW50LmhhbmRsZU1lc3NhZ2UoIG1lc3NhZ2UsIG9yaWdpbiwgdGhpcyApO1xuICAgICAgICAgIH0gKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG59XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuL2NoYW5uZWwnO1xuXG5leHBvcnQgZW51bSBEaXJlY3Rpb24ge1xuICBJTiA9IDEsXG4gIE9VVCA9IDIsXG4gIElOT1VUID0gM1xufTtcblxuZXhwb3J0IHR5cGUgSGFuZGxlTWVzc2FnZURlbGVnYXRlID0gKCBtZXNzYWdlOiBNZXNzYWdlPGFueT4sIHJlY2VpdmluZ0VuZFBvaW50PzogRW5kUG9pbnQsIHJlY2VpdmluZ0NoYW5uZWw/OiBDaGFubmVsICkgPT4gdm9pZDtcblxuLyoqXG4qIEFuIEVuZFBvaW50IGlzIGEgc2VuZGVyL3JlY2VpdmVyIGZvciBtZXNzYWdlLXBhc3NpbmcuIEl0IGhhcyBhbiBpZGVudGlmaWVyXG4qIGFuZCBhbiBvcHRpb25hbCBkaXJlY3Rpb24sIHdoaWNoIG1heSBiZSBJTiwgT1VUIG9yIElOL09VVCAoZGVmYXVsdCkuXG4qXG4qIEVuZFBvaW50cyBtYXkgaGF2ZSBtdWx0aXBsZSBjaGFubmVscyBhdHRhY2hlZCwgYW5kIHdpbGwgZm9yd2FyZCBtZXNzYWdlc1xuKiB0byBhbGwgb2YgdGhlbS5cbiovXG5leHBvcnQgY2xhc3MgRW5kUG9pbnRcbntcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIC8qKlxuICAqIEEgbGlzdCBvZiBhdHRhY2hlZCBDaGFubmVsc1xuICAqL1xuICBwcm90ZWN0ZWQgX2NoYW5uZWxzOiBDaGFubmVsW107XG5cbiAgLyoqXG4gICogQSBsaXN0IG9mIGF0dGFjaGVkIENoYW5uZWxzXG4gICovXG4gIHByb3RlY3RlZCBfbWVzc2FnZUxpc3RlbmVyczogSGFuZGxlTWVzc2FnZURlbGVnYXRlW107XG5cbiAgcHJpdmF0ZSBfZGlyZWN0aW9uOiBEaXJlY3Rpb247XG5cbiAgY29uc3RydWN0b3IoIGlkOiBzdHJpbmcsIGRpcmVjdGlvbjogRGlyZWN0aW9uID0gRGlyZWN0aW9uLklOT1VUIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG5cbiAgICB0aGlzLl9kaXJlY3Rpb24gPSBkaXJlY3Rpb247XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuXG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQ2xlYW51cCB0aGUgRW5kUG9pbnQsIGRldGFjaGluZyBhbnkgYXR0YWNoZWQgQ2hhbm5lbHMgYW5kIHJlbW92aW5nIGFueVxuICAqIG1lc3NhZ2UtbGlzdGVuZXJzLiBDYWxsaW5nIHNodXRkb3duKCkgaXMgbWFuZGF0b3J5IHRvIGF2b2lkIG1lbW9yeS1sZWFrc1xuICAqIGR1ZSB0byB0aGUgY2lyY3VsYXIgcmVmZXJlbmNlcyB0aGF0IGV4aXN0IGJldHdlZW4gQ2hhbm5lbHMgYW5kIEVuZFBvaW50c1xuICAqL1xuICBwdWJsaWMgc2h1dGRvd24oKVxuICB7XG4gICAgdGhpcy5kZXRhY2hBbGwoKTtcblxuICAgIHRoaXMuX21lc3NhZ2VMaXN0ZW5lcnMgPSBbXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIEVuZFBvaW50J3MgaWRcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9pZDtcbiAgfVxuXG4gIC8qKlxuICAqIEF0dGFjaCBhIENoYW5uZWwgdG8gdGhpcyBFbmRQb2ludC4gT25jZSBhdHRhY2hlZCwgdGhlIENoYW5uZWwgd2lsbCBmb3J3YXJkXG4gICogbWVzc2FnZXMgdG8gdGhpcyBFbmRQb2ludCwgYW5kIHdpbGwgYWNjZXB0IG1lc3NhZ2VzIG9yaWdpbmF0ZWQgaGVyZS5cbiAgKiBBbiBFbmRQb2ludCBjYW4gaGF2ZSBtdWx0aXBsZSBDaGFubmVscyBhdHRhY2hlZCwgaW4gd2hpY2ggY2FzZSBpdCB3aWxsXG4gICogYnJvYWRjYXN0IHRvIHRoZW0gYWxsIHdoZW4gc2VuZGluZywgYW5kIHdpbGwgcmVjZWl2ZSBtZXNzYWdlcyBpblxuICAqIGFycml2YWwtb3JkZXIuXG4gICovXG4gIHB1YmxpYyBhdHRhY2goIGNoYW5uZWw6IENoYW5uZWwgKVxuICB7XG4gICAgdGhpcy5fY2hhbm5lbHMucHVzaCggY2hhbm5lbCApO1xuXG4gICAgY2hhbm5lbC5hZGRFbmRQb2ludCggdGhpcyApO1xuICB9XG5cbiAgLyoqXG4gICogRGV0YWNoIGEgc3BlY2lmaWMgQ2hhbm5lbCBmcm9tIHRoaXMgRW5kUG9pbnQuXG4gICovXG4gIHB1YmxpYyBkZXRhY2goIGNoYW5uZWxUb0RldGFjaDogQ2hhbm5lbCApXG4gIHtcbiAgICBsZXQgaWR4ID0gdGhpcy5fY2hhbm5lbHMuaW5kZXhPZiggY2hhbm5lbFRvRGV0YWNoICk7XG5cbiAgICBpZiAoIGlkeCA+PSAwIClcbiAgICB7XG4gICAgICBjaGFubmVsVG9EZXRhY2gucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbHMuc3BsaWNlKCBpZHgsIDEgKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgKiBEZXRhY2ggYWxsIENoYW5uZWxzIGZyb20gdGhpcyBFbmRQb2ludC5cbiAgKi9cbiAgcHVibGljIGRldGFjaEFsbCgpXG4gIHtcbiAgICB0aGlzLl9jaGFubmVscy5mb3JFYWNoKCBjaGFubmVsID0+IHtcbiAgICAgIGNoYW5uZWwucmVtb3ZlRW5kUG9pbnQoIHRoaXMgKTtcbiAgICB9ICk7XG5cbiAgICB0aGlzLl9jaGFubmVscyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICogQXJlIGFueSBjaGFubmVscyBhdHRhY2hlZCB0byB0aGlzIEVuZFBvaW50P1xuICAqXG4gICogQHJldHVybnMgdHJ1ZSBpZiBFbmRwb2ludCBpcyBhdHRhY2hlZCB0byBhdC1sZWFzdC1vbmUgQ2hhbm5lbFxuICAqL1xuICBnZXQgYXR0YWNoZWQoKVxuICB7XG4gICAgcmV0dXJuICggdGhpcy5fY2hhbm5lbHMubGVuZ3RoID4gMCApO1xuICB9XG5cbiAgZ2V0IGRpcmVjdGlvbigpOiBEaXJlY3Rpb25cbiAge1xuICAgIHJldHVybiB0aGlzLl9kaXJlY3Rpb247XG4gIH1cblxuICAvKipcbiAgKiBIYW5kbGUgYW4gaW5jb21pbmcgTWVzc2FnZSwgbWV0aG9kIGNhbGxlZCBieSBDaGFubmVsLlxuICAqL1xuICBwdWJsaWMgaGFuZGxlTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+LCBmcm9tRW5kUG9pbnQ6IEVuZFBvaW50LCBmcm9tQ2hhbm5lbDogQ2hhbm5lbCApXG4gIHtcbiAgICB0aGlzLl9tZXNzYWdlTGlzdGVuZXJzLmZvckVhY2goIG1lc3NhZ2VMaXN0ZW5lciA9PiB7XG4gICAgICBtZXNzYWdlTGlzdGVuZXIoIG1lc3NhZ2UsIHRoaXMsIGZyb21DaGFubmVsICk7XG4gICAgfSApO1xuICB9XG5cbiAgLyoqXG4gICogU2VuZCBhIE1lc3NhZ2UuXG4gICovXG4gIHB1YmxpYyBzZW5kTWVzc2FnZSggbWVzc2FnZTogTWVzc2FnZTxhbnk+IClcbiAge1xuICAgIHRoaXMuX2NoYW5uZWxzLmZvckVhY2goIGNoYW5uZWwgPT4ge1xuICAgICAgY2hhbm5lbC5zZW5kTWVzc2FnZSggdGhpcywgbWVzc2FnZSApO1xuICAgIH0gKTtcbiAgfVxuXG4gIC8qKlxuICAqIFJlZ2lzdGVyIGEgZGVsZWdhdGUgdG8gcmVjZWl2ZSBpbmNvbWluZyBNZXNzYWdlc1xuICAqXG4gICogQHBhcmFtIG1lc3NhZ2VMaXN0ZW5lciAtIGRlbGVnYXRlIHRvIGJlIGNhbGxlZCB3aXRoIHJlY2VpdmVkIE1lc3NhZ2VcbiAgKi9cbiAgcHVibGljIG9uTWVzc2FnZSggbWVzc2FnZUxpc3RlbmVyOiBIYW5kbGVNZXNzYWdlRGVsZWdhdGUgKVxuICB7XG4gICAgdGhpcy5fbWVzc2FnZUxpc3RlbmVycy5wdXNoKCBtZXNzYWdlTGlzdGVuZXIgKTtcbiAgfVxufVxuXG4vKipcbiogQW4gaW5kZXhlZCBjb2xsZWN0aW9uIG9mIEVuZFBvaW50IG9iamVjdHMsIG5vcm1hbGx5IGluZGV4ZWQgdmlhIEVuZFBvaW50J3NcbiogdW5pcXVlIGlkZW50aWZpZXJcbiovXG5leHBvcnQgdHlwZSBFbmRQb2ludENvbGxlY3Rpb24gPSB7IFtpZDogc3RyaW5nXTogRW5kUG9pbnQ7IH07XG4iLCJpbXBvcnQgeyBNZXNzYWdlIH0gZnJvbSAnLi9tZXNzYWdlJztcbmltcG9ydCB7IEtpbmQsIEtpbmRJbmZvIH0gZnJvbSAnLi4va2luZC9raW5kJztcblxuZXhwb3J0IGVudW0gUHJvdG9jb2xUeXBlQml0c1xue1xuICBQQUNLRVQgPSAwLCAgICAgICAgIC8qKiBEYXRhZ3JhbS1vcmllbnRlZCAoYWx3YXlzIGNvbm5lY3RlZC4uLikgKi9cbiAgU1RSRUFNID0gMSwgICAgICAgICAvKiogQ29ubmVjdGlvbi1vcmllbnRlZCAqL1xuXG4gIE9ORVdBWSA9IDAsICAgICAgICAgLyoqIFVuaWRpcmVjdGlvbmFsIE9VVCAoc291cmNlKSAtPiBJTiAoc2luaykgKi9cbiAgQ0xJRU5UU0VSVkVSID0gNCwgICAvKiogQ29tbWFuZCBPVVQtPklOLCBSZXNwb25zZSBJTi0+T1VUICovXG4gIFBFRVIyUEVFUiA9IDYsICAgICAgLyoqIEJpZGlyZWN0aW9uYWw6IElOT1VUIDwtPiBJTk9VVCAqL1xuXG4gIFVOVFlQRUQgPSAwLCAgICAgICAgLyoqIFVudHlwZWQgZGF0YSAqL1xuICBUWVBFRCA9IDgsICAgICAgICAgIC8qKiBUeXBlZCBkYXRhICoqL1xufVxuXG5leHBvcnQgdHlwZSBQcm90b2NvbFR5cGUgPSBudW1iZXI7XG5cbmV4cG9ydCBjbGFzcyBQcm90b2NvbDxUPlxue1xuICBzdGF0aWMgcHJvdG9jb2xUeXBlOiBQcm90b2NvbFR5cGUgPSAwO1xufVxuXG4vKipcbiogQSBDbGllbnQtU2VydmVyIFByb3RvY29sLCB0byBiZSB1c2VkIGJldHdlZW5cbiovXG5jbGFzcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxUPiBleHRlbmRzIFByb3RvY29sPFQ+XG57XG4gIHN0YXRpYyBwcm90b2NvbFR5cGU6IFByb3RvY29sVHlwZSA9IFByb3RvY29sVHlwZUJpdHMuQ0xJRU5UU0VSVkVSIHwgUHJvdG9jb2xUeXBlQml0cy5UWVBFRDtcbn1cblxuY2xhc3MgQVBEVSBpbXBsZW1lbnRzIEtpbmQge1xuICBraW5kSW5mbzogS2luZEluZm87XG4gIHByb3BlcnRpZXM7XG59XG5cbmNsYXNzIEFQRFVNZXNzYWdlIGV4dGVuZHMgTWVzc2FnZTxBUERVPlxue1xufVxuXG5jbGFzcyBBUERVUHJvdG9jb2wgZXh0ZW5kcyBDbGllbnRTZXJ2ZXJQcm90b2NvbDxBUERVTWVzc2FnZT5cbntcblxufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuLyoqXG4qIEBjbGFzcyBQb3J0SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIGNvbXBvbmVudCdzIFBvcnRcbiovXG5leHBvcnQgY2xhc3MgUG9ydEluZm9cbntcbiAgLyoqXG4gICogRGlyZWN0aW9uOiBJTiwgT1VULCBvciBJTk9VVFxuICAqICAgZm9yIGNsaWVudC1zZXJ2ZXIsIE9VVD1DbGllbnQsIElOPVNlcnZlclxuICAqICAgZm9yIHNvY2tldFxuICAqL1xuICBkaXJlY3Rpb246IERpcmVjdGlvbjtcblxuICAvKipcbiAgKiBQcm90b2NvbCBpbXBsZW1lbnRlZCBieSB0aGUgcG9ydFxuICAqL1xuICBwcm90b2NvbDogUHJvdG9jb2w8YW55PjtcblxuICAvKipcbiAgKiBSRlUgLSBpbmRleGFibGUgcG9ydHNcbiAgKi9cbiAgaW5kZXg6IG51bWJlciA9IDA7XG5cbiAgLyoqXG4gICogdHJ1ZSBpcyBwb3J0IG11c3QgYmUgY29ubmVjdGVkIGZvciBjb21wb25lbnQgdG8gZXhlY3V0ZVxuICAqL1xuICByZXF1aXJlZDogYm9vbGVhbiA9IGZhbHNlO1xufVxuIiwiaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcblxuaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5cbi8qKlxuKiBAY2xhc3MgQ29tcG9uZW50SW5mb1xuKlxuKiBNZXRhZGF0YSBhYm91dCBhIENvbXBvbmVudFxuKi9cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRJbmZvXG57XG4gIC8qKlxuICAqIENvbXBvbmVudCBOYW1lXG4gICovXG4gIG5hbWU6IHN0cmluZztcblxuICAvKipcbiAgKiBCcmllZiBkZXNjcmlwdGlvbiBmb3IgdGhlIGNvbXBvbmVudCwgdG8gYXBwZWFyIGluICdoaW50J1xuICAqL1xuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuXG4gIC8qKlxuICAqIExpbmsgdG8gZGV0YWlsZWQgaW5mb3JtYXRpb24gZm9yIHRoZSBjb21wb25lbnRcbiAgKi9cbiAgZGV0YWlsTGluazogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQ2F0ZWdvcnkgbmFtZSBmb3IgdGhlIGNvbXBvbmVudCwgZ3JvdXBzIHNhbWUgY2F0ZWdvcmllcyB0b2dldGhlclxuICAqL1xuICBjYXRlZ29yeTogc3RyaW5nID0gJyc7XG5cbiAgLyoqXG4gICogQXV0aG9yJ3MgbmFtZVxuICAqL1xuICBhdXRob3I6IHN0cmluZyA9ICcnO1xuXG4gIC8qKlxuICAqIEFycmF5IG9mIFBvcnQgZGVzY3JpcHRvcnMuIFdoZW4gYWN0aXZlLCB0aGUgY29tcG9uZW50IHdpbGwgY29tbXVuaWNhdGVcbiAgKiB0aHJvdWdoIGNvcnJlc3BvbmRpbmcgRW5kUG9pbnRzXG4gICovXG4gIHBvcnRzOiB7IFtpZDogc3RyaW5nXTogUG9ydEluZm8gfSA9IHt9O1xuICBzdG9yZXM6IHsgW2lkOiBzdHJpbmddOiBQb3J0SW5mbyB9ID0ge307XG5cbiAgY29uc3RydWN0b3IoKVxuICB7XG4gIH1cbn1cbiIsIlxuLyoqXG4qIE1ldGFkYXRhIGFib3V0IGEgY29tcG9uZW50J3MgU3RvcmVcbiogVE9ETzogXG4qL1xuZXhwb3J0IGNsYXNzIFN0b3JlSW5mb1xue1xufVxuIiwiaW1wb3J0IHsgUG9ydEluZm8gfSBmcm9tICcuL3BvcnQtaW5mbyc7XG5pbXBvcnQgeyBTdG9yZUluZm8gfSBmcm9tICcuL3N0b3JlLWluZm8nO1xuaW1wb3J0IHsgQ29tcG9uZW50SW5mbyB9IGZyb20gJy4vY29tcG9uZW50LWluZm8nO1xuaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uLCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IFByb3RvY29sIH0gZnJvbSAnLi4vbWVzc2FnaW5nL3Byb3RvY29sJztcbmltcG9ydCB7IEtpbmQgfSBmcm9tICcuLi9raW5kL2tpbmQnO1xuXG4vKipcbiogQnVpbGRlciBmb3IgJ0NvbXBvbmVudCcgbWV0YWRhdGEgKHN0YXRpYyBjb21wb25lbnRJbmZvKVxuKi9cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRCdWlsZGVyXG57XG4gIHByaXZhdGUgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3I7XG5cbiAgY29uc3RydWN0b3IoIGN0b3I6IENvbXBvbmVudENvbnN0cnVjdG9yLCBkZXNjcmlwdGlvbjogc3RyaW5nLCBjYXRlZ29yeT86IHN0cmluZyApIHtcblxuICAgIHRoaXMuY3RvciA9IGN0b3I7XG5cbiAgICBjdG9yLmNvbXBvbmVudEluZm8gPSB7XG4gICAgICBuYW1lOiBjdG9yLm5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24sXG4gICAgICBkZXRhaWxMaW5rOiAnJyxcbiAgICAgIGNhdGVnb3J5OiBjYXRlZ29yeSxcbiAgICAgIGF1dGhvcjogJycsXG4gICAgICBwb3J0czoge30sXG4gICAgICBzdG9yZXM6IHt9XG4gICAgfTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgaW5pdCggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IsIGRlc2NyaXB0aW9uOiBzdHJpbmcsIGNhdGVnb3J5Pzogc3RyaW5nICk6IENvbXBvbmVudEJ1aWxkZXJcbiAge1xuICAgIGxldCBidWlsZGVyID0gbmV3IENvbXBvbmVudEJ1aWxkZXIoIGN0b3IsIGRlc2NyaXB0aW9uLCBjYXRlZ29yeSApO1xuXG4gICAgcmV0dXJuIGJ1aWxkZXI7XG4gIH1cblxuICBwdWJsaWMgcG9ydCggaWQ6IHN0cmluZywgZGlyZWN0aW9uOiBEaXJlY3Rpb24sIG9wdHM/OiB7IHByb3RvY29sPzogUHJvdG9jb2w8YW55PjsgaW5kZXg/OiBudW1iZXI7IHJlcXVpcmVkPzogYm9vbGVhbiB9ICk6IENvbXBvbmVudEJ1aWxkZXJcbiAge1xuICAgIG9wdHMgPSBvcHRzIHx8IHt9O1xuXG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8ucG9ydHNbIGlkIF0gPSB7XG4gICAgICBkaXJlY3Rpb246IGRpcmVjdGlvbixcbiAgICAgIHByb3RvY29sOiBvcHRzLnByb3RvY29sLFxuICAgICAgaW5kZXg6IG9wdHMuaW5kZXgsXG4gICAgICByZXF1aXJlZDogb3B0cy5yZXF1aXJlZFxuICAgIH07XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHB1YmxpYyBuYW1lKCBuYW1lOiBzdHJpbmcgKSB7XG4gICAgdGhpcy5jdG9yLmNvbXBvbmVudEluZm8ubmFtZSA9IG5hbWU7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbn1cblxuLyoqXG4qIENvbXBvbmVudHMgYXJlIHJ1bnRpbWUgb2JqZWN0cyB0aGF0IGV4ZWN1dGUgd2l0aGluIGEgR3JhcGguXG4qIEEgZ3JhcGggTm9kZSBpcyBhIHBsYWNlaG9sZGVyIGZvciB0aGUgYWN0dWFsIENvbXBvbmVudCB0aGF0XG4qIHdpbGwgZXhlY3V0ZS5cbiogVGhpcyBpbnRlcmZhY2UgZGVmaW5lcyB0aGUgc3RhbmRhcmQgbWV0aG9kcyBhbmQgcHJvcGVydGllcyB0aGF0IGEgQ29tcG9uZW50XG4qIGNhbiBvcHRpb25hbGx5IGltcGxlbWVudC5cbiovXG5leHBvcnQgaW50ZXJmYWNlIENvbXBvbmVudFxue1xuICBpbml0aWFsaXplPyggY29uZmlnOiBLaW5kICk6IEVuZFBvaW50Q29sbGVjdGlvbjtcbiAgdGVhcmRvd24/KCk7XG5cbiAgc3RhcnQ/KCk7XG4gIHN0b3A/KCk7XG5cbiAgcGF1c2U/KCk7XG4gIHJlc3VtZT8oKTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDb21wb25lbnRDb25zdHJ1Y3Rvclxue1xuICBuZXcgKCAuLi5hcmdzICk6IENvbXBvbmVudDtcblxuICBjb21wb25lbnRJbmZvPzogQ29tcG9uZW50SW5mbztcbn1cblxuLyoqXG4qIEV4YW1wbGUgdXNhZ2UgLi4uLlxuKi9cbmNsYXNzIEMgaW1wbGVtZW50cyBDb21wb25lbnQge1xuXG59XG5cbkNvbXBvbmVudEJ1aWxkZXIuaW5pdCggQywgJ1Rlc3QgQ29tcG9uZW50JyApXG4gICAgICAgICAgICAgICAgLnBvcnQoICdwMScsIERpcmVjdGlvbi5JTiApXG4gICAgICAgICAgICAgICAgO1xuIiwiLy9lbnVtIEtleVR5cGUgeyBcInB1YmxpY1wiLCBcInByaXZhdGVcIiwgXCJzZWNyZXRcIiB9O1xuXG4vL2VudW0gS2V5VXNhZ2UgeyBcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCIsIFwic2lnblwiLCBcInZlcmlmeVwiLCBcImRlcml2ZUtleVwiLCBcImRlcml2ZUJpdHNcIiwgXCJ3cmFwS2V5XCIsIFwidW53cmFwS2V5XCIgfTtcblxuZXhwb3J0IGNsYXNzIEtleSAvL2ltcGxlbWVudHMgQ3J5cHRvS2V5XG57XG4gIHByb3RlY3RlZCBpZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBjcnlwdG9LZXk6IENyeXB0b0tleTtcblxuICBjb25zdHJ1Y3RvciggaWQ6IHN0cmluZywga2V5PzogQ3J5cHRvS2V5IClcbiAge1xuICAgIHRoaXMuaWQgPSBpZDtcblxuICAgIGlmICgga2V5IClcbiAgICAgIHRoaXMuY3J5cHRvS2V5ID0ga2V5O1xuICAgIGVsc2VcbiAgICB7XG4gICAgICB0aGlzLmNyeXB0b0tleSA9XG4gICAgICB7XG4gICAgICAgIHR5cGU6IFwiXCIsXG4gICAgICAgIGFsZ29yaXRobTogXCJcIixcbiAgICAgICAgZXh0cmFjdGFibGU6IHRydWUsXG4gICAgICAgIHVzYWdlczogW11cbiAgICAgIH07XG4gICAgfVxuXG4gIH1cblxuICBwdWJsaWMgZ2V0IHR5cGUoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5jcnlwdG9LZXkudHlwZTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgYWxnb3JpdGhtKCk6IEtleUFsZ29yaXRobVxuICB7XG4gICAgcmV0dXJuIHRoaXMuY3J5cHRvS2V5LmFsZ29yaXRobTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgZXh0cmFjdGFibGUoKTogYm9vbGVhblxuICB7XG4gICAgcmV0dXJuIHRoaXMuY3J5cHRvS2V5LmV4dHJhY3RhYmxlO1xuICB9XG5cbiAgcHVibGljIGdldCB1c2FnZXMoKTogc3RyaW5nW11cbiAge1xuICAgIHJldHVybiB0aGlzLmNyeXB0b0tleS51c2FnZXM7XG4gIH1cblxuICBwdWJsaWMgZ2V0IGlubmVyS2V5KCk6IENyeXB0b0tleVxuICB7XG4gICAgcmV0dXJuIHRoaXMuY3J5cHRvS2V5O1xuICB9XG4vKiAgZ2V0Q29tcG9uZW50KCBjb21wb25lbnRJRDogc3RyaW5nICk6IGFueVxuICB7XG4gICAgcmV0dXJuIHRoaXMua2V5Q29tcG9uZW50c1sgY29tcG9uZW50SUQgXTtcbiAgfVxuXG4gIHNldENvbXBvbmVudCggY29tcG9uZW50SUQ6IHN0cmluZywgdmFsdWU6IGFueSApXG4gIHtcbiAgICB0aGlzLmtleUNvbXBvbmVudHNbIGNvbXBvbmVudElEIF0gPSB2YWx1ZTtcbiAgfSovXG59XG4iLCJpbXBvcnQgeyBLZXkgfSBmcm9tICcuL2tleSc7XG5cbmV4cG9ydCBjbGFzcyBQcml2YXRlS2V5IGV4dGVuZHMgS2V5XG57XG5cbn1cbiIsImltcG9ydCB7IEtleSB9IGZyb20gJy4va2V5JztcblxuZXhwb3J0IGNsYXNzIFB1YmxpY0tleSBleHRlbmRzIEtleVxue1xuXG59XG4iLCJpbXBvcnQgeyBQcml2YXRlS2V5IH0gZnJvbSAnLi9wcml2YXRlLWtleSc7XG5pbXBvcnQgeyBQdWJsaWNLZXkgfSBmcm9tICcuL3B1YmxpYy1rZXknO1xuXG5leHBvcnQgY2xhc3MgS2V5UGFpclxue1xuICBwcml2YXRlS2V5OiBQcml2YXRlS2V5O1xuICBwdWJsaWNLZXk6IFB1YmxpY0tleTtcbn1cbiIsImltcG9ydCB7IEJ5dGVBcnJheSB9IGZyb20gJy4uL2tpbmQvYnl0ZS1hcnJheSc7XG5pbXBvcnQgeyBLZXkgfSBmcm9tICcuL2tleSc7XG5pbXBvcnQgeyBQcml2YXRlS2V5IH0gZnJvbSAnLi9wcml2YXRlLWtleSc7XG5pbXBvcnQgeyBQdWJsaWNLZXkgfSBmcm9tICcuL3B1YmxpYy1rZXknO1xuaW1wb3J0IHsgS2V5UGFpciB9IGZyb20gJy4va2V5LXBhaXInO1xuXG5kZWNsYXJlIHZhciBtc3JjcnlwdG87XG5cbmV4cG9ydCBjbGFzcyBDcnlwdG9ncmFwaGljU2VydmljZSB7XG4gIHByb3RlY3RlZCBjcnlwdG86IFN1YnRsZUNyeXB0bztcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLmNyeXB0byA9IHdpbmRvdy5jcnlwdG8uc3VidGxlO1xuXG4gICAgaWYgKCAhdGhpcy5jcnlwdG8gJiYgbXNyY3J5cHRvIClcbiAgICAgICB0aGlzLmNyeXB0byA9IG1zcmNyeXB0bztcbiAgfVxuXG4gIGRlY3J5cHQoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogS2V5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHRoaXMuY3J5cHRvLmRlY3J5cHQoYWxnb3JpdGhtLCBrZXkuaW5uZXJLZXksIGRhdGEuYmFja2luZ0FycmF5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbi8vZGVyaXZlQml0cyhhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgYmFzZUtleTogQ3J5cHRvS2V5LCBsZW5ndGg6IG51bWJlcik6IGFueTtcbi8vZGVyaXZlS2V5KGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBiYXNlS2V5OiBDcnlwdG9LZXksIGRlcml2ZWRLZXlUeXBlOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogYW55O1xuICBkaWdlc3QoYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGRhdGE6IEJ5dGVBcnJheSk6IGFueSB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5jcnlwdG8uZGlnZXN0KGFsZ29yaXRobSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZW5jcnlwdCggYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGtleTogS2V5LCBkYXRhOiBCeXRlQXJyYXkgKTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB0aGlzLmNyeXB0by5lbmNyeXB0KGFsZ29yaXRobSwga2V5LmlubmVyS2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGV4cG9ydEtleSggZm9ybWF0OiBzdHJpbmcsIGtleTogS2V5ICk6IFByb21pc2U8Qnl0ZUFycmF5PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPEJ5dGVBcnJheT4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgdGhpcy5jcnlwdG8uZXhwb3J0S2V5KGZvcm1hdCwga2V5LmlubmVyS2V5KVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUobmV3IEJ5dGVBcnJheShyZXMpKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgIH0pO1xuICB9XG5cbiAgZ2VuZXJhdGVLZXkoIGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBleHRyYWN0YWJsZTogYm9vbGVhbiwga2V5VXNhZ2VzOiBzdHJpbmdbXSApOiBQcm9taXNlPEtleSB8IEtleVBhaXI+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8S2V5IHwgS2V5UGFpcj4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuXG4gICB9KTtcbiAgfVxuXG4gIGltcG9ydEtleShmb3JtYXQ6IHN0cmluZywga2V5RGF0YTogQnl0ZUFycmF5ICwgYWxnb3JpdGhtOiBzdHJpbmcgfCBBbGdvcml0aG0sIGV4dHJhY3RhYmxlOiBib29sZWFuLCBrZXlVc2FnZXM6IHN0cmluZ1tdKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8S2V5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB0aGlzLmNyeXB0by5pbXBvcnRLZXkoZm9ybWF0LCBrZXlEYXRhLmJhY2tpbmdBcnJheSwgYWxnb3JpdGhtLCBleHRyYWN0YWJsZSwga2V5VXNhZ2VzKVxuICAgICAgICAudGhlbigocmVzKSA9PiB7IHJlc29sdmUocmVzKTsgfSlcbiAgICAgICAgLmNhdGNoKChlcnIpID0+IHsgcmVqZWN0KGVycik7IH0pO1xuICAgfSk7XG4gIH1cblxuICBzaWduKGFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCBrZXk6IEtleSwgZGF0YTogQnl0ZUFycmF5KTogUHJvbWlzZTxCeXRlQXJyYXk+IHtcbiAgICByZXR1cm4gbmV3IFByb21pc2U8Qnl0ZUFycmF5PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICB0aGlzLmNyeXB0by5zaWduKGFsZ29yaXRobSwga2V5LmlubmVyS2V5LCBkYXRhLmJhY2tpbmdBcnJheSlcbiAgICAgICAgLnRoZW4oKHJlcykgPT4geyByZXNvbHZlKG5ldyBCeXRlQXJyYXkocmVzKSk7IH0pXG4gICAgICAgIC5jYXRjaCgoZXJyKSA9PiB7IHJlamVjdChlcnIpOyB9KTtcbiAgICB9KTtcbiAgfVxuXG4vL3Vud3JhcEtleShmb3JtYXQ6IHN0cmluZywgd3JhcHBlZEtleTogQXJyYXlCdWZmZXJWaWV3LCB1bndyYXBwaW5nS2V5OiBDcnlwdG9LZXksIHVud3JhcEFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtLCB1bndyYXBwZWRLZXlBbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwgZXh0cmFjdGFibGU6IGJvb2xlYW4sIGtleVVzYWdlczogc3RyaW5nW10pOiBhbnk7XG4gIHZlcmlmeShhbGdvcml0aG06IHN0cmluZyB8IEFsZ29yaXRobSwga2V5OiBLZXksIHNpZ25hdHVyZTogQnl0ZUFycmF5LCBkYXRhOiBCeXRlQXJyYXkpOiBQcm9taXNlPEJ5dGVBcnJheT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZTxCeXRlQXJyYXk+KChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHRoaXMuY3J5cHRvLnZlcmlmeShhbGdvcml0aG0sIGtleS5pbm5lcktleSwgc2lnbmF0dXJlLmJhY2tpbmdBcnJheSwgZGF0YS5iYWNraW5nQXJyYXkpXG4gICAgICAgIC50aGVuKChyZXMpID0+IHsgcmVzb2x2ZShuZXcgQnl0ZUFycmF5KHJlcykpOyB9KVxuICAgICAgICAuY2F0Y2goKGVycikgPT4geyByZWplY3QoZXJyKTsgfSk7XG4gICAgfSk7XG4gIH1cblxuLy93cmFwS2V5KGZvcm1hdDogc3RyaW5nLCBrZXk6IENyeXB0b0tleSwgd3JhcHBpbmdLZXk6IENyeXB0b0tleSwgd3JhcEFsZ29yaXRobTogc3RyaW5nIHwgQWxnb3JpdGhtKTogYW55O1xufVxuIiwiaW1wb3J0IHsgQ29udGFpbmVyLCBhdXRvaW5qZWN0IGFzIGluamVjdCB9IGZyb20gJ2F1cmVsaWEtZGVwZW5kZW5jeS1pbmplY3Rpb24nO1xuaW1wb3J0IHsgbWV0YWRhdGEgfSBmcm9tICdhdXJlbGlhLW1ldGFkYXRhJztcblxuZXhwb3J0IHsgQ29udGFpbmVyLCBpbmplY3QgfTtcbmV4cG9ydCBpbnRlcmZhY2UgSW5qZWN0YWJsZSB7XG4gIG5ldyggLi4uYXJncyApOiBPYmplY3Q7XG59XG4iLCJpbXBvcnQgeyBFdmVudEFnZ3JlZ2F0b3IsIFN1YnNjcmlwdGlvbiwgSGFuZGxlciBhcyBFdmVudEhhbmRsZXIgfSBmcm9tICdhdXJlbGlhLWV2ZW50LWFnZ3JlZ2F0b3InO1xuXG4vL2V4cG9ydCB7IEV2ZW50SGFuZGxlciB9O1xuXG5leHBvcnQgY2xhc3MgRXZlbnRIdWJcbntcbiAgX2V2ZW50QWdncmVnYXRvcjogRXZlbnRBZ2dyZWdhdG9yO1xuXG4gIGNvbnN0cnVjdG9yKCApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IgPSBuZXcgRXZlbnRBZ2dyZWdhdG9yKCk7XG4gIH1cblxuICBwdWJsaWMgcHVibGlzaCggZXZlbnQ6IHN0cmluZywgZGF0YT86IGFueSApXG4gIHtcbiAgICB0aGlzLl9ldmVudEFnZ3JlZ2F0b3IucHVibGlzaCggZXZlbnQsIGRhdGEgKTtcbiAgfVxuXG4gIHB1YmxpYyBzdWJzY3JpYmUoIGV2ZW50OiBzdHJpbmcsIGhhbmRsZXI6IEZ1bmN0aW9uICk6IFN1YnNjcmlwdGlvblxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2V2ZW50QWdncmVnYXRvci5zdWJzY3JpYmUoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cblxuICBwdWJsaWMgc3Vic2NyaWJlT25jZSggZXZlbnQ6IHN0cmluZywgaGFuZGxlcjogRnVuY3Rpb24gKTogU3Vic2NyaXB0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZXZlbnRBZ2dyZWdhdG9yLnN1YnNjcmliZU9uY2UoIGV2ZW50LCBoYW5kbGVyICk7XG4gIH1cbn1cblxuLypmdW5jdGlvbiBldmVudEh1YigpOiBhbnkge1xuICByZXR1cm4gZnVuY3Rpb24gZXZlbnRIdWI8VEZ1bmN0aW9uIGV4dGVuZHMgRnVuY3Rpb24sIEV2ZW50SHViPih0YXJnZXQ6IFRGdW5jdGlvbik6IFRGdW5jdGlvbiB7XG5cbiAgICB0YXJnZXQucHJvdG90eXBlLnN1YnNjcmliZSA9IG5ld0NvbnN0cnVjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUodGFyZ2V0LnByb3RvdHlwZSk7XG4gICAgbmV3Q29uc3RydWN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gdGFyZ2V0O1xuXG4gICAgcmV0dXJuIDxhbnk+IG5ld0NvbnN0cnVjdG9yO1xuICB9XG59XG5cbkBldmVudEh1YigpXG5jbGFzcyBNeUNsYXNzIHt9O1xuKi9cbiIsImltcG9ydCB7IEVuZFBvaW50LCBEaXJlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcblxuLyoqXG4qIEEgUG9ydCBpcyBhIHBsYWNlaG9sZGVyIGZvciBhbiBFbmRQb2ludCBwdWJsaXNoZWQgYnkgdGhlIHVuZGVybHlpbmdcbiogY29tcG9uZW50IG9mIGEgTm9kZS5cbiovXG5leHBvcnQgY2xhc3MgUG9ydFxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBOb2RlO1xuICBwcm90ZWN0ZWQgX3Byb3RvY29sSUQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgX2VuZFBvaW50OiBFbmRQb2ludDtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICBjb25zdHJ1Y3Rvciggb3duZXI6IE5vZGUsIGVuZFBvaW50OiBFbmRQb2ludCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgLy8gV2FzIGFuIEVuZFBvaW50IHN1cHBsaWVkP1xuICAgIGlmICggIWVuZFBvaW50IClcbiAgICB7XG4gICAgICBsZXQgZGlyZWN0aW9uID0gYXR0cmlidXRlcy5kaXJlY3Rpb24gfHwgRGlyZWN0aW9uLklOT1VUO1xuXG4gICAgICBpZiAoIHR5cGVvZiBhdHRyaWJ1dGVzLmRpcmVjdGlvbiA9PSBcInN0cmluZ1wiIClcbiAgICAgICAgZGlyZWN0aW9uID0gRGlyZWN0aW9uWyBkaXJlY3Rpb24udG9VcHBlckNhc2UoKSBdO1xuXG4gICAgICAvLyBDcmVhdGUgYSBcImR1bW15XCIgZW5kUG9pbnQgd2l0aCBjb3JyZWN0IGlkICsgZGlyZWN0aW9uXG4gICAgICBlbmRQb2ludCA9IG5ldyBFbmRQb2ludCggYXR0cmlidXRlcy5pZCwgZGlyZWN0aW9uICk7XG4gICAgfVxuXG4gICAgdGhpcy5fb3duZXIgPSBvd25lcjtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgZW5kUG9pbnQoKSB7XG4gICAgcmV0dXJuIHRoaXMuX2VuZFBvaW50O1xuICB9XG4gIHB1YmxpYyBzZXQgZW5kUG9pbnQoIGVuZFBvaW50OiBFbmRQb2ludCApIHtcbiAgICB0aGlzLl9lbmRQb2ludCA9IGVuZFBvaW50O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBQT0pPIGZvciBzZXJpYWxpemF0aW9uXG4gICAqL1xuICB0b09iamVjdCggb3B0cz86IGFueSApOiBPYmplY3RcbiAge1xuICAgIHZhciBwb3J0ID0ge1xuICAgICAgaWQ6IHRoaXMuX2VuZFBvaW50LmlkLFxuICAgICAgZGlyZWN0aW9uOiB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24sXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgfTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgUG9ydCdzIG93bmVyXG4gICAqL1xuICBnZXQgb3duZXIoKTogTm9kZSB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyXG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgcHJvdG9jb2wgSURcbiAgICovXG4gIGdldCBwcm90b2NvbElEKCk6IHN0cmluZ1xuICB7XG4gICAgcmV0dXJuIHRoaXMuX3Byb3RvY29sSUQ7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBQb3J0J3MgRW5kUG9pbnQgSURcbiAgICovXG4gIGdldCBpZCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9lbmRQb2ludC5pZDtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIFBvcnQncyBFbmRQb2ludCBEaXJlY3Rpb25cbiAgICovXG4gIGdldCBkaXJlY3Rpb24oKTogRGlyZWN0aW9uXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fZW5kUG9pbnQuZGlyZWN0aW9uO1xuICB9XG5cbn1cblxuZXhwb3J0IGNsYXNzIFB1YmxpY1BvcnQgZXh0ZW5kcyBQb3J0XG57XG4gIHByb3h5RW5kUG9pbnQ6IEVuZFBvaW50O1xuICBwcm94eUNoYW5uZWw6IENoYW5uZWw7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgZW5kUG9pbnQ6IEVuZFBvaW50LCBhdHRyaWJ1dGVzOiB7fSApXG4gIHtcbiAgICBzdXBlciggb3duZXIsIGVuZFBvaW50LCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsZXQgcHJveHlEaXJlY3Rpb24gPVxuICAgICAgKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLklOIClcbiAgICAgICAgPyBEaXJlY3Rpb24uT1VUXG4gICAgICAgIDogKCB0aGlzLl9lbmRQb2ludC5kaXJlY3Rpb24gPT0gRGlyZWN0aW9uLk9VVCApXG4gICAgICAgICAgPyBEaXJlY3Rpb24uSU5cbiAgICAgICAgICA6IERpcmVjdGlvbi5JTk9VVDtcblxuICAgIC8vIENyZWF0ZSBhbiBFbmRQb2ludCB0byBwcm94eSBiZXR3ZWVuIHRoZSBQdWJsaWMgYW5kIFByaXZhdGUgKGludGVybmFsKVxuICAgIC8vIHNpZGVzIG9mIHRoZSBQb3J0LlxuICAgIHRoaXMucHJveHlFbmRQb2ludCA9IG5ldyBFbmRQb2ludCggdGhpcy5fZW5kUG9pbnQuaWQsIHByb3h5RGlyZWN0aW9uICk7XG5cbiAgICAvLyBXaXJlLXVwIHByb3h5IC1cblxuICAgIC8vIEZvcndhcmQgaW5jb21pbmcgcGFja2V0cyAoZnJvbSBwdWJsaWMgaW50ZXJmYWNlKSB0byBwcml2YXRlXG4gICAgdGhpcy5wcm94eUVuZFBvaW50Lm9uTWVzc2FnZSggKCBtZXNzYWdlICkgPT4ge1xuICAgICAgdGhpcy5fZW5kUG9pbnQuaGFuZGxlTWVzc2FnZSggbWVzc2FnZSwgdGhpcy5wcm94eUVuZFBvaW50LCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICAgIH0pO1xuXG4gICAgLy8gRm9yd2FyZCBvdXRnb2luZyBwYWNrZXRzIChmcm9tIHByaXZhdGUgaW50ZXJmYWNlKSB0byBwdWJsaWNcbiAgICB0aGlzLl9lbmRQb2ludC5vbk1lc3NhZ2UoICggbWVzc2FnZSApID0+IHtcbiAgICAgIHRoaXMucHJveHlFbmRQb2ludC5zZW5kTWVzc2FnZSggbWVzc2FnZSApO1xuICAgIH0pO1xuXG4gICAgLy8gbm90IHlldCBjb25uZWN0ZWRcbiAgICB0aGlzLnByb3h5Q2hhbm5lbCA9IG51bGw7XG4gIH1cblxuICAvLyBDb25uZWN0IHRvIFByaXZhdGUgKGludGVybmFsKSBFbmRQb2ludC4gVG8gYmUgY2FsbGVkIGR1cmluZyBncmFwaFxuICAvLyB3aXJlVXAgcGhhc2VcbiAgcHVibGljIGNvbm5lY3RQcml2YXRlKCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIHRoaXMucHJveHlDaGFubmVsID0gY2hhbm5lbDtcblxuICAgIHRoaXMucHJveHlFbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIHB1YmxpYyBkaXNjb25uZWN0UHJpdmF0ZSgpXG4gIHtcbiAgICB0aGlzLnByb3h5RW5kUG9pbnQuZGV0YWNoKCB0aGlzLnByb3h5Q2hhbm5lbCApO1xuICB9XG5cbiAgdG9PYmplY3QoIG9wdHM/OiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgcG9ydCA9IHN1cGVyLnRvT2JqZWN0KCBvcHRzICk7XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuLi9ydW50aW1lL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBDb21wb25lbnRGYWN0b3J5fSBmcm9tICcuLi9ydW50aW1lL2NvbXBvbmVudC1mYWN0b3J5JztcbmltcG9ydCB7IEV2ZW50SHViIH0gZnJvbSAnLi4vZXZlbnQtaHViL2V2ZW50LWh1Yic7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuZXhwb3J0IGNsYXNzIE5vZGUgZXh0ZW5kcyBFdmVudEh1Ylxue1xuICBwcm90ZWN0ZWQgX293bmVyOiBHcmFwaDtcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfY29tcG9uZW50OiBzdHJpbmc7XG4gIHByb3RlY3RlZCBfaW5pdGlhbERhdGE6IE9iamVjdDtcblxuICBwcm90ZWN0ZWQgX3BvcnRzOiBNYXA8c3RyaW5nLCBQb3J0PjtcblxuICBwdWJsaWMgbWV0YWRhdGE6IGFueTtcblxuICAvKipcbiAgICogUnVudGltZSBhbmQgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgICovXG4gIHByb3RlY3RlZCBfY29udGV4dDogUnVudGltZUNvbnRleHQ7XG5cbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5faWQgPSBhdHRyaWJ1dGVzLmlkIHx8ICcnO1xuICAgIHRoaXMuX2NvbXBvbmVudCA9IGF0dHJpYnV0ZXMuY29tcG9uZW50O1xuICAgIHRoaXMuX2luaXRpYWxEYXRhID0gYXR0cmlidXRlcy5pbml0aWFsRGF0YSB8fCB7fTtcblxuICAgIHRoaXMuX3BvcnRzID0gbmV3IE1hcDxzdHJpbmcsIFBvcnQ+KCk7XG5cbiAgICB0aGlzLm1ldGFkYXRhID0gYXR0cmlidXRlcy5tZXRhZGF0YSB8fCB7IH07XG5cbiAgICAvLyBJbml0aWFsbHkgY3JlYXRlICdwbGFjZWhvbGRlcicgcG9ydHMuIE9uY2UgY29tcG9uZW50IGhhcyBiZWVuXG4gICAgLy8gbG9hZGVkIGFuZCBpbnN0YW50aWF0ZWQsIHRoZXkgd2lsbCBiZSBjb25uZWN0ZWQgY29ubmVjdGVkIHRvXG4gICAgLy8gdGhlIGNvbXBvbmVudCdzIGNvbW11bmljYXRpb24gZW5kLXBvaW50c1xuICAgIE9iamVjdC5rZXlzKCBhdHRyaWJ1dGVzLnBvcnRzIHx8IHt9ICkuZm9yRWFjaCggKGlkKSA9PiB7XG4gICAgICB0aGlzLmFkZFBsYWNlaG9sZGVyUG9ydCggaWQsIGF0dHJpYnV0ZXMucG9ydHNbIGlkIF0gKTtcbiAgICB9ICk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJuIFBPSk8gZm9yIHNlcmlhbGl6YXRpb25cbiAgICovXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgdmFyIG5vZGUgPSB7XG4gICAgICBpZDogdGhpcy5pZCxcbiAgICAgIGNvbXBvbmVudDogdGhpcy5fY29tcG9uZW50LFxuICAgICAgaW5pdGlhbERhdGE6IHRoaXMuX2luaXRpYWxEYXRhLFxuICAgICAgcG9ydHM6IHt9LFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGFcbiAgICB9O1xuXG4gICAgdGhpcy5fcG9ydHMuZm9yRWFjaCggKCBwb3J0LCBpZCApID0+IHtcbiAgICAgIG5vZGUucG9ydHNbIGlkIF0gPSBwb3J0LnRvT2JqZWN0KCk7XG4gICAgfSApO1xuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBOb2RlJ3Mgb3duZXJcbiAgICovXG4gIHB1YmxpYyBnZXQgb3duZXIoKTogR3JhcGgge1xuICAgIHJldHVybiB0aGlzLl9vd25lclxuICB9XG5cbiAgLyoqXG4gICAqIEdldCB0aGUgTm9kZSdzIGlkXG4gICAqL1xuICBnZXQgaWQoKTogc3RyaW5nXG4gIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cbiAgLyoqXG4gICAqIFNldCB0aGUgTm9kZSdzIGlkXG4gICAqIEBwYXJhbSBpZCAtIG5ldyBpZGVudGlmaWVyXG4gICAqL1xuICBzZXQgaWQoIGlkOiBzdHJpbmcgKVxuICB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIC8qKlxuICAgKiBBZGQgYSBwbGFjZWhvbGRlciBQb3J0XG4gICAqL1xuICBwcm90ZWN0ZWQgYWRkUGxhY2Vob2xkZXJQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFBvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybiBwb3J0cyBhcyBhbiBhcnJheSBvZiBQb3J0c1xuICAgKlxuICAgKiBAcmV0dXJuIFBvcnRbXVxuICAgKi9cbiAgZ2V0IHBvcnRzKCk6IE1hcDxzdHJpbmcsIFBvcnQ+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHM7XG4gIH1cblxuICBnZXRQb3J0QXJyYXkoKTogUG9ydFtdIHtcbiAgICBsZXQgeHBvcnRzOiBQb3J0W10gPSBbXTtcblxuICAgIHRoaXMuX3BvcnRzLmZvckVhY2goICggcG9ydCwgaWQgKSA9PiB7XG4gICAgICB4cG9ydHMucHVzaCggcG9ydCApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiB4cG9ydHM7XG4gIH1cblxuICAvKipcbiAgICogTG9va3VwIGEgUG9ydCBieSBpdCdzIElEXG4gICAqIEBwYXJhbSBpZCAtIHBvcnQgaWRlbnRpZmllclxuICAgKlxuICAgKiBAcmV0dXJuIFBvcnQgb3IgdW5kZWZpbmVkXG4gICAqL1xuICBnZXRQb3J0QnlJRCggaWQ6IHN0cmluZyApOiBQb3J0XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICB9XG5cbiAgaWRlbnRpZnlQb3J0KCBpZDogc3RyaW5nLCBwcm90b2NvbElEPzogc3RyaW5nICk6IFBvcnRcbiAge1xuICAgIHZhciBwb3J0OiBQb3J0O1xuXG4gICAgaWYgKCBpZCApXG4gICAgICBwb3J0ID0gdGhpcy5fcG9ydHMuZ2V0KCBpZCApO1xuICAgIGVsc2UgaWYgKCBwcm90b2NvbElEIClcbiAgICB7XG4gICAgICB0aGlzLl9wb3J0cy5mb3JFYWNoKCAoIHAsIGlkICkgPT4ge1xuICAgICAgICBpZiAoIHAucHJvdG9jb2xJRCA9PSBwcm90b2NvbElEIClcbiAgICAgICAgICBwb3J0ID0gcDtcbiAgICAgIH0sIHRoaXMgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcG9ydDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZW1vdmUgYSBQb3J0IGZyb20gdGhpcyBOb2RlXG4gICAqIEBwYXJhbSBpZCAtIGlkZW50aWZpZXIgb2YgUG9ydCB0byBiZSByZW1vdmVkXG4gICAqIEByZXR1cm4gdHJ1ZSAtIHBvcnQgcmVtb3ZlZFxuICAgKiAgICAgICAgIGZhbHNlIC0gcG9ydCBpbmV4aXN0ZW50XG4gICAqL1xuICByZW1vdmVQb3J0KCBpZDogc3RyaW5nICk6IGJvb2xlYW5cbiAge1xuICAgIHJldHVybiB0aGlzLl9wb3J0cy5kZWxldGUoIGlkICk7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5ICk6IFByb21pc2U8dm9pZD4ge1xuICAgIHRoaXMudW5sb2FkQ29tcG9uZW50KCk7XG5cbiAgICAvLyBHZXQgYSBDb21wb25lbnRDb250ZXh0IHJlc3BvbnNhYmxlIGZvciBDb21wb25lbnQncyBsaWZlLWN5Y2xlIGNvbnRyb2xcbiAgICBsZXQgY3R4ID0gdGhpcy5fY29udGV4dCA9IGZhY3RvcnkuY3JlYXRlQ29udGV4dCggdGhpcy5fY29tcG9uZW50LCB0aGlzLl9pbml0aWFsRGF0YSApO1xuXG4gICAgLy8gTWFrZSBOb2RlIHZpc2libGUgdG8gaW5zdGFuY2VcbiAgICBjdHguY29udGFpbmVyLnJlZ2lzdGVySW5zdGFuY2UoIE5vZGUsIHRoaXMgKTtcblxuICAgIGxldCBtZSA9IHRoaXM7XG5cbiAgICAvLyBMb2FkIGNvbXBvbmVudFxuICAgIHJldHVybiBjdHgubG9hZCgpO1xuICB9XG5cbiAgcHVibGljIGdldCBjb250ZXh0KCk6IFJ1bnRpbWVDb250ZXh0IHtcbiAgICByZXR1cm4gdGhpcy5fY29udGV4dDtcbiAgfVxuXG4gIHVubG9hZENvbXBvbmVudCgpXG4gIHtcbiAgICBpZiAoIHRoaXMuX2NvbnRleHQgKVxuICAgIHtcbiAgICAgIHRoaXMuX2NvbnRleHQucmVsZWFzZSgpO1xuXG4gICAgICB0aGlzLl9jb250ZXh0ID0gbnVsbDtcbiAgICB9XG4gIH1cblxufVxuIiwiaW1wb3J0IHsgS2luZCB9IGZyb20gJy4uL2tpbmQva2luZCc7XG5pbXBvcnQgeyBFbmRQb2ludENvbGxlY3Rpb24gfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuLi9ncmFwaC9ub2RlJztcbmltcG9ydCB7IENvbXBvbmVudEZhY3Rvcnl9IGZyb20gJy4vY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgQ29tcG9uZW50IH0gZnJvbSAnLi4vY29tcG9uZW50L2NvbXBvbmVudCc7XG5cbmltcG9ydCB7IENvbnRhaW5lciwgSW5qZWN0YWJsZSB9IGZyb20gJy4uL2RlcGVuZGVuY3ktaW5qZWN0aW9uL2NvbnRhaW5lcic7XG5cbmV4cG9ydCBlbnVtIFJ1blN0YXRlIHtcbiAgTkVXQk9STiwgICAgICAvLyBOb3QgeWV0IGxvYWRlZFxuICBMT0FESU5HLCAgICAgIC8vIFdhaXRpbmcgZm9yIGFzeW5jIGxvYWQgdG8gY29tcGxldGVcbiAgTE9BREVELCAgICAgICAvLyBDb21wb25lbnQgbG9hZGVkLCBub3QgeWV0IGV4ZWN1dGFibGVcbiAgUkVBRFksICAgICAgICAvLyBSZWFkeSBmb3IgRXhlY3V0aW9uXG4gIFJVTk5JTkcsICAgICAgLy8gTmV0d29yayBhY3RpdmUsIGFuZCBydW5uaW5nXG4gIFBBVVNFRCAgICAgICAgLy8gTmV0d29yayB0ZW1wb3JhcmlseSBwYXVzZWRcbn1cblxuLyoqXG4qIFRoZSBydW50aW1lIGNvbnRleHQgaW5mb3JtYXRpb24gZm9yIGEgQ29tcG9uZW50IGluc3RhbmNlXG4qL1xuZXhwb3J0IGNsYXNzIFJ1bnRpbWVDb250ZXh0XG57XG4gIC8qKlxuICAqIFRoZSBjb21wb25lbnQgaWQgLyBhZGRyZXNzXG4gICovXG4gIHByaXZhdGUgX2lkOiBzdHJpbmc7XG5cbiAgLyoqXG4gICogVGhlIHJ1bnRpbWUgY29tcG9uZW50IGluc3RhbmNlIHRoYXQgdGhpcyBub2RlIHJlcHJlc2VudHNcbiAgKi9cbiAgcHJpdmF0ZSBfaW5zdGFuY2U6IENvbXBvbmVudDtcblxuICAvKipcbiAgKiBJbml0aWFsIERhdGEgZm9yIHRoZSBjb21wb25lbnQgaW5zdGFuY2VcbiAgKi9cbiAgcHJpdmF0ZSBfY29uZmlnOiB7fTtcblxuICAvKipcbiAgKiBUaGUgcnVudGltZSBjb21wb25lbnQgaW5zdGFuY2UgdGhhdCB0aGlzIG5vZGUgcmVwcmVzZW50c1xuICAqL1xuICBwcml2YXRlIF9jb250YWluZXI6IENvbnRhaW5lcjtcblxuICAvKipcbiAgKiBUaGUgY29tcG9uZW50IGZhY3RvcnkgdGhhdCBjcmVhdGVkIHVzXG4gICovXG4gIHByaXZhdGUgX2ZhY3Rvcnk6IENvbXBvbmVudEZhY3Rvcnk7XG5cbiAgLyoqXG4gICpcbiAgKlxuICAqL1xuICBjb25zdHJ1Y3RvciggZmFjdG9yeTogQ29tcG9uZW50RmFjdG9yeSwgY29udGFpbmVyOiBDb250YWluZXIsIGlkOiBzdHJpbmcsIGNvbmZpZzoge30sIGRlcHM6IEluamVjdGFibGVbXSA9IFtdICkge1xuXG4gICAgdGhpcy5fZmFjdG9yeSA9IGZhY3Rvcnk7XG5cbiAgICB0aGlzLl9pZCA9IGlkO1xuXG4gICAgdGhpcy5fY29uZmlnID0gY29uZmlnO1xuXG4gICAgdGhpcy5fY29udGFpbmVyID0gY29udGFpbmVyO1xuXG4gICAgLy8gUmVnaXN0ZXIgYW55IGNvbnRleHQgZGVwZW5kZW5jaWVzXG4gICAgZm9yKCBsZXQgaSBpbiBkZXBzIClcbiAgICB7XG4gICAgICBpZiAoICF0aGlzLl9jb250YWluZXIuaGFzUmVzb2x2ZXIoIGRlcHNbaV0gKSApXG4gICAgICAgIHRoaXMuX2NvbnRhaW5lci5yZWdpc3RlclNpbmdsZXRvbiggZGVwc1tpXSwgZGVwc1tpXSApO1xuICAgIH1cbiAgfVxuXG4gIGdldCBpbnN0YW5jZSgpOiBDb21wb25lbnQge1xuICAgIHJldHVybiB0aGlzLl9pbnN0YW5jZTtcbiAgfVxuXG4gIGdldCBjb250YWluZXIoKTogQ29udGFpbmVyIHtcbiAgICByZXR1cm4gdGhpcy5fY29udGFpbmVyO1xuICB9XG5cbiAgbG9hZCggKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgbGV0IG1lID0gdGhpcztcblxuICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZTx2b2lkPiggKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gZ2V0IGFuIGluc3RhbmNlIGZyb20gdGhlIGZhY3RvcnlcbiAgICAgIG1lLl9ydW5TdGF0ZSA9IFJ1blN0YXRlLkxPQURJTkc7XG4gICAgICB0aGlzLl9mYWN0b3J5LmxvYWRDb21wb25lbnQoIHRoaXMsIHRoaXMuX2lkIClcbiAgICAgICAgLnRoZW4oIChpbnN0YW5jZSkgPT4ge1xuICAgICAgICAgIC8vIENvbXBvbmVudCAoYW5kIGFueSBkZXBlbmRlbmNpZXMpIGhhdmUgYmVlbiBsb2FkZWRcbiAgICAgICAgICBtZS5faW5zdGFuY2UgPSBpbnN0YW5jZTtcbiAgICAgICAgICBtZS5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuTE9BREVEICk7XG5cbiAgICAgICAgICByZXNvbHZlKCk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaCggKGVycikgPT4ge1xuICAgICAgICAgIC8vIFVuYWJsZSB0byBsb2FkXG4gICAgICAgICAgbWUuX3J1blN0YXRlID0gUnVuU3RhdGUuTkVXQk9STjtcblxuICAgICAgICAgIHJlamVjdCggZXJyICk7XG4gICAgICAgIH0pO1xuICAgIH0gKTtcbiAgfVxuXG4gIF9ydW5TdGF0ZTogUnVuU3RhdGUgPSBSdW5TdGF0ZS5ORVdCT1JOO1xuICBnZXQgcnVuU3RhdGUoKSB7XG4gICAgcmV0dXJuIHRoaXMuX3J1blN0YXRlO1xuICB9XG5cbiAgcHJpdmF0ZSBpblN0YXRlKCBzdGF0ZXM6IFJ1blN0YXRlW10gKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIG5ldyBTZXQ8UnVuU3RhdGU+KCBzdGF0ZXMgKS5oYXMoIHRoaXMuX3J1blN0YXRlICk7XG4gIH1cblxuICAvKipcbiAgKiBUcmFuc2l0aW9uIGNvbXBvbmVudCB0byBuZXcgc3RhdGVcbiAgKiBTdGFuZGFyZCB0cmFuc2l0aW9ucywgYW5kIHJlc3BlY3RpdmUgYWN0aW9ucywgYXJlOlxuICAqICAgTE9BREVEIC0+IFJFQURZICAgICAgaW5zdGFudGlhdGUgYW5kIGluaXRpYWxpemUgY29tcG9uZW50XG4gICogICBSRUFEWSAtPiBMT0FERUQgICAgICB0ZWFyZG93biBhbmQgZGVzdHJveSBjb21wb25lbnRcbiAgKlxuICAqICAgUkVBRFkgLT4gUlVOTklORyAgICAgc3RhcnQgY29tcG9uZW50IGV4ZWN1dGlvblxuICAqICAgUlVOTklORyAtPiBSRUFEWSAgICAgc3RvcCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICpcbiAgKiAgIFJVTk5JTkcgLT4gUEFVU0VEICAgIHBhdXNlIGNvbXBvbmVudCBleGVjdXRpb25cbiAgKiAgIFBBVVNFRCAtPiBSVU5OSU5HICAgIHJlc3VtZSBjb21wb25lbnQgZXhlY3V0aW9uXG4gICpcbiAgKi9cbiAgc2V0UnVuU3RhdGUoIHJ1blN0YXRlOiBSdW5TdGF0ZSApIHtcbiAgICBsZXQgaW5zdCA9IHRoaXMuaW5zdGFuY2U7XG5cbiAgICBzd2l0Y2goIHJ1blN0YXRlICkgLy8gdGFyZ2V0IHN0YXRlIC4uXG4gICAge1xuICAgICAgY2FzZSBSdW5TdGF0ZS5MT0FERUQ6IC8vIGp1c3QgbG9hZGVkLCBvciB0ZWFyZG93blxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5SRUFEWSwgUnVuU3RhdGUuUlVOTklORywgUnVuU3RhdGUuUEFVU0VEIF0gKSApIHtcbiAgICAgICAgICAvLyB0ZWFyZG93biBhbmQgZGVzdHJveSBjb21wb25lbnRcbiAgICAgICAgICBpZiAoIGluc3QudGVhcmRvd24gKVxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGluc3QudGVhcmRvd24oKTtcblxuICAgICAgICAgICAgLy8gYW5kIGRlc3Ryb3kgaW5zdGFuY2VcbiAgICAgICAgICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUkVBRFk6ICAvLyBpbml0aWFsaXplIG9yIHN0b3Agbm9kZVxuICAgICAgICBpZiAoIHRoaXMuaW5TdGF0ZSggWyBSdW5TdGF0ZS5MT0FERUQgXSApICkge1xuICAgICAgICAgIC8vIGluaXRpYWxpemUgY29tcG9uZW50XG4gICAgICAgICAgbGV0IGVuZFBvaW50czogRW5kUG9pbnRDb2xsZWN0aW9uID0ge307XG5cbiAgICAgICAgICAvLyBUT0RPOlxuICAgICAgICAgIGlmICggaW5zdC5pbml0aWFsaXplIClcbiAgICAgICAgICAgIGVuZFBvaW50cyA9IHRoaXMuaW5zdGFuY2UuaW5pdGlhbGl6ZSggPEtpbmQ+dGhpcy5fY29uZmlnICk7XG5cbiAgICAgICAgICB0aGlzLnJlY29uY2lsZVBvcnRzKCBlbmRQb2ludHMgKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gc3RvcCBjb21wb25lbnRcbiAgICAgICAgICBpZiAoIGluc3Quc3RvcCApXG4gICAgICAgICAgICB0aGlzLmluc3RhbmNlLnN0b3AoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBpbml0aWFsaXplZCwgbm90IGxvYWRlZCcgKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgUnVuU3RhdGUuUlVOTklORzogIC8vIHN0YXJ0L3Jlc3VtZSBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJFQURZLCBSdW5TdGF0ZS5SVU5OSU5HIF0gKSApIHtcbiAgICAgICAgICAvLyBzdGFydCBjb21wb25lbnQgZXhlY3V0aW9uXG4gICAgICAgICAgaWYgKCBpbnN0LnN0YXJ0IClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2Uuc3RhcnQoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gcmVzdW1lIGNvbXBvbmVudCBleGVjdXRpb24gYWZ0ZXIgcGF1c2VcbiAgICAgICAgICBpZiAoIGluc3QucmVzdW1lIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UucmVzdW1lKCk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvciggJ0NvbXBvbmVudCBjYW5ub3QgYmUgc3RhcnRlZCwgbm90IHJlYWR5JyApO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSBSdW5TdGF0ZS5QQVVTRUQ6ICAvLyBwYXVzZSBub2RlXG4gICAgICAgIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkddICkgKSB7XG4gICAgICAgICAgaWYgKCBpbnN0LnBhdXNlIClcbiAgICAgICAgICAgIHRoaXMuaW5zdGFuY2UucGF1c2UoKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICggdGhpcy5pblN0YXRlKCBbIFJ1blN0YXRlLlBBVVNFRCBdICkgKSB7XG4gICAgICAgICAgLy8gYWxyZWFkeSBwYXVzZWRcbiAgICAgICAgfVxuICAgICAgICBlbHNlXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCAnQ29tcG9uZW50IGNhbm5vdCBiZSBwYXVzZWQnICk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIHRoaXMuX3J1blN0YXRlID0gcnVuU3RhdGU7XG4gIH1cblxuICBwcm90ZWN0ZWQgcmVjb25jaWxlUG9ydHMoIGVuZFBvaW50czogRW5kUG9pbnRDb2xsZWN0aW9uICkge1xuICAgIC8vbGV0IHBvcnRzID0gdGhpcy5ub2RlLnBvcnRzO1xuICAgIC8vZW5kXG4gIH1cblxuICByZWxlYXNlKCkge1xuICAgIC8vIHJlbGVhc2UgaW5zdGFuY2UsIHRvIGF2b2lkIG1lbW9yeSBsZWFrc1xuICAgIHRoaXMuX2luc3RhbmNlID0gbnVsbDtcblxuICAgIHRoaXMuX2ZhY3RvcnkgPSBudWxsXG4gIH1cbn1cbiIsImV4cG9ydCBpbnRlcmZhY2UgTW9kdWxlTG9hZGVyIHtcbiAgaGFzTW9kdWxlPyggaWQ6IHN0cmluZyApOiBib29sZWFuO1xuXG4gIGxvYWRNb2R1bGUoIGlkOiBzdHJpbmcgKTogUHJvbWlzZTxhbnk+O1xufVxuXG5kZWNsYXJlIGludGVyZmFjZSBTeXN0ZW0ge1xuICBub3JtYWxpemVTeW5jKCBpZCApO1xuICBpbXBvcnQoIGlkICk7XG59O1xuZGVjbGFyZSB2YXIgU3lzdGVtOiBTeXN0ZW07XG5cbmNsYXNzIE1vZHVsZVJlZ2lzdHJ5RW50cnkge1xuICBjb25zdHJ1Y3RvciggYWRkcmVzczogc3RyaW5nICkge1xuXG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFN5c3RlbU1vZHVsZUxvYWRlciBpbXBsZW1lbnRzIE1vZHVsZUxvYWRlciB7XG5cbiAgcHJpdmF0ZSBtb2R1bGVSZWdpc3RyeTogTWFwPHN0cmluZywgTW9kdWxlUmVnaXN0cnlFbnRyeT47XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5tb2R1bGVSZWdpc3RyeSA9IG5ldyBNYXA8c3RyaW5nLCBNb2R1bGVSZWdpc3RyeUVudHJ5PigpO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRPckNyZWF0ZU1vZHVsZVJlZ2lzdHJ5RW50cnkoYWRkcmVzczogc3RyaW5nKTogTW9kdWxlUmVnaXN0cnlFbnRyeSB7XG4gICAgcmV0dXJuIHRoaXMubW9kdWxlUmVnaXN0cnlbYWRkcmVzc10gfHwgKHRoaXMubW9kdWxlUmVnaXN0cnlbYWRkcmVzc10gPSBuZXcgTW9kdWxlUmVnaXN0cnlFbnRyeShhZGRyZXNzKSk7XG4gIH1cblxuICBsb2FkTW9kdWxlKCBpZDogc3RyaW5nICk6IFByb21pc2U8YW55PiB7XG4gICAgbGV0IG5ld0lkID0gU3lzdGVtLm5vcm1hbGl6ZVN5bmMoaWQpO1xuICAgIGxldCBleGlzdGluZyA9IHRoaXMubW9kdWxlUmVnaXN0cnlbbmV3SWRdO1xuXG4gICAgaWYgKGV4aXN0aW5nKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGV4aXN0aW5nKTtcbiAgICB9XG5cbiAgICByZXR1cm4gU3lzdGVtLmltcG9ydChuZXdJZCkudGhlbihtID0+IHtcbiAgICAgIHRoaXMubW9kdWxlUmVnaXN0cnlbbmV3SWRdID0gbTtcbiAgICAgIHJldHVybiBtOyAvL2Vuc3VyZU9yaWdpbk9uRXhwb3J0cyhtLCBuZXdJZCk7XG4gICAgfSk7XG4gIH1cblxufVxuIiwiaW1wb3J0IHsgQ29tcG9uZW50LCBDb21wb25lbnRDb25zdHJ1Y3RvciB9IGZyb20gJy4uL2NvbXBvbmVudC9jb21wb25lbnQnO1xuaW1wb3J0IHsgUnVudGltZUNvbnRleHQgfSBmcm9tICcuL3J1bnRpbWUtY29udGV4dCc7XG5pbXBvcnQgeyBNb2R1bGVMb2FkZXIgfSBmcm9tICcuL21vZHVsZS1sb2FkZXInO1xuXG5pbXBvcnQgeyBDb250YWluZXIsIEluamVjdGFibGUgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuaW1wb3J0IHsgRW5kUG9pbnRDb2xsZWN0aW9uIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5cbmV4cG9ydCBjbGFzcyBDb21wb25lbnRGYWN0b3J5IHtcbiAgcHJpdmF0ZSBfbG9hZGVyOiBNb2R1bGVMb2FkZXI7XG4gIHByaXZhdGUgX2NvbnRhaW5lcjogQ29udGFpbmVyO1xuICBwcml2YXRlIF9jb21wb25lbnRzOiBNYXA8c3RyaW5nLCBDb21wb25lbnRDb25zdHJ1Y3Rvcj47XG5cbiAgY29uc3RydWN0b3IoIGNvbnRhaW5lcj86IENvbnRhaW5lciwgbG9hZGVyPzogTW9kdWxlTG9hZGVyICkge1xuICAgIHRoaXMuX2xvYWRlciA9IGxvYWRlcjtcbiAgICB0aGlzLl9jb250YWluZXIgPSBjb250YWluZXIgfHwgbmV3IENvbnRhaW5lcigpO1xuICAgIHRoaXMuX2NvbXBvbmVudHMgPSBuZXcgTWFwPHN0cmluZywgQ29tcG9uZW50Q29uc3RydWN0b3I+KCk7XG5cbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggdW5kZWZpbmVkLCBPYmplY3QgKTtcbiAgICB0aGlzLl9jb21wb25lbnRzLnNldCggXCJcIiwgT2JqZWN0ICk7XG4gIH1cblxuICBjcmVhdGVDb250ZXh0KCBpZDogc3RyaW5nLCBjb25maWc6IHt9LCBkZXBzOiBJbmplY3RhYmxlW10gPSBbXSApOiBSdW50aW1lQ29udGV4dFxuICB7XG4gICAgbGV0IGNoaWxkQ29udGFpbmVyOiBDb250YWluZXIgPSB0aGlzLl9jb250YWluZXIuY3JlYXRlQ2hpbGQoKTtcblxuICAgIHJldHVybiBuZXcgUnVudGltZUNvbnRleHQoIHRoaXMsIGNoaWxkQ29udGFpbmVyLCBpZCwgY29uZmlnLCBkZXBzICk7XG4gIH1cblxuICBnZXRDaGlsZENvbnRhaW5lcigpOiBDb250YWluZXIge1xuICAgIHJldHVybiA7XG4gIH1cblxuICBsb2FkQ29tcG9uZW50KCBjdHg6IFJ1bnRpbWVDb250ZXh0LCBpZDogc3RyaW5nICk6IFByb21pc2U8Q29tcG9uZW50PlxuICB7XG4gICAgbGV0IGNyZWF0ZUNvbXBvbmVudCA9IGZ1bmN0aW9uKCBjdG9yOiBDb21wb25lbnRDb25zdHJ1Y3RvciApOiBDb21wb25lbnRcbiAgICB7XG4gICAgICBsZXQgbmV3SW5zdGFuY2U6IENvbXBvbmVudCA9IGN0eC5jb250YWluZXIuaW52b2tlKCBjdG9yICk7XG5cbiAgICAgIHJldHVybiBuZXdJbnN0YW5jZTtcbiAgICB9XG5cbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPENvbXBvbmVudD4oIChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8vIENoZWNrIGNhY2hlXG4gICAgICBsZXQgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgPSB0aGlzLmdldCggaWQgKTtcblxuICAgICAgaWYgKCBjdG9yICkge1xuICAgICAgICAvLyB1c2UgY2FjaGVkIGNvbnN0cnVjdG9yXG4gICAgICAgIHJlc29sdmUoIGNyZWF0ZUNvbXBvbmVudCggY3RvciApICk7XG4gICAgICB9XG4gICAgICBlbHNlIGlmICggdGhpcy5fbG9hZGVyICkge1xuICAgICAgICAvLyBnb3QgYSBsb2FkZWQsIHNvIHRyeSB0byBsb2FkIHRoZSBtb2R1bGUgLi4uXG4gICAgICAgIHRoaXMuX2xvYWRlci5sb2FkTW9kdWxlKCBpZCApXG4gICAgICAgICAgLnRoZW4oICggY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKSA9PiB7XG5cbiAgICAgICAgICAgIC8vIHJlZ2lzdGVyIGxvYWRlZCBjb21wb25lbnRcbiAgICAgICAgICAgIG1lLl9jb21wb25lbnRzLnNldCggaWQsIGN0b3IgKTtcblxuICAgICAgICAgICAgLy8gaW5zdGFudGlhdGUgYW5kIHJlc29sdmVcbiAgICAgICAgICAgIHJlc29sdmUoIGNyZWF0ZUNvbXBvbmVudCggY3RvciApICk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAuY2F0Y2goICggZSApID0+IHtcbiAgICAgICAgICAgIHJlamVjdCggJ0NvbXBvbmVudEZhY3Rvcnk6IFVuYWJsZSB0byBsb2FkIGNvbXBvbmVudCBcIicgKyBpZCArICdcIiAtICcgKyBlICk7XG4gICAgICAgICAgfSApO1xuICAgICAgfVxuICAgICAgZWxzZSB7XG4gICAgICAgIC8vIG9vcHMuIG5vIGxvYWRlciAuLiBubyBjb21wb25lbnRcbiAgICAgICAgcmVqZWN0KCAnQ29tcG9uZW50RmFjdG9yeTogQ29tcG9uZW50IFwiJyArIGlkICsgJ1wiIG5vdCByZWdpc3RlcmVkLCBhbmQgTG9hZGVyIG5vdCBhdmFpbGFibGUnICk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICBnZXQoIGlkOiBzdHJpbmcgKTogQ29tcG9uZW50Q29uc3RydWN0b3Ige1xuICAgIHJldHVybiB0aGlzLl9jb21wb25lbnRzLmdldCggaWQgKTtcbiAgfVxuICByZWdpc3RlciggaWQ6IHN0cmluZywgY3RvcjogQ29tcG9uZW50Q29uc3RydWN0b3IgKSB7XG4gICAgdGhpcy5fY29tcG9uZW50cy5zZXQoIGlkLCBjdG9yICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IEVuZFBvaW50IH0gZnJvbSAnLi4vbWVzc2FnaW5nL2VuZC1wb2ludCc7XG5pbXBvcnQgeyBDaGFubmVsIH0gZnJvbSAnLi4vbWVzc2FnaW5nL2NoYW5uZWwnO1xuXG5pbXBvcnQgeyBHcmFwaCB9IGZyb20gJy4vZ3JhcGgnO1xuaW1wb3J0IHsgTm9kZSB9IGZyb20gJy4vbm9kZSc7XG5pbXBvcnQgeyBQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuZXhwb3J0IHR5cGUgRW5kUG9pbnRSZWYgPSB7IG5vZGVJRDogc3RyaW5nLCBwb3J0SUQ6IHN0cmluZyB9O1xuXG5leHBvcnQgY2xhc3MgTGlua1xue1xuICBwcm90ZWN0ZWQgX293bmVyOiBHcmFwaDtcbiAgcHJvdGVjdGVkIF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBfY2hhbm5lbDogQ2hhbm5lbDtcbiAgcHJvdGVjdGVkIF9mcm9tOiBFbmRQb2ludFJlZjtcbiAgcHJvdGVjdGVkIF90bzogRW5kUG9pbnRSZWY7XG5cbiAgcHJvdGVjdGVkIF9wcm90b2NvbElEOiBzdHJpbmc7XG4gIHByb3RlY3RlZCBtZXRhZGF0YTogYW55O1xuXG4gIGNvbnN0cnVjdG9yKCBvd25lcjogR3JhcGgsIGF0dHJpYnV0ZXM6IGFueSA9IHt9IClcbiAge1xuICAgIHRoaXMuX293bmVyID0gb3duZXI7XG4gICAgdGhpcy5faWQgPSBhdHRyaWJ1dGVzLmlkIHx8IFwiXCI7XG4gICAgLy90aGlzLl9jaGFubmVsID0gbnVsbDtcbiAgICB0aGlzLl9mcm9tID0gYXR0cmlidXRlc1sgJ2Zyb20nIF07XG4gICAgdGhpcy5fdG8gPSBhdHRyaWJ1dGVzWyAndG8nIF07XG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IGF0dHJpYnV0ZXNbICdwcm90b2NvbCcgXSB8fCAnYW55JztcblxuICAgIHRoaXMubWV0YWRhdGEgPSBhdHRyaWJ1dGVzLm1ldGFkYXRhIHx8IHsgeDogMTAwLCB5OiAxMDAgfTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzPzogYW55ICk6IE9iamVjdFxuICB7XG4gICAgbGV0IGxpbmsgPSB7XG4gICAgICBpZDogdGhpcy5faWQsXG4gICAgICBwcm90b2NvbDogKCB0aGlzLl9wcm90b2NvbElEICE9ICdhbnknICkgPyB0aGlzLl9wcm90b2NvbElEIDogdW5kZWZpbmVkLFxuICAgICAgbWV0YWRhdGE6IHRoaXMubWV0YWRhdGEsXG4gICAgICBmcm9tOiB0aGlzLl9mcm9tLFxuICAgICAgdG86IHRoaXMuX3RvXG4gICAgfTtcblxuICAgIHJldHVybiBsaW5rO1xuICB9XG5cbiAgc2V0IGlkKCBpZDogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBjb25uZWN0KCBjaGFubmVsOiBDaGFubmVsIClcbiAge1xuICAgIC8vIGlkZW50aWZ5IGZyb21Qb3J0IGluIGZyb21Ob2RlXG4gICAgbGV0IGZyb21Qb3J0OiBQb3J0ID0gdGhpcy5mcm9tTm9kZS5pZGVudGlmeVBvcnQoIHRoaXMuX2Zyb20ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICk7XG5cbiAgICAvLyBpZGVudGlmeSB0b1BvcnQgaW4gdG9Ob2RlXG4gICAgbGV0IHRvUG9ydDogUG9ydCA9IHRoaXMudG9Ob2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fdG8ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICk7XG5cbiAgICB0aGlzLl9jaGFubmVsID0gY2hhbm5lbDtcblxuICAgIGZyb21Qb3J0LmVuZFBvaW50LmF0dGFjaCggY2hhbm5lbCApO1xuICAgIHRvUG9ydC5lbmRQb2ludC5hdHRhY2goIGNoYW5uZWwgKTtcbiAgfVxuXG4gIGRpc2Nvbm5lY3QoKTogQ2hhbm5lbFxuICB7XG4gICAgbGV0IGNoYW4gPSB0aGlzLl9jaGFubmVsO1xuXG4gICAgaWYgKCBjaGFuIClcbiAgICB7XG4gICAgICB0aGlzLl9jaGFubmVsLmVuZFBvaW50cy5mb3JFYWNoKCAoIGVuZFBvaW50ICkgPT4ge1xuICAgICAgICBlbmRQb2ludC5kZXRhY2goIHRoaXMuX2NoYW5uZWwgKTtcbiAgICAgIH0gKTtcblxuICAgICAgdGhpcy5fY2hhbm5lbCA9IHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICByZXR1cm4gY2hhbjtcbiAgfVxuXG4gIGdldCBmcm9tTm9kZSgpOiBOb2RlXG4gIHtcbiAgICByZXR1cm4gdGhpcy5fb3duZXIuZ2V0Tm9kZUJ5SUQoIHRoaXMuX2Zyb20ubm9kZUlEICk7XG4gIH1cblxuICBnZXQgZnJvbVBvcnQoKTogUG9ydFxuICB7XG4gICAgbGV0IG5vZGUgPSB0aGlzLmZyb21Ob2RlO1xuXG4gICAgcmV0dXJuIChub2RlKSA/IG5vZGUuaWRlbnRpZnlQb3J0KCB0aGlzLl9mcm9tLnBvcnRJRCwgdGhpcy5fcHJvdG9jb2xJRCApIDogdW5kZWZpbmVkO1xuICB9XG5cbiAgc2V0IGZyb21Qb3J0KCBwb3J0OiBQb3J0IClcbiAge1xuICAgIHRoaXMuX2Zyb20gPSB7XG4gICAgICBub2RlSUQ6IHBvcnQub3duZXIuaWQsXG4gICAgICBwb3J0SUQ6IHBvcnQuaWRcbiAgICB9O1xuXG4gICAgdGhpcy5fcHJvdG9jb2xJRCA9IHBvcnQucHJvdG9jb2xJRDtcbiAgfVxuXG4gIGdldCB0b05vZGUoKTogTm9kZVxuICB7XG4gICAgcmV0dXJuIHRoaXMuX293bmVyLmdldE5vZGVCeUlEKCB0aGlzLl90by5ub2RlSUQgKTtcbiAgfVxuXG4gIGdldCB0b1BvcnQoKTogUG9ydFxuICB7XG4gICAgbGV0IG5vZGUgPSB0aGlzLnRvTm9kZTtcblxuICAgIHJldHVybiAobm9kZSkgPyBub2RlLmlkZW50aWZ5UG9ydCggdGhpcy5fdG8ucG9ydElELCB0aGlzLl9wcm90b2NvbElEICkgOiB1bmRlZmluZWQ7XG4gIH1cblxuICBzZXQgdG9Qb3J0KCBwb3J0OiBQb3J0IClcbiAge1xuICAgIHRoaXMuX3RvID0ge1xuICAgICAgbm9kZUlEOiBwb3J0Lm93bmVyLmlkLFxuICAgICAgcG9ydElEOiBwb3J0LmlkXG4gICAgfTtcblxuICAgIHRoaXMuX3Byb3RvY29sSUQgPSBwb3J0LnByb3RvY29sSUQ7XG4gIH1cblxuICBnZXQgcHJvdG9jb2xJRCgpOiBzdHJpbmdcbiAge1xuICAgIHJldHVybiB0aGlzLl9wcm90b2NvbElEO1xuICB9XG59XG4iLCJpbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeSB9IGZyb20gJy4uL3J1bnRpbWUvY29tcG9uZW50LWZhY3RvcnknO1xuaW1wb3J0IHsgUnVudGltZUNvbnRleHQsIFJ1blN0YXRlIH0gZnJvbSAnLi4vcnVudGltZS9ydW50aW1lLWNvbnRleHQnO1xuaW1wb3J0IHsgRW5kUG9pbnQgfSBmcm9tICcuLi9tZXNzYWdpbmcvZW5kLXBvaW50JztcbmltcG9ydCB7IENoYW5uZWwgfSBmcm9tICcuLi9tZXNzYWdpbmcvY2hhbm5lbCc7XG5cbmltcG9ydCB7IEdyYXBoIH0gZnJvbSAnLi9ncmFwaCc7XG5pbXBvcnQgeyBOb2RlIH0gZnJvbSAnLi9ub2RlJztcbmltcG9ydCB7IExpbmsgfSBmcm9tICcuL2xpbmsnO1xuaW1wb3J0IHsgUG9ydCwgUHVibGljUG9ydCB9IGZyb20gJy4vcG9ydCc7XG5cbmV4cG9ydCBjbGFzcyBOZXR3b3JrIGV4dGVuZHMgRXZlbnRIdWJcbntcbiAgc3RhdGljIEVWRU5UX1NUQVRFX0NIQU5HRSA9ICduZXR3b3JrOnN0YXRlLWNoYW5nZSc7XG4gIHN0YXRpYyBFVkVOVF9HUkFQSF9DSEFOR0UgPSAnbmV0d29yazpncmFwaC1jaGFuZ2UnO1xuXG4gIHByaXZhdGUgX2dyYXBoOiBHcmFwaDtcblxuICBwcml2YXRlIF9mYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5O1xuXG4gIGNvbnN0cnVjdG9yKCBmYWN0b3J5OiBDb21wb25lbnRGYWN0b3J5LCBncmFwaD86IEdyYXBoIClcbiAge1xuICAgIHN1cGVyKCk7XG5cbiAgICB0aGlzLl9mYWN0b3J5ID0gZmFjdG9yeTtcbiAgICB0aGlzLl9ncmFwaCA9IGdyYXBoIHx8IG5ldyBHcmFwaCggbnVsbCwge30gKTtcblxuICAgIGxldCBtZSA9IHRoaXM7XG4gICAgdGhpcy5fZ3JhcGguc3Vic2NyaWJlKCBHcmFwaC5FVkVOVF9BRERfTk9ERSwgKCBkYXRhOiB7IG5vZGU6IE5vZGUgfSApPT4ge1xuICAgICAgbGV0IHJ1blN0YXRlOiBSdW5TdGF0ZSA9IG1lLl9ncmFwaC5jb250ZXh0LnJ1blN0YXRlO1xuXG4gICAgICBpZiAoIHJ1blN0YXRlICE9IFJ1blN0YXRlLk5FV0JPUk4gKVxuICAgICAge1xuICAgICAgICBsZXQgeyBub2RlIH0gPSBkYXRhO1xuXG4gICAgICAgIG5vZGUubG9hZENvbXBvbmVudCggbWUuX2ZhY3RvcnkgKVxuICAgICAgICAgIC50aGVuKCAoKT0+IHtcbiAgICAgICAgICAgIGlmICggTmV0d29yay5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCwgUnVuU3RhdGUuUkVBRFkgXSwgcnVuU3RhdGUgKSApXG4gICAgICAgICAgICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIG5vZGUsIFJ1blN0YXRlLlJFQURZICk7XG5cbiAgICAgICAgICAgIGlmICggTmV0d29yay5pblN0YXRlKCBbIFJ1blN0YXRlLlJVTk5JTkcsIFJ1blN0YXRlLlBBVVNFRCBdLCBydW5TdGF0ZSApIClcbiAgICAgICAgICAgICAgTmV0d29yay5zZXRSdW5TdGF0ZSggbm9kZSwgcnVuU3RhdGUgKTtcblxuICAgICAgICAgICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX0dSQVBIX0NIQU5HRSwgeyBub2RlOiBub2RlIH0gKTtcbiAgICAgICAgICB9KVxuICAgICAgfVxuICAgIH0gKTtcbiAgfVxuXG4gIGdldCBncmFwaCgpOiBHcmFwaCB7XG4gICAgcmV0dXJuIHRoaXMuX2dyYXBoO1xuICB9XG5cbiAgLyoqXG4gICogTG9hZCBhbGwgY29tcG9uZW50c1xuICAqL1xuICBsb2FkQ29tcG9uZW50cygpOiBQcm9taXNlPHZvaWQ+XG4gIHtcbiAgICBsZXQgbWUgPSB0aGlzO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogUnVuU3RhdGUuTE9BRElORyB9ICk7XG5cbiAgICByZXR1cm4gdGhpcy5fZ3JhcGgubG9hZENvbXBvbmVudCggdGhpcy5fZmFjdG9yeSApLnRoZW4oICgpPT4ge1xuICAgICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogUnVuU3RhdGUuTE9BREVEIH0gKTtcbiAgICB9KTtcbiAgfVxuXG4gIGluaXRpYWxpemUoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUkVBRFkgKTtcbiAgfVxuXG4gIHRlYXJkb3duKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLkxPQURFRCApO1xuICB9XG5cbiAgc3RhdGljIGluU3RhdGUoIHN0YXRlczogUnVuU3RhdGVbXSwgcnVuU3RhdGU6IFJ1blN0YXRlICk6IGJvb2xlYW4ge1xuICAgIHJldHVybiBuZXcgU2V0PFJ1blN0YXRlPiggc3RhdGVzICkuaGFzKCBydW5TdGF0ZSApO1xuICB9XG5cbiAgLyoqXG4gICogQWx0ZXIgcnVuLXN0YXRlIG9mIGEgTm9kZSAtIExPQURFRCwgUkVBRFksIFJVTk5JTkcgb3IgUEFVU0VELlxuICAqIFRyaWdnZXJzIFNldHVwIG9yIFRlYXJkb3duIGlmIHRyYW5zaXRpb25pbmcgYmV0d2VlbiBSRUFEWSBhbmQgTE9BREVEXG4gICogV2lyZXVwIGEgZ3JhcGgsIGNyZWF0aW5nIENoYW5uZWwgYmV0d2VlbiBsaW5rZWQgTm9kZXNcbiAgKiBBY3RzIHJlY3Vyc2l2ZWx5LCB3aXJpbmcgdXAgYW55IHN1Yi1ncmFwaHNcbiAgKi9cbiAgcHJpdmF0ZSBzdGF0aWMgc2V0UnVuU3RhdGUoIG5vZGU6IE5vZGUsIHJ1blN0YXRlOiBSdW5TdGF0ZSApXG4gIHtcbiAgICBsZXQgY3R4ID0gbm9kZS5jb250ZXh0O1xuICAgIGxldCBjdXJyZW50U3RhdGUgPSBjdHgucnVuU3RhdGU7XG5cbiAgICBpZiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApXG4gICAge1xuICAgICAgLy8gMS4gUHJlcHJvY2Vzc1xuICAgICAgLy8gICAgYS4gSGFuZGxlIHRlYXJkb3duXG4gICAgICAvLyAgICBiLiBQcm9wYWdhdGUgc3RhdGUgY2hhbmdlIHRvIHN1Ym5ldHNcbiAgICAgIGxldCBub2RlczogTWFwPHN0cmluZywgTm9kZT4gPSBub2RlLm5vZGVzO1xuXG4gICAgICBpZiAoICggcnVuU3RhdGUgPT0gUnVuU3RhdGUuTE9BREVEICkgJiYgKCBjdXJyZW50U3RhdGUgPj0gUnVuU3RhdGUuUkVBRFkgKSApIHtcbiAgICAgICAgLy8gdGVhcmluZyBkb3duIC4uIHVubGluayBncmFwaCBmaXJzdFxuICAgICAgICBsZXQgbGlua3M6IE1hcDxzdHJpbmcsIExpbms+ID0gbm9kZS5saW5rcztcblxuICAgICAgICAvLyB1bndpcmUgKGRlYWN0aXZhdGUgYW5kIGRlc3Ryb3kgKSBDaGFubmVscyBiZXR3ZWVuIGxpbmtlZCBub2Rlc1xuICAgICAgICBsaW5rcy5mb3JFYWNoKCAoIGxpbmsgKSA9PlxuICAgICAgICB7XG4gICAgICAgICAgTmV0d29yay51bndpcmVMaW5rKCBsaW5rICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH1cblxuICAgICAgLy8gUHJvcGFnYXRlIHN0YXRlIGNoYW5nZSB0byBzdWItbmV0cyBmaXJzdFxuICAgICAgbm9kZXMuZm9yRWFjaCggZnVuY3Rpb24oIHN1Yk5vZGUgKVxuICAgICAge1xuICAgICAgICBOZXR3b3JrLnNldFJ1blN0YXRlKCBzdWJOb2RlLCBydW5TdGF0ZSApO1xuICAgICAgfSApO1xuXG4gICAgICAvLyAyLiBDaGFuZ2Ugc3RhdGUgLi4uXG4gICAgICBjdHguc2V0UnVuU3RhdGUoIHJ1blN0YXRlICk7XG5cbiAgICAgIC8vIDMuIFBvc3Rwcm9jZXNzXG4gICAgICAvLyAgICBhLiBIYW5kbGUgc2V0dXBcbiAgICAgIGlmICggKCBydW5TdGF0ZSA9PSBSdW5TdGF0ZS5SRUFEWSApICYmICggY3VycmVudFN0YXRlID49IFJ1blN0YXRlLkxPQURFRCApICkge1xuXG4gICAgICAgIC8vIHNldHRpbmcgdXAgLi4gbGlua3VwIGdyYXBoIGZpcnN0XG4gICAgICAgIGxldCBsaW5rczogTWFwPHN0cmluZywgTGluaz4gPSBub2RlLmxpbmtzO1xuICAgICAgICAvLyB0cmVhdCBncmFwaCByZWN1cnNpdmVseVxuXG4gICAgICAgIC8vIDIuIHdpcmV1cCAoY3JlYXRlIGFuZCBhY3RpdmF0ZSkgYSBDaGFubmVsIGJldHdlZW4gbGlua2VkIG5vZGVzXG4gICAgICAgIGxpbmtzLmZvckVhY2goICggbGluayApID0+XG4gICAgICAgIHtcbiAgICAgICAgICBOZXR3b3JrLndpcmVMaW5rKCBsaW5rICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgLy8gQ2hhbmdlIHN0YXRlIC4uLlxuICAgICAgY3R4LnNldFJ1blN0YXRlKCBydW5TdGF0ZSApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAqIFVud2lyZSBhIGxpbmssIHJlbW92aW5nIHRoZSBDaGFubmVsIGJldHdlZW4gdGhlIGxpbmtlZCBOb2Rlc1xuICAqL1xuICBwcml2YXRlIHN0YXRpYyB1bndpcmVMaW5rKCBsaW5rOiBMaW5rIClcbiAge1xuICAgIC8vIGdldCBsaW5rZWQgbm9kZXMgKExpbmsgZmluZHMgTm9kZXMgaW4gcGFyZW50IEdyYXBoKVxuICAgIGxldCBmcm9tTm9kZSA9IGxpbmsuZnJvbU5vZGU7XG4gICAgbGV0IHRvTm9kZSA9IGxpbmsudG9Ob2RlO1xuXG4gICAgbGV0IGNoYW46IENoYW5uZWwgPSBsaW5rLmRpc2Nvbm5lY3QoKTtcblxuICAgIGlmICggY2hhbiApXG4gICAgICBjaGFuLmRlYWN0aXZhdGUoKTtcbiAgfVxuXG4gIC8qKlxuICAqIFdpcmV1cCBhIGxpbmssIGNyZWF0aW5nIENoYW5uZWwgYmV0d2VlbiB0aGUgbGlua2VkIE5vZGVzXG4gICovXG4gIHByaXZhdGUgc3RhdGljIHdpcmVMaW5rKCBsaW5rOiBMaW5rIClcbiAge1xuICAgIC8vIGdldCBsaW5rZWQgbm9kZXMgKExpbmsgZmluZHMgTm9kZXMgaW4gcGFyZW50IEdyYXBoKVxuICAgIGxldCBmcm9tTm9kZSA9IGxpbmsuZnJvbU5vZGU7XG4gICAgbGV0IHRvTm9kZSA9IGxpbmsudG9Ob2RlO1xuXG4gICAgLy9kZWJ1Z01lc3NhZ2UoIFwiTGluayhcIitsaW5rLmlkK1wiKTogXCIgKyBsaW5rLmZyb20gKyBcIiAtPiBcIiArIGxpbmsudG8gKyBcIiBwcm90bz1cIitsaW5rLnByb3RvY29sICk7XG5cbiAgICBsZXQgY2hhbm5lbCA9IG5ldyBDaGFubmVsKCk7XG5cbiAgICBsaW5rLmNvbm5lY3QoIGNoYW5uZWwgKTtcblxuICAgIGNoYW5uZWwuYWN0aXZhdGUoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXRSdW5TdGF0ZSggcnVuU3RhdGU6IFJ1blN0YXRlIClcbiAge1xuICAgIE5ldHdvcmsuc2V0UnVuU3RhdGUoIHRoaXMuX2dyYXBoLCBydW5TdGF0ZSApO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBOZXR3b3JrLkVWRU5UX1NUQVRFX0NIQU5HRSwgeyBzdGF0ZTogcnVuU3RhdGUgfSApO1xuICB9XG5cbiAgc3RhcnQoIGluaXRpYWxseVBhdXNlZDogYm9vbGVhbiA9IGZhbHNlICkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIGluaXRpYWxseVBhdXNlZCA/IFJ1blN0YXRlLlBBVVNFRCA6IFJ1blN0YXRlLlJVTk5JTkcgKTtcbiAgfVxuXG4gIHN0ZXAoKSB7XG4gICAgLy8gVE9ETzogU2luZ2xlLXN0ZXBcbiAgfVxuXG4gIHN0b3AoKSB7XG4gICAgdGhpcy5zZXRSdW5TdGF0ZSggUnVuU3RhdGUuUkVBRFkgKTtcbiAgfVxuXG4gIHBhdXNlKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlBBVVNFRCApO1xuICB9XG5cbiAgcmVzdW1lKCkge1xuICAgIHRoaXMuc2V0UnVuU3RhdGUoIFJ1blN0YXRlLlJVTk5JTkcgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeX0gZnJvbSAnLi4vcnVudGltZS9jb21wb25lbnQtZmFjdG9yeSc7XG5pbXBvcnQgeyBFdmVudEh1YiB9IGZyb20gJy4uL2V2ZW50LWh1Yi9ldmVudC1odWInO1xuXG5pbXBvcnQgeyBOZXR3b3JrIH0gZnJvbSAnLi9uZXR3b3JrJztcbmltcG9ydCB7IE5vZGUgfSBmcm9tICcuL25vZGUnO1xuaW1wb3J0IHsgTGluayB9IGZyb20gJy4vbGluayc7XG5pbXBvcnQgeyBQb3J0LCBQdWJsaWNQb3J0IH0gZnJvbSAnLi9wb3J0JztcblxuLyoqXG4gKiBBIEdyYXBoIGlzIGEgY29sbGVjdGlvbiBvZiBOb2RlcyBpbnRlcmNvbm5lY3RlZCB2aWEgTGlua3MuXG4gKiBBIEdyYXBoIGlzIGl0c2VsZiBhIE5vZGUsIHdob3NlIFBvcnRzIGFjdCBhcyBwdWJsaXNoZWQgRW5kUG9pbnRzLCB0byB0aGUgR3JhcGguXG4gKi9cbmV4cG9ydCBjbGFzcyBHcmFwaCBleHRlbmRzIE5vZGVcbntcbiAgc3RhdGljIEVWRU5UX0FERF9OT0RFID0gJ2dyYXBoOmFkZC1ub2RlJztcbiAgc3RhdGljIEVWRU5UX1VQRF9OT0RFID0gJ2dyYXBoOnVwZC1ub2RlJztcbiAgc3RhdGljIEVWRU5UX0RFTF9OT0RFID0gJ2dyYXBoOmRlbC1ub2RlJztcblxuICBzdGF0aWMgRVZFTlRfQUREX0xJTksgPSAnZ3JhcGg6YWRkLWxpbmsnO1xuICBzdGF0aWMgRVZFTlRfVVBEX0xJTksgPSAnZ3JhcGg6dXBkLWxpbmsnO1xuICBzdGF0aWMgRVZFTlRfREVMX0xJTksgPSAnZ3JhcGg6ZGVsLWxpbmsnO1xuXG4gIC8qKlxuICAqIE5vZGVzIGluIHRoaXMgZ3JhcGguIEVhY2ggbm9kZSBtYXkgYmU6XG4gICogICAxLiBBIENvbXBvbmVudFxuICAqICAgMi4gQSBzdWItZ3JhcGhcbiAgKi9cbiAgcHJvdGVjdGVkIF9ub2RlczogTWFwPHN0cmluZywgTm9kZT47XG5cbiAgLy8gTGlua3MgaW4gdGhpcyBncmFwaC4gRWFjaCBub2RlIG1heSBiZTpcbiAgcHJvdGVjdGVkIF9saW5rczogTWFwPHN0cmluZywgTGluaz47XG5cbiAgLy8gUHVibGljIFBvcnRzIGluIHRoaXMgZ3JhcGguIEluaGVyaXRlZCBmcm9tIE5vZGVcbiAgLy8gcHJpdmF0ZSBQb3J0cztcbiAgY29uc3RydWN0b3IoIG93bmVyOiBHcmFwaCwgYXR0cmlidXRlczogYW55ID0ge30gKVxuICB7XG4gICAgc3VwZXIoIG93bmVyLCBhdHRyaWJ1dGVzICk7XG5cbiAgICB0aGlzLmluaXRGcm9tT2JqZWN0KCBhdHRyaWJ1dGVzICk7XG4gIH1cblxuICBpbml0RnJvbVN0cmluZygganNvblN0cmluZzogc3RyaW5nIClcbiAge1xuICAgIHRoaXMuaW5pdEZyb21PYmplY3QoIEpTT04ucGFyc2UoIGpzb25TdHJpbmcgKSApO1xuICB9XG5cbiAgaW5pdEZyb21PYmplY3QoIGF0dHJpYnV0ZXM6IGFueSApIHtcblxuICAgIHRoaXMuaWQgPSBhdHRyaWJ1dGVzLmlkIHx8IFwiJGdyYXBoXCI7XG5cbiAgICB0aGlzLl9ub2RlcyA9IG5ldyBNYXA8c3RyaW5nLCBOb2RlPigpO1xuICAgIHRoaXMuX2xpbmtzID0gbmV3IE1hcDxzdHJpbmcsIExpbms+KCk7XG5cbiAgICBPYmplY3Qua2V5cyggYXR0cmlidXRlcy5ub2RlcyB8fCB7fSApLmZvckVhY2goIChpZCkgPT4ge1xuICAgICAgdGhpcy5hZGROb2RlKCBpZCwgYXR0cmlidXRlcy5ub2Rlc1sgaWQgXSApO1xuICAgIH0pO1xuXG4gICAgT2JqZWN0LmtleXMoIGF0dHJpYnV0ZXMubGlua3MgfHwge30gKS5mb3JFYWNoKCAoaWQpID0+IHtcbiAgICAgIHRoaXMuYWRkTGluayggaWQsIGF0dHJpYnV0ZXMubGlua3NbIGlkIF0gKTtcbiAgICB9KTtcbiAgfVxuXG4gIHRvT2JqZWN0KCBvcHRzOiBhbnkgKTogT2JqZWN0XG4gIHtcbiAgICB2YXIgZ3JhcGggPSBzdXBlci50b09iamVjdCgpO1xuXG4gICAgbGV0IG5vZGVzID0gZ3JhcGhbIFwibm9kZXNcIiBdID0ge307XG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbi8vICAgICAgaWYgKCBub2RlICE9IHRoaXMgKVxuICAgICAgICBub2Rlc1sgaWQgXSA9IG5vZGUudG9PYmplY3QoKTtcbiAgICB9KTtcblxuICAgIGxldCBsaW5rcyA9IGdyYXBoWyBcImxpbmtzXCIgXSA9IHt9O1xuICAgIHRoaXMuX2xpbmtzLmZvckVhY2goICggbGluaywgaWQgKSA9PiB7XG4gICAgICBsaW5rc1sgaWQgXSA9IGxpbmsudG9PYmplY3QoKTtcbiAgICB9KTtcblxuICAgIHJldHVybiBncmFwaDtcbiAgfVxuXG4gIGxvYWRDb21wb25lbnQoIGZhY3Rvcnk6IENvbXBvbmVudEZhY3RvcnkgKTogUHJvbWlzZTx2b2lkPlxuICB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPHZvaWQ+KCAocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgcGVuZGluZ0NvdW50ID0gMDtcblxuICAgICAgbGV0IG5vZGVzID0gbmV3IE1hcDxzdHJpbmcsIE5vZGU+KCB0aGlzLl9ub2RlcyApO1xuICAgICAgbm9kZXMuc2V0KCAnJGdyYXBoJywgdGhpcyApO1xuXG4gICAgICBub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgICBsZXQgZG9uZTogUHJvbWlzZTx2b2lkPjtcblxuICAgICAgICBwZW5kaW5nQ291bnQrKztcblxuICAgICAgICBpZiAoIG5vZGUgPT0gdGhpcyApIHtcbiAgICAgICAgICBkb25lID0gc3VwZXIubG9hZENvbXBvbmVudCggZmFjdG9yeSApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIGRvbmUgPSBub2RlLmxvYWRDb21wb25lbnQoIGZhY3RvcnkgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGRvbmUudGhlbiggKCkgPT4ge1xuICAgICAgICAgIC0tcGVuZGluZ0NvdW50O1xuICAgICAgICAgIGlmICggcGVuZGluZ0NvdW50ID09IDAgKVxuICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goICggcmVhc29uICkgPT4ge1xuICAgICAgICAgIHJlamVjdCggcmVhc29uICk7XG4gICAgICAgIH0gKTtcbiAgICAgIH0gKTtcbiAgICB9ICk7XG4gIH1cblxuICBwdWJsaWMgZ2V0IG5vZGVzKCk6IE1hcDxzdHJpbmcsIE5vZGU+XG4gIHtcbiAgICByZXR1cm4gdGhpcy5fbm9kZXM7XG4gIH1cblxuLyogIHB1YmxpYyBnZXRBbGxOb2RlcygpOiBOb2RlW11cbiAge1xuICAgIGxldCBub2RlczogTm9kZVtdID0gW107XG5cbiAgICB0aGlzLl9ub2Rlcy5mb3JFYWNoKCAoIG5vZGUsIGlkICkgPT4ge1xuICAgICAgLy8gRG9uJ3QgcmVjdXJzZSBvbiBncmFwaCdzIHBzZXVkby1ub2RlXG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIG5vZGVzID0gbm9kZXMuY29uY2F0KCBub2RlLmdldEFsbE5vZGVzKCkgKTtcblxuICAgICAgbm9kZXMucHVzaCggbm9kZSApO1xuICAgIH0gKTtcblxuICAgIHJldHVybiBub2RlcztcbiAgfSovXG5cbiAgcHVibGljIGdldCBsaW5rcygpOiBNYXA8c3RyaW5nLCBMaW5rPlxuICB7XG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzO1xuICB9XG5cbi8qICBwdWJsaWMgZ2V0QWxsTGlua3MoKTogTGlua1tdXG4gIHtcbiAgICBsZXQgbGlua3M6IExpbmtbXSA9IFtdO1xuXG4gICAgdGhpcy5fbm9kZXMuZm9yRWFjaCggKCBub2RlLCBpZCApID0+IHtcbiAgICAgIGlmICggKCBub2RlICE9IHRoaXMgKSAmJiAoIG5vZGUgaW5zdGFuY2VvZiBHcmFwaCApIClcbiAgICAgICAgbGlua3MgPSBsaW5rcy5jb25jYXQoIG5vZGUuZ2V0QWxsTGlua3MoKSApO1xuICAgIH0gKVxuXG4gICAgdGhpcy5fbGlua3MuZm9yRWFjaCggKCBsaW5rLCBpZCApID0+IHtcbiAgICAgIGxpbmtzLnB1c2goIGxpbmsgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gbGlua3M7XG4gIH0qL1xuXG4vKiAgcHVibGljIGdldEFsbFBvcnRzKCk6IFBvcnRbXVxuICB7XG4gICAgbGV0IHBvcnRzOiBQb3J0W10gPSBzdXBlci5nZXRQb3J0QXJyYXkoKTtcblxuICAgIHRoaXMuX25vZGVzLmZvckVhY2goICggbm9kZSwgaWQgKSA9PiB7XG4gICAgICBpZiAoICggbm9kZSAhPSB0aGlzICkgJiYgKCBub2RlIGluc3RhbmNlb2YgR3JhcGggKSApXG4gICAgICAgIHBvcnRzID0gcG9ydHMuY29uY2F0KCBub2RlLmdldEFsbFBvcnRzKCkgKTtcbiAgICAgIGVsc2VcbiAgICAgICAgcG9ydHMgPSBwb3J0cy5jb25jYXQoIG5vZGUuZ2V0UG9ydEFycmF5KCkgKTtcbiAgICB9ICk7XG5cbiAgICByZXR1cm4gcG9ydHM7XG4gIH0qL1xuXG4gIHB1YmxpYyBnZXROb2RlQnlJRCggaWQ6IHN0cmluZyApOiBOb2RlXG4gIHtcbiAgICBpZiAoIGlkID09ICckZ3JhcGgnIClcbiAgICAgIHJldHVybiB0aGlzO1xuXG4gICAgcmV0dXJuIHRoaXMuX25vZGVzLmdldCggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBhZGROb2RlKCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzPzoge30gKTogTm9kZSB7XG5cbiAgICBsZXQgbm9kZSA9IG5ldyBOb2RlKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG5cbiAgICBub2RlLmlkID0gaWQ7XG5cbiAgICB0aGlzLl9ub2Rlcy5zZXQoIGlkLCBub2RlICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0FERF9OT0RFLCB7IG5vZGU6IG5vZGUgfSApO1xuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICBwdWJsaWMgcmVuYW1lTm9kZSggaWQ6IHN0cmluZywgbmV3SUQ6IHN0cmluZyApIHtcblxuICAgIGxldCBub2RlID0gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuXG4gICAgaWYgKCBpZCAhPSBuZXdJRCApXG4gICAge1xuICAgICAgbGV0IGV2ZW50RGF0YSA9IHsgbm9kZTogbm9kZSwgYXR0cnM6IHsgaWQ6IG5vZGUuaWQgfSB9O1xuXG4gICAgICB0aGlzLl9ub2Rlcy5kZWxldGUoIGlkICk7XG5cbiAgICAgIG5vZGUuaWQgPSBuZXdJRDtcblxuICAgICAgdGhpcy5fbm9kZXMuc2V0KCBuZXdJRCwgbm9kZSApO1xuXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX1VQRF9OT0RFLCBldmVudERhdGEgKTtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgcmVtb3ZlTm9kZSggaWQ6IHN0cmluZyApOiBib29sZWFuIHtcblxuICAgIGxldCBub2RlID0gdGhpcy5fbm9kZXMuZ2V0KCBpZCApO1xuICAgIGlmICggbm9kZSApXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0RFTF9OT0RFLCB7IG5vZGU6IG5vZGUgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX25vZGVzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBnZXRMaW5rQnlJRCggaWQ6IHN0cmluZyApOiBMaW5rIHtcblxuICAgIHJldHVybiB0aGlzLl9saW5rc1sgaWQgXTtcbiAgfVxuXG4gIHB1YmxpYyBhZGRMaW5rKCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzPzoge30gKTogTGluayB7XG5cbiAgICBsZXQgbGluayA9IG5ldyBMaW5rKCB0aGlzLCBhdHRyaWJ1dGVzICk7XG5cbiAgICBsaW5rLmlkID0gaWQ7XG5cbiAgICB0aGlzLl9saW5rcy5zZXQoIGlkLCBsaW5rICk7XG5cbiAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0FERF9MSU5LLCB7IGxpbms6IGxpbmsgfSApO1xuXG4gICAgcmV0dXJuIGxpbms7XG4gIH1cblxuICBwdWJsaWMgcmVuYW1lTGluayggaWQ6IHN0cmluZywgbmV3SUQ6IHN0cmluZyApIHtcblxuICAgIGxldCBsaW5rID0gdGhpcy5fbGlua3MuZ2V0KCBpZCApO1xuXG4gICAgdGhpcy5fbGlua3MuZGVsZXRlKCBpZCApO1xuXG4gICAgbGV0IGV2ZW50RGF0YSA9IHsgbGluazogbGluaywgYXR0cnM6IHsgaWQ6IGxpbmsuaWQgfSB9O1xuXG4gICAgbGluay5pZCA9IG5ld0lEO1xuXG4gICAgdGhpcy5wdWJsaXNoKCBHcmFwaC5FVkVOVF9VUERfTk9ERSwgZXZlbnREYXRhICk7XG5cbiAgICB0aGlzLl9saW5rcy5zZXQoIG5ld0lELCBsaW5rICk7XG4gIH1cblxuICBwdWJsaWMgcmVtb3ZlTGluayggaWQ6IHN0cmluZyApOiBib29sZWFuIHtcblxuICAgIGxldCBsaW5rID0gdGhpcy5fbGlua3MuZ2V0KCBpZCApO1xuICAgIGlmICggbGluayApXG4gICAgICB0aGlzLnB1Ymxpc2goIEdyYXBoLkVWRU5UX0RFTF9MSU5LLCB7IGxpbms6IGxpbmsgfSApO1xuXG4gICAgcmV0dXJuIHRoaXMuX2xpbmtzLmRlbGV0ZSggaWQgKTtcbiAgfVxuXG4gIHB1YmxpYyBhZGRQdWJsaWNQb3J0KCBpZDogc3RyaW5nLCBhdHRyaWJ1dGVzOiB7fSApOiBQdWJsaWNQb3J0XG4gIHtcbiAgICBhdHRyaWJ1dGVzW1wiaWRcIl0gPSBpZDtcblxuICAgIGxldCBwb3J0ID0gbmV3IFB1YmxpY1BvcnQoIHRoaXMsIG51bGwsIGF0dHJpYnV0ZXMgKTtcblxuICAgIHRoaXMuX3BvcnRzLnNldCggaWQsIHBvcnQgKTtcblxuICAgIHJldHVybiBwb3J0O1xuICB9XG59XG4iLCJpbXBvcnQgeyBNb2R1bGVMb2FkZXIgfSBmcm9tICcuL21vZHVsZS1sb2FkZXInO1xuaW1wb3J0IHsgQ29tcG9uZW50RmFjdG9yeSB9IGZyb20gJy4vY29tcG9uZW50LWZhY3RvcnknO1xuXG5pbXBvcnQgeyBDb250YWluZXIgfSBmcm9tICcuLi9kZXBlbmRlbmN5LWluamVjdGlvbi9jb250YWluZXInO1xuXG5cbmV4cG9ydCBjbGFzcyBTaW11bGF0aW9uRW5naW5lXG57XG4gIGxvYWRlcjogTW9kdWxlTG9hZGVyO1xuICBjb250YWluZXI6IENvbnRhaW5lcjtcblxuICAvKipcbiAgKiBDcmVhdGVzIGFuIGluc3RhbmNlIG9mIFNpbXVsYXRpb25FbmdpbmUuXG4gICogQHBhcmFtIGxvYWRlciBUaGUgbW9kdWxlIGxvYWRlci5cbiAgKiBAcGFyYW0gY29udGFpbmVyIFRoZSByb290IERJIGNvbnRhaW5lciBmb3IgdGhlIHNpbXVsYXRpb24uXG4gICovXG4gIGNvbnN0cnVjdG9yKCBsb2FkZXI6IE1vZHVsZUxvYWRlciwgY29udGFpbmVyOiBDb250YWluZXIgKSB7XG4gICAgdGhpcy5sb2FkZXIgPSBsb2FkZXI7XG4gICAgdGhpcy5jb250YWluZXIgPSBjb250YWluZXI7XG4gIH1cblxuXG4gIC8qKlxuICAqIFJldHVybiBhIENvbXBvbmVudEZhY3RvcnkgZmFjYWRlXG4gICovXG4gIGdldENvbXBvbmVudEZhY3RvcnkoKTogQ29tcG9uZW50RmFjdG9yeSB7XG4gICAgcmV0dXJuIG5ldyBDb21wb25lbnRGYWN0b3J5KCB0aGlzLmNvbnRhaW5lciwgdGhpcy5sb2FkZXIgKTtcbiAgfVxuXG59XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=
