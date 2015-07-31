
'use strict';
class HexCodec {
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
class Base64Codec {
    static decode(b64) {
        var i, j, l, tmp, placeHolders, arr;
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
        var len = b64.length;
        placeHolders = b64.charAt(len - 2) === '=' ? 2 : b64.charAt(len - 1) === '=' ? 1 : 0;
        arr = new Uint8Array(b64.length * 3 / 4 - placeHolders);
        l = placeHolders > 0 ? b64.length - 4 : b64.length;
        var L = 0;
        function push(v) {
            arr[L++] = v;
        }
        for (i = 0, j = 0; i < l; i += 4, j += 3) {
            tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3));
            push((tmp & 0xFF0000) >> 16);
            push((tmp & 0xFF00) >> 8);
            push(tmp & 0xFF);
        }
        if (placeHolders === 2) {
            tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4);
            push(tmp & 0xFF);
        }
        else if (placeHolders === 1) {
            tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2);
            push((tmp >> 8) & 0xFF);
            push(tmp & 0xFF);
        }
        return arr;
    }
    static encode(uint8) {
        var i;
        var extraBytes = uint8.length % 3;
        var output = '';
        var temp, length;
        const lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        function encode(num) {
            return lookup.charAt(num);
        }
        function tripletToBase64(num) {
            return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F);
        }
        for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
            temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
            output += tripletToBase64(temp);
        }
        switch (extraBytes) {
            case 1:
                temp = uint8[uint8.length - 1];
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
    constructor(bytes, opt) {
        if (bytes instanceof ArrayBuffer)
            this.byteArray = new Uint8Array(bytes);
        else if (bytes instanceof ByteArray)
            this.byteArray = bytes.byteArray;
        else if (bytes instanceof Array)
            this.byteArray = new Uint8Array(bytes);
        else if (typeof bytes == "string") {
            if (opt.format && opt.format.toLowerCase() == 'base64') {
                this.byteArray = Base64Codec.decode(bytes);
            }
            else if (opt.format && opt.format.toLowerCase() == 'hex') {
                this.byteArray = HexCodec.decode(bytes);
            }
            else {
                this.byteArray = new Uint8Array(bytes);
            }
        }
        else if (bytes instanceof Uint8Array)
            this.byteArray = bytes;
        this.length = (bytes) ? this.byteArray.length : 0;
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
    bytes(offset, count) {
        return new ByteArray(this.byteArray.subarray(offset, offset + count));
    }
    toString(opt) {
    }
}

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

export class KindHelper {
    init(kindName, description) {
        this.kindInfo = {
            title: kindName,
            description: description,
            type: "object",
            properties: {}
        };
        return this;
    }
    field(name, description, dataType, opts) {
        this.kindInfo.properties[name] = {
            description: description,
            type: dataType
        };
        return this;
    }
    seal() {
        let ki = this.kindInfo;
        this.kindInfo = new KindInfo();
        return ki;
    }
}
export class KindInfo {
}
KindInfo.$kindHelper = new KindHelper();

export class Message {
    constructor(header, payload) {
        this.header = header;
        this.payload = payload;
    }
    getHeader() {
        return this.header;
    }
    getPayload() {
        return this.payload;
    }
}

export var Direction;
(function (Direction) {
    Direction[Direction["IN"] = 0] = "IN";
    Direction[Direction["OUT"] = 1] = "OUT";
    Direction[Direction["INOUT"] = 2] = "INOUT";
})(Direction || (Direction = {}));
;
export class EndPoint {
    constructor(direction) {
        this.direction = direction;
        this.channel = null;
        this.eventListeners = [];
        this.messageListeners = [];
    }
    shutdown() {
        this.channel = null;
        this.eventListeners = [];
        this.messageListeners = [];
    }
    connect(channel) {
        function triggerEventOnListener(fromPoint, event) {
            this.eventListeners.forEach(eventListener => {
                eventListener(fromPoint, event);
            });
        }
        ;
        function sendMessageToListener(fromPoint, message) {
            this.messageListeners.forEach(messageListener => {
                messageListener(fromPoint, message);
            });
        }
        this.channel = channel;
        channel.addEndPoint(this, triggerEventOnListener, sendMessageToListener);
    }
    disconnect() {
        if (this.channel)
            this.channel.removeEndPoint(this);
        this.channel = null;
    }
    get isConnected() {
        return (this.channel && this.channel.isConnected);
    }
    triggerEvent(event) {
        if (!this.isConnected)
            return;
        this.channel.triggerEvent(this, event);
    }
    sendMessage(message) {
        if (!this.isConnected)
            return;
        this.channel.sendMessage(this, message);
    }
    onEvent(eventListener) {
        this.eventListeners.push(eventListener);
    }
    onMessage(messageListener) {
        this.messageListeners.push(messageListener);
    }
}



export class EndPointEntry {
}
export class Channel {
    constructor() {
        this.connected = false;
        this.endPointRegistry = [];
        this.taskScheduler = null;
    }
    get isConnected() {
        return this.connected;
    }
    connect() {
        this.taskScheduler = new TaskScheduler();
        this.connected = true;
    }
    disconnect() {
        this.taskScheduler = null;
        this.connected = false;
    }
    addEndPoint(endPoint, eventListener, messageListener) {
        let regEntry = {
            endPoint: endPoint,
            direction: endPoint.direction,
            eventListener: eventListener.bind(endPoint),
            messageListener: messageListener.bind(endPoint),
        };
        this.endPointRegistry.push(regEntry);
    }
    removeEndPoint(endPoint) {
        for (let idx in this.endPointRegistry) {
            let regEntry = this.endPointRegistry[idx];
            if (endPoint == regEntry.endPoint)
                delete this.endPointRegistry[idx];
        }
    }
    getEndPoints() {
        var endPoints = [];
        this.endPointRegistry.forEach(regEntry => {
            endPoints.push(regEntry.endPoint);
        });
        return endPoints;
    }
    triggerEvent(origin, event) {
        if (!this.connected)
            return;
        this.endPointRegistry.forEach(regEntry => {
            if (origin != regEntry.endPoint) {
                if (regEntry.eventListener && (regEntry.direction != Direction.OUT)) {
                    this.taskScheduler.queueTask(() => {
                        regEntry.eventListener(origin, event);
                    });
                }
            }
        });
    }
    sendMessage(origin, message) {
        if (!this.connected)
            return;
        this.endPointRegistry.forEach(regEntry => {
            if (origin != regEntry.endPoint) {
                if (regEntry.messageListener && (regEntry.direction != Direction.OUT)) {
                    this.taskScheduler.queueTask(() => {
                        regEntry.messageListener(origin, message);
                    });
                }
            }
        });
    }
}



export class xComponent {
    onCreate(initialData) {
    }
    onDestroy() {
    }
    onStart(endPoints) {
    }
    onPause() {
    }
    onResume() {
    }
    onStop() {
    }
}
export class ComponentRegistry {
    constructor() {
        this.components = [];
    }
    setComponent(name, comp) {
        this.components[name] = comp;
    }
    getComponent(name) {
        return this.components[name];
    }
    loadComponent(name) {
        return new Promise((resolve, reject) => {
            resolve(this.getComponent[name]);
        });
    }
    getComponentInstance(name, initialData) {
        let createComponent = function (componentType) {
            let newInstance = null;
            let injects = [];
            if (componentType.$inject instanceof Array)
                injects = componentType.$inject;
            else if (typeof componentType.$inject == "function")
                injects = componentType.$inject();
            if (injects && injects.length > 0)
                ;
            newInstance = new componentType();
            if (newInstance.onCreate)
                newInstance.onCreate(initialData);
            return newInstance;
        };
        let componentType = this.getComponent(name);
        if (componentType) {
            return new Promise((resolve, reject) => {
                resolve(createComponent(componentType));
            });
        }
        return new Promise((resolve, reject) => {
            this.loadComponent(name)
                .then((componentType) => {
                resolve(createComponent(componentType));
            });
        });
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


export class CryptographicServiceProvider {
    constructor() {
        this.crypto = window.crypto.subtle;
        if (!this.crypto && msrcrypto)
            this.crypto = msrcrypto;
    }
    decrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            this.crypto.decrypt(algorithm, key.innerKey, data.byteArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    digest(algorithm, data) {
        return new Promise((resolve, reject) => {
            this.crypto.digest(algorithm, data.byteArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    encrypt(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            this.crypto.encrypt(algorithm, key.innerKey, data.byteArray)
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
            this.crypto.importKey(format, keyData.byteArray, algorithm, extractable, keyUsages)
                .then((res) => { resolve(res); })
                .catch((err) => { reject(err); });
        });
    }
    sign(algorithm, key, data) {
        return new Promise((resolve, reject) => {
            this.crypto.sign(algorithm, key.innerKey, data.byteArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
    verify(algorithm, key, signature, data) {
        return new Promise((resolve, reject) => {
            this.crypto.verify(algorithm, key.innerKey, signature.byteArray, data.byteArray)
                .then((res) => { resolve(new ByteArray(res)); })
                .catch((err) => { reject(err); });
        });
    }
}

export class SimulationEngine {
}


export class Port extends EndPoint {
    constructor(owner, attributes) {
        super(attributes.direction || Direction.INOUT);
        this.view = attributes.view || { x: 100, y: 100 };
        this._protocolID = attributes["protocol"] || "any";
        this.ownerNode = owner;
    }
    toObject(opts) {
        var port = {};
        return port;
    }
    get id() {
        return this._id;
    }
    set id(id) {
        this._id = id;
    }
    get node() {
        return this.ownerNode;
    }
    get protocol() {
        return this._protocolID;
    }
}
export class PublicPort extends Port {
    constructor(owner, attributes) {
        super(owner, attributes);
        let proxyDirection = (this.direction == Direction.IN)
            ? Direction.OUT
            : (this.direction == Direction.OUT)
                ? Direction.IN
                : Direction.INOUT;
        this.proxyEndPoint = new EndPoint(proxyDirection);
        this.proxyEndPoint.onEvent((from, evt) => {
            this.triggerEvent(evt);
        });
        this.proxyEndPoint.onMessage((from, message) => {
            this.sendMessage(message);
        });
        this.onEvent((from, evt) => {
            this.proxyEndPoint.triggerEvent(evt);
        });
        this.onMessage((from, message) => {
            this.proxyEndPoint.sendMessage(message);
        });
        this.proxyChannel = null;
    }
    connectPrivate(channel) {
        this.proxyChannel = channel;
        this.proxyEndPoint.connect(channel);
    }
    disconnectPrivate() {
        this.proxyEndPoint.disconnect();
    }
    toObject(opts) {
        var port = {};
        return port;
    }
}


export class Node {
    constructor(owner, attributes) {
        this.ownerGraph = owner;
        this.view = attributes.view || { x: 100, y: 100 };
        this.ports = {};
        this.component = null;
        this.componentName = attributes.componentName || "";
        this.setupData = attributes.setupData || {};
        Object.keys(attributes.ports || {}).forEach((id) => {
            this.addPort(id, attributes.ports[id]);
        });
    }
    toObject(opts) {
        var node = {
            id: this.id,
            ports: {},
        };
        Object.keys(this.ports).forEach((id) => {
            node.ports[id] = this.ports[id].toObject();
        });
        return node;
    }
    initializeComponent(registry) {
        let me = this;
        this.component = {};
        return new Promise((resolve, reject) => {
            if (!this.componentName || (this.componentName == ""))
                resolve();
            else
                registry.getComponentInstance(this.componentName, this.setupData)
                    .then((newInstance) => {
                    me.component = newInstance;
                    resolve();
                })
                    .catch((err) => {
                    reject(err);
                });
        });
    }
    addPort(id, attributes) {
        let port = new Port(this, attributes);
        port.id = id;
        this.ports[id] = port;
        return port;
    }
    get id() {
        return this._id;
    }
    set id(id) {
        this._id = id;
    }
    getPorts() {
        let ports = [];
        Object.keys(this.ports).forEach((id) => {
            ports.push(this.ports[id]);
        });
        return ports;
    }
    getPortByID(id) {
        return this.ports[id];
    }
    identifyPort(id, protocol) {
        var port;
        if (id)
            port = this.ports[id];
        else if (protocol) {
            Object.keys(this.ports).forEach((id) => {
                let p = this.ports[id];
                if (p.protocol == protocol)
                    port = p;
            }, this);
        }
        return port;
    }
}

export class Link {
    constructor(owner, link) {
        this.channel = null;
        this._id = "";
        this.ownerGraph = owner;
        for (let prop in Link.propertyMap) {
            this[Link.propertyMap[prop]] = link[prop];
        }
    }
    toObject(opts) {
        let link = {
            id: this._id,
            protocol: this._protocolID,
            from: this.from,
            to: this.to
        };
        return link;
    }
    set id(id) {
        this._id = id;
    }
    connect(channel) {
        var fromPort = this.fromNode.identifyPort(this.from.portID, this.protocolID);
        var toPort = this.toNode.identifyPort(this.to.portID, this.protocolID);
        this.channel = channel;
        fromPort.connect(channel);
        toPort.connect(channel);
    }
    disconnect() {
        this.channel.getEndPoints().forEach((endPoint) => {
            endPoint.disconnect();
        });
        this.channel = null;
    }
    get fromNode() {
        return this.ownerGraph.getNodeByID(this.from.nodeID);
    }
    get fromPort() {
        var node = this.fromNode;
        return (node) ? node.identifyPort(this.from.portID, this.protocolID) : undefined;
    }
    set fromPort(port) {
        this.from = {
            nodeID: port.node.id,
            portID: port.id
        };
        this._protocolID = port.protocol;
    }
    get toNode() {
        return this.ownerGraph.getNodeByID(this.to.nodeID);
    }
    get toPort() {
        var node = this.toNode;
        return (node) ? node.identifyPort(this.to.portID, this.protocolID) : undefined;
    }
    set toPort(port) {
        this.to = {
            nodeID: port.node.id,
            portID: port.id
        };
        this._protocolID = port.protocol;
    }
    get protocolID() {
        return this._protocolID;
    }
}
Link.propertyMap = {
    protocol: "_protocolID",
    from: "from",
    to: "to",
};


export class Network {
    constructor(graph, componentRegistry) {
        this.graph = graph;
        this.componentRegistry = componentRegistry;
    }
    initialize() {
        this.nodes = this.graph.getAllNodes();
        this.links = this.graph.getAllLinks();
        this.ports = this.graph.getAllPorts();
        return this.initializeGraph();
    }
    initializeGraph() {
        return this.graph.initializeComponent(this.componentRegistry);
    }
    wireupGraph(router) {
        var me = this;
        this.nodes.forEach(function (node) {
        });
        this.links.forEach((link) => {
            var fromNode = link.fromNode;
            var toNode = link.toNode;
            let channel = new Channel();
            link.connect(channel);
            channel.connect();
        });
    }
}




export class Graph extends Node {
    constructor(owner, attributes) {
        super(owner, attributes);
        this.id = attributes.id || "<graph>";
        this.nodes = {};
        this.links = {};
        this.nodes[this.id] = this;
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
        Object.keys(this.nodes).forEach((id) => {
            let node = this.nodes[id];
            if (node != this)
                nodes[id] = node.toObject();
        });
        let links = graph["links"] = {};
        Object.keys(this.links).forEach((id) => {
            links[id] = this.links[id].toObject();
        });
        return graph;
    }
    initializeComponent(registry) {
        return new Promise((resolve, reject) => {
            let pendingCount = 0;
            Object.keys(this.nodes).forEach((id) => {
                let node = this.nodes[id];
                if (node != this) {
                    pendingCount++;
                    node.initializeComponent(registry)
                        .then(() => {
                        --pendingCount;
                        if (pendingCount == 0)
                            resolve();
                    })
                        .catch((reason) => {
                        reject(reason);
                    });
                }
            });
        });
    }
    getNodes() {
        return this.nodes;
    }
    getAllNodes() {
        let nodes = [];
        Object.keys(this.nodes).forEach((id) => {
            let node = this.nodes[id];
            if ((node != this) && (node instanceof Graph))
                nodes = nodes.concat(node.getAllNodes());
            nodes.push(node);
        });
        return nodes;
    }
    getLinks() {
        return this.links;
    }
    getAllLinks() {
        let links = [];
        Object.keys(this.nodes).forEach((id) => {
            let node = this.nodes[id];
            if ((node != this) && (node instanceof Graph))
                links = links.concat(node.getAllLinks());
        });
        Object.keys(this.links).forEach((id) => {
            let link = this.links[id];
            links.push(link);
        });
        return links;
    }
    getAllPorts() {
        let ports = super.getPorts();
        Object.keys(this.nodes).forEach((id) => {
            let node = this.nodes[id];
            if ((node != this) && (node instanceof Graph))
                ports = ports.concat(node.getAllPorts());
            else
                ports = ports.concat(node.getPorts());
        });
        return ports;
    }
    getNodeByID(id) {
        return this.nodes[id];
    }
    addNode(id, attributes) {
        let node = new Node(this, attributes);
        node.id = id;
        this.nodes[id] = node;
        return node;
    }
    renameNode(id, newID) {
        let node = this.nodes[id];
        this.nodes[newID] = node;
        delete this.nodes[id];
    }
    removeNode(id) {
        delete this.nodes[id];
    }
    getLinkByID(id) {
        return this.links[id];
    }
    addLink(id, attributes) {
        let link = new Link(this, attributes);
        link.id = id;
        this.links[id] = link;
        return link;
    }
    renameLink(id, newID) {
        let link = this.links[id];
        link.id = newID;
        this.links[newID] = link;
        delete this.links[id];
    }
    removeLink(id) {
        delete this.links[id];
    }
    addPublicPort(id, attributes) {
        let port = new PublicPort(this, attributes);
        port.id = id;
        this.ports[id] = port;
        return port;
    }
}


export default class GraphTester {
    execTests() {
        let graph = {
            id: "gr",
            componentName: "g",
            ports: {
                "pxa": { direction: "inout", "type": "PublicPort" },
                "pxb": {},
            },
            nodes: {
                "n1": {
                    componentName: "a",
                    ports: {
                        "p1a": { direction: "out", },
                        "p1b": { direction: "inout", },
                        "p1x": { direction: "inout", },
                    },
                },
                "n2": {
                    componentName: "b",
                    ports: {
                        "p2a": { direction: "in", },
                        "p2b": { direction: "inout", },
                    },
                },
            },
            links: {
                "lx": {
                    from: { nodeID: "gr", portID: "pxa" },
                    to: { nodeID: "n1", portID: "p1x" },
                    protocolID: "data"
                },
                "l1": {
                    from: { nodeID: "n1", portID: "p1a" },
                    to: { nodeID: "n2", portID: "p2a" },
                    protocolID: "data"
                },
                "l2": {
                    from: { nodeID: "n1", portID: "p1b" },
                    to: { nodeID: "n2", portID: "p2b" },
                    protocolID: "data"
                },
            },
        };
        this.graph = new Graph(null, graph);
        let gr = this.graph;
        let n1 = gr.getNodeByID("n1");
        let p1x = n1.getPortByID("p1x");
        let p2a = gr.getNodeByID("n2").getPortByID("p2a");
    }
}
