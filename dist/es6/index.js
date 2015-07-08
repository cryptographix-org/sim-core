export class Key {
    constructor(id, attributes) {
        this.id = id;
        this.keyComponents = attributes;
    }
    getComponent(componentID) {
        return this.keyComponents[componentID];
    }
    setComponent(componentID, value) {
        this.keyComponents[componentID] = value;
    }
}


export class PublicKey extends Key {
}

var BN = forge.jsbn.BigInteger;
export class CryptographicServiceProvider {
    constructor() {
    }
    makePublicKey(m, e) {
        let mod = new forge.jsbn.BigInteger(m, 16);
        let exp = new forge.jsbn.BigInteger(e, 16);
        let pk = forge.rsa.setPublicKey(mod, exp);
        console.log(pk.n);
        console.log(pk.e);
        return pk;
    }
    decrypt(cg, pk) {
        //var bb = new forge.util.ByteBuffer( cg, 16 );
        var xx = pk.encrypt(cg, "RAW");
        return xx;
    }
}
CryptographicServiceProvider.BN = forge.jsbn.BigInteger;

export class ByteArray {
    constructor(bytes, opt) {
        if (bytes instanceof ByteArray)
            this.byteArray = bytes.byteArray;
        else if (bytes instanceof Array)
            this.byteArray = new Uint8Array(bytes);
        else if (typeof bytes == "string") {
            var str = bytes.replace(/ /g, "");
            var len = str.length / 2;
            this.byteArray = new Uint8Array(len);
            for (var ii = 0, jj = 0; ii < len; ++ii, jj += 2)
                this.byteArray[ii] = parseInt(str.substring(jj, jj + 2), 16);
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
