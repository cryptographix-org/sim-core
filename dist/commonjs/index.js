"use strict";

exports.__esModule = true;

var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var Key = (function () {
    function Key(id, attributes) {
        _classCallCheck(this, Key);

        this.id = id;
        this.keyComponents = attributes;
    }

    Key.prototype.getComponent = function getComponent(componentID) {
        return this.keyComponents[componentID];
    };

    Key.prototype.setComponent = function setComponent(componentID, value) {
        this.keyComponents[componentID] = value;
    };

    return Key;
})();

exports.Key = Key;

var PublicKey = (function (_Key) {
    function PublicKey() {
        _classCallCheck(this, PublicKey);

        _Key.apply(this, arguments);
    }

    _inherits(PublicKey, _Key);

    return PublicKey;
})(Key);

exports.PublicKey = PublicKey;

var BN = forge.jsbn.BigInteger;

var CryptographicServiceProvider = (function () {
    function CryptographicServiceProvider() {
        _classCallCheck(this, CryptographicServiceProvider);
    }

    CryptographicServiceProvider.prototype.makePublicKey = function makePublicKey(m, e) {
        var mod = new forge.jsbn.BigInteger(m, 16);
        var exp = new forge.jsbn.BigInteger(e, 16);
        var pk = forge.rsa.setPublicKey(mod, exp);
        console.log(pk.n);
        console.log(pk.e);
        return pk;
    };

    CryptographicServiceProvider.prototype.decrypt = function decrypt(cg, pk) {
        var xx = pk.encrypt(cg, "RAW");
        return xx;
    };

    return CryptographicServiceProvider;
})();

exports.CryptographicServiceProvider = CryptographicServiceProvider;

CryptographicServiceProvider.BN = forge.jsbn.BigInteger;

var ByteArray = (function () {
    function ByteArray(bytes, opt) {
        _classCallCheck(this, ByteArray);

        if (bytes instanceof ByteArray) this.byteArray = bytes.byteArray;else if (bytes instanceof Array) this.byteArray = new Uint8Array(bytes);else if (typeof bytes == "string") {
            var str = bytes.replace(/ /g, "");
            var len = str.length / 2;
            this.byteArray = new Uint8Array(len);
            for (var ii = 0, jj = 0; ii < len; ++ii, jj += 2) this.byteArray[ii] = parseInt(str.substring(jj, jj + 2), 16);
        } else if (bytes instanceof Uint8Array) this.byteArray = bytes;
        this.length = bytes ? this.byteArray.length : 0;
    }

    ByteArray.prototype.byteAt = function byteAt(offset) {
        return this.byteArray[offset];
    };

    ByteArray.prototype.wordAt = function wordAt(offset) {
        return (this.byteArray[offset] << 8) + this.byteArray[offset + 1];
    };

    ByteArray.prototype.littleEndianWordAt = function littleEndianWordAt(offset) {
        return this.byteArray[offset] + (this.byteArray[offset + 1] << 8);
    };

    ByteArray.prototype.dwordAt = function dwordAt(offset) {
        return (this.byteArray[offset] << 24) + (this.byteArray[offset + 1] << 16) + (this.byteArray[offset + 2] << 8) + this.byteArray[offset + 3];
    };

    ByteArray.prototype.bytes = function bytes(offset, count) {
        return new ByteArray(this.byteArray.subarray(offset, offset + count));
    };

    return ByteArray;
})();

exports.ByteArray = ByteArray;

var TaskScheduler = (function () {
    function TaskScheduler() {
        _classCallCheck(this, TaskScheduler);

        this.taskQueue = [];
        var self = this;
        if (typeof TaskScheduler.BrowserMutationObserver === "function") {
            this.requestFlushTaskQueue = TaskScheduler.makeRequestFlushFromMutationObserver(function () {
                return self.flushTaskQueue();
            });
        } else {
            this.requestFlushTaskQueue = TaskScheduler.makeRequestFlushFromTimer(function () {
                return self.flushTaskQueue();
            });
        }
    }

    TaskScheduler.makeRequestFlushFromMutationObserver = function makeRequestFlushFromMutationObserver(flush) {
        var toggle = 1;
        var observer = new TaskScheduler.BrowserMutationObserver(flush);
        var node = document.createTextNode("");
        observer.observe(node, { characterData: true });
        return function requestFlush() {
            toggle = -toggle;
            node["data"] = toggle;
        };
    };

    TaskScheduler.makeRequestFlushFromTimer = function makeRequestFlushFromTimer(flush) {
        return function requestFlush() {
            var timeoutHandle = setTimeout(handleFlushTimer, 0);
            var intervalHandle = setInterval(handleFlushTimer, 50);
            function handleFlushTimer() {
                clearTimeout(timeoutHandle);
                clearInterval(intervalHandle);
                flush();
            }
        };
    };

    TaskScheduler.prototype.queueTask = function queueTask(task) {
        if (this.taskQueue.length < 1) {
            this.requestFlushTaskQueue();
        }
        this.taskQueue.push(task);
    };

    TaskScheduler.prototype.flushTaskQueue = function flushTaskQueue() {
        var queue = this.taskQueue,
            capacity = TaskScheduler.taskQueueCapacity,
            index = 0,
            task;
        while (index < queue.length) {
            task = queue[index];
            try {
                task.call();
            } catch (error) {
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
    };

    TaskScheduler.prototype.onError = function onError(error, task) {
        if ("onError" in task) {
            task.onError(error);
        } else if (TaskScheduler.hasSetImmediate) {
            setImmediate(function () {
                throw error;
            });
        } else {
            setTimeout(function () {
                throw error;
            }, 0);
        }
    };

    return TaskScheduler;
})();

exports.TaskScheduler = TaskScheduler;

TaskScheduler.BrowserMutationObserver = window["MutationObserver"] || window["WebKitMutationObserver"];
TaskScheduler.hasSetImmediate = typeof setImmediate === "function";
TaskScheduler.taskQueueCapacity = 1024;

var KindHelper = (function () {
    function KindHelper() {
        _classCallCheck(this, KindHelper);
    }

    KindHelper.prototype.init = function init(kindName, description) {
        this.kindInfo = {
            title: kindName,
            description: description,
            type: "object",
            properties: {}
        };
        return this;
    };

    KindHelper.prototype.field = function field(name, description, dataType, opts) {
        this.kindInfo.properties[name] = {
            description: description,
            type: dataType
        };
        return this;
    };

    KindHelper.prototype.seal = function seal() {
        var ki = this.kindInfo;
        this.kindInfo = new KindInfo();
        return ki;
    };

    return KindHelper;
})();

exports.KindHelper = KindHelper;

var KindInfo = function KindInfo() {
    _classCallCheck(this, KindInfo);
};

exports.KindInfo = KindInfo;

KindInfo.$kindHelper = new KindHelper();

var Message = (function () {
    function Message(header, payload) {
        _classCallCheck(this, Message);

        this.header = header;
        this.payload = payload;
    }

    Message.prototype.getHeader = function getHeader() {
        return this.header;
    };

    Message.prototype.getPayload = function getPayload() {
        return this.payload;
    };

    return Message;
})();

exports.Message = Message;
var Direction;
exports.Direction = Direction;
(function (Direction) {
    Direction[Direction["IN"] = 0] = "IN";
    Direction[Direction["OUT"] = 1] = "OUT";
    Direction[Direction["INOUT"] = 2] = "INOUT";
})(Direction || (exports.Direction = Direction = {}));
;

var EndPoint = (function () {
    function EndPoint(direction) {
        _classCallCheck(this, EndPoint);

        this.direction = direction;
        this.channel = null;
        this.eventListeners = [];
        this.messageListeners = [];
    }

    EndPoint.prototype.shutdown = function shutdown() {
        this.channel = null;
        this.eventListeners = [];
        this.messageListeners = [];
    };

    EndPoint.prototype.connect = function connect(channel) {
        function triggerEventOnListener(fromPoint, event) {
            this.eventListeners.forEach(function (eventListener) {
                eventListener(fromPoint, event);
            });
        }
        ;
        function sendMessageToListener(fromPoint, message) {
            this.messageListeners.forEach(function (messageListener) {
                messageListener(fromPoint, message);
            });
        }
        this.channel = channel;
        channel.addEndPoint(this, triggerEventOnListener, sendMessageToListener);
    };

    EndPoint.prototype.disconnect = function disconnect() {
        if (this.channel) this.channel.removeEndPoint(this);
        this.channel = null;
    };

    EndPoint.prototype.triggerEvent = function triggerEvent(event) {
        if (!this.isConnected) return;
        this.channel.triggerEvent(this, event);
    };

    EndPoint.prototype.sendMessage = function sendMessage(message) {
        if (!this.isConnected) return;
        this.channel.sendMessage(this, message);
    };

    EndPoint.prototype.onEvent = function onEvent(eventListener) {
        this.eventListeners.push(eventListener);
    };

    EndPoint.prototype.onMessage = function onMessage(messageListener) {
        this.messageListeners.push(messageListener);
    };

    _createClass(EndPoint, [{
        key: "isConnected",
        get: function get() {
            return this.channel && this.channel.isConnected;
        }
    }]);

    return EndPoint;
})();

exports.EndPoint = EndPoint;

var EndPointEntry = function EndPointEntry() {
    _classCallCheck(this, EndPointEntry);
};

exports.EndPointEntry = EndPointEntry;

var Channel = (function () {
    function Channel() {
        _classCallCheck(this, Channel);

        this.connected = false;
        this.endPointRegistry = [];
        this.taskScheduler = null;
    }

    Channel.prototype.connect = function connect() {
        this.taskScheduler = new TaskScheduler();
        this.connected = true;
    };

    Channel.prototype.disconnect = function disconnect() {
        this.taskScheduler = null;
        this.connected = false;
    };

    Channel.prototype.addEndPoint = function addEndPoint(endPoint, eventListener, messageListener) {
        var regEntry = {
            endPoint: endPoint,
            direction: endPoint.direction,
            eventListener: eventListener.bind(endPoint),
            messageListener: messageListener.bind(endPoint)
        };
        this.endPointRegistry.push(regEntry);
    };

    Channel.prototype.removeEndPoint = function removeEndPoint(endPoint) {
        for (var idx in this.endPointRegistry) {
            var regEntry = this.endPointRegistry[idx];
            if (endPoint == regEntry.endPoint) delete this.endPointRegistry[idx];
        }
    };

    Channel.prototype.getEndPoints = function getEndPoints() {
        var endPoints = [];
        this.endPointRegistry.forEach(function (regEntry) {
            endPoints.push(regEntry.endPoint);
        });
        return endPoints;
    };

    Channel.prototype.triggerEvent = function triggerEvent(origin, event) {
        var _this = this;

        if (!this.connected) return;
        this.endPointRegistry.forEach(function (regEntry) {
            if (origin != regEntry.endPoint) {
                if (regEntry.eventListener && regEntry.direction != Direction.OUT) {
                    _this.taskScheduler.queueTask(function () {
                        regEntry.eventListener(origin, event);
                    });
                }
            }
        });
    };

    Channel.prototype.sendMessage = function sendMessage(origin, message) {
        var _this2 = this;

        if (!this.connected) return;
        this.endPointRegistry.forEach(function (regEntry) {
            if (origin != regEntry.endPoint) {
                if (regEntry.messageListener && regEntry.direction != Direction.OUT) {
                    _this2.taskScheduler.queueTask(function () {
                        regEntry.messageListener(origin, message);
                    });
                }
            }
        });
    };

    _createClass(Channel, [{
        key: "isConnected",
        get: function get() {
            return this.connected;
        }
    }]);

    return Channel;
})();

exports.Channel = Channel;

var xComponent = (function () {
    function xComponent() {
        _classCallCheck(this, xComponent);
    }

    xComponent.prototype.onCreate = function onCreate(initialData) {};

    xComponent.prototype.onDestroy = function onDestroy() {};

    xComponent.prototype.onStart = function onStart(endPoints) {};

    xComponent.prototype.onPause = function onPause() {};

    xComponent.prototype.onResume = function onResume() {};

    xComponent.prototype.onStop = function onStop() {};

    return xComponent;
})();

exports.xComponent = xComponent;

var ComponentRegistry = (function () {
    function ComponentRegistry() {
        _classCallCheck(this, ComponentRegistry);

        this.components = [];
    }

    ComponentRegistry.prototype.setComponent = function setComponent(name, comp) {
        this.components[name] = comp;
    };

    ComponentRegistry.prototype.getComponent = function getComponent(name) {
        return this.components[name];
    };

    ComponentRegistry.prototype.loadComponent = function loadComponent(name) {
        var _this3 = this;

        return new Promise(function (resolve, reject) {
            resolve(_this3.getComponent[name]);
        });
    };

    ComponentRegistry.prototype.getComponentInstance = function getComponentInstance(name, initialData) {
        var _this4 = this;

        var createComponent = function createComponent(componentType) {
            var newInstance = null;
            var injects = [];
            if (componentType.$inject instanceof Array) injects = componentType.$inject;else if (typeof componentType.$inject == "function") injects = componentType.$inject();
            if (injects && injects.length > 0) ;
            newInstance = new componentType();
            if (newInstance.onCreate) newInstance.onCreate(initialData);
            return newInstance;
        };
        var componentType = this.getComponent(name);
        if (componentType) {
            return new Promise(function (resolve, reject) {
                resolve(createComponent(componentType));
            });
        }
        return new Promise(function (resolve, reject) {
            _this4.loadComponent(name).then(function (componentType) {
                resolve(createComponent(componentType));
            });
        });
    };

    return ComponentRegistry;
})();

exports.ComponentRegistry = ComponentRegistry;

var SimulationEngine = function SimulationEngine() {
    _classCallCheck(this, SimulationEngine);
};

exports.SimulationEngine = SimulationEngine;

var Port = (function (_EndPoint) {
    function Port(owner, attributes) {
        _classCallCheck(this, Port);

        _EndPoint.call(this, attributes.direction || Direction.INOUT);
        this.view = attributes.view || { x: 100, y: 100 };
        this._protocolID = attributes["protocol"] || "any";
        this.ownerNode = owner;
    }

    _inherits(Port, _EndPoint);

    Port.prototype.toObject = function toObject(opts) {
        var port = {};
        return port;
    };

    _createClass(Port, [{
        key: "id",
        get: function get() {
            return this._id;
        },
        set: function set(id) {
            this._id = id;
        }
    }, {
        key: "node",
        get: function get() {
            return this.ownerNode;
        }
    }, {
        key: "protocol",
        get: function get() {
            return this._protocolID;
        }
    }]);

    return Port;
})(EndPoint);

exports.Port = Port;

var PublicPort = (function (_Port) {
    function PublicPort(owner, attributes) {
        var _this5 = this;

        _classCallCheck(this, PublicPort);

        _Port.call(this, owner, attributes);
        var proxyDirection = this.direction == Direction.IN ? Direction.OUT : this.direction == Direction.OUT ? Direction.IN : Direction.INOUT;
        this.proxyEndPoint = new EndPoint(proxyDirection);
        this.proxyEndPoint.onEvent(function (from, evt) {
            _this5.triggerEvent(evt);
        });
        this.proxyEndPoint.onMessage(function (from, message) {
            _this5.sendMessage(message);
        });
        this.onEvent(function (from, evt) {
            _this5.proxyEndPoint.triggerEvent(evt);
        });
        this.onMessage(function (from, message) {
            _this5.proxyEndPoint.sendMessage(message);
        });
        this.proxyChannel = null;
    }

    _inherits(PublicPort, _Port);

    PublicPort.prototype.connectPrivate = function connectPrivate(channel) {
        this.proxyChannel = channel;
        this.proxyEndPoint.connect(channel);
    };

    PublicPort.prototype.disconnectPrivate = function disconnectPrivate() {
        this.proxyEndPoint.disconnect();
    };

    PublicPort.prototype.toObject = function toObject(opts) {
        var port = {};
        return port;
    };

    return PublicPort;
})(Port);

exports.PublicPort = PublicPort;

var Node = (function () {
    function Node(owner, attributes) {
        var _this6 = this;

        _classCallCheck(this, Node);

        this.ownerGraph = owner;
        this.view = attributes.view || { x: 100, y: 100 };
        this.ports = {};
        this.component = null;
        this.componentName = attributes.componentName || "";
        this.setupData = attributes.setupData || {};
        Object.keys(attributes.ports || {}).forEach(function (id) {
            _this6.addPort(id, attributes.ports[id]);
        });
    }

    Node.prototype.toObject = function toObject(opts) {
        var _this7 = this;

        var node = {
            id: this.id,
            ports: {}
        };
        Object.keys(this.ports).forEach(function (id) {
            node.ports[id] = _this7.ports[id].toObject();
        });
        return node;
    };

    Node.prototype.initializeComponent = function initializeComponent(registry) {
        var _this8 = this;

        var me = this;
        this.component = {};
        return new Promise(function (resolve, reject) {
            if (!_this8.componentName || _this8.componentName == "") resolve();else registry.getComponentInstance(_this8.componentName, _this8.setupData).then(function (newInstance) {
                me.component = newInstance;
                resolve();
            })["catch"](function (err) {
                reject(err);
            });
        });
    };

    Node.prototype.addPort = function addPort(id, attributes) {
        var port = new Port(this, attributes);
        port.id = id;
        this.ports[id] = port;
        return port;
    };

    Node.prototype.getPorts = function getPorts() {
        var _this9 = this;

        var ports = [];
        Object.keys(this.ports).forEach(function (id) {
            ports.push(_this9.ports[id]);
        });
        return ports;
    };

    Node.prototype.getPortByID = function getPortByID(id) {
        return this.ports[id];
    };

    Node.prototype.identifyPort = function identifyPort(id, protocol) {
        var _this10 = this;

        var port;
        if (id) port = this.ports[id];else if (protocol) {
            Object.keys(this.ports).forEach(function (id) {
                var p = _this10.ports[id];
                if (p.protocol == protocol) port = p;
            }, this);
        }
        return port;
    };

    _createClass(Node, [{
        key: "id",
        get: function get() {
            return this._id;
        },
        set: function set(id) {
            this._id = id;
        }
    }]);

    return Node;
})();

exports.Node = Node;

var Link = (function () {
    function Link(owner, link) {
        _classCallCheck(this, Link);

        this.channel = null;
        this._id = "";
        this.ownerGraph = owner;
        for (var prop in Link.propertyMap) {
            this[Link.propertyMap[prop]] = link[prop];
        }
    }

    Link.prototype.toObject = function toObject(opts) {
        var link = {
            id: this._id,
            protocol: this._protocolID,
            from: this.from,
            to: this.to
        };
        return link;
    };

    Link.prototype.connect = function connect(channel) {
        var fromPort = this.fromNode.identifyPort(this.from.portID, this.protocolID);
        var toPort = this.toNode.identifyPort(this.to.portID, this.protocolID);
        this.channel = channel;
        fromPort.connect(channel);
        toPort.connect(channel);
    };

    Link.prototype.disconnect = function disconnect() {
        this.channel.getEndPoints().forEach(function (endPoint) {
            endPoint.disconnect();
        });
        this.channel = null;
    };

    _createClass(Link, [{
        key: "id",
        set: function set(id) {
            this._id = id;
        }
    }, {
        key: "fromNode",
        get: function get() {
            return this.ownerGraph.getNodeByID(this.from.nodeID);
        }
    }, {
        key: "fromPort",
        get: function get() {
            var node = this.fromNode;
            return node ? node.identifyPort(this.from.portID, this.protocolID) : undefined;
        },
        set: function set(port) {
            this.from = {
                nodeID: port.node.id,
                portID: port.id
            };
            this._protocolID = port.protocol;
        }
    }, {
        key: "toNode",
        get: function get() {
            return this.ownerGraph.getNodeByID(this.to.nodeID);
        }
    }, {
        key: "toPort",
        get: function get() {
            var node = this.toNode;
            return node ? node.identifyPort(this.to.portID, this.protocolID) : undefined;
        },
        set: function set(port) {
            this.to = {
                nodeID: port.node.id,
                portID: port.id
            };
            this._protocolID = port.protocol;
        }
    }, {
        key: "protocolID",
        get: function get() {
            return this._protocolID;
        }
    }]);

    return Link;
})();

exports.Link = Link;

Link.propertyMap = {
    protocol: "_protocolID",
    from: "from",
    to: "to"
};

var Network = (function () {
    function Network(graph, componentRegistry) {
        _classCallCheck(this, Network);

        this.graph = graph;
        this.componentRegistry = componentRegistry;
    }

    Network.prototype.initialize = function initialize() {
        this.nodes = this.graph.getAllNodes();
        this.links = this.graph.getAllLinks();
        this.ports = this.graph.getAllPorts();
        return this.initializeGraph();
    };

    Network.prototype.initializeGraph = function initializeGraph() {
        return this.graph.initializeComponent(this.componentRegistry);
    };

    Network.prototype.wireupGraph = function wireupGraph(router) {
        var me = this;
        this.nodes.forEach(function (node) {});
        this.links.forEach(function (link) {
            var fromNode = link.fromNode;
            var toNode = link.toNode;
            var channel = new Channel();
            link.connect(channel);
            channel.connect();
        });
    };

    return Network;
})();

exports.Network = Network;

var Graph = (function (_Node) {
    function Graph(owner, attributes) {
        var _this11 = this;

        _classCallCheck(this, Graph);

        _Node.call(this, owner, attributes);
        this.id = attributes.id || "<graph>";
        this.nodes = {};
        this.links = {};
        this.nodes[this.id] = this;
        Object.keys(attributes.nodes || {}).forEach(function (id) {
            _this11.addNode(id, attributes.nodes[id]);
        });
        Object.keys(attributes.links || {}).forEach(function (id) {
            _this11.addLink(id, attributes.links[id]);
        });
    }

    _inherits(Graph, _Node);

    Graph.prototype.toObject = function toObject(opts) {
        var _this12 = this;

        var graph = _Node.prototype.toObject.call(this);
        var nodes = graph["nodes"] = {};
        Object.keys(this.nodes).forEach(function (id) {
            var node = _this12.nodes[id];
            if (node != _this12) nodes[id] = node.toObject();
        });
        var links = graph["links"] = {};
        Object.keys(this.links).forEach(function (id) {
            links[id] = _this12.links[id].toObject();
        });
        return graph;
    };

    Graph.prototype.initializeComponent = function initializeComponent(registry) {
        var _this13 = this;

        return new Promise(function (resolve, reject) {
            var pendingCount = 0;
            Object.keys(_this13.nodes).forEach(function (id) {
                var node = _this13.nodes[id];
                if (node != _this13) {
                    pendingCount++;
                    node.initializeComponent(registry).then(function () {
                        --pendingCount;
                        if (pendingCount == 0) resolve();
                    })["catch"](function (reason) {
                        reject(reason);
                    });
                }
            });
        });
    };

    Graph.prototype.getNodes = function getNodes() {
        return this.nodes;
    };

    Graph.prototype.getAllNodes = function getAllNodes() {
        var _this14 = this;

        var nodes = [];
        Object.keys(this.nodes).forEach(function (id) {
            var node = _this14.nodes[id];
            if (node != _this14 && node instanceof Graph) nodes = nodes.concat(node.getAllNodes());
            nodes.push(node);
        });
        return nodes;
    };

    Graph.prototype.getLinks = function getLinks() {
        return this.links;
    };

    Graph.prototype.getAllLinks = function getAllLinks() {
        var _this15 = this;

        var links = [];
        Object.keys(this.nodes).forEach(function (id) {
            var node = _this15.nodes[id];
            if (node != _this15 && node instanceof Graph) links = links.concat(node.getAllLinks());
        });
        Object.keys(this.links).forEach(function (id) {
            var link = _this15.links[id];
            links.push(link);
        });
        return links;
    };

    Graph.prototype.getAllPorts = function getAllPorts() {
        var _this16 = this;

        var ports = _Node.prototype.getPorts.call(this);
        Object.keys(this.nodes).forEach(function (id) {
            var node = _this16.nodes[id];
            if (node != _this16 && node instanceof Graph) ports = ports.concat(node.getAllPorts());else ports = ports.concat(node.getPorts());
        });
        return ports;
    };

    Graph.prototype.getNodeByID = function getNodeByID(id) {
        return this.nodes[id];
    };

    Graph.prototype.addNode = function addNode(id, attributes) {
        var node = new Node(this, attributes);
        node.id = id;
        this.nodes[id] = node;
        return node;
    };

    Graph.prototype.renameNode = function renameNode(id, newID) {
        var node = this.nodes[id];
        this.nodes[newID] = node;
        delete this.nodes[id];
    };

    Graph.prototype.removeNode = function removeNode(id) {
        delete this.nodes[id];
    };

    Graph.prototype.getLinkByID = function getLinkByID(id) {
        return this.links[id];
    };

    Graph.prototype.addLink = function addLink(id, attributes) {
        var link = new Link(this, attributes);
        link.id = id;
        this.links[id] = link;
        return link;
    };

    Graph.prototype.renameLink = function renameLink(id, newID) {
        var link = this.links[id];
        link.id = newID;
        this.links[newID] = link;
        delete this.links[id];
    };

    Graph.prototype.removeLink = function removeLink(id) {
        delete this.links[id];
    };

    Graph.prototype.addPublicPort = function addPublicPort(id, attributes) {
        var port = new PublicPort(this, attributes);
        port.id = id;
        this.ports[id] = port;
        return port;
    };

    return Graph;
})(Node);

exports.Graph = Graph;

var GraphTester = (function () {
    function GraphTester() {
        _classCallCheck(this, GraphTester);
    }

    GraphTester.prototype.execTests = function execTests() {
        var graph = {
            id: "gr",
            componentName: "g",
            ports: {
                "pxa": { direction: "inout", "type": "PublicPort" },
                "pxb": {}
            },
            nodes: {
                "n1": {
                    componentName: "a",
                    ports: {
                        "p1a": { direction: "out" },
                        "p1b": { direction: "inout" },
                        "p1x": { direction: "inout" }
                    }
                },
                "n2": {
                    componentName: "b",
                    ports: {
                        "p2a": { direction: "in" },
                        "p2b": { direction: "inout" }
                    }
                }
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
                }
            }
        };
        this.graph = new Graph(null, graph);
        var gr = this.graph;
        var n1 = gr.getNodeByID("n1");
        var p1x = n1.getPortByID("p1x");
        var p2a = gr.getNodeByID("n2").getPortByID("p2a");
    };

    return GraphTester;
})();

exports["default"] = GraphTester;