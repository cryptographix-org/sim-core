System.register(["sim-core"], function (_export) {
    "use strict";

    var Container, inject, ByteArray, Graph, Node, Port, Direction, Channel, EndPoint, Message, __decorate, __metadata, C1, C2, jsonGraph1, IntegerMessage;

    function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

    function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

    return {
        setters: [function (_simCore) {
            Container = _simCore.Container;
            inject = _simCore.inject;
            ByteArray = _simCore.ByteArray;
            Graph = _simCore.Graph;
            Node = _simCore.Node;
            Port = _simCore.Port;
            Direction = _simCore.Direction;
            Channel = _simCore.Channel;
            EndPoint = _simCore.EndPoint;
            Message = _simCore.Message;
        }],
        execute: function () {
            __decorate = undefined && undefined.__decorate || function (decorators, target, key, desc) {
                if (typeof Reflect === "object" && typeof Reflect.decorate === "function") return Reflect.decorate(decorators, target, key, desc);
                switch (arguments.length) {
                    case 2:
                        return decorators.reduceRight(function (o, d) {
                            return d && d(o) || o;
                        }, target);
                    case 3:
                        return decorators.reduceRight(function (o, d) {
                            return d && d(target, key), void 0;
                        }, void 0);
                    case 4:
                        return decorators.reduceRight(function (o, d) {
                            return d && d(target, key, o) || o;
                        }, desc);
                }
            };

            __metadata = undefined && undefined.__metadata || function (k, v) {
                if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
            };

            C1 = function C1() {
                _classCallCheck(this, C1);
            };

            C2 = function C2(c1) {
                _classCallCheck(this, C2);

                this.c1 = c1;
            };

            C2 = __decorate([inject(), __metadata('design:paramtypes', [C1])], C2);
            describe("DI Container", function () {
                it("Must inject", function () {
                    var jector = new Container();
                    jector.registerSingleton(C1, C1);
                });
            });

            describe('A ByteArray', function () {
                it('stores a sequence of bytes', function () {
                    var bs = new ByteArray([0, 1, 2, 3, 4]);
                    expect(bs.toString()).toBe("0001020304");
                });
                it('can be instanciated from an array of bytes', function () {
                    var bs = new ByteArray([0, 1, 2, 3, 4]);
                    expect(bs.toString()).toBe("0001020304");
                    var bytes = [];
                    for (var i = 0; i < 10000; ++i) {
                        bytes[i] = i & 0xff;
                    }bs = new ByteArray(bytes);
                    expect(bs.length).toBe(10000);
                });
                it('can be compared (equal)', function () {
                    var bs1 = new ByteArray([0, 1, 2, 3, 4]);
                    var bs2 = new ByteArray("00 01 02 03 04", ByteArray.HEX);
                    var bs3 = bs1.clone().setByteAt(1, 0x99);

                    expect(bs1.equals(bs1)).toBe(true);

                    expect(bs1.equals(bs2)).toBe(true);
                    expect(bs1.equals(bs3)).not.toBe(true);
                });
            });

            jsonGraph1 = {
                id: "Graph1",
                component: "g",
                ports: {
                    "pxa": { direction: "inout", type: "PublicPort" },
                    "pxb": {}
                },
                nodes: {
                    "n1": {
                        component: "a",
                        ports: {
                            "p1a": { direction: "out" },
                            "p1b": { direction: "inout" },
                            "p1x": { direction: "inout" }
                        }
                    },
                    "n2": {
                        component: "b",
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

            describe("A Graph", function () {
                it("can be instantiated from a JSON object", function () {
                    var graph1 = new Graph(null, jsonGraph1);
                    expect(graph1 instanceof Node).toBe(true);
                    expect(graph1 instanceof Graph).toBe(true);
                    var n1 = graph1.getNodeByID("n1");
                    expect(n1 instanceof Node).toBe(true);
                    var p1x = n1.getPortByID("p1x");
                    expect(p1x instanceof Port).toBe(true);
                    expect(p1x.id).toEqual("p1x");
                    var p2a = graph1.getNodeByID("n2").getPortByID("p2a");
                    expect(p2a instanceof Port).toBe(true);
                    expect(p2a.id).toEqual("p2a");
                    expect(p1x.direction).toEqual(Direction.INOUT);
                    expect(p2a.direction).toEqual(Direction.IN);
                });
            });

            describe("A Node", function () {
                beforeEach(function () {
                    this.graph1 = new Graph(null, {});
                    this.node1 = new Node(this.graph1, {
                        id: 'node1'
                    });
                    this.node2 = new Node(this.graph1, {
                        id: 'node2',
                        componentID: 'component2',
                        ports: {
                            "n2p1": {},
                            "n2p2": {}
                        }
                    });
                });
                describe("has a constructor that", function () {
                    it("sets the Node's owner", function () {
                        expect(this.node1.owner).toEqual(this.graph1);
                    });
                    it("sets the Node's id", function () {
                        expect(this.node1.id).toEqual('node1');
                    });
                    it("creates the Node's ports collection", function () {
                        expect(this.node1.getPorts().length).toBe(0);
                        expect(this.node2.getPorts().length).toBe(2);
                    });
                    it("sets the Node's componentID", function () {
                        expect(this.node1.toObject().componentID).toBeUndefined();
                        expect(this.node2.toObject().componentID).toEqual('component2');
                    });
                });
                describe('has a Ports collection', function () {
                    it('that can be retrieved as an array', function () {
                        var p1 = this.node2.getPorts()[0];
                        var p2 = this.node2.getPorts()[1];
                        expect(p1 instanceof Port).toBe(true);
                        expect(p1.id).toEqual('n2p1');
                        expect(p2.id).toEqual('n2p2');
                    });
                    it('that can be searched by port-id', function () {
                        var p1 = this.node2.getPortByID('n2p1');
                        var p2 = this.node2.getPortByID('n2p2');
                        var p3 = this.node2.getPortByID('inexistent');
                        expect(p1 instanceof Port).toBe(true);
                        expect(p1.id).toEqual('n2p1');
                        expect(p2.id).toEqual('n2p2');
                        expect(p3).toBeUndefined();
                    });
                });
            });

            IntegerMessage = (function (_Message) {
                _inherits(IntegerMessage, _Message);

                function IntegerMessage(value) {
                    _classCallCheck(this, IntegerMessage);

                    _Message.call(this, undefined, value);
                }

                return IntegerMessage;
            })(Message);

            describe('A Channel', function () {
                describe('can be active or inactive', function () {
                    var ch = new Channel();
                    it('is initially inactive', function () {
                        expect(ch.active).toBe(false);
                    });
                    it('can be activated', function () {
                        expect(ch.active).toBe(false);
                        ch.activate();
                        expect(ch.active).toBe(true);
                        ch.activate();
                        expect(ch.active).toBe(true);
                    });
                    it('can be deactivated', function () {
                        expect(ch.active).toBe(true);
                        ch.deactivate();
                        expect(ch.active).toBe(false);
                        ch.deactivate();
                        expect(ch.active).toBe(false);
                    });
                });
                describe('has a registry of EndPoints', function () {
                    var ch = new Channel();
                    var ep1 = new EndPoint('ep1');
                    var ep2 = new EndPoint('ep2');
                    it('to which EndPoints can be added', function () {
                        ch.addEndPoint(ep1);
                        expect(ch.endPoints.length).toBe(1);

                        ch.addEndPoint(ep2);
                        expect(ch.endPoints.length).toBe(2);
                    });
                    it('... and removed', function () {
                        ch.removeEndPoint(ep1);
                        expect(ch.endPoints).toContain(ep2);
                        ch.removeEndPoint(ep2);
                        expect(ch.endPoints.length).toBe(0);
                    });
                    it('... even when Channel is activated', function () {
                        ch.activate();
                        expect(ch.active).toBe(true);
                        ch.addEndPoint(new EndPoint('epx'));
                        ch.addEndPoint(new EndPoint('epx'));
                        ch.addEndPoint(ep1);
                        expect(ch.endPoints).toContain(ep1);
                        expect(ch.endPoints.length).toBe(3);
                        ch.removeEndPoint(ep1);
                        expect(ch.endPoints).not.toContain(ep1);
                        ch.shutdown();
                        expect(ch.endPoints.length).toBe(0);
                    });
                });
                describe('communicates between endpoints', function () {
                    var ch = new Channel();
                    var ep1 = new EndPoint('ep1', Direction.OUT);
                    var ep2 = new EndPoint('ep2', Direction.IN);
                    ep1.attach(ch);
                    ep2.attach(ch);
                    ch.activate();
                    it('can bounce messages', function (done) {
                        ep2.onMessage(function (m, ep) {
                            m.header.isResponse = true;ep2.sendMessage(m);
                        });
                        ep1.sendMessage(new IntegerMessage(100));
                        ep1.onMessage(function (m) {
                            done();
                        });
                    });
                });
            });
        }
    };
});