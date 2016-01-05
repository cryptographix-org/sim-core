  import { Container, inject, ByteArray, Channel, EndPoint, Message, Direction, Graph, Node, Port } from 'cryptographix-sim-core';

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
class C1 {
}
let C2 = class {
    constructor(c1) {
        this.c1 = c1;
    }
};
C2 = __decorate([
    inject(), 
    __metadata('design:paramtypes', [C1])
], C2);
describe("DI Container", () => {
    it("Must inject", () => {
        let jector = new Container();
        jector.registerSingleton(C1, C1);
    });
});

describe('A ByteArray', () => {
    it('stores a sequence of bytes', () => {
        let bs = new ByteArray([0, 1, 2, 3, 4]);
        expect(bs.toString()).toBe("0001020304");
    });
    it('can be instanciated from an array of bytes', () => {
        let bs = new ByteArray([0, 1, 2, 3, 4]);
        expect(bs.toString()).toBe("0001020304");
        var bytes = [];
        for (let i = 0; i < 10000; ++i)
            bytes[i] = i & 0xff;
        bs = new ByteArray(bytes);
        expect(bs.length).toBe(10000);
    });
    it('can be compared (equal)', () => {
        let bs1 = new ByteArray([0, 1, 2, 3, 4]);
        let bs2 = new ByteArray("00 01 02 03 04", ByteArray.HEX);
        let bs3 = bs1.clone().setByteAt(1, 0x99);
        //    console.log( bs1.equals( bs1 ) + ':' + bs1.toString() );
        expect(bs1.equals(bs1)).toBe(true);
        //    console.log( bs1.equals( bs2 )  + ':' + bs2.toString() );
        expect(bs1.equals(bs2)).toBe(true);
        expect(bs1.equals(bs3)).not.toBe(true);
    });
});

class IntegerMessage extends Message {
    constructor(value) {
        super(undefined, value);
    }
}
describe('A Channel', () => {
    describe('can be active or inactive', () => {
        let ch = new Channel();
        it('is initially inactive', () => {
            expect(ch.active).toBe(false);
        });
        it('can be activated', () => {
            expect(ch.active).toBe(false);
            ch.activate();
            expect(ch.active).toBe(true);
            ch.activate();
            expect(ch.active).toBe(true);
        });
        it('can be deactivated', () => {
            expect(ch.active).toBe(true);
            ch.deactivate();
            expect(ch.active).toBe(false);
            ch.deactivate();
            expect(ch.active).toBe(false);
        });
    });
    describe('has a registry of EndPoints', () => {
        let ch = new Channel();
        var ep1 = new EndPoint('ep1');
        var ep2 = new EndPoint('ep2');
        it('to which EndPoints can be added', () => {
            // add an EndPoint
            ch.addEndPoint(ep1);
            expect(ch.endPoints.length).toBe(1);
            // add another
            ch.addEndPoint(ep2);
            expect(ch.endPoints.length).toBe(2);
        });
        it('... and removed', () => {
            // remove first EndPoint
            ch.removeEndPoint(ep1);
            expect(ch.endPoints).toContain(ep2);
            ch.removeEndPoint(ep2);
            expect(ch.endPoints.length).toBe(0);
        });
        it('... even when Channel is activated', () => {
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
    describe('communicates between endpoints', () => {
        let ch = new Channel();
        var ep1 = new EndPoint('ep1', Direction.OUT);
        var ep2 = new EndPoint('ep2', Direction.IN);
        ep1.attach(ch);
        ep2.attach(ch);
        ch.activate();
        it('can bounce messages', (done) => {
            ep2.onMessage((m, ep) => { m.header.isResponse = true; ep2.sendMessage(m); });
            ep1.sendMessage(new IntegerMessage(100));
            ep1.onMessage((m) => { done(); });
        });
    });
});

let jsonGraph1 = {
    id: "Graph1",
    component: "g",
    ports: {
        "pxa": { direction: "inout", type: "PublicPort" },
        "pxb": {},
    },
    nodes: {
        "n1": {
            component: "a",
            ports: {
                "p1a": { direction: "out", },
                "p1b": { direction: "inout", },
                "p1x": { direction: "inout", },
            },
        },
        "n2": {
            component: "b",
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
describe("A Graph", () => {
    it("can be instantiated from a JSON object", () => {
        let graph1 = new Graph(null, jsonGraph1);
        expect(graph1 instanceof Node).toBe(true);
        expect(graph1 instanceof Graph).toBe(true);
        let n1 = graph1.getNodeByID("n1");
        expect(n1 instanceof Node).toBe(true);
        let p1x = n1.getPortByID("p1x");
        expect(p1x instanceof Port).toBe(true);
        expect(p1x.id).toEqual("p1x");
        let p2a = graph1.getNodeByID("n2").getPortByID("p2a");
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
            id: 'node1',
        });
        this.node2 = new Node(this.graph1, {
            id: 'node2',
            componentID: 'component2',
            ports: {
                "n2p1": {},
                "n2p2": {},
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
            let p1 = this.node2.getPorts()[0];
            let p2 = this.node2.getPorts()[1];
            expect(p1 instanceof Port).toBe(true);
            expect(p1.id).toEqual('n2p1');
            expect(p2.id).toEqual('n2p2');
        });
        it('that can be searched by port-id', function () {
            let p1 = this.node2.getPortByID('n2p1');
            let p2 = this.node2.getPortByID('n2p2');
            let p3 = this.node2.getPortByID('inexistent');
            expect(p1 instanceof Port).toBe(true);
            expect(p1.id).toEqual('n2p1');
            expect(p2.id).toEqual('n2p2');
            expect(p3).toBeUndefined();
        });
        /*    it( 'can have new Ports added', function() {
              let p1 = this.node1.addPort( 'n1p1', {} );
        
              expect( p1 instanceof Port ).toBe( true );
              expect( p1.id ).toEqual( 'n1p1' );
        
              let p1x = this.node1.getPortByID( 'n1p1' );
              expect( p1x ).toEqual( p1 );
            });
        
            it( 'can have ports removed', function() {
              let p1 = this.node2.getPortByID('n2p1');
        
              expect( p1.id ).toEqual( 'n2p1' );
              let res1 = this.node2.removePort( 'n2p1' );
              expect( res1 ).toBe( true );
        
              let p1x = this.node2.getPortByID('n2p1');
              expect( p1x ).toBeUndefined();
        
              expect( this.node2.getPorts().length ).toEqual( 1 );
        
              let res2 = this.node2.removePort( 'n2p1' );
              expect( res2 ).toBe( false );
            });*/
    });
});
