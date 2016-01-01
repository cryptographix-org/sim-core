import { Graph } from 'sim-core';
import { Node, Port } from 'sim-core';

describe("A Node", function() {
  beforeEach( function() {
    this.graph1 = new Graph( null, {} );
    this.node1 = new Node( this.graph1, {
      id: 'node1',
    } );

    this.node2 = new Node( this.graph1, {
      id: 'node2',
      componentID: 'component2',
      ports: {
        "n2p1": {},
        "n2p2": {},
      }
    });
  });

  describe( "has a constructor that", function() {
    it( "sets the Node's owner", function() {
      expect( this.node1.owner ).toEqual( this.graph1 );
    });

    it( "sets the Node's id", function() {
      expect( this.node1.id ).toEqual( 'node1' );
    });

    it( "creates the Node's ports collection", function() {
      expect( this.node1.getPorts().length ).toBe( 0 );
      expect( this.node2.getPorts().length ).toBe( 2 );
    });

    it( "sets the Node's componentID", function() {
      expect( this.node1.toObject().componentID ).toBeUndefined();
      expect( this.node2.toObject().componentID ).toEqual( 'component2' );
    });
  } );

  describe( 'has a Ports collection', function() {
    it( 'that can be retrieved as an array', function() {
      let p1 = this.node2.getPorts()[0];
      let p2 = this.node2.getPorts()[1];

      expect( p1 instanceof Port ).toBe( true );
      expect( p1.id ).toEqual( 'n2p1' );
      expect( p2.id ).toEqual( 'n2p2' );
    });

    it( 'that can be searched by port-id', function() {
      let p1 = this.node2.getPortByID('n2p1');
      let p2 = this.node2.getPortByID('n2p2');
      let p3 = this.node2.getPortByID('inexistent');

      expect( p1 instanceof Port ).toBe( true );
      expect( p1.id ).toEqual( 'n2p1' );
      expect( p2.id ).toEqual( 'n2p2' );

      expect( p3 ).toBeUndefined();
    });

    it( 'can have new Ports added', function() {
      let p1 = this.node1.addPort( 'n1p1', {} );

      expect( p1 instanceof Port ).toBe( true );
      expect( p1.id ).toEqual( 'n1p1' );
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
    });

  });

/*    let p1x = node1.getPortByID( "p1x" );
    expect( p1x instanceof Port ).toBe( true );
    expect( p1x.id ).toEqual( "p1x" );

    let p2a = graph1.getNodeByID( "n2" ).getPortByID( "p2a" );
    expect( p2a instanceof Port ).toBe( true );
    expect( p2a.id ).toEqual( "p2a" );*/
} );
