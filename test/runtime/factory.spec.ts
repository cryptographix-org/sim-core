import { Kind, EndPoint, EndPointCollection} from 'cryptographix-sim-core';
import { Network, Graph, Node } from 'cryptographix-sim-core';
import { ComponentFactory, ModuleLoader, Container, inject } from 'cryptographix-sim-core';

let gr1 = {
  nodes: {
    "n1": {
      component: "c1",
    },
  }
};

@inject()
class C {

  constructor( node: Node )
  {
    console.log( 'C1 got node: ' + node.id );
  }

  setup( initialData: Kind ): EndPointCollection {
    console.log( 'C1 created with init data' + JSON.stringify( initialData ) );

    return {};
  }

  start() {
    console.log( 'C1 started ' );
  }

  stop() {
    console.log( 'C1 stopped' );
  }
}

/*    let loader: ModuleLoader = {
      loadModule: function( id: string ): Promise<any> {
        return Promise.resolve( C );
      }
    }*/

describe("A ComponentFactory", function() {
  it("can be used without a loader", function( done ) {
    let factory = new ComponentFactory();
    let graph = new Graph( null, gr1 );
    let net = new Network( factory, graph );

    // register a test Component
    factory.register( 'c1', C );

    // load the components
    net.loadComponents()
      .then( ()=> {
        expect( graph.nodes.get('n1').context.instance ).toBeDefined();
        net.setup();
      })
      .then( () => {
        done();
      });
  } );

  beforeEach( function() {
    // Factory with def. container and no loader
    this.factory = new ComponentFactory();
    this.factory.register( 'c1', C );
  } );

  it( "loads and registers Components", function(done) {
    let graph = new Graph( null, gr1 );
    let net = new Network( this.factory, graph );

    net.loadComponents()
      .then( ()=> {
        expect( net.graph.nodes.get('n1').context ).toBeDefined();
        net.setup();
      })
      .then( () => {
        done();
      })
    //expect( graph1 instanceof Node ).toBe( true );
    //expect( graph1 instanceof Graph ).toBe( true );

    //expect( p1x.direction ).toEqual( Direction.INOUT );
    //expect( p2a.direction ).toEqual( Direction.IN );

  } );
} );
