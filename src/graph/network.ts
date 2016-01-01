import { ComponentFactory } from '../runtime/component-factory';
import { EndPoint } from '../messaging/end-point';
import { Channel } from '../messaging/channel';

import { Graph } from './graph';
import { Node } from './node';
import { Link } from './link';
import { Port, PublicPort } from './port';

export class Network
{
  private graph: Graph;
  private nodes: Node[];
  private links: Link[];
  private ports: Port[];

  private factory: ComponentFactory;

  constructor( graph: Graph, factory: ComponentFactory )
  {
    this.graph = graph;
    this.factory = factory;
  }

  initialize( ): Promise<void>
  {
    this.nodes = this.graph.getAllNodes();
    this.links = this.graph.getAllLinks();
    this.ports = this.graph.getAllPorts();

    return this.initializeGraph( );
  }

  protected initializeGraph( ): Promise<void>
  {
/*    return new Promise<void>( (resolve, reject) => {

      .then( return this.wireupGraph() => { resolve() } );
      .then( () => { resolve() } );

    })
*/
    return this.graph.initComponent( this.factory );
  }

  wireupGraph( router: any )
  {
    var me = this;

    this.nodes.forEach( function( node )
    {
      //node.router = router;
      //node.mapPorts();
    } );

    // Build linkList from config link elements
    // Each element links ports on two nodes
    this.links.forEach( ( link ) =>
    {
      // find linked nodes
      var fromNode = link.fromNode;
      var toNode = link.toNode;

      //debugMessage( "Link("+link.id+"): " + link.from + " -> " + link.to + " proto="+link.protocol );

      let channel = new Channel();

      link.connect( channel );

      channel.activate();
    } );
  }
}
