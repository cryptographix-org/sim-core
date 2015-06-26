import { Graph, Node, Link, Port, PublicPort } from "./index";
import { ComponentRegistry, Channel, EndPoint } from "../base/index";

declare class Promise<T> {};

export default class Network
{
  private graph: Graph;
  private nodes: Node[];
  private links: Link[];
  private ports: Port[];

  private componentRegistry: ComponentRegistry;

  constructor( graph: Graph, componentRegistry: ComponentRegistry )
  {
    this.graph = graph;
    this.componentRegistry = componentRegistry;
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
    return this.graph.initializeComponent( this.componentRegistry );
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

      channel.connect();
    } );
  }
}
