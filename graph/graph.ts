import { ComponentRegistry, Network, Link, Port, PublicPort } from "./graph-package";

// Separate import for Node base-class!
import Node from "./node";

/*
 * Graph is
 */
export default class Graph extends Node
{
  // Nodes in this graph. Each node may be:
  //   1. A Component
  //   2. A sub-graph
  protected nodes: { [id: string]: Node; };

  // Links in this graph. Each node may be:
  protected links: { [id: string]: Link; };

  // Public Ports in this graph. Inherited from Node
  // private Ports;
  constructor( owner: Graph, attributes: any )
  {
    super( owner, attributes );

    this.id = attributes.id || "<graph>";

    this.nodes = {};
    this.links = {};

    // Add ourselves as a Node, so that Links can reference PublicPorts
    // on containing Graph
    this.nodes[ this.id ] = this;

    Object.keys( attributes.nodes || {} ).forEach( (id) => {
      this.addNode( id, attributes.nodes[ id ] );
    });

    Object.keys( attributes.links || {} ).forEach( (id) => {
      this.addLink( id, attributes.links[ id ] );
    });
  }

  toObject( opts: any ): Object
  {
    var graph = super.toObject();

    let nodes = graph[ "nodes" ] = {};
    Object.keys( this.nodes ).forEach( (id) => {
      let node = this.nodes[ id ];

      if ( node != this )
        nodes[ id ] = node.toObject();
    });

    let links = graph[ "links" ] = {};
    Object.keys( this.links ).forEach( (id) => {
      links[ id ] = this.links[ id ].toObject();
    });

    return graph;
  }

  initializeComponents( registry: ComponentRegistry ): Promise<void>
  {
    return new Promise<void>( (resolve, reject) => {
      let pendingCount = 0;

      Object.keys( this.nodes ).forEach( (id) => {
        let node = this.nodes[ id ];

        if ( node != this )
        {
          pendingCount++;

          node.initializeComponents( registry )
            .then( () => {
              --pendingCount;
              if ( pendingCount == 0 )
                resolve();
            })
            .catch( ( reason ) => {
              reject( reason );
            } );
        }
      } );
    } );
  }

  getAllNodes(): Node[]
  {
    let nodes: Node[] = [];

    Object.keys( this.nodes ).forEach( (id) => {
      let node = this.nodes[ id ];

      // Don't recurse on graph's pseudo-node
      if ( ( node != this ) && ( node instanceof Graph ) )
        nodes = nodes.concat( node.getAllNodes() );

      nodes.push( node );
    } );

    return nodes;
  }

  getAllLinks(): Link[]
  {
    let links: Link[] = [];

    Object.keys( this.nodes ).forEach( (id) => {
      let node = this.nodes[ id ];

      if ( ( node != this ) && ( node instanceof Graph ) )
        links = links.concat( node.getAllLinks() );
    } )

    Object.keys( this.links ).forEach( (id) => {
      let link = this.links[ id ];

      links.push( link );
    } );

    return links;
  }

  getAllPorts(): Port[]
  {
    let ports: Port[] = super.getPorts();

    Object.keys( this.nodes ).forEach( (id) => {
      let node = this.nodes[ id ];

      if ( ( node != this ) && ( node instanceof Graph ) )
        ports = ports.concat( node.getAllPorts() );
      else
        ports = ports.concat( node.getPorts() );
    } );

    return ports;
  }

  getNodeByID( id: string ): Node
  {
    return this.nodes[ id ];
  }

  addNode( id: string, attributes: {} )
  {
    let node = new Node( this, attributes );

    node.id = id;

    this.nodes[ id ] = node;

    return node;
  }

  renameNode( id: string, newID: string )
  {
    let node = this.nodes[ id ];

    this.nodes[ newID ] = node;

    delete this.nodes[ id ];
  }

  removeNode( id: string )
  {
    delete this.nodes[ id ];
  }

  addLink( id: string, attributes: {} )
  {
    let link = new Link( this, attributes );

    link.id = id;

    this.links[ id ] = link;

    return link;
  }

  renameLink( id: string, newID: string )
  {
    let link = this.links[ id ];

    link.id = newID;
    this.links[ newID ] = link;

    delete this.links[ id ];
  }

  removeLink( id: string )
  {
    delete this.links[ id ];
  }

  addPublicPort( id: string, attributes: any )
  {
    let port = new PublicPort( this, attributes );

    port.id = id;

    this.ports[ id ] = port;

    return port;
  }
}
