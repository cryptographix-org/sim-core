import { ComponentRegistry, Component } from "../base/base-package";
import { Graph, Port } from "./graph-package";

export default class Node
{
  protected ownerGraph: Graph;
  protected _id: string;

  protected ports: { [id: string]: Port; };

  protected componentName: string;
  protected setupData: Object;

  protected component: Component;

  constructor( owner: Graph, attributes )
  {
    this.ownerGraph = owner;

    this.ports = {};

    this.component = null;

    this.componentName = attributes.componentName || "";
    this.setupData = attributes.setupData || {};

    Object.keys( attributes.ports || {} ).forEach( (id) => {
      this.addPort( id, attributes.ports[ id ] );
    } );
  }

  toObject( opts?: any ): Object
  {
    var node = {
      id: this.id,
      ports: {},
    };

    Object.keys( this.ports ).forEach( (id) => {
      node.ports[ id ] = this.ports[ id ].toObject();
    });

    return node;
  }

  initializeComponents( registry: ComponentRegistry ): Promise<void>
  {
    let me = this;

    return new Promise<void>( (resolve, reject) => {
      registry.getComponentInstance( this.componentName, this.setupData )
      .then( (newInstance) => {
        me.component = newInstance;
        resolve();
      })
      .catch( (err) => {
        reject( err );
      });
    } );
  }

  addPort( id: string, attributes: any ): Port
  {
    let port = new Port( this, attributes );

    port.id = id;

    this.ports[ id ] = port;

    return port;
  }

  get id(): string
  {
    return this._id;
  }
  set id( id: string )
  {
    this._id = id;
  }

  getPorts(): Port[]
  {
    let ports = [];

    Object.keys( this.ports ).forEach( (id) => {
      ports.push( this.ports[ id ] );
    });

    return ports;
  }

  getPortByID( id: string ): Port
  {
    return this.ports[ id ];
  }

  identifyPort( id: string, protocol: string ): Port
  {
    return this.ports[ id ];
  }
}
