import { ComponentContext } from '../runtime/component-context';
import { ComponentFactory} from '../runtime/component-factory';

import { Graph } from './graph';
import { Port } from './port';

export class Node
{
  protected _owner: Graph;
  protected _id: string;
  protected _componentID: string;
  protected _initialData: Object;

  protected _ports: { [id: string]: Port; };

  public metadata: any;

  /**
   * The runtime component instance that this node represents
   */
  context: ComponentContext;

  constructor( owner: Graph, attributes: any = {} )
  {
    this._owner = owner;
    this._id = attributes.id || '';
    this._componentID = attributes.componentID;
    this._initialData = attributes.initialData || {};

    this._ports = {};

    this.metadata = attributes.metadata || { };

    Object.keys( attributes.ports || {} ).forEach( (id) => {
      this.addPort( id, attributes.ports[ id ] );
    } );
  }

  /**
   * Return POJO for serialization
   */
  toObject( opts?: any ): Object
  {
    var node = {
      id: this.id,
      componentID: this._componentID,
      initialData: this._initialData,
      ports: {},
      metadata: this.metadata
    };

    Object.keys( this._ports ).forEach( (id) => {
      node.ports[ id ] = this._ports[ id ].toObject();
    });

    return node;
  }

  /**
   * Get the Node's owner
   */
  get owner(): Graph {
    return this._owner
  }

  /**
   * Get the Node's id
   */
  get id(): string
  {
    return this._id;
  }
  /**
   * Set the Node's id
   * @param id - new identifier
   */
  set id( id: string )
  {
    this._id = id;
  }

  /**
   * Add a new Port
   */
  addPort( id: string, attributes: any ): Port
  {
    let port = new Port( this, id, attributes );

    this._ports[ id ] = port;

    return port;
  }

  /**
   * Return ports as an array of Ports
   *
   * @return Port[]
   */
  getPorts(): Port[]
  {
    let ports = [];

    Object.keys( this._ports ).forEach( (id) => {
      ports.push( this._ports[ id ] );
    });

    return ports;
  }

  /**
   * Lookup a Port by it's ID
   * @param id - port identifier
   *
   * @return Port or undefined
   */
  getPortByID( id: string ): Port
  {
    return this._ports[ id ];
  }

  identifyPort( id: string, protocolID?: string ): Port
  {
    var port: Port;

    if ( id )
      port = this._ports[ id ];
    else if ( protocolID )
    {
      Object.keys( this._ports ).forEach( (id) => {
        let p = this._ports[ id ];

        if ( p.protocolID == protocolID )
          port = p;
      }, this );
    }

    return port;
  }

  /**
   * Remove a Port from this Node
   * @param id - identifier of Port to be removed
   * @return true - port removed
   *         false - port inexistent
   */
  removePort( id: string ): boolean
  {
    if ( this._ports[ id ] )
    {
      delete this._ports[ id ];

      return true;
    }

    // not found
    return false;
  }

  initComponent( factory: ComponentFactory ): Promise<void> {
    return Promise.resolve<void>( null );
  }
}
