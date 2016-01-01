import { EndPoint, Direction } from '../messaging/end-point';
import { Channel } from '../messaging/channel';

import { Graph } from './graph';
import { Node } from './node';

export class Port extends EndPoint
{
  protected _owner: Node;
  protected _protocolID: string;

  public metadata: any;

  constructor( owner: Node, id: string, attributes: any = {} )
  {
    super( id, attributes.direction || Direction.INOUT );

    this._owner = owner;
    this._protocolID = attributes[ 'protocol' ] || 'any';

    this.metadata = attributes.metadata || { x: 100, y: 100 };
  }

  /**
   * Return POJO for serialization
   */
  toObject( opts?: any ): Object
  {
    var port = {
      id: this.id,
      direction: this.direction,
      protocol: ( this._protocolID != 'any' ) ? this._protocolID : undefined,
      metadata: this.metadata,
    };

    return port;
  }

  /**
   * Get the Port's owner
   */
  get owner(): Node {
    return this._owner
  }

  /**
   * Get the Port's protocol ID
   */
  get protocolID(): string
  {
    return this._protocolID;
  }
}

export class PublicPort extends Port
{
  protected ownerNode: Node;
  proxyEndPoint: EndPoint;
  proxyChannel: Channel;

  constructor( owner: Graph, attributes: any )
  {
    super( owner, attributes );

    let proxyDirection =
      ( this.direction == Direction.IN )
        ? Direction.OUT
        : ( this.direction == Direction.OUT )
          ? Direction.IN
          : Direction.INOUT;

    // Create an EndPoint to proxy between the Public and Private (internal)
    // sides of the Port.
    this.proxyEndPoint = new EndPoint( this.id, proxyDirection );

    // Wire-up proxy -

    // Forward incoming packets (from public interface) to private
    this.proxyEndPoint.onMessage( ( message, from: EndPoint ) => {
      this.sendMessage( message );
    });

    // Forward outgoing packets (from private interface) to public
    this.onMessage( ( message, from: EndPoint ) => {
      this.proxyEndPoint.sendMessage( message );
    });

    // not yet connected
    this.proxyChannel = null;
  }

  // Connect to Private (internal) EndPoint. To be called during graph
  // wireUp phase
  public connectPrivate( channel: Channel )
  {
    this.proxyChannel = channel;

    this.proxyEndPoint.attach( channel );
  }

  public disconnectPrivate()
  {
    this.proxyEndPoint.detach( this.proxyChannel );
  }

  toObject( opts?: any ): Object
  {
    var port = {

    };

    return port;
  }
}
