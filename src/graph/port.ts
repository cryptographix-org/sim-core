import { EndPoint, Direction } from '../base/end-point';
import { Channel } from '../base/channel';

import { Graph } from './graph';
import { Node } from './node';

export class Port extends EndPoint
{
  protected ownerNode: Node;
  protected _id: string;
  protected _protocolID: string;

  public view: any;

  constructor( owner: Node, attributes: any )
  {
    super( attributes.direction || Direction.INOUT );

    this.view = attributes.view || { x: 100, y: 100 };

    this._protocolID = attributes[ "protocol" ] || "any";

    this.ownerNode = owner;
  }

  toObject( opts?: any ): Object
  {
    var port = {

    };

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

  get node(): Node
  {
    return this.ownerNode;
  }

  get protocol(): string
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
    this.proxyEndPoint = new EndPoint( proxyDirection );

    // Wire-up proxy -

    // Forward incoming events (from public interface) to private
    this.proxyEndPoint.onEvent( ( from: EndPoint, evt ) => {
      this.triggerEvent( evt );
    });

    // Forward incoming packets (from public interface) to private
    this.proxyEndPoint.onMessage( ( from: EndPoint, message ) => {
      this.sendMessage( message );
    });

    // Forward outgoing events (from private interface) to public
    this.onEvent( ( from: EndPoint, evt ) => {
      this.proxyEndPoint.triggerEvent( evt );
    });

    // Forward outgoing packets (from private interface) to public
    this.onMessage( ( from: EndPoint, message ) => {
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

    this.proxyEndPoint.connect( channel );
  }

  public disconnectPrivate()
  {
    this.proxyEndPoint.disconnect();
  }

  toObject( opts?: any ): Object
  {
    var port = {

    };

    return port;
  }
}
