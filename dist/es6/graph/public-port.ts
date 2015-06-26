import Graph from './graph';
import Node from './node';
import Port from "./port";

import Message from "../base/message";
import Channel from "../base/channel";
import EndPoint from "../base/end-point";
import { Direction } from "../base/end-point"

export default class PublicPort extends Port
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
