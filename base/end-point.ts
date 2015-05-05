import { TaskScheduler, Channel, Packet } from "./base-package";

export enum Direction {
  IN,
  OUT,
  INOUT
};

export type OnEventDelegate = ( fromEndPoint: EndPoint, event: any ) => void;
export type OnPacketDelegate =  ( fromEndPoint: EndPoint, packet: Packet ) => void;

export default class EndPoint
{
  protected channel: Channel;

  protected eventListeners: OnEventDelegate[];
  protected packetListeners: OnPacketDelegate[];

  direction: Direction;

  constructor( direction?: Direction )
  {
    this.direction = direction;
    this.channel = null;
    this.eventListeners = [];
    this.packetListeners = [];
  }

  public shutdown()
  {
    this.channel = null;
    this.eventListeners = [];
    this.packetListeners = [];
  }

  public connect( channel: Channel )
  {
    function triggerEventOnListener( fromPoint: EndPoint, event: any )
    {
      this.eventListeners.forEach( eventListener => {
        eventListener( fromPoint, event );
      } );
    };

    function sendPacketToListener( fromPoint: EndPoint, packet: Packet )
    {
      this.packetListeners.forEach( packetListener => {
        packetListener( fromPoint, packet );
      } );
    }

    this.channel = channel;

    channel.addEndPoint( this, triggerEventOnListener, sendPacketToListener );
  }

  public disconnect()
  {
    if ( this.channel )
      this.channel.removeEndPoint( this );
  }

  get isConnected()
  {
    return ( this.channel && this.channel.isConnected );
  }

  public triggerEvent( event: any )
  {
    if ( !this.isConnected )
      return;

    this.channel.triggerEvent( this, event );
  }

  public sendPacket( packet: Packet )
  {
    if ( !this.isConnected )
      return;

    this.channel.sendPacket( this, packet );
  }

  public onEvent( eventListener: OnEventDelegate )
  {
    this.eventListeners.push( eventListener );
  }

  public onPacket( packetListener: OnPacketDelegate )
  {
    this.packetListeners.push( packetListener );
  }
}
