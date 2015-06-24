import { TaskScheduler, Channel, Message } from "./base-package";

export enum Direction {
  IN,
  OUT,
  INOUT
};

export type OnEventDelegate = ( fromEndPoint: EndPoint, event: any ) => void;
export type OnMessageDelegate =  ( fromEndPoint: EndPoint, message: Message ) => void;

export type EndPoints = { [id: string]: EndPoint; };

export default class EndPoint
{
  protected channel: Channel;

  protected eventListeners: OnEventDelegate[];
  protected messageListeners: OnMessageDelegate[];

  direction: Direction;

  constructor( direction?: Direction )
  {
    this.direction = direction;
    this.channel = null;
    this.eventListeners = [];
    this.messageListeners = [];
  }

  public shutdown()
  {
    this.channel = null;
    this.eventListeners = [];
    this.messageListeners = [];
  }

  public connect( channel: Channel )
  {
    function triggerEventOnListener( fromPoint: EndPoint, event: any )
    {
      this.eventListeners.forEach( eventListener => {
        eventListener( fromPoint, event );
      } );
    };

    function sendMessageToListener( fromPoint: EndPoint, message: Message )
    {
      this.messageListeners.forEach( messageListener => {
        messageListener( fromPoint, message );
      } );
    }

    this.channel = channel;

    channel.addEndPoint( this, triggerEventOnListener, sendMessageToListener );
  }

  public disconnect()
  {
    if ( this.channel )
      this.channel.removeEndPoint( this );

    this.channel = null;
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

  public sendMessage( message: Message )
  {
    if ( !this.isConnected )
      return;

    this.channel.sendMessage( this, message );
  }

  public onEvent( eventListener: OnEventDelegate )
  {
    this.eventListeners.push( eventListener );
  }

  public onMessage( messageListener: OnMessageDelegate )
  {
    this.messageListeners.push( messageListener );
  }

  static Direction: Direction;
}
