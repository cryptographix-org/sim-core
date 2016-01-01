import { Message } from './message';
import { Channel } from './channel';

export enum Direction {
  IN = 1,
  OUT = 2,
  INOUT = 3
};

export type OnMessageDelegate =  ( message: Message<any>, fromEndPoint?: EndPoint ) => void;

export type EndPointCollection = { [id: string]: EndPoint; };

/**
* An EndPoint (sender/receiver) for message-passing
*
* EndPoints may have multiple channels attached, and will forward messages
* to all of them.
*/
export class EndPoint
{
  protected _id: string;

  /**
  * A list of attached Channels
  */
  protected _channels: Channel[];

  /**
  * A list of attached Channels
  */
  protected _messageListeners: OnMessageDelegate[];

  private _direction: Direction;

  constructor( id: string, direction?: Direction )
  {
    this._id = id;

    this._direction = direction;

    this._channels = [];

    this._messageListeners = [];
  }

  /**
  * Cleanup the EndPoint, detaching any attached Channels and removing any
  * message-listeners. Calling shutdown() is mandatory to avoid memory-leaks
  * due to the circular references that exist between Channels and EndPoints
  */
  public shutdown()
  {
    this.detachAll();

    this._messageListeners = [];
  }

  /**
   * Get the EndPoint's id
   */
  get id(): string
  {
    return this._id;
  }

  /**
  * Attach a Channel to this EndPoint. Once attached, the Channel will forward
  * messages to this EndPoint, and will accept messages originated here.
  * An EndPoint can have multiple Channels attached, in which case it will
  * broadcast to them all when sending, and will receive messages in
  * arrival-order.
  */
  public attach( channel: Channel )
  {
    this._channels.push( channel );

    channel.addEndPoint( this );
  }

  /**
  * Handle an incoming Message.
  */
  public handleMessage( message: Message<any>, fromEndPoint: EndPoint, fromChannel: Channel )
  {
    this._messageListeners.forEach( messageListener => {
      messageListener( message, fromEndPoint );
    } );
  }

  /**
  * Detach a specific Channel from this EndPoint.
  */
  public detach( channelToDetach: Channel )
  {
    let idx = this._channels.indexOf( channelToDetach );

    if ( idx >= 0 )
    {
      channelToDetach.removeEndPoint( this );

      this._channels.splice( idx, 1 );
    }
  }

  /**
  * Detach all Channels from this EndPoint.
  */
  public detachAll()
  {
    this._channels.forEach( channel => {
      channel.removeEndPoint( this );
    } );

    this._channels = [];
  }

  /**
  * Are any channels attached to this EndPoint?
  *
  * @returns true if Endpoint is attached to at-least-one Channel
  */
  get attached()
  {
    return ( this._channels.length > 0 );
  }

  get direction(): Direction
  {
    return this._direction;
  }

  public sendMessage( message: Message<any> )
  {
    this._channels.forEach( channel => {
      channel.sendMessage( this, message );
    } );
  }

  /**
  * Register a delegate to receive any incoming Messages
  *
  * @param messageListener - delegate to be called with received Message
  */
  public onMessage( messageListener: OnMessageDelegate )
  {
    this._messageListeners.push( messageListener );
  }
}
