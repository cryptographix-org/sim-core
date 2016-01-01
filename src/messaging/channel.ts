import { TaskScheduler } from '../runtime/task-scheduler';
import { EndPoint, OnMessageDelegate, Direction } from './end-point';
import { Message } from './message';

/**
* A message-passing channel between multiple EndPoints
*
* EndPoints must first register with the Channel. Whenever the Channel is in
* an active state, calls to sendMessage will forward the message to all
* registered EndPoints (except the originator EndPoint).
*/
export class Channel
{
  private _active: boolean;

  private _endPoints: EndPoint[];
  private _taskScheduler: TaskScheduler;

  constructor()
  {
    this._active = false;
    this._endPoints = [];
  }

  /**
  * Cleanup the Channel, deactivate, remove all EndPoints and
  * abort any pending communications.
  */
  public shutdown()
  {
    this._active = false;

    this._endPoints = [];

    if ( this._taskScheduler )
      this._taskScheduler.shutdown();

    this._taskScheduler = undefined;
  }

  /**
  * Is Channel active?
  *
  * @returns true if channel is active, false otherwise
  */
  public get active(): boolean
  {
    return this._active;
  }

  /**
  * Activate the Channel, enabling communication
  */
  public activate()
  {
    this._taskScheduler = new TaskScheduler();

    this._active = true;
  }

  /**
  * Deactivate the Channel, disabling any further communication
  */
  public deactivate()
  {
    this._taskScheduler = undefined;

    this._active = false;
  }

  /**
  * Register an EndPoint to send and receive messages via this Channel.
  *
  * @param endPoint - the EndPoint to register
  */
  public addEndPoint( endPoint: EndPoint )
  {
    this._endPoints.push( endPoint );
  }

  /**
  * Unregister an EndPoint.
  *
  * @param endPoint - the EndPoint to unregister
  */
  public removeEndPoint( endPoint: EndPoint )
  {
    let idx = this._endPoints.indexOf( endPoint );

    if ( idx >= 0 )
    {
      this._endPoints.splice( idx, 1 );
    }
  }

  /**
  * Get EndPoints registered with this Channel
  *
  * @return Array of EndPoints
  */
  public get endPoints(): EndPoint[]
  {
    return this._endPoints;
  }

  /**
  * Send a message to all listeners (except origin)
  *
  * @param origin - EndPoint that is sending the message
  * @param message - Message to be sent
  */
  public sendMessage( origin: EndPoint, message: Message<any> )
  {
    let isResponse = ( message.header && message.header.isResponse );

    if ( !this._active )
      return;

    this._endPoints.forEach( endPoint => {
      // Send to all listeners, except for originator ...
      if ( origin != endPoint )
      {
        if ( endPoint.direction != Direction.OUT || isResponse )
        {
          this._taskScheduler.queueTask( () => {
            endPoint.handleMessage( message, origin, this );
          } );
        }
      }
    });
  }
}
