import { TaskScheduler, EndPoint, Packet } from "./base-package";
import { OnEventDelegate, OnPacketDelegate, Direction } from "./end-point";

class EndPointEntry {
  endPoint: EndPoint;
  direction: Direction;
  eventListener: OnEventDelegate;
  packetListener: OnPacketDelegate;
}

export default class Channel
{
  connected;

  endPointRegistry: EndPointEntry[];
  taskScheduler: TaskScheduler;

  constructor()
  {
    this.connected = false;
    this.endPointRegistry = [];
    this.taskScheduler = null;
  }

  get isConnected(): boolean
  {
    return this.connected;
  }

  connect()
  {
    this.taskScheduler = new TaskScheduler();
    this.connected = true;
  }

  disconnect()
  {
    this.taskScheduler = null;
    this.connected = false;
  }

  addEndPoint( endPoint: EndPoint, eventListener: OnEventDelegate, packetListener: OnPacketDelegate )
  {
    let regEntry = {
      endPoint: endPoint,
      direction: endPoint.direction,
      eventListener: eventListener.bind( endPoint ),
      packetListener: packetListener.bind( endPoint ),
    };

    this.endPointRegistry.push( regEntry );
  }

  public removeEndPoint( endPoint: EndPoint )
  {
    for( let idx in this.endPointRegistry )
    {
      let regEntry = this.endPointRegistry[ idx ];

      if ( endPoint == regEntry.endPoint )
        delete this.endPointRegistry[ idx ]
    }
  }

  public getEndPoints(): EndPoint[]
  {
    var endPoints: EndPoint[] = [];

    this.endPointRegistry.forEach( regEntry => {
      endPoints.push( regEntry.endPoint );
    } );

    return endPoints;

  }
  public triggerEvent( origin: EndPoint, event: any )
  {
    if ( !this.connected )
      return;

    this.endPointRegistry.forEach( regEntry => {
      if ( origin != regEntry.endPoint )
      {
        if ( regEntry.eventListener && ( regEntry.direction != Direction.OUT ) )
        {
          this.taskScheduler.queueTask( () => {
            regEntry.eventListener( origin, event );
          } );
        }
      }
    });
  }

  public sendPacket( origin: EndPoint, packet: Packet )
  {
    if ( !this.connected )
      return;

    this.endPointRegistry.forEach( regEntry => {
      if ( origin != regEntry.endPoint )
      {
        if ( regEntry.packetListener && ( regEntry.direction != Direction.OUT ) )
        {
          this.taskScheduler.queueTask( () => {
            regEntry.packetListener( origin, packet );
          } );
        }
      }
    });
  }
}
