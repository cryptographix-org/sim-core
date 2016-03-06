import { PortInfo } from './port-info';
import { StoreInfo } from './store-info';
import { ComponentInfo } from './component-info';
import { EndPoint, Direction } from '../messaging/end-point';
import { Protocol } from '../messaging/protocol';
import { Kind, KindConstructor } from '../kind/kind';

/**
* Builder for 'Component' metadata (static componentInfo)
*/
export class ComponentBuilder
{
  private ctor: ComponentConstructor;

  constructor( ctor: ComponentConstructor, name: string, description: string, category?: string ) {

    this.ctor = ctor;

    ctor.componentInfo = {
      name: name || ctor.name,
      description: description,
      detailLink: '',
      category: category,
      author: '',
      ports: {},
      stores: {},
      configKind: Kind,
      defaultConfig: {}
    };
  }

  public static init( ctor: ComponentConstructor, name: string, description: string, category?: string ): ComponentBuilder
  {
    let builder = new ComponentBuilder( ctor, name, description, category );

    return builder;
  }

  public config( configKind: KindConstructor, defaultConfig?: Kind ): this {

    this.ctor.componentInfo.configKind = configKind;
    this.ctor.componentInfo.defaultConfig = defaultConfig;

    return this;
  }

  public port( id: string, description: string, direction: Direction, opts?: { protocol?: Protocol<any>; count?: number; required?: boolean } ): this
  {
    opts = opts || {};

    this.ctor.componentInfo.ports[ id ] = {
      direction: direction,
      description: description,
      protocol: opts.protocol,
      count: opts.count,
      required: opts.required
    };

    return this;
  }
}

/**
* Components are runtime objects that execute within a Graph.
*
* A graph Node is a placeholder for the actual Component that
* will execute.
*
* This interface defines the standard methods and properties that a Component
* can optionally implement.
*/
export interface Component
{
  // Initialization and shutdown
  initialize?( config?: Kind ): EndPoint[];
  teardown?();

  // Running
  start?();
  stop?();

  // Pausing and continuing execution (without resetting ..)
  pause?();
  resume?();

  bindView?( view: any );
  unbindView?();
}

export interface ComponentConstructor
{
  new ( ...args ): Component;

  componentInfo?: ComponentInfo;
}
