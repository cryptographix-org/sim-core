import { Component, ComponentConstructor } from './component';
import { ComponentContext } from './component-context';
import { ModuleLoader } from './module-loader';

import { Container } from '../dependency-injection/container';
import { EndPointCollection } from '../messaging/end-point';

export class ComponentFactory {
  private loader: ModuleLoader;
  container: Container;

  constructor( loader: ModuleLoader, container: Container ) {
    this.loader = loader;
    this.container = container;
  }

  createContext( id: string ): ComponentContext
  {
    let context = new ComponentContext( this, id );

    return context;
  }

  loadComponent( id: string ): Promise<Component>
  {
    let createComponent = function( ctor: ComponentConstructor ): Component
    {
      let newInstance: Component = null;
      let injects: string[] = [];

/*      if ( componentType.$inject instanceof Array )
        injects = <string[]>componentType.$inject;
      else if ( typeof componentType.$inject == "function" )
        injects = ( <()=>string[]> componentType.$inject )();*/

      // if ( injects && injects.length > 0 )
      //   ;

      newInstance = new ctor( );
      //if ( newInstance.onCreate )
      //  newInstance.onCreate( initialData );

      return newInstance;
    }

    let ctor: ComponentConstructor = this.get( id );

    if ( ctor )
    {
      return new Promise<Component>( (resolve, reject) => {
        resolve( createComponent( ctor ) );
      });
    }

    return null;
  }

  components: Map<string, ComponentConstructor>;
  get( id: string ): ComponentConstructor {
    return this.components.get( id );
  }
  set( id: string, type: ComponentConstructor ) {
    this.components.set( id, type );
  }
}
