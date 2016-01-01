import { Component, InjectType } from './component';
import { ComponentContext } from './component-context';
import { ModuleLoader } from './module-loader';

import { Container } from '../dependency-injection/container';
import { EndPoints } from '../message-passing/end-point';

export class xComponent implements Component
{
  static $inject : InjectType;

  onCreate( initialData: Object )
  {

  }

  onDestroy()
  {

  }

  onStart( endPoints: EndPoints )
  {

  }

  onPause()
  {

  }

  onResume()
  {

  }

  onStop()
  {

  }
}
export type ComponentType = typeof xComponent;

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

  loadComponent( id: string ): Promise<ComponentType>
  {
    let createComponent = function( componentType: ComponentType ): Component
    {
      let newInstance: Component = null;
      let injects: string[] = [];

      if ( componentType.$inject instanceof Array )
        injects = <string[]>componentType.$inject;
      else if ( typeof componentType.$inject == "function" )
        injects = ( <()=>string[]> componentType.$inject )();

      // if ( injects && injects.length > 0 )
      //   ;

      newInstance = new componentType( );
      //if ( newInstance.onCreate )
      //  newInstance.onCreate( initialData );

      return newInstance;
    }

    let componentType: ComponentType = this.get( id );

    if ( componentType )
    {
      return new Promise<Component>( (resolve, reject) => {
        resolve( createComponent( componentType ) );
      });
    }

    return new Promise<ComponentType>( (resolve, reject) => {
      resolve( this.get( name ) );
    });
  }

  components: Map<string, ComponentType>;
  get( id: string ): ComponentType {
    return this.components.get( id );
  }
  set( id: string, type: ComponentType ) {
    this.components.set( id, type );
  }
}
