import { EndPoints } from '../message-passing/end-point';

export type InjectType = ( string[] | ( () => string[] ) );

export interface Component
{
//  static $inject : InjectType;

  onCreate?( initialData: Object );
  onDestroy?();

  onStart?( endPoints: EndPoints );
  onStop?();
}
