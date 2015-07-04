import { EndPoints } from './end-point';

export type InjectType = ( string[] | ( () => string[] ) );

export interface ComponentInterface
{
//  static $inject : InjectType;

  onCreate?( initialData: Object );
  onDestroy?();

  onStart?( endPoints: EndPoints );
  onStop?();
}
