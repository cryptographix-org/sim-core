import { EndPoints } from "./end-point";

export type InjectType = ( string[] | ( () => string[] ) );

interface ComponentInterface
{
//  static $inject : InjectType;

  onCreate?( initialData: Object );
  onDestroy?();

  onStart?( endPoints: EndPoints );
  onStop?();
}

export default ComponentInterface;
