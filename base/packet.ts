import Kind from '../base/kind';
import KindInfo from "./kind-info";

export default class Packet
{
  private kind: Kind;

  constructor( kind: Kind )
  {
    this.kind = kind;
  }

}
