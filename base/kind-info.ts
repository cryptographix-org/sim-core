import KindHelper from "./kind-helper";

///
/// @class KindInfo
///
/// Metadata about a 'Kind'
export default class KindInfo
{
  static $kindHelper: KindHelper = new KindHelper();

  title: string;

  description: string;

  "type": string;

  properties: {};
}
