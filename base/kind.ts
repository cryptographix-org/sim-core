import { KindInfo } from "./base-package";

///
/// @interface Kind
///
/// Kind represents a serializable and inspectable data-type
/// implemented as a hash-map containing key-value pairs,
/// meta-data description of each key using a json-scheme
interface Kind
{
  kindInfo: KindInfo;
  properties: {};
}

export default Kind;
