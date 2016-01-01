///
/// @class KindHelper
///
/// Builder for 'Kind' metadata
export class KindHelper
{
  private kindInfo: KindInfo;

  public init( kindName: string, description: string ): KindHelper
  {
    this.kindInfo = {
      //"$schema": "http://json-schema.org/draft-04/schema#",
      title: kindName,
      description: description,
      type: "object",
      properties: {}
    };

    return this;
  }

  public field( name: string, description: string, dataType: string, opts? ): KindHelper
  {
    this.kindInfo.properties[ name ] = {
      description: description,
      type: dataType
    };

    return this;
  }

  seal(): KindInfo
  {
    let ki = this.kindInfo;

    this.kindInfo = new KindInfo();

    return ki;
  }
}

/*  makeKind( kindConstructor, kindOptions )
  {
    var $kindInfo = kindOptions.kindInfo;

    kindConstructor.$kindName = $kindInfo.title;

    var keys = Object.keys( kindOptions.kindMethods );

    for ( var j = 0, jj = keys.length; j < jj; j++ ) {
      var key = keys[j];
      kindConstructor[key] = kindOptions.kindMethods[key];
    }

    kindConstructor.getKindInfo = kindConstructor.prototype.getKindInfo = function getKindInfo() {
      return $kindInfo;
    }

    return kindConstructor;
  }
*/
///
/// @class KindInfo
///
/// Metadata about a 'Kind'
export class KindInfo
{
  static $kindHelper: KindHelper = new KindHelper();

  title: string;

  description: string;

  "type": string;

  properties: {};
}

///
/// @interface Kind
///
/// Kind represents a serializable and inspectable data-type
/// implemented as a hash-map containing key-value pairs,
/// meta-data description of each key using a json-scheme
export interface Kind
{
  kindInfo: KindInfo;

  properties: {};
}
