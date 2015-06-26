/// <reference path="../../typings/forge.d.ts"/>
/// <reference path="../../typings/jsbn.d.ts"/>
import PublicKey from "./public-key";

var BN = forge.jsbn.BigInteger;

export default class CryptographicServiceProvider
{
  constructor()
  {
  }

  makePublicKey( m: string, e: string ): forge.rsa.PublicKey
  {
    let mod: jsbn.BigInteger = new forge.jsbn.BigInteger( m, 16 );
    let exp: jsbn.BigInteger = new forge.jsbn.BigInteger( e, 16 );

    let pk = forge.rsa.setPublicKey( mod, exp );

    console.log( pk.n );
    console.log( pk.e );

    return pk;
  }

  decrypt( cg: string, pk: forge.rsa.PublicKey ): string
  {
    //var bb = new forge.util.ByteBuffer( cg, 16 );

//    var xx = forge.rsa.decrypt( em, pk, true, false );
    var xx = pk.encrypt( cg, "RAW" );

    return xx;

  }
  static BN = forge.jsbn.BigInteger;
}
