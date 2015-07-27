/// <xreference path="../../types/forge/forge.d.ts"/>
/// <xreference path="../../types/jsbn/jsbn.d.ts"/>
import { PublicKey } from './public-key';
import * as forge from 'forge';
import * as jsbn from 'jsbn';

var BN = forge.jsbn.BigInteger;

export class CryptographicServiceProvider
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
