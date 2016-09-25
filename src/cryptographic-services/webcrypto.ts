import { ByteArray } from '../kind/byte-array';
import { CryptographicServiceProvider, CryptographicOperation, CryptographicService, CryptographicKeyService } from './cryptographic-service-registry';

declare var msrcrypto, crypto, window;

export class WebCryptoService implements CryptographicService, CryptographicKeyService {
  protected crypto: SubtleCrypto;

  constructor() {
  }

  static _subtle: SubtleCrypto;
  static get subtle(): SubtleCrypto {
    let subtle = WebCryptoService._subtle
//      || ( crypto && crypto.subtle )
      || ( window && window.crypto && window.crypto.subtle )
//      || msrcrypto
      ;

    if ( !WebCryptoService._subtle )
       WebCryptoService._subtle = subtle;

    return subtle;
  }

  encrypt( algorithm: string | Algorithm, key: CryptoKey, data: ByteArray ): Promise<ByteArray> {
    return new Promise<ByteArray>((resolve, reject) => {
      WebCryptoService.subtle.encrypt(algorithm, key, data.backingArray)
        .then((res) => { resolve(new ByteArray(res)); },
              (err) => { reject(err); });
    });
  }

  decrypt(algorithm: string | Algorithm, key: CryptoKey, data: ByteArray): Promise<ByteArray> {
    return new Promise<ByteArray>((resolve, reject) => {
      WebCryptoService.subtle.decrypt(algorithm, key, data.backingArray)
        .then((res) => { resolve(new ByteArray(res)); },
              (err) => { reject(err); });
    });
  }

  digest(algorithm: string | Algorithm, data: ByteArray): any {
    return new Promise<ByteArray>((resolve, reject) => {
      WebCryptoService.subtle.digest(algorithm, data.backingArray)
       .then((res) => { resolve(new ByteArray(res)); },
             (err) => { reject(err); });
    });
  }

  exportKey( format: string, key: CryptoKey ): Promise<ByteArray | JsonWebKey> {
    return new Promise<ByteArray | JsonWebKey>((resolve, reject) => {
      // TODO: support JsonWebKey
      WebCryptoService.subtle.exportKey(format, key)
        .then((res) => {
          if ( res instanceof ArrayBuffer )
            resolve( new ByteArray( res ) );
          else
            resolve( res as JsonWebKey );
        }, (err) => { reject(err); });
    });
  }

  generateKey( algorithm: string | Algorithm, extractable: boolean, keyUsages: string[] ): Promise<CryptoKey | CryptoKeyPair> {
    return new Promise<CryptoKey | CryptoKeyPair>((resolve, reject) => {

   });
  }

  importKey(format: string, keyData: ByteArray, algorithm: string | Algorithm, extractable: boolean, keyUsages: string[]): Promise<CryptoKey> {
    return new Promise<CryptoKey>((resolve, reject) => {
      WebCryptoService.subtle.importKey(format, keyData.backingArray, algorithm, extractable, keyUsages)
        .then((res) => { resolve(res); },
              (err) => { reject(err); });
   });
  }

  sign(algorithm: string | Algorithm, key: CryptoKey, data: ByteArray): Promise<ByteArray> {
    return new Promise<ByteArray>((resolve, reject) => {
      // cast algorithm to string, since sign prototype is restrictive
      WebCryptoService.subtle.sign(algorithm as string, key, data.backingArray)
        .then((res) => { resolve(new ByteArray(res)); },
              (err) => { reject(err); });
    });
  }

  verify(algorithm: string | Algorithm, key: CryptoKey, signature: ByteArray, data: ByteArray): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      // cast algorithm to string, since sign prototype is restrictive
      WebCryptoService.subtle.verify( algorithm as string, key, signature.backingArray, data.backingArray)
        .then((res) => { resolve( res ); },
              (err) => { reject(err); });
    });
  }
}

/*class SHA1CryptoService implements CryptographicService {
  digest( algorithm: string | Algorithm, data: ByteArray ): Promise<ByteArray> {
    return new Promise<ByteArray>((resolve, reject) => {
      // TODO: Implement SHA-1
      msrcrypto.digest(algorithm, data.backingArray)
       .then((res) => { resolve(new ByteArray(res)); })
       .catch((err) => { reject(err); });
    });
  }
}

CryptographicServiceProvider.registerService( 'SHA-1', SHA1CryptoService, [ CryptographicOperation.DIGEST ] );

CryptographicServiceProvider.registerService( 'SHA-256', WebCryptoService, [ CryptographicOperation.DIGEST ] );
CryptographicServiceProvider.registerService( 'SHA-512', WebCryptoService, [ CryptographicOperation.DIGEST ] );
*/

if ( WebCryptoService.subtle ) {
  CryptographicServiceProvider.registerService( 'AES-CBC', WebCryptoService, [ CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT ] );
  CryptographicServiceProvider.registerService( 'AES-GCM', WebCryptoService, [ CryptographicOperation.ENCRYPT, CryptographicOperation.DECRYPT ] );
  //CryptographicServiceProvider.registerService( 'RSASSA-XYZ', WebCryptoService );

}
