import { Container, inject } from 'sim-core';

class C1
{

}

@inject()
class C2
{
  constructor( public c1: C1 ) {

  }
}

describe("DI Container", ()=> {
  it( "Must inject", () => {
    let jector = new Container();

    jector.registerSingleton( C1, C1 );

  });
});
