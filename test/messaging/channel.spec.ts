import { Channel, EndPoint, Message, Direction } from 'cryptographix-sim-core';

class IntegerMessage extends Message<number>
{
  constructor( value: number )
  {
    super( undefined, value );
  }
}

describe('A Channel', ()=> {
  describe('can be active or inactive', ()=> {
    let ch = new Channel();

    it('is initially inactive', ()=> {
      expect( ch.active ).toBe( false );
    });

    it('can be activated', ()=> {
      expect( ch.active ).toBe( false );
      ch.activate();
      expect( ch.active ).toBe( true );
      ch.activate();
      expect( ch.active ).toBe( true );
    });

    it('can be deactivated', ()=> {
      expect( ch.active ).toBe( true );
      ch.deactivate();
      expect( ch.active ).toBe( false );
      ch.deactivate();
      expect( ch.active ).toBe( false );
    });
  });

  describe('has a registry of EndPoints', ()=> {
    let ch = new Channel();
    var ep1 = new EndPoint('ep1');
    var ep2 = new EndPoint('ep2');

    it( 'to which EndPoints can be added', ()=> {
      // add an EndPoint
      ch.addEndPoint( ep1 );
      expect( ch.endPoints.length ).toBe( 1 );

      // add another
      ch.addEndPoint( ep2 );
      expect( ch.endPoints.length ).toBe( 2 );
    });

    it( '... and removed', ()=> {
      // remove first EndPoint
      ch.removeEndPoint( ep1 );
      expect( ch.endPoints ).toContain( ep2 );

      ch.removeEndPoint( ep2 );
      expect( ch.endPoints.length ).toBe( 0 );
    });

    it( '... even when Channel is activated', ()=> {
      ch.activate();
      expect( ch.active ).toBe( true );

      ch.addEndPoint( new EndPoint('epx') );
      ch.addEndPoint( new EndPoint('epx') );

      ch.addEndPoint( ep1 );
      expect( ch.endPoints ).toContain( ep1 );
      expect( ch.endPoints.length ).toBe( 3 );

      ch.removeEndPoint( ep1 );
      expect( ch.endPoints ).not.toContain( ep1 );

      ch.shutdown();
      expect( ch.endPoints.length ).toBe( 0 );
    });

  });

  describe('communicates between endpoints', ()=> {
    let ch = new Channel();
    var ep1 = new EndPoint( 'ep1', Direction.OUT );
    var ep2 = new EndPoint( 'ep2', Direction.IN );

    ep1.attach( ch );
    ep2.attach( ch );
    ch.activate();

    it( 'can bounce messages', (done) => {
      ep2.onMessage( (m: Message<any>, ep: EndPoint ) => { m.header.isResponse = true; ep2.sendMessage( m ); } );
      ep1.sendMessage( new IntegerMessage(100) );
      ep1.onMessage( (m: Message<any>) => { done() } );
    } );

  });


})
