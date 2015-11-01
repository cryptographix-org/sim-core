  import { ByteArray } from 'sim-core';

function isEqual(ba1, ba2) {
    let ok = ba1.length == ba2.length;
    if (ok) {
        for (let i = 0; ok && (i < ba1.length); ++i)
            ok = ok && (ba1.byteAt(i) == ba2.byteAt(i));
    }
    return ok;
}
describe('A ByteArray', () => {
    it('stores a sequence of bytes', () => {
        let bs = new ByteArray([0, 1, 2, 3, 4]);
        expect(bs.toString()).toBe("0001020304");
    });
    it('can be instanciated from an array of bytes', () => {
        let bs = new ByteArray([0, 1, 2, 3, 4]);
        expect(bs.toString()).toBe("0001020304");
        var bytes = [];
        for (let i = 0; i < 10000; ++i)
            bytes[i] = i & 0xff;
        bs = new ByteArray(bytes);
        expect(bs.length).toBe(10000);
    });
    it('can be compared to another', () => {
        let bs1 = new ByteArray([0, 1, 2, 3, 4]);
        let bs2 = new ByteArray("00 01 02 03 04", { format: "hex" });
        expect(isEqual(bs1, bs2)).toBe(true);
    });
});
