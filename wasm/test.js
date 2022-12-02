import init from "./pkg/krustology_wasm.js";
import * as kwasm from "./pkg/krustology_wasm.js";

function testDkg() {
    console.log("TEST DKG");

    // Setup.
    let ctx = new Uint8Array([1,2,3,4]);
    let aOthers = new Uint32Array([2, 3]);
    let bOthers = new Uint32Array([1, 3]);
    let cOthers = new Uint32Array([1, 2]);
    let ar0 = krust.frost_secp256k1_dkg_init(1, 2, ctx, aOthers);
    let br0 = krust.frost_secp256k1_dkg_init(2, 2, ctx, bOthers);
    let cr0 = krust.frost_secp256k1_dkg_init(3, 2, ctx, cOthers);
    console.log("round 0", ar0, br0, cr0);

    // Round 1.
    let aSecret = new Array(32).fill(0x7f);
    let bSecret = new Array(32).fill(0x7e);
    let cSecret = new Array(32).fill(0x7f); // not 0x7d
    let ao1 = krust.frost_secp256k1_dkg_r1(ar0, aSecret);
    let bo1 = krust.frost_secp256k1_dkg_r1(br0, bSecret);
    let co1 = krust.frost_secp256k1_dkg_r1(cr0, cSecret);
    console.log("round 1", ao1, bo1, co1);

    // Round 2.
    let aInBc = [[2, bo1.bcast], [3, co1.bcast]];
    let bInBc = [[1, ao1.bcast], [3, co1.bcast]];
    let cInBc = [[1, ao1.bcast], [2, bo1.bcast]];
    let aRecv = [[2, bo1.sends.get(1)], [3, co1.sends.get(1)]];
    let bRecv = [[1, ao1.sends.get(2)], [3, co1.sends.get(2)]];
    let cRecv = [[1, ao1.sends.get(3)], [2, bo1.sends.get(3)]];
    console.log("recvs", [aRecv, bRecv, cRecv]);
    let ao2 = krust.frost_secp256k1_dkg_r2(ao1.state, aInBc, aRecv);
    let bo2 = krust.frost_secp256k1_dkg_r2(bo1.state, bInBc, bRecv);
    let co2 = krust.frost_secp256k1_dkg_r2(co1.state, cInBc, cRecv);
    console.log("round 2", ao2, bo2, co2);

    let vk = krust.frost_secp256k1_export_bip340_pk(ao2.bcast);
    console.log(vk);
}

async function main() {
    let w = await init();
    window.krust = kwasm;
    window.krust.krustology_init();
    console.log('wasm!', w);

    testDkg();
}

main();
