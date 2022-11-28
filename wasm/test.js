import init from './pkg/krustology_wasm.js';

async function testMain() {
    let krust = await init();
    console.log('wasm!', krust.add(1, 2));
}

testMain();
