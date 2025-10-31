#!/bin/bash -e

if [ ! -f build_wasm.sh ]; then
  printf "Please run this script from the wasm_build folder.\n"
fi

if [ ! -d scrypt-wasm ]; then
  printf "Cloning https://github.com/MyEtherWallet/scrypt-wasm... \n"
  git clone https://github.com/MyEtherWallet/scrypt-wasm
fi

cd scrypt-wasm

rust_is_installed="$(which rustc | wc -l)"

if [ "$rust_is_installed" == "0" ]; then
  printf "rust language compilers & tools will need to be installed."
  printf "using rustup.rs: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh \n"
  read -p "is this ok? [y] " -n 1 -r
  printf "\n"
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  else
      printf "exiting due to no rust compiler"
      exit 1
  fi
fi

if [ ! -d pkg ]; then
  printf "running Makefile for MyEtherWallet/scrypt-wasm... \n"
	rustup target add wasm32-unknown-unknown
	cargo install wasm-pack --force
	wasm-pack build --target no-modules
fi

cd ../

cp scrypt-wasm/pkg/scrypt_wasm_bg.wasm ../static/scrypt.wasm

echo '
// THIS FILE IS GENERATED AUTOMATICALLY
// Dont edit this file by hand. 
// Either edit proofOfWorkerStub.js or edit the build script located in the wasm_build folder.
' > ../static/proofOfWorker.js

cat ../proofOfWorkerStub.js | tail -n +6  >> ../static/proofOfWorker.js

# wasm was defined at the top of proofOfWorker.js, so don't define it again.
cat scrypt-wasm/pkg/scrypt_wasm.js  | grep -v 'let wasm = ' >> ../static/proofOfWorker.js

# see: https://rustwasm.github.io/docs/wasm-bindgen/examples/without-a-bundler.html
echo '
scrypt = wasm_bindgen.scrypt;
scryptPromise = wasm_bindgen({module_or_path: "/static/scrypt.wasm"});

' >> ../static/proofOfWorker.js




## -----------------------------------------------------------



## The proofOfWorker_CrossOrigin.js version embeds the WebAssembly binary into the WebWorker script,
## This is neccesary when the pow-bot-deterrent static assets can't be hosted on the same origin
## However, it also means that the site can't use a content-security-policy which restricts external javascript


echo '
// THIS FILE IS GENERATED AUTOMATICALLY
// Dont edit this file by hand. 
// Either edit proofOfWorkerStub.js or edit the build script located in the wasm_build folder.
' > ../static/proofOfWorker_CrossOrigin.js

cat ../proofOfWorkerStub.js | tail -n +6  >> ../static/proofOfWorker_CrossOrigin.js

# wasm was defined at the top of proofOfWorker.js, so don't define it again.
cat scrypt-wasm/pkg/scrypt_wasm.js  | grep -v 'let wasm = ' >> ../static/proofOfWorker_CrossOrigin.js

# see: https://rustwasm.github.io/docs/wasm-bindgen/examples/without-a-bundler.html
echo '


// https://caniuse.com/mdn-javascript_builtins_uint8array_frombase64 its at 60% in oct 2025
if (!Uint8Array.fromBase64) {
  Uint8Array.fromBase64 = function(base64String) {
    const binaryString = atob(base64String);
    const toReturn = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      toReturn[i] = binaryString.charCodeAt(i);
    }
    return toReturn;
  };
}

const base64WASM = "'"$(cat ../static/scrypt.wasm | base64 -w 0)"'";

const wasmBinary = Uint8Array.fromBase64(base64WASM);


scrypt = wasm_bindgen.scrypt;
scryptPromise = wasm_bindgen({module_or_path: wasmBinary});

' >> ../static/proofOfWorker_CrossOrigin.js






