
// THIS FILE IS GENERATED AUTOMATICALLY
// Dont edit this file by hand. 
// Either edit proofOfWorkerStub.js or edit the build script located in the wasm_build folder.



let scrypt;
let scryptPromise;
let wasm;

let working = false;
const batchSize = 8;

onmessage = function(e) {
  if(e.data.stop) {
    working = false;
    return;
  }

  const challengeBase64 = e.data.challenge;
  const workerId = e.data.workerId;
  if(!challengeBase64) {
    postMessage({
      type: "error", 
      challenge: challengeBase64,
      message: `challenge was not provided`
    });
  }
  working = true;
  let challengeJSON = null;
  let challenge = null;
  try {
    challengeJSON = atob(challengeBase64);
  } catch (err) {
    postMessage({
      type: "error", 
      challenge: challengeBase64,
      message: `couldn't decode challenge '${challengeBase64}' as base64: ${err}`
    });
  }
  try {
    challenge = JSON.parse(challengeJSON);
  } catch (err) {
    postMessage({
      type: "error", 
      challenge: challengeBase64,
      message: `couldn't parse challenge '${challengeJSON}' as json: ${err}`
    });
  }

  challenge = {
    cpuAndMemoryCost: challenge.N,
    blockSize:        challenge.r,
    paralellization:  challenge.p,
    keyLength:        challenge.klen,
    preimage:         challenge.i,
    difficulty:       challenge.d,
    difficultyLevel:  challenge.dl
  }

  const probabilityOfFailurePerAttempt = 1-(1/Math.pow(2, challenge.difficultyLevel));

  let i = workerId * Math.pow(2, challenge.difficultyLevel) * 1000;
  const hexPreimage = base64ToHex(challenge.preimage);
  let smallestHash = challenge.difficulty.split("").map(x => "f").join("");

  postMessage({
    type: "progress", 
    challenge: challengeBase64,
    attempts: 0,
    smallestHash: smallestHash,
    difficulty: challenge.difficulty,
    probabilityOfFailurePerAttempt: probabilityOfFailurePerAttempt
  });

  const doWork = () => {

    var j = 0;
    while(j < batchSize) {
      j++;
      i++;
  
      let nonceHex = i.toString(16);
      if((nonceHex.length % 2) == 1) {
        nonceHex = `0${nonceHex}`;
      }
      const hashHex = scrypt(
        nonceHex, 
        hexPreimage, 
        challenge.cpuAndMemoryCost, 
        challenge.blockSize, 
        challenge.paralellization, 
        challenge.keyLength
      );

      //console.log(i.toString(16), hashHex);
  
      const endOfHash = hashHex.substring(hashHex.length-challenge.difficulty.length);
      if(endOfHash < smallestHash) {
        smallestHash = endOfHash
      }
      if(endOfHash <= challenge.difficulty) {
        postMessage({
          type: "success", 
          challenge: challengeBase64,
          nonce: nonceHex,
          smallestHash: endOfHash,
          difficulty: challenge.difficulty
        });
        break
      }
    }

    postMessage({
      type: "progress", 
      challenge: challengeBase64,
      attempts: batchSize,
      smallestHash: smallestHash,
      difficulty: challenge.difficulty,
      probabilityOfFailurePerAttempt: probabilityOfFailurePerAttempt
    });

    if(working) {
      this.setTimeout(doWork, 1);
    }
  };

  if(wasm && scrypt) {
    doWork();
  } else {
    scryptPromise.then(() => {
      doWork();  
    });
  }
}

// https://stackoverflow.com/questions/39460182/decode-base64-to-hexadecimal-string-with-javascript
function base64ToHex(str) {
  const raw = atob(str);
  let result = '';
  for (let i = 0; i < raw.length; i++) {
    const hex = raw.charCodeAt(i).toString(16);
    result += (hex.length === 2 ? hex : '0' + hex);
  }
  return result;
}
let wasm_bindgen;
(function() {
    const __exports = {};
    let script_src;
    if (typeof document !== 'undefined' && document.currentScript !== null) {
        script_src = new URL(document.currentScript.src, location.href).toString();
    }

    let WASM_VECTOR_LEN = 0;

    let cachedUint8ArrayMemory0 = null;

    function getUint8ArrayMemory0() {
        if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
            cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
        }
        return cachedUint8ArrayMemory0;
    }

    const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

    const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
        ? function (arg, view) {
        return cachedTextEncoder.encodeInto(arg, view);
    }
        : function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    });

    function passStringToWasm0(arg, malloc, realloc) {

        if (realloc === undefined) {
            const buf = cachedTextEncoder.encode(arg);
            const ptr = malloc(buf.length, 1) >>> 0;
            getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
            WASM_VECTOR_LEN = buf.length;
            return ptr;
        }

        let len = arg.length;
        let ptr = malloc(len, 1) >>> 0;

        const mem = getUint8ArrayMemory0();

        let offset = 0;

        for (; offset < len; offset++) {
            const code = arg.charCodeAt(offset);
            if (code > 0x7F) break;
            mem[ptr + offset] = code;
        }

        if (offset !== len) {
            if (offset !== 0) {
                arg = arg.slice(offset);
            }
            ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
            const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
            const ret = encodeString(arg, view);

            offset += ret.written;
            ptr = realloc(ptr, len, offset, 1) >>> 0;
        }

        WASM_VECTOR_LEN = offset;
        return ptr;
    }

    const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

    if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

    function getStringFromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
    }
    /**
     * @param {string} password
     * @param {string} salt
     * @param {number} n
     * @param {number} r
     * @param {number} p
     * @param {number} dklen
     * @returns {string}
     */
    __exports.scrypt = function(password, salt, n, r, p, dklen) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.scrypt(ptr0, len0, ptr1, len1, n, r, p, dklen);
            deferred3_0 = ret[0];
            deferred3_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    };

    async function __wbg_load(module, imports) {
        if (typeof Response === 'function' && module instanceof Response) {
            if (typeof WebAssembly.instantiateStreaming === 'function') {
                try {
                    return await WebAssembly.instantiateStreaming(module, imports);

                } catch (e) {
                    if (module.headers.get('Content-Type') != 'application/wasm') {
                        console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                    } else {
                        throw e;
                    }
                }
            }

            const bytes = await module.arrayBuffer();
            return await WebAssembly.instantiate(bytes, imports);

        } else {
            const instance = await WebAssembly.instantiate(module, imports);

            if (instance instanceof WebAssembly.Instance) {
                return { instance, module };

            } else {
                return instance;
            }
        }
    }

    function __wbg_get_imports() {
        const imports = {};
        imports.wbg = {};
        imports.wbg.__wbindgen_init_externref_table = function() {
            const table = wasm.__wbindgen_export_0;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
            ;
        };

        return imports;
    }

    function __wbg_init_memory(imports, memory) {

    }

    function __wbg_finalize_init(instance, module) {
        wasm = instance.exports;
        __wbg_init.__wbindgen_wasm_module = module;
        cachedUint8ArrayMemory0 = null;


        wasm.__wbindgen_start();
        return wasm;
    }

    function initSync(module) {
        if (wasm !== undefined) return wasm;


        if (typeof module !== 'undefined') {
            if (Object.getPrototypeOf(module) === Object.prototype) {
                ({module} = module)
            } else {
                console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
            }
        }

        const imports = __wbg_get_imports();

        __wbg_init_memory(imports);

        if (!(module instanceof WebAssembly.Module)) {
            module = new WebAssembly.Module(module);
        }

        const instance = new WebAssembly.Instance(module, imports);

        return __wbg_finalize_init(instance, module);
    }

    async function __wbg_init(module_or_path) {
        if (wasm !== undefined) return wasm;


        if (typeof module_or_path !== 'undefined') {
            if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
                ({module_or_path} = module_or_path)
            } else {
                console.warn('using deprecated parameters for the initialization function; pass a single object instead')
            }
        }

        if (typeof module_or_path === 'undefined' && typeof script_src !== 'undefined') {
            module_or_path = script_src.replace(/\.js$/, '_bg.wasm');
        }
        const imports = __wbg_get_imports();

        if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
            module_or_path = fetch(module_or_path);
        }

        __wbg_init_memory(imports);

        const { instance, module } = await __wbg_load(await module_or_path, imports);

        return __wbg_finalize_init(instance, module);
    }

    wasm_bindgen = Object.assign(__wbg_init, { initSync }, __exports);

})();

scrypt = wasm_bindgen.scrypt;
scryptPromise = wasm_bindgen({module_or_path: "/static/scrypt.wasm"});


