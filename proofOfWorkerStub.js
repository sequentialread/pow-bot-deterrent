// IN ORDER FOR CHANGES TO THIS FILE TO "TAKE" AND BE USED IN THE APP, THE BUILD IN wasm_build HAS TO BE RE-RUN
// scrypt and scryptPromise will be filled out by js code that gets appended below this script by the wasm_build process

// --- snip ---



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
