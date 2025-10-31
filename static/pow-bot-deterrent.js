(function(window, document, undefined){

  const numberOfWebWorkersToCreate = 4;

  window.powBotDeterrentReset = () => {
    window.powBotDeterrentInitDone = false;
  };

  const trimSlashes = x => x.replace(/^\/|\/$/g, '');

  window.powBotDeterrentInit = () => {
    if(window.powBotDeterrentInitDone) {
      console.error("powBotDeterrentInit was called twice!");
      return
    }
    window.powBotDeterrentInitDone = true;

    const challenges = Array.from(document.querySelectorAll("[data-pow-bot-deterrent-challenge]"));
    const challengesMap = {};
    let staticAssetsCrossOriginURL = "";
    let staticAssetsPath = trimSlashes("/pow-bot-deterrent-static/")
    let proofOfWorker = { postMessage: () => console.error("error: proofOfWorker was never loaded. ") };

    challenges.forEach(element => {
      if(element.dataset.powBotDeterrentStaticAssetsCrossOriginUrl) {
        staticAssetsCrossOriginURL = trimSlashes(element.dataset.powBotDeterrentStaticAssetsCrossOriginUrl);
      } else if(element.dataset.powBotDeterrentStaticAssetsPath) {
        staticAssetsPath = trimSlashes(element.dataset.powBotDeterrentStaticAssetsPath);
      }

      if(!element.dataset.powBotDeterrentCallback) {
        console.error("error: element with data-pow-bot-deterrent-challenge property is missing the data-pow-bot-deterrent-callback property");
        return
      }

      if(typeof element.dataset.powBotDeterrentCallback != "string") {
        console.error("error: data-pow-bot-deterrent-callback property should be of type 'string'");
        return
      }

      const callback = getCallbackFromGlobalNamespace(element.dataset.powBotDeterrentCallback);
      if(!callback) {
        console.warn(`warning: data-pow-bot-deterrent-callback '${element.dataset.powBotDeterrentCallback}' `
                     + "is not defined in the global namespace yet. It had better be defined by the time it's called!");
      }
      
  
      let form = null;
      let parent = element.parentElement;
      let sanity = 1000;
      while(parent && !form && sanity > 0) {
        sanity--;
        if(parent.tagName.toLowerCase() == "form") {
          form = parent
        }
        parent = parent.parentElement
      }
      if(!form) {
        console.error("error: element with data-pow-bot-deterrent-challenge property was not inside a form element");
        //todo
      }


      let cssIsAlreadyLoaded;
      if(staticAssetsCrossOriginURL) {
        cssIsAlreadyLoaded = document.querySelector(`link[href='/${staticAssetsPath}/pow-bot-deterrent.css']`);
      } else {
        cssIsAlreadyLoaded = document.querySelector(`link[href='${staticAssetsCrossOriginURL}/pow-bot-deterrent.css']`);
      }

      cssIsAlreadyLoaded = cssIsAlreadyLoaded || Array.from(document.styleSheets).some(x => {
        try {
          return Array.from(x.rules).some(x => x.selectorText == ".pow-bot-deterrent")
        } catch (err) {
          return false
        }
      });

      if(!cssIsAlreadyLoaded) {
        const stylesheet = createElement(document.head, "link", {
          "rel": "stylesheet",
          "charset": "utf8",
        });
        stylesheet.onload = () => renderProgressInfo(element);
        stylesheet.setAttribute("href", `${staticAssetsCrossOriginURL || staticAssetsPath}/pow-bot-deterrent.css`);
      } else {
        renderProgressInfo(element);
      }
  
      window.powBotDeterrentTrigger = () => {
        
        const challenge = element.dataset.powBotDeterrentChallenge;
        if(!challengesMap[challenge]) {
          challengesMap[challenge] = {
            element: element,
            attempts: 0,
            startTime: new Date().getTime(),
          };
          const mainElement = element.querySelector(".pow-bot-deterrent");
          mainElement.style.display = "inline-block";

          const progressBarContainer = element.querySelector(".pow-bot-deterrent-progress-bar-container");
          // if progressBarContainer is null, that means that WASM is disabled
          if(!progressBarContainer) {
            return;
          }
          progressBarContainer.style.display = "block";
          const gears = element.querySelector(".pow-gears-icon");
          gears.style.display = "block";

          challengesMap[challenge].updateProgressInterval = setInterval(() => {
            // calculate the probability of finding a valid nonce after n tries
            if(challengesMap[challenge].probabilityOfFailurePerAttempt && !challengesMap[challenge].done) {
              const probabilityOfSuccessSoFar = 1-Math.pow(
                challengesMap[challenge].probabilityOfFailurePerAttempt, 
                challengesMap[challenge].attempts
              );
              const element = challengesMap[challenge].element;
              const progressBar = element.querySelector(".pow-bot-deterrent-progress-bar");
              const bestHashElement = element.querySelector(".pow-bot-deterrent-best-hash");
              bestHashElement.textContent = getHashProgressText(challengesMap[challenge]);
              progressBar.style.width = `${probabilityOfSuccessSoFar*100}%`;
            }
          }, 500);


          proofOfWorker.postMessage({challenge: challenge});
        }
      };
  
      const inputElements = Array.from(form.querySelectorAll("input"))
                      .concat(Array.from(form.querySelectorAll("textarea")));
      
      inputElements.forEach(inputElement => {
        inputElement.onchange = () => window.powBotDeterrentTrigger();
        inputElement.onkeydown = () => window.powBotDeterrentTrigger();
      });
    });
  
    if (!window.Worker) {
      console.error("error: webworker is not support");
      //todo
    }

    let webWorkerPointerDataURL = null;
    if(staticAssetsCrossOriginURL != "") {
      // https://stackoverflow.com/questions/21913673/execute-web-worker-from-different-origin/62914052#62914052
      const webWorkerCrossOriginURL = `${staticAssetsCrossOriginURL}/proofOfWorker_CrossOrigin.js`;

      webWorkerPointerDataURL = URL.createObjectURL( 
        new Blob(
          [ `importScripts( "${ webWorkerCrossOriginURL }" );` ], 
          { type: "text/javascript" }
        )
      );
    }

    let webWorkers;
    webWorkers = [...Array(numberOfWebWorkersToCreate)].map((_, i) => {
      let webWorker;
      if(staticAssetsCrossOriginURL != "") {
        webWorker = new Worker(webWorkerPointerDataURL);
      } else {
        webWorker = new Worker(`/${staticAssetsPath}/proofOfWorker.js?v=2`);
      }
      webWorker.onmessage = function(e) {
        const challengeState = challengesMap[e.data.challenge]
        if(!challengeState) {
          console.error(`error: webworker sent message with unknown challenge '${e.data.challenge}'`);
        }
        if(e.data.type == "progress") {
          challengeState.difficulty = e.data.difficulty;
          challengeState.probabilityOfFailurePerAttempt = e.data.probabilityOfFailurePerAttempt;
          if(!challengeState.smallestHash || challengeState.smallestHash > e.data.smallestHash) {
            challengeState.smallestHash = e.data.smallestHash;
          }
          challengeState.attempts += e.data.attempts;
        } else if(e.data.type == "success") {
          if(!challengeState.done) {
            challengeState.done = true;
            clearInterval(challengeState.updateProgressInterval);

            const element = challengeState.element;
            const progressBar = element.querySelector(".pow-bot-deterrent-progress-bar");
            const checkmark = element.querySelector(".pow-checkmark-icon");
            const gears = element.querySelector(".pow-gears-icon");
            const bestHashElement = element.querySelector(".pow-bot-deterrent-best-hash");
            const description = element.querySelector(".pow-bot-deterrent-description");
            challengeState.smallestHash = e.data.smallestHash;
            bestHashElement.textContent = getHashProgressText(challengeState);
            bestHashElement.classList.add("pow-bot-deterrent-best-hash-done");
            checkmark.style.display = "block";
            checkmark.style.animationPlayState = "running";
            gears.style.display = "none";
            progressBar.style.width = "100%";

            description.innerHTML = "";
            createElement(
              description, 
              "a", 
              {"href": "https://en.wikipedia.org/wiki/Proof_of_work"}, 
              "PoW"
            );
            appendFragment(description, " complete, you may continue.");
            createElement(description, "br");
            appendFragment(description, "Privacy-respecting anti-spam measure.");
            
            webWorkers.forEach(x => x.postMessage({stop: "STOP"}));

            const callback = getCallbackFromGlobalNamespace(element.dataset.powBotDeterrentCallback);
            if(!callback) {
              console.error(`error: data-pow-bot-deterrent-callback '${element.dataset.powBotDeterrentCallback}' `
                           + "is not defined in the global namespace!");
            } else {
              console.log(`firing callback for challenge ${e.data.challenge} w/ nonce ${e.data.nonce}, smallestHash: ${e.data.smallestHash}, difficulty: ${e.data.difficulty}`);
              callback(e.data.nonce);
            }
          } else {
            console.log("success recieved twice");
          }
        } else if(e.data.type == "error") {
          console.error(`error: webworker errored out: '${e.data.message}'`);
        } else {
          console.error(`error: webworker sent message with unknown type '${e.data.type}'`);
        }
      };
      return webWorker;
    });

    proofOfWorker = { 
      postMessage: arg => webWorkers.forEach((x, i) => {
        x.postMessage({ ...arg, workerId: i })
      })
    };

    window.powBotDeterrentReset = () => {
      window.powBotDeterrentInitDone = false;
      webWorkers.forEach(x => x.terminate());
    };
  };

  const challenges = Array.from(document.querySelectorAll("[data-pow-bot-deterrent-challenge]"));
  if(challenges.length) {
    window.powBotDeterrentInit();
  }
  
  function getCallbackFromGlobalNamespace(callbackString) {
    const callbackPath = callbackString.split(".");
    let context = window;
    callbackPath.forEach(pathElement => {
      if(!context[pathElement]) {
        return null;
      } else {
        context = context[pathElement];
      }
    });

    return context;
  }

  function getHashProgressText(challengeState) {
    const durationSeconds = ((new Date().getTime()) - challengeState.startTime)/1000;
    let hashesPerSecond = '[...]';
    if (durationSeconds > 1) {
      hashesPerSecondFloat = challengeState.attempts / durationSeconds;
      hashesPerSecond = `[${leftPad(Math.round(hashesPerSecondFloat), 3)}h/s]`;
    }

    return `${hashesPerSecond} ${challengeState.smallestHash} < ${challengeState.difficulty}`;
  }

  function leftPad (str, max) {
    str = str.toString();
    return str.length < max ? leftPad(" " + str, max) : str;
  }

  function renderProgressInfo(parent) {

    const svgXMLNS = "http://www.w3.org/2000/svg";
    const xmlnsXMLNS = 'http://www.w3.org/2000/xmlns/';
    const xmlSpaceXMLNS = 'http://www.w3.org/XML/1998/namespace';

    parent.innerHTML = "";

    const main = createElement(parent, "div", {"class": "pow-bot-deterrent pow-bot-deterrent-hidden"});
    const mainRow = createElement(main, "div", {"class": "pow-bot-deterrent-row"});
    const mainColumn = createElement(mainRow, "div");
    const headerLink = createElement(
      mainColumn, 
      "a", 
      {
        "class": "pow-bot-deterrent-link",
        "href": "https://git.sequentialread.com/forest/pow-bot-deterrent",
        "target": "_blank"
      }, 
      "💥PoW! "
    );
    createElement(headerLink, "span", null, "Bot Deterrent");
    const description = createElement(mainColumn, "div", {"class": "pow-bot-deterrent-description"});

    if (typeof WebAssembly === 'undefined') {
      appendFragment(description, "Browser Compatibility Issue (WebAssembly)");

      const steps = createElement(description, "ol");
      const firstStep = createElement(steps, "li");
      appendFragment(firstStep, 'Click the "Site Settings" Button to the left of the URL. It should look like this: ');
      const settingsIcon = createElementNS(firstStep, svgXMLNS, "svg", { 
        "xmlns": [xmlnsXMLNS, svgXMLNS],
        "viewBox": "0 2 25 25",
      });
      settingsIcon.style.display = 'inline';
      settingsIcon.style.width = '5vw';
      settingsIcon.style.height = '5vw';
      settingsIcon.style.position = 'relative';
      settingsIcon.style.top = '1.5vw';
      settingsIcon.style.marginTop = '-2vw';
      createElementNS(settingsIcon, svgXMLNS, "circle", {cx: "6", cy: "10", stroke:"#ffffff", fill:"#ffffff", "stroke-width":"5", r:"3"});
      createElementNS(settingsIcon, svgXMLNS, "circle", {cx: "6", cy: "10", stroke:"#000000", fill:"none", "stroke-width":"2", r:"3"});
      createElementNS(settingsIcon, svgXMLNS, "line", {x1:"14", y1:"10", x2:"21", y2:"10", stroke:"#ffffff", "stroke-width":"5", "stroke-linecap":"round"});
      createElementNS(settingsIcon, svgXMLNS, "line", {x1:"14", y1:"10", x2:"21", y2:"10", stroke:"#000000", "stroke-width":"2", "stroke-linecap":"round"});
      createElementNS(settingsIcon, svgXMLNS, "circle", {cx: "19", cy: "20", stroke:"#ffffff", fill:"#ffffff", "stroke-width":"5", r:"3"});
      createElementNS(settingsIcon, svgXMLNS, "circle", {cx: "19", cy: "20", stroke:"#000000", fill:"none", "stroke-width":"2", r:"3"});
      createElementNS(settingsIcon, svgXMLNS, "line", {x1:"4", y1:"20", x2:"11", y2:"20", stroke:"#ffffff", "stroke-width":"5", "stroke-linecap":"round"});
      createElementNS(settingsIcon, svgXMLNS, "line", {x1:"4", y1:"20", x2:"11", y2:"20", stroke:"#000000", "stroke-width":"2", "stroke-linecap":"round"});

      createElement(steps, "li", {}, 'Click on "Permissions"');
      createElement(steps, "li", {}, 'Enable "JavaScript JIT"');

      appendFragment(description, `JavaScript Just In Time compilation is disabled on some privacy-focused web browsers, like on GrapheneOS.
                                   This site requires it for the hash function we use to stick it to the bots.  
                                   Sorry for the inconvenience.`);

    } else {
      appendFragment(description, "Creating ");
      createElement(
        description, 
        "a", 
        { "href": "https://en.wikipedia.org/wiki/Proof_of_work", "target": "_blank" }, 
        "Proof of Work"
      );
      appendFragment(description, ". ");
      createElement(description, "br");
      appendFragment(description, "Privacy-respecting anti-spam measure.");
      const bestHashContainer = createElement(mainRow, "div");
      createElement(bestHashContainer, "div", {"class": "pow-bot-deterrent-best-hash"}, "loading...");
      const progressBarContainer = createElement(main, "div", {
        "class": "pow-bot-deterrent-progress-bar-container pow-bot-deterrent-hidden"
      });
      createElement(progressBarContainer, "div", {"class": "pow-bot-deterrent-progress-bar"});
      const iconContainer = createElement(mainRow, "div", {"class": "pow-bot-deterrent-icon-container"});
      
      
      const checkmarkIcon = createElementNS(iconContainer, svgXMLNS, "svg", { 
        "xmlns": [xmlnsXMLNS, svgXMLNS],
        "xml:space": [xmlSpaceXMLNS, 'preserve'],
        "version": "1.1",
        "viewBox": "0 0 512 512",
        "class": "pow-checkmark-icon pow-bot-deterrent-icon pow-bot-deterrent-hidden"
      });
      createElementNS(checkmarkIcon, svgXMLNS, "polyline", {
        "class": "pow-checkmark-icon-checkmark",
        "points": "444,110 206,343 120,252" 
      });
      createElementNS(checkmarkIcon, svgXMLNS, "polyline", {
        "class": "pow-checkmark-icon-border",
        "points": "240,130 30,130 30,470 370,470 370,350" 
      });

      const gearsIcon = createElementNS(iconContainer, svgXMLNS, "svg", { 
        "xmlns": [xmlnsXMLNS, svgXMLNS],
        "xml:space": [xmlSpaceXMLNS, 'preserve'],
        "version": "1.1",
        "viewBox": "-30 -5 250 223",
        "class": "pow-gears-icon pow-bot-deterrent-icon pow-bot-deterrent-hidden"
      });
      createElementNS(gearsIcon, svgXMLNS, "path", { 
        "class": "pow-gears-icon-gear-large",
        "d": "M113.595,133.642l-5.932-13.169c5.655-4.151,10.512-9.315,14.307-15.209l13.507,5.118c2.583,0.979,5.469-0.322,6.447-2.904	l4.964-13.103c0.47-1.24,0.428-2.616-0.117-3.825c-0.545-1.209-1.547-2.152-2.788-2.622l-13.507-5.118	c1.064-6.93,0.848-14.014-0.637-20.871l13.169-5.932c1.209-0.545,2.152-1.547,2.622-2.788c0.47-1.24,0.428-2.616-0.117-3.825	l-5.755-12.775c-1.134-2.518-4.096-3.638-6.612-2.505l-13.169,5.932c-4.151-5.655-9.315-10.512-15.209-14.307l5.118-13.507	c0.978-2.582-0.322-5.469-2.904-6.447L93.88,0.82c-1.239-0.469-2.615-0.428-3.825,0.117c-1.209,0.545-2.152,1.547-2.622,2.788	l-5.117,13.506c-6.937-1.07-14.033-0.849-20.872,0.636L55.513,4.699c-0.545-1.209-1.547-2.152-2.788-2.622	c-1.239-0.469-2.616-0.428-3.825,0.117L36.124,7.949c-2.518,1.134-3.639,4.094-2.505,6.612l5.932,13.169	c-5.655,4.151-10.512,9.315-14.307,15.209l-13.507-5.118c-1.239-0.469-2.615-0.427-3.825,0.117	c-1.209,0.545-2.152,1.547-2.622,2.788L0.326,53.828c-0.978,2.582,0.322,5.469,2.904,6.447l13.507,5.118	c-1.064,6.929-0.848,14.015,0.637,20.871L4.204,92.196c-1.209,0.545-2.152,1.547-2.622,2.788c-0.47,1.24-0.428,2.616,0.117,3.825	l5.755,12.775c0.544,1.209,1.547,2.152,2.787,2.622c1.241,0.47,2.616,0.429,3.825-0.117l13.169-5.932	c4.151,5.656,9.314,10.512,15.209,14.307l-5.118,13.507c-0.978,2.582,0.322,5.469,2.904,6.447l13.103,4.964	c0.571,0.216,1.172,0.324,1.771,0.324c0.701,0,1.402-0.147,2.054-0.441c1.209-0.545,2.152-1.547,2.622-2.788l5.117-13.506	c6.937,1.069,14.034,0.849,20.872-0.636l5.931,13.168c0.545,1.209,1.547,2.152,2.788,2.622c1.24,0.47,2.617,0.429,3.825-0.117	l12.775-5.754C113.607,139.12,114.729,136.16,113.595,133.642z M105.309,86.113c-4.963,13.1-17.706,21.901-31.709,21.901	c-4.096,0-8.135-0.744-12.005-2.21c-8.468-3.208-15.18-9.522-18.899-17.779c-3.719-8.256-4-17.467-0.792-25.935	c4.963-13.1,17.706-21.901,31.709-21.901c4.096,0,8.135,0.744,12.005,2.21c8.468,3.208,15.18,9.522,18.899,17.778	C108.237,68.434,108.518,77.645,105.309,86.113z"
      });
      createElementNS(gearsIcon, svgXMLNS, "path", { 
        "class": "pow-gears-icon-gear-small",
        "d": "M216.478,154.389c-0.896-0.977-2.145-1.558-3.469-1.615l-9.418-0.404	c-0.867-4.445-2.433-8.736-4.633-12.697l6.945-6.374c2.035-1.867,2.17-5.03,0.303-7.064l-6.896-7.514	c-0.896-0.977-2.145-1.558-3.47-1.615c-1.322-0.049-2.618,0.416-3.595,1.312l-6.944,6.374c-3.759-2.531-7.9-4.458-12.254-5.702	l0.404-9.418c0.118-2.759-2.023-5.091-4.782-5.209l-10.189-0.437c-2.745-0.104-5.091,2.023-5.209,4.781l-0.404,9.418	c-4.444,0.867-8.735,2.433-12.697,4.632l-6.374-6.945c-0.896-0.977-2.145-1.558-3.469-1.615c-1.324-0.054-2.618,0.416-3.595,1.312	l-7.514,6.896c-2.035,1.867-2.17,5.03-0.303,7.064l6.374,6.945c-2.531,3.759-4.458,7.899-5.702,12.254l-9.417-0.404	c-2.747-0.111-5.092,2.022-5.21,4.781l-0.437,10.189c-0.057,1.325,0.415,2.618,1.312,3.595c0.896,0.977,2.145,1.558,3.47,1.615	l9.417,0.403c0.867,4.445,2.433,8.736,4.632,12.698l-6.944,6.374c-0.977,0.896-1.558,2.145-1.615,3.469	c-0.057,1.325,0.415,2.618,1.312,3.595l6.896,7.514c0.896,0.977,2.145,1.558,3.47,1.615c1.319,0.053,2.618-0.416,3.595-1.312	l6.944-6.374c3.759,2.531,7.9,4.458,12.254,5.702l-0.404,9.418c-0.118,2.759,2.022,5.091,4.781,5.209l10.189,0.437	c0.072,0.003,0.143,0.004,0.214,0.004c1.25,0,2.457-0.468,3.381-1.316c0.977-0.896,1.558-2.145,1.615-3.469l0.404-9.418	c4.444-0.867,8.735-2.433,12.697-4.632l6.374,6.945c0.896,0.977,2.145,1.558,3.469,1.615c1.33,0.058,2.619-0.416,3.595-1.312	l7.514-6.896c2.035-1.867,2.17-5.03,0.303-7.064l-6.374-6.945c2.531-3.759,4.458-7.899,5.702-12.254l9.417,0.404	c2.756,0.106,5.091-2.022,5.21-4.781l0.437-10.189C217.847,156.659,217.375,155.366,216.478,154.389z M160.157,183.953	c-12.844-0.55-22.846-11.448-22.295-24.292c0.536-12.514,10.759-22.317,23.273-22.317c0.338,0,0.678,0.007,1.019,0.022	c12.844,0.551,22.846,11.448,22.295,24.292C183.898,174.511,173.106,184.497,160.157,183.953z"
      });
    }
  }

  function createElementNS(parent, ns, tag, attr) {
    const element = document.createElementNS(ns, tag);
    if(attr) {
      Object.entries(attr).forEach(kv => {
        const value = kv[1];
        if((typeof value) == "string") {
          element.setAttributeNS(null, kv[0], kv[1])
        } else {
          element.setAttributeNS(value[0], kv[0], value[1])
        }
        
      });
    }
    parent.appendChild(element);
    return element;
  }

  function createElement(parent, tag, attr, textContent) {
    const element = document.createElement(tag);
    if(attr) {
      Object.entries(attr).forEach(kv => element.setAttribute(kv[0], kv[1]));
    }
    if(textContent) {
      element.textContent = textContent;
    }
    parent.appendChild(element);
    return element;
  }

  function appendFragment(parent, textContent) {
    const fragment = document.createDocumentFragment()
    fragment.textContent = textContent
    parent.appendChild(fragment)
  }

})(window, document);