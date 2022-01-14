const { toSafeURL, fromSafeURL, parseTimeSafeSec } = require("./utils");
const {
  hmac,
  encrypt,
  decrypt,
  keydecrypt,
  keyencrypt,
  genSalt,
  getTimeToken,
  getTimeEndedProof
} = require("./crypto");
const prettyTime = require("pretty-ms");

var express = require("express");
var cookieParser = require("cookie-parser");
var logger = require("morgan");

const { hashStep } = require("./cryptolib/cryptoUtils");

var app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  return next();
});
app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const rateLimit = require("express-rate-limit");
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 20,
  keyGenerator: (req, res) => req.ip,
  statusCode: 200,
  headers: false,
  message: `{"err": "Too many requests, please wait a while"}`
});

//  apply to all requests
app.use(limiter);

app.get("/api/redirect", (rq, rs) => {
  rs.status(403).send({ err: "/api/redirect deprecated" });
});

// [token times] => {salt=time+rnd, tokens=[{time,hmac(salt+time)}] }
app.get("/api/setup", (req, resp) => {
  var tokens = req.query["time"] || ["15m", "30m", "3h", "2d"];
  if (!Array.isArray(tokens)) tokens = [`${tokens}`];

  var tokenTimes = tokens.map((e) => {
    var salt = genSalt();
    return {
      name: e,
      salt: salt,
      proof: getTimeToken(salt, e)
    };
  });

  var result = { tokens: tokenTimes, salt: "no_shared_salt" };
  resp.send(result);
});

// {pass,salt} => enc_key = enc({pass, hmac(pass + salt+"enc")})
app.get("/api/enc", (req, resp) => {
  if (!req.query["pass"] || !req.query["salts"]) {
    resp.send({ err: "Missing params in /enc or salt not array" });
    return;
  }

  const pass = req.query["pass"];
  var salts = req.query["salts"];
  if (!Array.isArray(req.query["salts"])) salts = [`${salts}`];

  const encDataArray = salts.map((s) =>
    toSafeURL(encrypt(JSON.stringify({ p: pass, s: s })))
  );

  // This assume good intentions when encrypting
  // 1) No lying about data_hash
  // 2) Use it to encrypt and throw away
  resp.send({ enckey: encDataArray });
});

// {pass,hashparts[]} => [enc(hashparts, password = pass+secret)]
app.get("/api/enchash", (req, resp) => {
  // Because we will only decrypt if password is
  // proven to be time unlocked, the user has no incentive
  // to enter a different random password...
  // because no time free password will work since it doesnt have
  // proof of unlock..

  if (!req.query["hashparts"] || !req.query["pass"]) {
    resp.send({ err: "Missing params in /enchash " });
    return;
  }

  const pass = req.query["pass"];

  // Encrypt hashs without depending on salt..
  // keyencrypt() uses our severKey so user can't unlock even
  //    if saving tempPass in textplain
  let hashpartsResult = [];
  if (req.query["hashparts"]) {
    let hashparts = req.query["hashparts"];
    if (!Array.isArray(req.query["hashparts"])) hashparts = [`${hashparts}`];
    hashpartsResult = hashparts.map((e) => keyencrypt(`${e}`, pass));
  }

  resp.send({ encparts: hashpartsResult });
});

const DEFAULT_UNLOCK_WINDOW_MIN = 15;
// {enckey, token_time, token_hmac, salt} => {end_time,timed_proof = hmac(time,data_hash)}
app.get("/api/unlock/begin", (req, resp) => {
  if (
    !req.query["enckey"] ||
    !req.query["token"] ||
    !req.query["tokenproof"] ||
    !req.query["offsetstartmin"] ||
    !req.query["duration"] ||
    !req.query["salt"]
  ) {
    resp.send({ err: "Missing params in /unlock/begin" });
    return;
  }
  const enckey = fromSafeURL(req.query["enckey"]);
  const time_string = req.query["token"];
  const time_token = req.query["tokenproof"];
  const offset_strat_min = parseInt(req.query["offsetstartmin"], 10) || 0;
  const duration =
    parseInt(req.query["duration"], 10) || DEFAULT_UNLOCK_WINDOW_MIN;
  const salt = req.query["salt"];

  console.log(
    `>${salt}<, >${time_string}<, >${getTimeToken(
      salt,
      time_string
    )}< , >${time_token}<`
  );
  if (getTimeToken(salt, time_string) !== time_token) {
    resp.send({ err: `Can't validate token: '${time_token}'` });
  } else {
    let waitTimeMin = parseTimeSafeSec(time_string) / 60;

    let startTime = new Date();
    startTime.setMinutes(
      startTime.getMinutes() + waitTimeMin + offset_strat_min
    );

    let endTime = new Date();
    endTime.setMinutes(
      endTime.getMinutes() + waitTimeMin + offset_strat_min + duration
    );

    let timeProof = getTimeEndedProof(salt, startTime, endTime, enckey);
    resp.send({
      from: startTime.getTime(),
      to: endTime.getTime(),
      proof: timeProof
    });
  }
});

function unlockSuccessSimple(
  query,
  password,
  timeEnd,
  nowTime,
  sendResult,
  extraProps = {}
) {
  sendResult({
    pass: password,
    timeLeftOpen: prettyTime(timeEnd - nowTime),
    ...extraProps
  });
}

function unlockSuccessHash(
  query,
  password,
  timeEnd,
  nowTime,
  sendResult,
  extraProps = {}
) {
  // Optional 2-step hash
  const hashType = query["hashtype"] || "";
  const hashState = query["hashstate"] || "";
  const hashServerSecret = query["hashsecret"] || "";

  let hashNextState = "";
  if (!!hashType && hashType !== "undefined") {
    // Same pass for partial hash
    // Assume client hash smart like
    //    (code + key_client1 + key_server + key_client2)
    //    so client can't abuse us to get state and remember
    //    like in case of (server_key + client_key + code)
    let hashKeyPlain = keydecrypt(hashServerSecret, password);
    hashNextState = hashStep(hashKeyPlain, hashType, hashState);
  }

  unlockSuccessSimple(query, password, timeEnd, nowTime, sendResult, {
    password: "<hash-only>",
    hashstep: hashNextState
  });
}

function unlockSuccessOTP(
  query,
  password,
  timeEnd,
  nowTime,
  sendResult,
  extraProps = {}
) {
  // Optional 2-step hash
  const hashType = query["hashtype"] || "";
  const hashServerSecret = query["hashsecret"] || "";
  const hashExtra = query["hashextra"] || "";

  let hashNextState = "";
  if (!!hashType && hashType !== "undefined") {
    // Same pass for partial hash
    // Assume client hash smart like
    //    (code + key_client1 + key_server + key_client2)
    //    so client can't abuse us to get state and remember
    //    like in case of (server_key + client_key + code)
    let hashKeyPlain = keydecrypt(hashServerSecret, password);

    // Assume both array of bits
    const hashKeyBits = JSON.parse(hashKeyPlain || "[]");
    const hashExtraBits = JSON.parse(hashExtra || "[]");

    if (hashKeyBits.length < 5 || hashExtra.length < 5) {
      sendResult({ err: "Both key & data must be non empty arrays" });
    } else {
      hashNextState = hashStep(hashKeyBits, hashType, null);
      hashNextState = hashStep(hashExtraBits, hashType, hashNextState);

      unlockSuccessSimple(query, password, timeEnd, nowTime, sendResult, {
        password: "<hash-only>",
        hashstep: hashNextState
      });
    }
  }
}

const unlockSucessCB = {
  simple: unlockSuccessSimple,
  "sha-step": unlockSuccessHash,
  "otp-step": unlockSuccessOTP
};

// {enckey,end_time,timed_proof, salt} => key
app.get("/api/unlock/finish", (req, resp) => {
  if (
    !req.query["enckey"] ||
    !req.query["from"] ||
    !req.query["to"] ||
    !req.query["proof"] ||
    !req.query["salt"]
  ) {
    resp.send({ err: "Missing params in /unlock/finsih" });
    return;
  }
  const mode = req.query["mode"] || "simple"; // optional hash\otp step based on password

  const enckey = fromSafeURL(req.query["enckey"]);
  const timeStart = new Date(parseInt(req.query["from"] || "0", 10));
  const timeEnd = new Date(parseInt(req.query["to"] || "0", 10));
  const timeProof = req.query["proof"];
  const salt = req.query["salt"];

  let calcTimeProof = getTimeEndedProof(salt, timeStart, timeEnd, enckey);
  if (calcTimeProof !== timeProof) {
    resp.send({ err: `Can't validate proof: '${timeProof}'` });
  } else {
    const nowTime = new Date();

    if (timeStart < nowTime && nowTime < timeEnd) {
      const keyData = JSON.parse(decrypt(enckey));
      //
      if ((keyData.salt || keyData.s) === salt) {
        const password = keyData.pass || keyData.p || "error-no-pass-key";
        const sendResult = (obj) => resp.send(obj);

        unlockSucessCB[mode](req.query, password, timeEnd, nowTime, sendResult);
      } else {
        resp.send({
          err: "Salt of encrypted data mismatch!"
        });
      }
    } else {
      resp.send({
        err: `Time window wrong!, Left: ${prettyTime(timeStart - nowTime)}`
      });
    }
  }
});

app.get("/api/", (req, resp) => {
  resp.send("my default home");
});

const {
  tempTokenBeginAPI,
  createFastCopyTempTokenAPI,
  tempUnlockBeginAPI
} = require("./temp-token");

app.get("/api/temp/begin", (req, resp) => {
  if (!req.query["token"] || !req.query["tokenproof"] || !req.query["salt"]) {
    resp.send({ err: "Missing params in /temp/begin" });
    return;
  }

  const time_string = req.query["token"];
  const time_token = req.query["tokenproof"];
  const salt = req.query["salt"];

  tempTokenBeginAPI(salt, time_string, time_token, (e) => resp.send(e));
});

app.get("/api/temp/fastcopy", (req, resp) => {
  if (
    !req.query["token"] ||
    !req.query["tempproof"] ||
    !req.query["from"] ||
    !req.query["salt"]
  ) {
    resp.send({ err: "Missing params in /temp/fastcopy" });
    return;
  }

  const time_string = req.query["token"];
  const temp_token = req.query["tempproof"];
  const createTime = req.query["from"];
  const salt = req.query["salt"];

  createFastCopyTempTokenAPI(time_string, salt, createTime, temp_token, (e) =>
    resp.send(e)
  );
});

app.get("/api/temp/unlock", (req, resp) => {
  if (
    !req.query["token"] ||
    !req.query["salt"] ||
    !req.query["mindiff"] ||
    !req.query["fastproof"] ||
    !req.query["enckey"]
  ) {
    resp.send({ err: "Missing params in /temp/unlock" });
    return;
  }

  const time_string = req.query["token"];
  const salt = req.query["salt"];
  const minutediff = req.query["mindiff"];
  const fastproof = req.query["fastproof"];
  const enckey = fromSafeURL(req.query["enckey"]);
  const duration =
    parseInt(req.query["duration"], 10) || DEFAULT_UNLOCK_WINDOW_MIN;

  tempUnlockBeginAPI(
    time_string,
    salt,
    minutediff,
    fastproof,
    duration,
    enckey,
    (e) => resp.send(e)
  );
});

module.exports = { app };
