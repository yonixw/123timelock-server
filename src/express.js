const { toSafeURL, fromSafeURL, parseTimeSafeSec } = require("./utils");
const {
  hmac,
  encrypt,
  decrypt,
  genSalt,
  getTimeToken,
  getTimeEndedProof
} = require("./crypto");

var express = require("express");
var cookieParser = require("cookie-parser");
var logger = require("morgan");

var app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  return next();
});
app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const prettyTime = require("pretty-ms");

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

const DEFAULT_UNLOCK_WINDOW_MIN = 15;
// {enckey, token_time, token_hmac, salt} => {end_time,timed_proof = hmac(time,data_hash)}
app.get("/api/unlock/begin", (req, resp) => {
  setTimeout(() => {
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
  }, 0.5 * 1000 /* Cooldown 5 sec against bruteforce short hash */);
});

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
        resp.send({
          pass: keyData.pass || keyData.p || "error-no-pass-key",
          timeLeftOpen: prettyTime(timeEnd - nowTime)
        });
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

app.get("/api/temp/begin", (req, resp) => {
  if (!req.query["token"] || !req.query["tokenproof"] || !req.query["salt"]) {
    resp.send({ err: "Missing params in /temp/begin" });
    return;
  }

  const time_string = req.query["token"];
  const time_token = req.query["tokenproof"];
  const salt = req.query["salt"];

  //tempTokenBegin(salt, time_string, time_token, (e)=>resp.send(e));
});

app.get("/api/temp/fastcopy", (req, resp) => {
  if (
    !req.query["token"] ||
    !req.query["tempproof"] ||
    !req.query["from"] ||
    !req.query["salt"]
  ) {
    resp.send({ err: "Missing params in /temp/fast" });
    return;
  }

  const time_string = req.query["token"];
  const temp_token = req.query["tempproof"];
  const createTime = req.query["from"];
  const salt = req.query["salt"];

  //createFastCopyTempToken(time_string, salt, createTime, temp_token, resp);
});

app.get("/api/temp/unlock", (req, resp) => {
  if (
    !req.query["token"] ||
    !req.query["salt"] ||
    !req.query["sec"] ||
    !req.query["min"] ||
    !req.query["fastproof"]
  ) {
    resp.send({ err: "Missing params in /temp/fast" });
    return;
  }

  //verifyFastTempToken(time_string, salt, sec, minute, fastproof)
});

module.exports = { app };
