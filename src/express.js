var express = require("express");
var path = require("path");
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

const key = process.env.KEY; // echo "$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 64)"
const encryptor = require("simple-encryptor")(key);
const parseTime = require("parse-duration");
const prettyTime = require("pretty-ms");

function randString(length) {
  var result = [];
  var characters = "abcdefghijklmnopqrstuvwxyz0123456789";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result.push(
      characters.charAt(Math.floor(Math.random() * charactersLength))
    );
  }
  return result.join("");
}

function parseTimeSafeSec(e) {
  return Math.max(parseTime(e) || 60 * 1000, 60 * 1000) / 1000;
}

function toSafeURL(text) {
  return text.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "~");
}

function fromSafeURL(text) {
  return text.replace(/-/g, "+").replace(/_/g, "/").replace(/~/g, "=");
}

function addInLast(str, n = 6) {
  return str.substr(0, str.length - n) + "_" + str.substr(str.length - n);
}

function padDigits(number, digits) {
  return (
    Array(Math.max(digits - String(number).length + 1, 0)).join(0) + number
  );
}

function reverse(str) {
  return [...str].reduce((rev, currentChar) => currentChar + rev, "");
}

function genSalt() {
  //const salt = `${Date.now()}_${randString(10)}`;
  const salt = Date.now()
    .toString()
    .substr(0, 8)
    .split("")
    .map((e, i) => (i % 5 == 4 ? e + "_" : e))
    .join("");
  return "salt_" + salt + "_" + Math.ceil(Math.random() * 100000);
}

function getTimeToken(salt, time_string) {
  let hmac = encryptor.hmac("token_" + salt + parseTimeSafeSec(time_string));

  return (
    "token_" +
    hmac
      .substr(0, 10)
      .split("")
      .map((e, i) => (i % 5 == 4 ? e + "_" : e))
      .join("") +
    padDigits(
      parseInt(reverse(hmac.replace(/[a-z]/gi, "")).substr(0, 5), 10) || 0,
      5
    )
  );
}

function getTimeEndedProof(salt, timeStart, timeEnd, enc_data) {
  return (
    "begintime_" +
    encryptor.hmac(
      `begintime_${salt}|${timeStart.getTime()}|${timeEnd.getTime()}|${enc_data}`
    )
  );
}

function getTempTimeToken(time_string, salt, timeCreated) {
  // long token to help you proove you had the key (token) in time X
  let hmac = encryptor.hmac("temp_" + salt + time_string + timeCreated);
  return "temp_" + hmac;
}

function getISOMin(d) {
  // '2021-10-11T19:03:14.619Z' -> '2021-10-11T19:03'
  return d.toISOString().split(/:[0-9]{2}\./)[0];
}

function getFastTempTimeToken(time_string, salt, timeCreated) {
  // short text to copy to other device that will work for 2 minute
  // after you show the temp proof
  let now = new Date();

  let secDiff = ((((now.getDate() - timeCreated) % 60) * 1000) / 60) * 1000;
  let minDiff = Math.floor(
    ((now.getDate() - timeCreated - secDiff * 60 * 1000) / 60) * 60 * 1000
  );

  let sec = padDigits(secDiff, 2);
  let minute = padDigits(minDiff, 2);

  let fastTempProof = encryptor
    .hmac([time_string, salt, sec, minute, getISOMin(now)].join("|"))
    .substr(0, 6);

  return {
    secdiff: sec,
    mindiff: minute,
    fastproof: fastTempProof
  };
}

const fastTempValidMin = 3;
function verifyFastTempToken(time_string, salt, sec, minute, fastproof) {
  let d = new Date();

  let fastTempValid = false;
  for (let i = 0; i < fastTempValidMin; i++) {
    let expected_proof = encryptor
      .hmac([time_string, salt, sec, minute, getISOMin(d)].join("|"))
      .substr(0, 6);

    if (expected_proof === fastproof) {
      fastTempValid = true;
    }
  }

  return fastTempValid;
}

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
    toSafeURL(encryptor.encrypt(JSON.stringify({ p: pass, s: s })))
  );

  // This assume good intentions when encrypting
  // 1) No lying about data_hash
  // 2) Use it to encrypt and throw away
  resp.send({ enckey: encDataArray });
});

app.get("/api/temp/begin", (req, resp) => {
  if (!req.query["token"] || !req.query["tokenproof"] || !req.query["salt"]) {
    resp.send({ err: "Missing params in /temp/begin" });
    return;
  }

  const time_string = req.query["token"];
  const time_token = req.query["tokenproof"];
  const salt = req.query["salt"];

  if (getTimeToken(salt, time_string) !== time_token) {
    resp.send({ err: `Can't validate token: '${time_token}'` });
  } else {
    let createTime = Date.now();
    let tempProof = getTempTimeToken(time_string, salt, createTime);

    resp.send({ from: createTime, tempproof: tempProof });
  }
});

app.get("/api/temp/fast", (req, resp) => {
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

  if (getTempTimeToken(time_string, salt, createTime) !== temp_token) {
    resp.send({ err: `Can't validate temp token: '${temp_token}'` });
  } else {
    let fastTokenInfo = getFastTempTimeToken(time_string, salt, createTime);
    resp.send(fastTokenInfo);
  }
});

app.get("/api/temp/finish", (req, resp) => {
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
      const keyData = JSON.parse(encryptor.decrypt(enckey));
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

module.exports = { app };
