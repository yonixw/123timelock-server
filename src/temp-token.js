const { padDigits, parseTimeSafeSec } = require("./utils");
const { hmac, getTimeToken, getTimeEndedProof } = require("./crypto");

function getTempTimeToken(time_string, salt, timeCreated) {
  // long token to help you proove you had the key (token) in time X
  let hmac = hmac("temp_" + salt + time_string + timeCreated);
  return "temp_" + hmac;
}

function getISOMin(d) {
  // '2021-10-11T19:03:14.619Z' -> '2021-10-11T19:03'
  return d.toISOString().split(/:[0-9]{2}\./)[0];
}

function tempTokenBeginAPI(salt, time_string, time_token, callback) {
  if (getTimeToken(salt, time_string) !== time_token) {
    callback({ err: `Can't validate time token: '${time_token}'` });
  } else {
    // This will be sent to us so exact date + long hash:
    let createTime = Date.now();
    let tempProof = getTempTimeToken(time_string, salt, createTime);

    callback({ from: createTime, tempproof: tempProof });
  }
}

function getFastTempTimeToken(time_string, salt, createTime) {
  // short text to copy to other device that will work for 2 minute
  // after you show the temp proof
  let now = new Date();

  let secDiff = ((((now.getDate() - createTime) % 60) * 1000) / 60) * 1000;
  let minDiff = Math.floor(
    ((now.getDate() - createTime - secDiff * 60 * 1000) / 60) * 60 * 1000
  );

  let minutePassed = padDigits(minDiff, 2);

  let fastCopyStamp = getISOMin(now);

  let fastTempProof = hmac(
    [time_string, salt, minutePassed, fastCopyStamp].join("|")
  ).substr(0, 6);

  return {
    mindiff: minutePassed, // minute the user waited since creation of timestamp
    fastproof: fastTempProof
  };
}

function createFastCopyTempTokenAPI(
  time_string,
  salt,
  createTime,
  temp_token,
  callback
) {
  if (getTempTimeToken(time_string, salt, createTime) !== temp_token) {
    callback({ err: `Can't validate temp token: '${temp_token}'` });
  } else {
    let fastTokenInfo = getFastTempTimeToken(
      time_string,
      salt,
      parseInt(createTime, 10)
    );
    callback(fastTokenInfo);
  }
}

const fastCopyTempValidMin = 3;
function verifyFastTempToken(time_string, salt, minutediff, fastproof) {
  let d = new Date();

  let fastTempValid = false;
  for (let i = 0; i < fastCopyTempValidMin; i++) {
    let expected_proof = hmac(
      [time_string, salt, minutediff, getISOMin(d)].join("|")
    ).substr(0, 6);

    if (expected_proof === fastproof) {
      fastTempValid = true;
    }

    d.setMinutes(d.getMinutes() - 1); // Go back 1 minute.
  }

  return fastTempValid;
}

function tempUnlockBeginAPI(
  time_string,
  salt,
  minutediff,
  fastproof,
  duration,
  enckey,
  callback
) {
  if (!verifyFastTempToken(time_string, salt, minutediff, fastproof)) {
    callback({ err: `Can't validate fast copy proof '${fastproof}'` });
  } else {
    let minutesToWait = parseTimeSafeSec(time_string) - minutediff;
    if (minutesToWait < 1) minutesToWait = 1;

    let d = new Date();
    d.setMinutes(d.getMinutes() + minutesToWait);
    let startTime = d.getTime();
    d.setMinutes(d.getMinutes() + duration);
    let endTime = d.getTime();

    let timeProof = getTimeEndedProof(salt, startTime, endTime, enckey);
    callback({
      from: startTime.getTime(),
      to: endTime.getTime(),
      proof: timeProof
    });
  }
}

module.exports = {
  tempTokenBeginAPI,
  createFastCopyTempTokenAPI,
  tempUnlockBeginAPI
};
