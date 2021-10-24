function padDigits(number, digits) {
  return (
    Array(Math.max(digits - String(number).length + 1, 0)).join(0) + number
  );
}

function getTempTimeToken(hmacFn, reqBody, time_string, salt, timeCreated) {
  // long token to help you proove you had the key (token) in time X
  let hmac = hmacFn("temp_" + salt + time_string + timeCreated);
  return "temp_" + hmac;
}

function getISOMin(d) {
  // '2021-10-11T19:03:14.619Z' -> '2021-10-11T19:03'
  return d.toISOString().split(/:[0-9]{2}\./)[0];
}

function getFastTempTimeToken(hmacFn, reqBody, time_string, salt, timeCreated) {
  // short text to copy to other device that will work for 2 minute
  // after you show the temp proof
  let now = new Date();

  let secDiff = ((((now.getDate() - timeCreated) % 60) * 1000) / 60) * 1000;
  let minDiff = Math.floor(
    ((now.getDate() - timeCreated - secDiff * 60 * 1000) / 60) * 60 * 1000
  );

  let minute = padDigits(minDiff, 2);

  let fastTempProof = hmacFn(
    [time_string, salt, minute, getISOMin(now)].join("|")
  ).substr(0, 6);

  return {
    mindiff: minute,
    fastproof: fastTempProof
  };
}

const fastTempValidMin = 3;
function verifyFastTempToken(
  hmacFn,
  reqBody,
  time_string,
  salt,
  sec,
  minute,
  fastproof
) {
  let d = new Date();

  let fastTempValid = false;
  for (let i = 0; i < fastTempValidMin; i++) {
    let expected_proof = hmacFn(
      [time_string, salt, sec, minute, getISOMin(d)].join("|")
    ).substr(0, 6);

    if (expected_proof === fastproof) {
      fastTempValid = true;
    }
  }

  return fastTempValid;
}
