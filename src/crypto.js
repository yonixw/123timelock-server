const { padDigits, reverse, parseTimeSafeSec } = require("./utils");

const _simpleenc = require("simple-encryptor");
const key = process.env.KEY; // echo "$(< /dev/urandom tr -dc A-Za-z0-9 | head -c 64)"
const encryptor = _simpleenc(key);

function genSalt() {
  //const salt = `${Date.now()}_${randString(10)}`;
  const salt = Date.now()
    .toString()
    .substr(0, 8)
    .split("")
    .map((e, i) => (i % 5 == 4 ? e + "_" : e))
    .join("");
  return (
    "salt_" +
    salt +
    "_" +
    Math.ceil(Math.random() * (100 * 1000 - 10 * 1000) + 10 * 1000)
  );
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

function keyencrypt(data, encKey) {
  const encryptor = _simpleenc("hashstep" + key + encKey);
  return encryptor.encrypt(data);
}

function keydecrypt(chiper, encKey) {
  const encryptor = _simpleenc("hashstep" + key + encKey);
  return encryptor.decrypt(chiper);
}

module.exports = {
  encryptor: encryptor,
  hmac: encryptor.hmac,
  encrypt: encryptor.encrypt,
  decrypt: encryptor.decrypt,
  keyencrypt,
  keydecrypt,
  genSalt,
  getTimeToken,
  getTimeEndedProof
};
