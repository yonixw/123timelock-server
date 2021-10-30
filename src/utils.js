const parseTime = require("parse-duration");

function __deprecated__randString(length) {
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

function __depracated__addInLast(str, n = 6) {
  return str.substr(0, str.length - n) + "_" + str.substr(str.length - n);
}

function padDigits(number, digits) {
  return (
    Array(Math.max(digits - String(number).length + 1, 0)).join(0) + number
  );
}

function toSafeURL(text) {
  return text.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "~");
}

function fromSafeURL(text) {
  return text.replace(/-/g, "+").replace(/_/g, "/").replace(/~/g, "=");
}

function reverse(str) {
  return [...str].reduce((rev, currentChar) => currentChar + rev, "");
}

function parseTimeSafeSec(e) {
  return Math.max(parseTime(e) || 60 * 1000, 60 * 1000) / 1000;
}

module.exports = {
  padDigits,

  toSafeURL,
  fromSafeURL,

  reverse,
  parseTimeSafeSec
};
