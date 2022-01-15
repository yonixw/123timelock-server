const sjcl = require("./custom_sjcl_1.0.8");

// data can be string or array of numbers (bits)
function hashStep(data, type = "sha256", state = null) {
  let hash = type === "sha256" ? new sjcl.hash.sha256() : new sjcl.hash.sha1();
  if (state) {
    hash.import(state);
  }
  hash.update(data);
  return hash.export();
}

module.exports = { hashStep: hashStep };
