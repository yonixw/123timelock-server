const sjcl = require("./custom_sjcl_1.0.8");

function hashStep(text, type = "sha256", state = null) {
  let hash = type === "sha256" ? new sjcl.hash.sha256() : new sjcl.hash.sha1();
  if (state) {
    hash.import(state);
  }
  hash.update(text);
  return hash.export();
}

module.exports = { hashStep: hashStep };
