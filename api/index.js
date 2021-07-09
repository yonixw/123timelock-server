const { app } = require("../src/express");

if (process.env.VERCEL === "1") {
  app.get("/api/health", (rq, rs) => {
    rs.send("OK [api] v" + 2);
  });

  module.exports = app;
}
