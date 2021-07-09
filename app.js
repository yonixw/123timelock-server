const { app } = require("./src/express");

if (process.env.VERCEL !== "1") {
  // only if not in vercel
  app.get("/api/health", (rq, rs) => {
    rs.send("OK [express] v" + 2);
  });

  app.get("/", (rq, rs) => {
    rs.send("Home [express] v" + 2);
  });

  var listener = app.listen(8080, function () {
    console.log("Listening on port " + listener.address().port);
  });
}
