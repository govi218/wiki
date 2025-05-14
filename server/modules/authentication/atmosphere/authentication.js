const jwt = require("jsonwebtoken");
/* const { createPublicKey } = require("crypto"); */

const CustomStrategy = require("passport-custom").Strategy;

/* global WIKI */
// ------------------------------------
// Custom Auth Microservice
// ------------------------------------
// Requires: jsonwebtoken, node-jose, axios

module.exports = {
  init(passport, conf) {
    // Create a Custom Auth strategy
    const client = new CustomStrategy(async function(req, done) {
      try {
        // Check if this is the callback from the auth service with the token
        if (req.query.auth_token) {
          // Get JWKS using await
          const jwksRequestOptions = {
            method: "GET",
            redirect: "follow"
          };

          const jwksResponse = await fetch(
            `${conf.authorizationURL}/.well-known/jwks.json`,
            jwksRequestOptions
          );
          const jwksData = await jwksResponse.json();

          // Get the keys array from the JWKS response
          const keys = jwksData.keys;

          if (!keys || keys.length === 0) {
            throw new Error("No keys found in JWKS response");
          }

          const decoded = jwt.decode(req.query.auth_token, { complete: true });
          // Match the 'kid' from the JWT header
          const [jwk] = keys.filter(k => k["kid"] === decoded.header["kid"]);
          if (!jwk) {
            throw new Error("No valid key found to decode auth token");
          }

          // TODO: is this useful/part of the flow?
          // Verify and decode the auth_token
          // Convert JWK to a format usable by jsonwebtoken
          /* const publicKey = createPublicKey({
           *   key: jwk,
           *   format: "jwk"
           * });

           * const userDataToken = jwt.verify(req.query.auth_token, publicKey, {
           *   algorithms: [jwk.alg]
           * }); */

          const myHeaders = new Headers();
          myHeaders.append("Authorization", `Bearer ${req.query.auth_token}`);

          const userDataRequestOptions = {
            method: "GET",
            headers: myHeaders,
            redirect: "follow"
          };

          const userDataResponse = await fetch(
            `${conf.authorizationURL}/xrpc/com.atproto.server.getSession`,
            userDataRequestOptions
          );
          const userData = await userDataResponse.json();

          // Find or create user based on the returned data
          const user = await WIKI.models.users.processProfile({
            providerKey: conf.key,
            profile: {
              id: userData.did,
              email: userData.email,
              displayName: userData.handle || userData.email,
              picture: userData.picture ?? null
            }
          });
          if (user) {
            return done(null, user);
          } else {
            return done(new Error("Unable to authenticate user."), null);
          }
        } else {
          // Initial authentication request - redirect to the auth service
          req.res.redirect(conf.authorizationURL);
          return done(null, false, {
            message: "Redirecting to authentication service..."
          });
        }
      } catch (err) {
        return done(err, null);
      }
    });

    // Register the strategy
    passport.use(conf.key, client);
  },

  logout(conf) {
    if (!conf.logoutURL) {
      return "/";
    } else {
      return conf.logoutURL;
    }
  }
};
