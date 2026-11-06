const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER || "dinedesk-api";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "dinedesk-app";

if (!JWT_SECRET) {
  throw new Error("Initialization Failed: Missing required environment variable [JWT_SECRET].");
}

if (JWT_SECRET.length < 32) {
  throw new Error("Initialization Failed: Configuration rule violation [JWT_SECRET must be at least 32 characters long].");
}

module.exports = {
  jwtSecret: JWT_SECRET,
  jwtIssuer: JWT_ISSUER,
  jwtAudience: JWT_AUDIENCE
};
