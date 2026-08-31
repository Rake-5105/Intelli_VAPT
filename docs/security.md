# Security and authorized use

IntelliVAPT is for explicitly authorized assessments only. Keep `DEMO_MODE=true` for demonstrations. Before enabling any real scanner, set a strong `JWT_SECRET`, use TLS behind a reverse proxy, configure CORS to the deployed frontend origin, and ensure users have only the role they require.

Never expose scanner configuration endpoints to viewers. Do not add targets that are not documented in the assessment authorization. Scan adapters must treat tool output as untrusted input and preserve logs without secrets.
