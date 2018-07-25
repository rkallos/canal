%% defaults
-define(DEFAULT_MAX_AUTH_RETRY, 3).
-define(DEFAULT_RENEW_INCREMENT, 600).
-define(DEFAULT_RENEW_PREDICATE_FUNCTION, {canal, should_renew, 10000}).
-define(DEFAULT_REQUEST_TIMEOUT, 10000).
-define(DEFAULT_URL, "https://localhost:8200").
