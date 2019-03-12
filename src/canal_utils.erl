-module(canal_utils).
-include("include/canal_internal.hrl").

-export([
    error_msg/1,
    error_msg/2,
    getopt/1,
    info_msg/1,
    info_msg/2,
    warning_msg/1,
    warning_msg/2
]).


-spec error_msg(iolist()) -> ok.

error_msg(Msg) ->
    error_logger:error_report(Msg).


-spec error_msg(io:format(), list()) -> ok.

error_msg(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    error_logger:error_report(Msg).


-spec getopt(atom()) -> term().

getopt(auth_payload) ->
    getopt2([
        os:getenv("VAULT_AUTH_PAYLOAD"),
        ?GET_ENV(auth_payload, false),
        <<"">>
    ]);

getopt(timeout) ->
    getopt2([
        os:getenv("CANAL_REQUEST_TIMEOUT"),
        ?GET_ENV(request_timeout, false),
        ?DEFAULT_REQUEST_TIMEOUT
    ]);

getopt(token) ->
    getopt2([
        os:getenv("VAULT_TOKEN"),
        ?GET_ENV(vault_token, false),
        undefined
    ]);

getopt(url) ->
    iolist_to_binary(getopt2([
        os:getenv("VAULT_URL"),
        ?GET_ENV(url, false),
        ?DEFAULT_URL
    ])).


-spec info_msg(iolist()) -> ok.

info_msg(Msg) ->
    error_logger:info_report(Msg).


-spec info_msg(io:format(), list()) -> ok.

info_msg(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    error_logger:info_report(Msg).


-spec warning_msg(iolist()) -> ok.

warning_msg(Msg) ->
    error_logger:warning_report(Msg).


-spec warning_msg(io:format(), list()) -> ok.

warning_msg(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    error_logger:warning_report(Msg).



%% private

-spec getopt2([false | term()]) -> false | term().

getopt2([Last]) -> Last;

getopt2([false | T]) -> getopt2(T);

getopt2([H | _]) -> H.
