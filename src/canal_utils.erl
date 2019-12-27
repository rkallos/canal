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


-spec error_msg(string()) -> ok.

error_msg(Msg) ->
    error_logger:error_msg(Msg).


-spec error_msg(string(), list()) -> ok.

error_msg(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    Msg2 = lists:flatten(Msg),
    error_logger:error_msg(Msg2).


-spec getopt(atom()) -> term().

getopt(credentials) ->
    ?GET_ENV(credentials, undefined);

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


-spec info_msg(string()) -> ok.

info_msg(Msg) ->
    error_logger:info_msg(Msg).


-spec info_msg(string(), list()) -> ok.

info_msg(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    Msg2 = lists:flatten(Msg),
    error_logger:info_msg(Msg2).


-spec warning_msg(string()) -> ok.

warning_msg(Msg) ->
    error_logger:warning_msg(Msg).


-spec warning_msg(string(), list()) -> ok.

warning_msg(Format, Args) ->
    Msg = io_lib:format(Format, Args),
    Msg2 = lists:flatten(Msg),
    error_logger:warning_msg(Msg2).


%% private

-spec getopt2([false | term()]) -> false | term().

getopt2([Last]) -> Last;

getopt2([false | T]) -> getopt2(T);

getopt2([H | _]) -> H.
