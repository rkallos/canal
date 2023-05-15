-module(canal_tests).
-include_lib("canal/include/canal_internal.hrl").
-include("canal_test.hrl").
-include_lib("eunit/include/eunit.hrl").


%% runners
canal_test_() ->
    {setup,
        fun () -> setup() end,
        fun (_) -> cleanup() end,
    [
        fun auth_approle_subtest/0,
        fun auth_kubernetes_subtest/0,
        fun read_subtest/0,
        fun write_subtest/0,
        fun cache_subtest/0
    ]}.

%% tests

auth_approle_subtest() ->
    Creds = {approle, ?FIXTURE_APPROLE_ROLE, ?FIXTURE_APPROLE_SECRET},
    ok = canal:auth(Creds),
    Creds = ?GET_OPT(credentials).


auth_kubernetes_subtest() ->
    Creds = {kubernetes, ?FIXTURE_KUBERNETES_ROLE, ?FIXTURE_KUBERNETES_JWT},
    ok = canal:auth(Creds),
    Creds = ?GET_OPT(credentials).


read_subtest() ->
    ok = canal:auth({approle, ?FIXTURE_APPROLE_ROLE, ?FIXTURE_APPROLE_SECRET}),
    {error, {404, []}} = canal:read(<<"foo">>).


write_subtest() ->
    ok = canal:auth({approle, ?FIXTURE_APPROLE_ROLE, ?FIXTURE_APPROLE_SECRET}),
    ok = canal:write(<<"foo">>, <<"bar">>),
    {ok, #{<<"value">> := <<"bar">>}} = canal:read(<<"foo">>).

cache_subtest() ->
    ok = canal:auth({approle, ?FIXTURE_APPROLE_ROLE, ?FIXTURE_APPROLE_SECRET}),
    ok = canal:write(<<"foo">>, <<"bar">>),
    {ok, #{<<"value">> := <<"bar">>}} = canal:read(<<"foo">>),
    canal_http_server:stop(),
    {ok, #{<<"value">> := <<"bar">>}} = canal:read(<<"foo">>).


%% utils
cleanup() ->
    ets:delete(?TABLE),
    canal_app:stop(),
    canal_http_server:stop().


setup() ->
    ets:new(?TABLE, [ordered_set, named_table, public]),
    {ok, _} = canal_http_server:start(),
    application:set_env(canal, url, <<"http://127.0.0.1:8200">>),
    canal_app:start().
