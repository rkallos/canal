-module(canal_http_server).
-include_lib("canal/include/canal_internal.hrl").
-include("canal_test.hrl").

-export([
    start/0,
    stop/0
]).

-export([
    init/2
]).


start() ->
    application:ensure_all_started(cowboy),
    Dispatch = cowboy_router:compile([{'_', [
        {"/v1/:op/[:rest/[...]]", ?MODULE, #{}}
    ]}]),
    {ok, _} = cowboy:start_clear(?MODULE, [{port, 8200}], #{
        env => #{dispatch => Dispatch},
        max_keepalive => infinity,
        request_timeout => infinity
    }).

stop() ->
    cowboy:stop_listener(?MODULE).


%% cowboy callbacks

init(Req, State) ->
    case {cowboy_req:method(Req), cowboy_req:binding(op, Req)} of
        {<<"POST">>, <<"auth">>} ->
            Path = cowboy_req:path(Req),
            Split = binary:split(Path, <<"/">>, [global]),
            case lists:last(Split) of
                <<"login">> ->
                    Method =
                        binary_to_existing_atom(cowboy_req:binding(rest, Req)),
                    {ok, ReqBody, _} = cowboy_req:read_body(Req),
                    handle_auth_req(Req, Method, ?DECODE(ReqBody), State)
            end;
        {<<"GET">>, <<"secret">>} ->
            handle_read_req(Req, State);
        {<<"POST">>, <<"secret">>} ->
            handle_write_req(Req, State)
    end.


%% private

handle_auth_req(
    Req,
    kubernetes,
    #{<<"role">> := ?FIXTURE_KUBERNETES_ROLE,
      <<"jwt">> := ?FIXTURE_KUBERNETES_JWT},
    State
) ->
    do_handle_auth(Req, State);

handle_auth_req(
    Req,
    approle,
    #{<<"role_id">> := ?FIXTURE_APPROLE_ROLE,
      <<"secret_id">> := ?FIXTURE_APPROLE_SECRET},
    State
) ->
    do_handle_auth(Req, State).


do_handle_auth(Req, State) ->
    Body = ?ENCODE(#{auth => #{
        client_token => <<"bob_the_client_token">>,
        lease_duration => 600
    }}),
    reply(200, Body, Req, State).


handle_read_req(Req, State) ->
    Key = cowboy_req:binding(rest, Req),
    case ets:lookup(?TABLE, Key) of
        [] ->
            Body = ?ENCODE(#{errors => []}),
            reply(404, Body, Req, State);
        [{_, Val}] ->
            reply(200, ?ENCODE(#{data => Val}), Req, State)
    end.


handle_write_req(Req, State) ->
    Key = cowboy_req:binding(rest, Req),
    {ok, Value, Req2} = read_body(Req, <<"">>),
    ets:insert(?TABLE, {Key, ?DECODE(Value)}),
    reply(204, <<"">>, Req2, State).


read_body(Req0, Acc) ->
    case cowboy_req:read_body(Req0) of
        {ok, Data, Req} -> {ok, << Acc/binary, Data/binary >>, Req};
        {more, Data, Req} -> read_body(Req, << Acc/binary, Data/binary >>)
    end.


reply(StatusCode, Body, Req, State) ->
    Req2 = cowboy_req:reply(StatusCode, #{
        <<"Content-Type">> => <<"text/json">>
    }, Body, Req),
    {ok, Req2, State}.
