-module(canal).
-include_lib("shackle/include/shackle.hrl").
-include_lib("buoy/include/buoy.hrl").
-include("canal_internal.hrl").

-export([
    auth/1,
    read/1,
    reauth/0,
    write/2
]).

-export([
    start_link/0
]).

-behaviour(gen_server).
-export([
    code_change/3,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    init/1,
    terminate/2
]).

-record(auth, {
    payload   = undefined          :: {buoy_url(), binary()} | undefined,
    timestamp = erlang:timestamp() :: erlang:timestamp(),
    token     = undefined          :: binary() | undefined,
    ttl       = undefined          :: non_neg_integer() | undefined
}).

-type auth() :: #auth{}.

-record(state, {
    auth            = undefined                   :: auth() | undefined,
    request_timeout = undefined                   :: non_neg_integer(),
    requests        = #{}                         :: #{req_id() => req()},
    url             = undefined                   :: binary()
}).

-type state() :: #state{}.


%% API

-spec auth(auth_method()) -> ok | {error, term()}.

auth(Creds = {approle, _Id, _SecretId}) ->
    gen_server:call(?MODULE, {auth, Creds}).


-spec read(binary()) -> {ok, term()} | {error, term()}.

read(Key) ->
    gen_server:call(?MODULE, {read, Key}).


-spec reauth() -> ok.

reauth() ->
    gen_server:cast(?MODULE, reauth).


-spec start_link() -> {ok, pid()}.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


-spec write(iodata(), term()) -> ok | {error, term()}.

write(Key, Val) ->
    Body = ?ENCODE(#{<<"value">> => Val}),
    gen_server:call(?MODULE, {write, Key, Body}).


%% gen_server callbacks

-spec code_change(term() | {down, term()}, state(), term()) -> {ok, state()}.

code_change(_Old, State, _Extra) ->
    {ok, State}.


-spec handle_call(_, _, state()) ->
    {reply, term(), state()} | {noreply, state()} | {stop, term(), state()}.

handle_call({auth, Creds}, _From, State) ->
    Payload = make_auth_request(Creds, State),
    case do_auth(Payload, State) of
        {ok, Data} ->
            {reply, ok, update_auth(State, Data, Payload)};
        Err = {error, _} ->
            canal_utils:error_msg("Auth failed with ~p", [Err]),
            {reply, Err, State}
    end;


handle_call({read, Key}, From, State) ->
    Headers = headers(State),
    Url = url(State, ["/v1/secret/", Key]),
    Opts = #{
        headers => Headers,
        pid => self(),
        timeout => req_timeout(State)
    },
    {ok, ReqId} = buoy:async_get(Url, Opts),

    {noreply, add_request(ReqId, {From, read}, State)};

handle_call({write, Key, Body}, From, State) ->
    Url = url(State, ["/v1/secret/", Key]),
    Opts = #{
        body => Body,
        headers => headers(State),
        pid => self(),
        timeout => req_timeout(State)
    },
    {ok, ReqId} = buoy:async_post(Url, Opts),

    {noreply, add_request(ReqId, {From, write}, State)}.


-spec handle_cast(_, state()) -> {noreply, state()}.

handle_cast(reauth, State = #state{auth = #auth{payload = Payload}}) ->
    State2 = case do_auth(Payload, State) of
        {ok, Data} ->
            update_auth(State, Data, Payload);
        Err = {error, _} ->
            canal_utils:error_msg("Auth failed with ~p", [Err]),
            State
    end,
    {noreply, State2};

handle_cast(_Req, State) ->
    {noreply, State}.


-spec handle_info(_, state()) -> {noreply, state()}.

handle_info({#cast{request_id = RequestId}, Error = {error, _}}, State) ->
    case {req_type(RequestId, State), req_origin(RequestId, State)} of
        {read, From} ->
            gen_server:reply(From, Error);
        {write, From} ->
            gen_server:reply(From, Error)
    end,
    {noreply, del_request(RequestId, State)};

handle_info(Response = {#cast{request_id = RequestId}, {ok, _}}, State) ->
    case req_type(RequestId, State) of
        read ->
            handle_read_response(Response, State);
        write ->
            handle_write_response(Response, State);
        _ ->
            {noreply, del_request(RequestId, State)}
    end;


handle_info({token, Token}, State) ->
    case do_lookup(Token, State) of
        {ok, State2} ->
            {noreply, State2};
        Err = {error, _} ->
            Fmt = "Token lookup failed with ~p",
            Msg = io_lib:format(Fmt, [Err]),
            canal_utils:error_msg(Msg),
            {stop, {error, token_auth_failed}, State}
    end;

handle_info(_Req, State) ->
    {noreply, State}.


-spec init(_) -> {ok, state()}.

init(_) ->
    Url = ?GET_OPT(url),
    Timeout = ?GET_OPT(timeout),

    case ?GET_OPT(token) of
        undefined ->
            ok;
        Token ->
            self() ! {token, Token}
    end,

    Options = [{pool_size, 1}],

    ok = buoy_pool:start(buoy_utils:parse_url(Url), Options),

    State = #state{
        url = Url,
        request_timeout = Timeout
    },

    {ok, State}.


-spec terminate(term(), state()) -> ok.
terminate(_Reason, #state{url = Url}) ->
    buoy_pool:stop(buoy_utils:parse_url(Url)),
    ok.


%% private

-spec add_request(req_id(), req(), state()) -> state().

add_request(ReqId, Req, State = #state{requests = Requests}) ->
    State#state{requests = Requests#{ReqId => Req}}.


-spec del_request(req_id(), state()) -> state().

del_request(ReqId, State = #state{requests = Requests}) ->
    Requests2 = maps:remove(ReqId, Requests),
    State#state{requests = Requests2}.


do_auth({Url, Body}, State) ->
    do_auth2(Url, Body, req_timeout(State)).


do_auth2(Url, Body, Timeout) ->
    Opts = #{
        body => Body,
        headers => [],
        timeout => Timeout
    },
    {ok, #buoy_resp{body = RespBody, status_code = StatusCode}} =
        buoy:post(Url, Opts),

    case do_auth3(RespBody) of
        {ok, Auth} ->
            {ok, Auth};
        {error, Err} ->
            {error, {StatusCode, Err}}
    end.


do_auth3(Body) ->
    case ?DECODE(Body) of
        #{<<"auth">> := Auth} ->
            {ok, Auth};
        #{<<"errors">> := Err} ->
            {error, Err}
    end.


do_lookup(Token, State) ->
    Url = url(State, ["/v1/auth/token/lookup-self"]),
    Opts = #{
        body => [],
        headers => [{"X-Vault-Token", Token}],
        pid => self(),
        timeout => req_timeout(State)
    },
    {ok, #buoy_resp{body = RespBody, status_code = StatusCode}} =
        buoy:get(Url, Opts),

    case do_lookup2(Token, RespBody, State) of
        {ok, State2} ->
            {ok, State2};
        {error, Errors} ->
            {error, {StatusCode, Errors}}
    end.


do_lookup2(Token, Body, State) ->
    case ?DECODE(Body) of
        #{<<"data">> := Data} ->
            #{
                <<"ttl">> := Ttl
            } = Data,
            Auth2 = #auth{
                token = Token,
                ttl = Ttl
            },
            Msg = "Token found. Disabling reauthentication.",
            canal_utils:info_msg(Msg),
            {ok, State#state{auth = Auth2}};
        #{<<"errors">> := Errors} ->
            {error, Errors}
    end.


handle_read_response(
    {#cast{request_id = RequestId},
    {ok, #buoy_resp{body = Reply, status_code = StatusCode}}},
    State = #state{requests = Requests}) ->

    #{RequestId := {From, read}} = Requests,
    Reply2 = ?DECODE(Reply),
    Ret = case Reply2 of
        #{<<"data">> := Data} -> {ok, Data};
        #{<<"errors">> := Err} -> {error, {StatusCode, Err}}
    end,

    State2 = del_request(RequestId, State),
    gen_server:reply(From, Ret),
    {noreply, State2}.


handle_write_response({#cast{request_id = RequestId}, Response}, State) ->

    From = req_origin(RequestId, State),
    Reply = case Response of
        {ok, #buoy_resp{status_code = 204}} ->
            ok;
        {ok, #buoy_resp{body = Body, status_code = StatusCode}} ->
            case ?DECODE(Body) of
                #{<<"errors">> := Errors} ->
                    {error, {StatusCode, Errors}};
                _ ->
                    ok
            end
    end,

    gen_server:reply(From, Reply),
    {noreply, del_request(RequestId, State)}.


headers(State) ->
    {ok, Token} = token(State),
    [{"X-Vault-Token", Token}].


-spec make_auth_request(auth_method(), state()) -> {buoy_url(), binary()}.

make_auth_request({approle, RoleId, SecretId}, State) ->
    Map = #{<<"role_id">> => RoleId, <<"secret_id">> => SecretId},
    make_auth_request2("approle", Map, State).


-spec make_auth_request2(string(), #{binary() => binary()}, state()) ->
    {buoy_url(), binary()}.

make_auth_request2(AuthMethod, Map, State) ->
    Url = url(State, ["/v1/auth/", AuthMethod, "/login"]),
    Body = ?ENCODE(Map),
    {Url, Body}.


-spec req_origin(req_id(), state()) -> {pid(), reference()} | undefined.

req_origin(RequestId, #state{requests = Requests}) ->
    case Requests of
        #{RequestId := {From, _Type}} ->
            From;
        _ ->
            undefined
    end.


-spec req_timeout(state()) -> timeout().

req_timeout(#state{request_timeout = Timeout}) ->
    Timeout.


-spec req_type(req_id(), state()) -> lookup | read | write | undefined.

req_type(RequestId, #state{requests = Requests}) ->
    case Requests of
        #{RequestId := {_, Type}} ->
            Type;
        #{RequestId := _} ->
            undefined;
        _ ->
            badkey
    end.


-spec token(state()) -> {ok, binary()} | undefined.

token(#state{auth = undefined}) ->
    undefine;

token(#state{auth = #auth{token = undefined}}) ->
    undefined;

token(#state{auth = #auth{token = Token}}) ->
    {ok, Token}.


-spec update_auth(state(), map(), {buoy_url(), binary()} | undefined) ->
    state().

update_auth(State, Data, Payload) ->
    #{
        <<"client_token">> := Token,
        <<"lease_duration">> := Ttl
    } = Data,
    NewAuth = #auth{
        payload = Payload,
        timestamp = erlang:timestamp(),
        token = Token,
        ttl = Ttl
    },
    ReauthTime = floor(Ttl * 0.9),
    {ok, _} = timer:apply_after(ReauthTime, ?MODULE, reauth, []),
    State#state{auth = NewAuth}.


-spec url(state(), iolist()) -> buoy_url().

url(#state{url = BaseUrl}, IOList) ->
    buoy_utils:parse_url(iolist_to_binary([BaseUrl | IOList])).
