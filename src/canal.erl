-module(canal).
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
    payload   = undefined          :: {string(), binary()} | undefined,
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

-define(JSON, "application/json").


%% API

-spec auth(auth_method()) -> ok | {error, term()}.

auth(Creds = {approle, _Id, _SecretId}) ->
    application:set_env(?APP, credentials, Creds, [{persistent, true}]),
    gen_server:call(?MODULE, {auth, Creds});

auth(Creds = {ldap, _Username, _Password}) ->
    application:set_env(?APP, credentials, Creds, [{persistent, true}]),
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
            canal_utils:error_msg("canal: auth failed with ~p", [Err]),
            {reply, Err, State}
    end;


handle_call({read, Key}, From, State) ->
    Headers = headers(State),
    Url = url(State, ["/v1/secret/", Key]),
    {Opts, HttpOpts} = opts(async, req_timeout(State)),

    Request = {Url, Headers},
    {ok, ReqId} = httpc:request(get, Request, HttpOpts, Opts),

    {noreply, add_request(ReqId, {From, read}, State)};

handle_call({write, Key, Body}, From, State) ->
    Headers = headers(State),
    Url = url(State, ["/v1/secret/", Key]),
    {Opts, HttpOpts} = opts(async, req_timeout(State)),

    Request = {Url, Headers, ?JSON, Body},
    {ok, ReqId} = httpc:request(post, Request, HttpOpts, Opts),

    {noreply, add_request(ReqId, {From, write}, State)}.


-spec handle_cast(_, state()) -> {noreply, state()}.

% payload = undefined disambiguates a #auth{} from a passed-in token from canal
% doing its own auth
handle_cast(reauth, State = #state{auth = #auth{payload = undefined}}) ->
    {noreply, State};

handle_cast(reauth, State = #state{auth = #auth{payload = Payload}}) ->
    State2 = case do_auth(Payload, State) of
        {ok, Data} ->
            update_auth(State, Data, Payload);
        Err = {error, _} ->
            canal_utils:error_msg("canal: auth failed with ~p", [Err]),
            State
    end,
    {noreply, State2};

handle_cast(reauth, State = #state{auth = undefined}) ->
    case ?GET_OPT(credentials) of
        undefined ->
            Msg = "canal: not authenticated, and no credentials stored",
            canal_utils:error_msg(Msg),
            {stop, {error, no_credentials}, State};
        Creds ->
            canal_utils:info_msg("canal: auth using credentials in env"),
            Payload = make_auth_request(Creds, State),
            case do_auth(Payload, State) of
                {ok, Data} ->
                    {noreply, update_auth(State, Data, Payload)};
                Err = {error, _} ->
                    canal_utils:error_msg("canal: auth failed with ~p", [Err]),
                    {stop, Err, State}
            end
    end;

handle_cast(_Req, State) ->
    {noreply, State}.


-spec handle_info(_, state()) -> {noreply, state()}.

handle_info({http, Response = {RequestId, _}}, State) ->
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
            Fmt = "canal: token lookup failed with ~p",
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
            self() ! {token, iolist_to_binary(Token)}
    end,

    case ?GET_OPT(credentials) of
        undefined ->
            ok;
        _Creds ->
            gen_server:cast(self(), reauth())
    end,

    State = #state{
        url = Url,
        request_timeout = Timeout
    },

    {ok, State}.


-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
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
    {Opts, HttpOpts} = opts(sync, Timeout),

    Request = {Url, [], ?JSON, Body},
    {ok, {{_NewVersion, StatusCode, _Status}, _RespHeaders, RespBody}} =
        httpc:request(post, Request, HttpOpts, Opts),

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
    Headers = [{"X-Vault-Token", binary_to_list(Token)}],
    {Opts, HttpOpts} = opts(sync, req_timeout(State)),

    Request = {Url, Headers},
    {ok, {{_NewVersion, StatusCode, _Status}, _RespHeaders, RespBody}} =
        httpc:request(get, Request, HttpOpts, Opts),

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
            Msg = "canal: token found. Disabling reauthentication.",
            canal_utils:info_msg(Msg),
            {ok, State#state{auth = Auth2}};
        #{<<"errors">> := Errors} ->
            {error, Errors}
    end.


handle_read_response(
    {RequestId, {{_, StatusCode, _}, _, Reply}},
    State = #state{requests = Requests}) ->

    #{RequestId := {From, read}} = Requests,
    Reply2 = ?DECODE(Reply),
    Ret = case Reply2 of
        #{<<"data">> := Data} -> {ok, Data};
        #{<<"errors">> := Err} -> {error, {StatusCode, Err}}
    end,

    gen_server:reply(From, Ret),
    {noreply, del_request(RequestId, State)}.


handle_write_response({RequestId, Response}, State) ->
    From = req_origin(RequestId, State),
    Reply = case Response of
        {{_, 204, _}, _, _} ->
            ok;
        {{_, StatusCode, _}, _, Body} ->
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
    case token(State) of
        {ok, Token} ->
            [{"X-Vault-Token", binary_to_list(Token)}];
        _ ->
            []
    end.


-spec make_auth_request(auth_method(), state()) -> {string(), binary()}.

make_auth_request({approle, RoleId, SecretId}, State) ->
    Map = #{<<"role_id">> => RoleId, <<"secret_id">> => SecretId},
    make_auth_request2("approle", Map, State);

make_auth_request({ldap, Username, Password}, State) ->
    Map = #{<<"password">> => Password},
    Url = url(State, ["/v1/auth/ldap/login/", Username]),
    Body = ?ENCODE(Map),
    {Url, Body}.


-spec make_auth_request2(string(), #{binary() => binary()}, state()) ->
    {string(), binary()}.

make_auth_request2(AuthMethod, Map, State) ->
    Url = url(State, ["/v1/auth/", AuthMethod, "/login"]),
    Body = ?ENCODE(Map),
    {Url, Body}.


-spec opts(sync | async, integer() | atom()) -> {list(), list()}.

opts(Sync, Timeout) ->
    Sync2 = case Sync of
        sync -> true;
        async -> false
    end,
    HttpOpts = [{timeout, Timeout}],
    Opts = [{body_format, binary}, {sync, Sync2}],
    {Opts, HttpOpts}.


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


-spec req_type(req_id(), state()) -> read | write | undefined.

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
    undefined;

token(#state{auth = #auth{token = undefined}}) ->
    undefined;

token(#state{auth = #auth{token = Token}}) ->
    {ok, Token}.


-spec update_auth(state(), map(), {string(), binary()} | undefined) ->
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
    {Megas, Seconds, _Micros} = erlang:timestamp(),
    TimeAtReauth = {Megas, Seconds + ReauthTime, 0},
    DatetimeAtReauth = calendar:now_to_local_time(TimeAtReauth),
    canal_utils:info_msg("canal: will reauth at ~p", [DatetimeAtReauth]),
    {ok, _} = timer:apply_after(timer:seconds(ReauthTime), ?MODULE, reauth, []),
    State#state{auth = NewAuth}.


-spec url(state(), iolist()) -> string().

url(#state{url = BaseUrl}, IOList) ->
    binary_to_list(iolist_to_binary([BaseUrl | IOList])).
