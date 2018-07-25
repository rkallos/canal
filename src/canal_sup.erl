-module(canal_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).


%% public

-spec start_link() -> {ok, pid()}.

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).


%% callbacks

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.

init([]) ->
    {ok, { {one_for_all, 0, 1}, []} }.

%%====================================================================
%% Internal functions
%%====================================================================
