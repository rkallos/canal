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
    Flags = #{
      strategy => one_for_one,
      intensity => 5,
      period => 10
    },
    CanalServer = #{
      id => canal,
      modules => [canal],
      restart => permanent,
      shutdown => brutal_kill,
      start => {canal, start_link, []},
      type => worker
    },
    Children = [CanalServer],
    {ok, {Flags, Children}}.
