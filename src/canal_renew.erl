-module(canal_renew).
-include("include/canal_internal.hrl").

-export([
    default/3,
    no_reauth/3
]).


-spec default(non_neg_integer(), erlang:timestamp(), non_neg_integer()) ->
    {renew_action(), non_neg_integer()}.

default(LeaseTime, Timestamp, Period) ->
    LeaseTimeMs = timer:seconds(LeaseTime),
    Diff = timer:now_diff(erlang:timestamp(), Timestamp),
    Action = case Diff of
        N when N > LeaseTimeMs ->
            reauth;
        N when N > (0.9 * LeaseTimeMs) ->
            renew;
        _N ->
            no_action
    end,
    {Action, Period}.


-spec no_reauth(non_neg_integer(), erlang:timestamp(), non_neg_integer()) ->
    {renew_action(), non_neg_integer()}.

no_reauth(LeaseTime, Timestamp, Period) ->
    LeaseTimeMs = timer:seconds(LeaseTime),
    Diff = timer:now_diff(erlang:timestamp(), Timestamp),
    Action = case Diff of
        N when N > LeaseTimeMs ->
            M = "Vault token expired. Subsequent requests will no longer work",
            canal_utils:info_msg(M),
            no_action;
        N when N > (0.9 * LeaseTimeMs) ->
            renew;
        _N ->
            no_action
    end,
    {Action, Period}.
