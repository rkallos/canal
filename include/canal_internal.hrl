-include("canal_defaults.hrl").

% macros

-define(APP, canal).
-define(GET_ENV(Key), application:get_env(?APP, Key, undefined)).
-define(GET_ENV(Key, Default), application:get_env(?APP, Key, Default)).
-define(GET_OPT(Atom), canal_utils:getopt(Atom)).
-define(ENCODE(Thing), jiffy:encode(Thing)).
-define(DECODE(Thing), jiffy:decode(Thing, [return_maps])).


% types

-type req_id()  :: shackle:request_id().
-type req() :: {{pid(), reference()}, write | read} | renew.
-type auth_method() :: {approle, binary(), binary()}.
-type renew_action() :: no_action | renew | reauth.
-type renew_pred() :: fun((non_neg_integer(), erlang:timestamp(), term()) ->
    {renew_action(), term()}).
