-include("canal_defaults.hrl").

% macros

-define(APP, canal).
-define(GET_ENV(Key), application:get_env(?APP, Key, undefined)).
-define(GET_ENV(Key, Default), application:get_env(?APP, Key, Default)).
-define(GET_OPT(Atom), canal_utils:getopt(Atom)).
-define(ENCODE(Thing), jiffy:encode(Thing)).
-define(DECODE(Thing), jiffy:decode(Thing, [return_maps])).


% types

-type req_id()  :: httpc:request_id().
-type req() :: {{pid(), reference()}, write | read}.
-type auth_method() :: {approle | ldap, binary(), binary()}.
