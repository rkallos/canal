ELVIS=./bin/elvis
REBAR3=./bin/rebar3

all: compile

clean:
	$(REBAR3) clean -a

compile:
	$(REBAR3) as compile compile

coveralls:
	$(REBAR3) as test coveralls send

dialyzer:
	$(REBAR3) as compile dialyzer

elvis:
	$(ELVIS) rock

eunit:
	$(REBAR3) do eunit -cv, cover -v

test: elvis xref eunit dialyzer

travis: test coveralls

xref:
	$(REBAR3) xref

.PHONY: clean compile coveralls dialyzer elvis eunit xref
