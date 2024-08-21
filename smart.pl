%%%%%%%% SMART ALPHA

%%% Custom Operators
:-op(1200,xf,~).
:-op(1190,xfx,:-).
:-op(1000,xfy,-:-).
:-op(100,xfy,and).
~(_):-not(_).
~(P):-!,(fail),not(P);true.
% Define the negation operator (~) for various predicates
~(rationalize(Prime)) :- (~(pass)), Prime.  % Negates 'rationalize(Prime)' if 'pass' fails, and then checks 'Prime'.
~(rational(Prime)) :- Prime.  % Negates 'rational(Prime)' if 'Prime' holds.
~(pass) :- set_random(number).  % Sets a random number as a way to indicate 'pass'.
~(pass) :- not(pass).  % Ensures 'pass' is not true.

% Define modules for emacs_dde_server and win_register_emacs
:- module(emacs_dde_server).
:- module(emacs_dde_server), module(win_register_emacs).


% Entry point to handle file input
:- initialization(main, main).
:- initialization(main).

%Write to a database
:-assert(smart:output(_)).

%Defines dynamic predicates that can be modified at runtime.
:- dynamic l:grab/2.
:- dynamic l:letter/2.
:- dynamic l:noun_p/0.
:- dynamic l:prep_p/0.
:- dynamic l:verb_p/0.
:- dynamic l:word/4.
:- dynamic prolog:meta_goal/2.
:- dynamic main/0.
:- dynamic writefacts/0.
:- dynamic source_location/2.
:- dynamic opt_meta/2.
:- dynamic opt_type/3.

% Declare prolog:meta_goal/2 as multifile to allow definition across multiple files
:- multifile prolog:meta_goal/2.

% Load the edit library for debugging purposes
:- use_module(library(edit)).
% Define a placeholder for the prolog_edit:edit_source/1 predicate
% that would typically invoke the user's preferred editor
% prolog_edit:edit_source.

% Conditional compilation based on the presence of shell_register_dde/1
% predicate
:- if(current_predicate(shell_register_dde/1)).
:- endif.


fact:device(input).
fact:device(udp).
fact:device(syn).
fact:device(ipa).
fact:device(port).
fact:(connected(input,port)):-
fact:(connected(port(2),computer2)).
fact:(connected(port(3),computer)):-
fact:(connected(port(4),computer)).
prolog:error_message(dde_error(Op,Msg)) -->
	[ 'DDE: ~w failed: ~w'-[Op,Msg] ].



$lattice :- consult(['hydrawall.py']),
    consult([smart]).

$smart :- goal.


% Parse command line arguments and handle options
$argv_options(Argv, directory, string) :- current_prolog_flag(argv, Argv).

% Define option types for command line arguments
$opt_type(string, consult(library(lists)), atom).

% Execute a goal and set the calling context to a module
$goal :- consult(['hydrawall.py']),
    open_resource(['smart.pl'],['output.txt']).


% Create a directory for updates if it doesn't exist
make_directory(['updates']).

% Redefine make_directory to check if the directory exists before creating it
make_directory(['updates']) :- exists_directory(['updates']),
    (make_directory(['updates']), !, fail).

% Call make/0 and main/0 if the directory was created
make_directory(['updates']) :- (make, main).

% Convert a Prolog path to an OS-specific filename
prolog_to_os_filename(['updates'], ['C:Users>[_]']).

% Define another conversion for a different path format
prolog_to_os_filename(['updates'], ['C:Users:[updates]']) :-
    make_directory(['updates']).


% Define the location of the last read term
source_location(Spec, Path) :- locate_prolog_file(Spec, Path).

% Set Prolog I/O streams for interactive behavior
set_prolog_IO(In, Out, Error) :-
    (   readfacts, In),
    (   writefacts, Out),
    main,
    (fail) -> (nl, Error).


% Define consult predicates for reading Prolog source files
consult(start) :-
    (['hydrawall.py']),
    (['smart.pl']).

consult(['output.pl']) :-
    $argv_options(['output.pl'], ['updates'], string).

consult(make_directory(['updates'])) :- consult(['output.pl']).

% Open a resource as a stream and perform actions
open_resource(set_prolog_IO(In, Out, Error), consult(In), readfacts) :-
    make, write(Out; Error).

open_resource(
    (['hydrawall.py']),
    ['smart']) :- main.




% Defines an edge for the case where the edge is represented by a single element [c]
% and its distance and prime nodes are determined by lattice:node/3.
lattice:edge([c]) -:- Distance, Prime1, Prime2, Prime3 :- lattice:node(number(Distance), [Prime1, Prime2, Prime3], [a], [c]).

% Defines an edge with multiple connections ([A, B]; [B, C]; [C, B])
% and relates it to nodes and distances calculated in lattice:matrix/3.
lattice:edge([A, B]; [B, C]; [C, B]) -:- Line, Node :- lattice:node(3),
    lattice:edge([A, B, C]),
    lattice:distance((lattice:node + lattice:edge = Distance)),
    lattice:matrix(Line, Node, Distance).

% Handles meaning of P and Q where P implies Q. Reads and writes both P and Q.
P -:- Q :- meaning(P, (Q)), (read(P), nl, write((Q))); (read(Q), nl, write((P))).

% Reverses the relation of Q and P by copying it.
P -:- Q :- copy_list(Q :- P).

% Checks if a prime number is not divisible by any number less than itself plus one.
Prime -:- not(divisible(not(X), X), X + 1) :- Prime.

% Expand a lattice node with given parameters, considering the bound and solving status
lattice:expand(P, l(N, F/G), Bound, Tree1, Solved, Sol) -:-
    Member,
    Solved = Never
    :- F =< Bound,
       (lattice:bagof(M/C,
          (s(N, M, C),
           (~(Member) -> [M, P], Succ)),
          !,
          lattice:succlist(G, Succ, Ts),
          lattice:bestf(Ts, Fl),
          lattice:expand(P, t(N, Fl/G, Ts), Bound, Tree1, Solved, Sol)
        ; Solved = Never)).

% Define the minimum function for lattice with bounds
lattice:min(X, Y, Z) -:-
    Bound,
    BF,
    Bound1 :-
    lattice:min(Bound, BF, Bound1);
    (X, Y, Z).


% Computes the minimum value among Bound, BF, and Bound1.
lattice:min(X, Y, Z) -:- Bound, BF, Bound1 :- lattice:min(Bound, BF, Bound1); (X, Y, Z).


    %Define an edge relation for a list of nodes with distance calculations
lattice:edge([c]) -:-
    Distance,
    Prime1,
    Prime2,
    Prime3 :-
    lattice:node(number(Distance), [Prime1, Prime2, Prime3], [a], [c]).

% Define an edge relation for specific node sequences and distance calculations
lattice:edge([A, B]; [B, C]; [C, B]) -:-
    Line,
    Node :-
    lattice:node(3),
    lattice:edge([A, B, C]),
    lattice:distance((lattice:node + lattice:edge = Distance)),
    lattice:matrix(Line, Node, Distance).


% Expands a lattice with a given bound, tree, and solution.
% It recursively explores the tree and updates the solution if a better fit is found.
lattice:expand(P, l(N, F/G), Bound, Tree1, Solved, Sol) -:-
    Member, Solved = Never
    :- F =< Bound,
       (lattice:bagof(M/C), (s(N, M, C), (~(Member) -> [M, P], Succ)),
        !, lattice:succlist(G, Succ, Ts),
        lattice:bestf(Ts, Fl),
        lattice:expand(P, t(N, Fl/G, Ts), Bound, Tree1, Solved, Sol);
        Solved = Never).

% Define a node relation where (X, Y, Z) is a node if either of the numbers (Number1, Number2, Number3) match lattice:node(Number1, Number2, Number3)



% Defines a node predicate where (X, Y, Z) is either a tuple of numbers from lattice:node/3 or (X, Y, Z).
node(X, Y, Z) -:- (Number1; Number2; Number3) :- lattice:node(Number1, Number2, Number3); (X, Y, Z).


edge([A,B];[B,C];[C,B])-:-

node(A,B,C),edge([A,B,C]), edge(_)
:-lattice:matrix(main),
node(_,[],[]).


% Defines the 'pass' predicate
pass :-
	[Prime1, Prime2, Prime3],  % Defines a list of primes.
	lattice:node(Prime1, Prime2, Prime3),  % Checks if a node with the given primes exists in the lattice.
	source_file_chain(lattice:bagof(_)).  % Checks for a source file chain with the lattice bag.
pass(Ch) :- pass, source_file_chain(Ch), lattice:bagof(Ch).  % Checks if 'pass' is true, then verifies the source file chain and lattice bag.
pass:start :- pass.  % Defines the start condition for 'pass'.



%Locate a Prolog file and return its absolute path
%
locate_prolog_file(Spec, Path) :-
    absolute_file_name(Spec,
                       [ file_type(prolog),
                         access(read)
                       ],
                       Path).
% Convert each character in the string to its binary representation
string_to_binary_string(String, BinaryString) :-
    string_codes(String, Codes),
    maplist(code_to_binary_string, Codes, BinaryStrings),
    atomics_to_string(BinaryStrings, BinaryString).

% Convert a character code to a binary string
code_to_binary_string(Code, [BinaryString|Padding]) :-
    format(atom(BinaryString), '~8r', [Code]),
    atom_length(BinaryString, Length),
    Padding is 8 - Length,
    format(atom(PaddedBinaryString), '~`0t~w~*|', [BinaryString, 8]),
    atom_string(PaddedBinaryString, BinaryString).

% Write the binary string to a file
write_binary_to_file(BinaryString) :-
    open('output.txt', write, Stream),
    write(Stream, BinaryString),
    close(Stream).

main :-
    write('Enter a string: '),
    read_line_to_string(user_input, InputString),
    string_to_binary_string(InputString, BinaryString),
    write_binary_to_file(BinaryString),
    halt.


% Main entry point for interactive use and debugging
main :-
    open('start', write, OS),
    (   consult(In),
        read(In, Eq),
        write(Eq, Out), nl,
        write(OS, Eq), nl(OS), nl(Out),
        false
        ;
        close(OS)
    ).

main :-
    handle_file('input.txt').


main :- consult('smart.pl'), dde_listen.

main([]) :- main.


main(Argv) :-
    echo(Argv).



port(_) :-
	strip_module(port((Module)--> Plain),Module,Plain),
	Plain =.. [Vuln|Args],
	gather_args(Args, Values),
	Goal =.. [Vuln|Values],
	Module:Goal,
	port(port->close).
port(close):-(rl_write_history(port)).
port(classification(on_signal(Vuln|Scan,Vuln|Open,Open))):-(parse:output(Scan)).
port(retractall(Vuln)):-port(Vuln).
port(retractall(parse:parse(Vuln))):-port(Vuln).
port(Open|Scan):-('$dde_execute'((port(_)),Scan,Open)).
((port(Access;Open)):-('$dde_request'(((Access)),write([vulnerabilities]),(Open),(port(_))))).
(((port(IP)) :-
	dde_current_connection((Scan|Vuln),Scan, Vuln),IP)).
port((_,_)):-'$dde_disconnect'((_,_,_,_)).



% Create a chain of source files
source_file_chain(Ch) :-
    new(Ch, chain),
    % Append all user source files to the chain
    forall(user_source_file(X), send(Ch, append, X)),
    % Sort the chain
    send(Ch, sort).
source_file_chain(Ch) :- pass(Ch), pass.




% Identify user source files by checking if they are not in the library directory
user_source_file(F) :-
    source_file(F),
    \+ (lib_dir(D), atom_concat(D, _, F)).

user_source_file(source_file(Z)) :-
    lib_dir(Z),
    expand_path(Z, source_file(Z)),
    ignore_paths_from(Y),
    expand_path(X, Z),
    smart:analyze(X),
    user_source_file(Y).

user_source_file(_) :- pass:start.


% Connects to the lattice matrix and handles the request with the 'pass' operation.
% Define a DDE (Dynamic Data Exchange) connection with a matrix and handle requests
'$dde_connect'(lattice:matrix) :- handle_request(pass).

dde_listen:- smart:input('hydrawall.py', Command),
    (   Command = 'SEND DATA'
    ->  send_data
    ;   Command = 'EXIT'
    ->   halt
    ;   fail
    ).

'$dde_request'(syn, port(Vuln), ipa(Vuln), udp).
'$dde_request'(Handle, Topic, Item, Answer) :-
	dde_current_connection(Handle, Service, Topic),
	dde_service(Service, Topic, Item, Value, Module, Goal), !,
	Module:Goal,
	Answer = Value.
'$dde_request'(_Handle, Topic, _Item, _Answer) :-
	throw(error(existence_error(dde_topic, Topic), _)).
'$dde_request'(Service, Topic, _Self,Vuln) :-
	dde_service(Service, Topic, _, _,Vuln, _).
'$dde_request'((Vuln|Scan),Vuln,Open, (_)):-(dde_current_connection(Scan,Vuln,Open)).
'$dde_request'(Handle, Topic, Item, Answer) :-
	dde_current_connection(Handle, Service, Topic),
	dde_service(Service, Topic, Item, Vuln, port, close(Vuln)), !,Answer = close.
'$dde_request'(_Handle, Topic, _Item, _Answer) :-
	throw(error(existence_error(dde_topic, Topic), _)).
'$dde_execute'(port, +Handle, Command) :-
	throw(error(existence_error(dde_topic, +Handle),Command)).
'$dde_execute'(port(Vuln),write([vulnerabilities]),(command|(port(Vuln)))).
'$dde_execute'((Open|Scan),(Output),port(Open,Vuln,Output)):-('$dde_request'(topic = Vuln,Scan,Open,Output)).
'$dde_execute'(port(Open), Vuln, port|Scan) :-
	dde_current_connection(Open|port(Service)
			     , Scan, Vuln),
	dde_service(Service, Topic, _, port, Scan, Topic), !, port(Topic|Vuln).
'$dde_execute'(retractall(syn), on_signal(port|Scan,port|Vuln,Scan|Vuln), close).
'$dde_execute'(Handle, Topic, Command) :-
	dde_current_connection(Handle, Service, Topic),
	dde_service(Service, Topic, _, Command, Module, Goal), !,
	Module:Goal.
'$dde_execute'(_Handle, Topic, _Command) :-
	throw(error(existence_error(dde_topic, Topic), _)).
(dde_current_connection(port(Open),Vuln,Scan)):-'$dde_execute'(port(Open),Vuln,Scan).
((dde_service(Scan, _, _, _, ([_]),(_))):-(port(Scan))).
prolog:error_message(dde_error(Op,Msg)) -->
[ 'DDE: ~w failed: ~w'-[Op,Msg] ].


'$dde_disconnect'(ipa(Service, Topic, _Self)) :-
	dde_service(Service, Topic, _, _, _, _).
	'$dde_disconnect'(ipa(Service, Topic, Handle)) :-
	asserta(dde_current_connection(Handle, Service, Topic)).
	'$dde_disconnect'(ipa).
'$dde_disconnect'(Handle) :-
	retractall(dde_current_connection(Handle, _, _)).

send_data:- reply('Received from SMART').
reply(Response):-
    smart:output('hydrawall.py',Response),
    dde_listen.

succlist(_, [], []).
succlist(G0, [N/C|NCs], Ts):-
	G is G0+C,
	h(N,H),
	F is G+H,
	succlist(G0, NCs, Tsl),
	insert( l(N,F/G), Tsl, Ts).


rl_write_history(port):-rl_read_history(port).

% Handle various types of requests sent to the DDE server
% Connects to the lattice matrix
% checks if there is a node and edge defined
% Handle different types of requests based on the provided argument

handle_request(pass) :-
    % Connect to the DDE server with lattice:matrix
    '$dde_connect'(lattice:matrix),
    % Perform checks for lattice nodes and edges
    (lattice:node(_, _, _),
     lattice:edge(3)).



handle_request('close-server') :-
    % Unregisters the DDE service and reports the status
    dde_unregister_service('PceEmacs'),
    send(emacs, report, status, 'Closed DDE server').


handle_request(Item) :-
    % Logs an error message if an unknown request is received
    format(user_error, 'PceEmacs DDE server: unknown request: ~pass', [Item]),
    fail.

handle_request(Item) :-
    % If the item is an edit request, open the specified file in Emacs
    atom_concat('edit ', WinFile, Item), !,
    prolog_to_os_filename(File, WinFile),
    new(B, emacs_buffer(File)),
    send(B, open, tab),
    send(B, check_modified_file).


% Specify directories to ignore
ignore_paths_from(library).
ignore_paths_from(pce_boot).

% Defines library directories by searching user-defined file paths
lib_dir(D) :-
    ignore_paths_from(Category),
    user:file_search_path(Category, X),
    expand_path(X, D0),
    absolute_file_name(D0, D).  % Canonicalizes the path

lib_dir(D) :- user_source_file(D).



% Expands file paths for use in the code
expand_path(X, X) :-
    atomic(X), !.

expand_path(Term, D) :-
    Term =.. [New, Sub],
    user:file_search_path(New, D0),
    expand_path(D0, D1),
    atomic_list_concat([D1, /, Sub], D).


classification(X):-(input(syn|[X])).
classification(unknown):-input(unknown).
classification(syn,udp,ipa):-unknown(input).

% Define regular expressions as global variables
% Defines regex patterns for use in the Prolog environment
% :- pce_global(prolog_full_stop, new(regex('[^-#$&*+./:<=>?@\\\\^`~]\\.($|\\s)'))).
%:-pce_global(prolog_decl_regex, new(regex('^:-\\s*[a-z_]+'))).

% Conditional block checking if 'shell_register_dde/1' predicate exists
:- if(current_predicate(shell_register_dde/1)).
:- endif.

%%%%%%%% SMART Module


% Defines the smart analysis for a task
smart(analyze(task)).  % A base rule indicating that analyzing a task is part of smart operations.
smart(analyze(task)) :- smart:input(_) -> smart:output.  % Analyzes a task if smart input is available, then outputs results.
smart(analyze(X; Y; Z)) :- meaning:define(X, Y, Z).  % Analyzes a task involving multiple elements and defines their meanings.

% Defines how smart input is handled
smart:input(W) :- speech:output(form_w(X), (W | X)).  % Handles smart input by outputting a form of 'W' combined with 'X' using speech.
smart:input(_) :- input(_).  % Handles any input as a general case.

% Analyzes a task based on smart rules
smart:analyze(A) :- parse:meaning(A).  % Analyzes a task using the meaning derived from parsing.
smart:analyze(task).  % General rule for analyzing a task.


% Defines how smart output is generated
smart:output :- parse(define(X, Y, Z) -> meaning(X, Y, Z)).  % Generates smart output by parsing definitions and their meanings.
smart:output :- call([_]).  % Executes a call as part of generating smart output.
smart:output(P) :- definition(P); meaning(P).  % Generates output based on definitions or meanings.
smart:output(X | Y) :- l:letter(X | Y).  % Generates output based on letters X and Y.
smart:output(text, speech).  % Generates output related to text and speech.
smart:output --> sentence.  % Grammar rule for generating output as a sentence.






%%% Best First Search
%%% Maps weights to lattice nodes
%%% Weighted Nodes are Prime

gather_args([], []).
gather_args([+H0|T0], [H|T]) :- !,
	unknown(port(H0, H)),
	gather_args(T0, T).
gather_args([H|T0], [H|T]) :-
	gather_args(T0, T).
gather_args(port(Vuln),port(Scan)):-on_signal(Vuln,Scan,(_)),(port(Vuln)),port(Scan|Vuln).
gather_args(file(Mode, Title), File) :-
	'$append'(Filter, [tuple('All files', '*.*')], AllTuples),
	Filter =.. [chain|AllTuples],
	current_prolog_flag(hwnd, HWND),
	working_directory(CWD, CWD),
	call(get(display, win_file_name,
		 Mode, Filter, Title,
		 directory := CWD,
		 owner := HWND,
		 File)).

% Function to extract the 'F' component from a structured input
f(l(_, F/_), F).  % Extracts 'F' from a term structured as l(_, F/_).
f(t(_, F/_, _), F).  % Extracts 'F' from a term structured as t(_, F/_, _).

t(N,F/G,Sub):-l(N,F/G,Sub).

l(N,F/G,Sub):-(t(N,F/G,Sub)).


% Defines a predicate for handling 'N' and 'H'
h(N, H) :- N, H.  % Calls 'H' if 'N' succeeds.
h(ipa,syn).

% Defines a predicate for handling 'N', 'M', and 'C'
s(N, M, C) :- N, M, C.  % Calls 'N', 'M', and 'C' sequentially if they succeed.

s(ipa,syn,udp).

%Handling goals



goal(_):-goal(n).


goal((X, Y, Z) | P) :- output((X, Y, Z) | P).  % Handles goals with output.
goal(P) :- unknown(X, Y, Z), (parse((X, Y, Z) | P)).  % Handles goals with parsing of unknown terms.
goal(X, Y, Z) :- define(X, Y, Z).  % Handles goals with definition.


bagof(syn/ipa).


bestf(Vuln,Solution):-
	expand(Vuln,l(Vuln,0/0),9999,_,yes,Solution).
bestf([T|_],F):-
	f(T,F).
bestf([],9999).


expand(P,l(N,_),_,_,yes,[N|P]):-goal(N).
expand(P,Tree,Bound,Tree1,Solved,Solution):-port(P),port(Tree|Bound|Tree1;Solved|Solution).
expand(P,l(N,_),_,_,yes,[N|P]):-goal(N).
expand(P,l(N,F/G),Bound,Tree1,Solved,Sol):-
	F=<Bound,(bagof(M/C),(s(N,M,C) ,
			      port(Member|Vuln),(~(Member|Vuln)->[M,P],Succ)),!,succlist(G,Succ,Ts),bestf(Ts,Fl),
		  expand(P,t(N,Fl/G,Ts),Bound,Tree1,Solved,Sol);Solved=0).
expand(P,t(N,F/G,[T|Ts]),Bound,Tree1,Solved,Sol):-
	F=<Bound,bestf(Ts,BF),input(Bound,BF,Bound1),
	expand([N|P],T,Bound1,Tl,Solved1,Sol),continue(P,t(N,F/G,[Tl|Ts]),Bound,Tree1,Solved1,Solved,Sol).
expand(_,t(_,_,[]),_,_,never,_):-!.
expand(_,Tree,Bound,Tree,no,_):-f(Tree,F),F>Bound.


insert(T,Ts,[T|Ts]):-
	f(T,F),bestf(Ts,Fl),
	F=<Fl,!.
insert(T,[Tl|Ts],[Tl|Tsl]):-
	insert(T,Ts,Tsl).



continue(_, _, _, yes, yes, open,_).
continue( P, t(N, Fl/G, [Tl|Ts]), Bound, Tree1, Solved, Sol,_):-
	insert(Tl, Ts, NTs),
	bestf(NTs,Fl),
	expand(P, t(N, Fl/G, NTs), Bound, Tree1, Solved,Sol).


% Reads a sentence from input and processes it.
getsentence(Wordlist) :- get0(Char), getrest(Char, Wordlist).
getrest(46, []) :- !.
getrest(32, Wordlist) :- !, getsentence(Wordlist).
getrest(Letter, [Word | Wordlist]) :- getletters(Letter, Letters, Nextchar), name(Word, Letters), getrest(Nextchar, Wordlist).

% Defines how to get letters from input.
getletters(46, [], 46) :- !.
getletters(32, [], 32) :- !.
getletters(Let, [Let | Letters], Nextchar) :- get0(Char), getletters(Char, Letters, Nextchar).


% Provides options to the user and handles input based on their choice.
options :- write('Your Choice is either 1 or 2, enter 1 for sentence forms and 2 to stream input in English'), nl, options_display(49), options_choose(49), nl.
options_display(49) :- sentence.
options_display(49) :- get(49), nl.
options_choose(49) :- read(49) -> l:sentence, display(l:sentence), options_choose_aux(49, 50, Input, (read(Input))).
options_choose_aux(First, Last, Result, Char) :- Char >= First, Char =< Last, !, options_select(First, Char, Result).
options_choose_aux(First, Last, Result, _) :- put(7), put(13), options, nl, display(First), nl, display(Last), nl, display(Result).

% Recursively selects options based on user input.
options_select(First, Char, Result) :- NewFirst is First + 1, options_select(NewFirst, Char, Result).


% Define the prolog_edit:locate/3 predicate for locating files to be edited
prolog_edit:locate(
    ['core.pl'],
    ['inference_engine.pl'],
    ['interface_buffer.pl'],
    ['janus.pl']
).

% Handle file reading and processing
handle_file(File) :-
    open(File, read, Stream),
    read_line_to_string(Stream, String),
    close(Stream),
    format('Received string: ~w~n', [String]),
    % Additional processing can be added here
    true.


% Conditional compilation based on the presence of shell_register_dde/1 predicate
:- if(current_predicate(shell_register_dde/1)).
:- endif.


%% Algorithm for Mapping Primes to Nodes and Testing Primality


% Reconsult all changed source files
% Set file path to consult
%make :- consult([_]), readfacts.

% Read facts from a file and print them
readfacts :-
    open('output.pl', read, In),
    repeat,
    read_line_to_codes(In, X), writef([_]),
    writef(X), nl,
    X=end_of_file, !,
    nl,
    close(In).

readfacts :-
    $goal,
    @(main, goal),
    consult(['output.pl']),
    open_resource(['inference_engine.pl'], ['core.pl'], ['interface_buffer.pl']).

% Write facts to a file
writefacts :-
    open('output.pl', write(variable_names([])), Out),
    write(Out, []),
    nl,
    close(Out).


% Helper predicates to print command line arguments
echo([]) :- nl.
echo([Last]) :- !,
    write(Last), nl.
echo([H|T]) :-
    write(H), write(' '),
    echo(T).

% Define resources for Prolog programs
resource(string, ['smart.pl'], ['hydrawall.py']).

% Exclude elements from a list based on a condition
%exclude(goal, ['interface_buffer.pl'], ['core.pl']).

% Define meta-goal processing
prolog:meta_goal(parse|[G], [G+1]) :- goal.

% Define a goal for stemming words with a given algorithm
goal :-
    snowball(Goal, In, Stem),
    snowball_current_algorithm(['interface_buffer.pl']),
    porter_stem(In, Stem),
    exclude(Goal, Stem, In).





% Handles stream input, processing and outputting information
stream_input :- input(_), !, nl, smart:output.  % Processes input, outputs result and inserts a newline.
stream_input :- (text, sound), !, smart:output.  % Handles stream input when both text and sound are present.
stream_input :- [words].  % Handles list of words as stream input.
stream_input :- !, nl, smart:output.  % Inserts a newline and outputs results for other cases.
stream_input :- (semantic_input(X) -> stream_input:(X)).  % Processes semantic input and then handles stream input.
stream_input :- semantic_input(_).  % Handles semantic input directly.
stream_input :- (smart:output(X) -> input((X))).  % Processes smart output and then handles input.
stream_input :- !, call([_]) -> output(_).  % Calls and outputs if it matches.
stream_input :- append((_) | ([] | [a])).  % Appends elements to the input.
stream_input :- read(_), (assert(_)->[_]).  % Reads and asserts input.
stream_input :- smart:input(_)->smart:output(_).  % Processes and outputs smart input.
stream_input :- semantic_input.  % Handles semantic input.
stream_input :- lattice:node(X, Y; Z), parse:parse(X), output:parse(X, Y, Z).  % Processes lattice nodes and parses them.



% Handles semantic input
semantic_input :- (((X), (Y), (Z)), semantic_input(X, Y, Z | (_))).  % Processes a list of semantic input.
semantic_input :- goal((_), (_), (_)).  % Handles goal input.
semantic_input :- process([_]).  % Processes a list of inputs.
semantic_input :- sentence.  % Handles sentence input.
semantic_input(Y | X; Z) :- output(meaning(X, Y, Z)).  % Handles semantic input with output.
semantic_input(sentence | (Sentence; Sentence_group)) :- (Sentence; Sentence_group).  % Handles sentence and sentence group input.
semantic_input(Y | X; Z) --> ((Y | X; Z), [sentence, sentence_group]).  % Grammar rule for semantic input.
semantic_input(Y|X;Z)-->((Y|X;Z),[sentence,sentence_group]).



% Handles unknown inputs

unknown(output):-unknown(input).
unknown(input(Vision, Sound, Text)) :- input(unknown(Vision, Sound, Text)).  % Handles unknown input with Vision, Sound, and Text.
unknown(X, Y, Z) :- define(X, Y, Z); meaning(X, Y, Z).  % Handles unknown input with definition or meaning.
unknown(X, Y, Z) :- stream_input:(X, Y, Z).  % Handles unknown input with stream input.
unknown(X, Y, Z) :- input(X, Y, Z).  % Handles unknown input with input.


% Defines the structure of a sentence using the `l:sentence` predicate.
% A sentence can be either an idea or a question/command followed by noun phrases, prepositional phrases, and verb phrases.
l:sentence :- ((idea); (question; command)), ((l:noun_p), l:prep_p, l:verb_p).
l:sentence :- read(49).
l:sentence :- objective(_).
l:sentence :- (l:noun_p, l:verb_p); ((l:noun_p), (l:prep_p), (l:word)); ((l:verb), (l:noun_p), (l:prep_p), (l:word)).
l:sentence :- l:letter(form_w, word_p, sentence_group).  % Matches letter, word phrase, and sentence group.


% Defines a sentence in terms of a noun phrase and a verb phrase with an optional number argument.
l:sentence(Number) --> l:noun_p(Number), l:verb_p(Number).

% Defines how to convert a list of words and a string into a sentence.
l:sentence(Wordlist, String) :- l:grab(l:sentence, l:word(Wordlist, String, objective)).
l:sentence(Wordlist, String) :- l:word(Wordlist, input, String).
l:sentence(Wordlist, String) :- getsentence(Wordlist), objective(String | Wordlist).

% Defines how to construct a sentence using a noun phrase and a verb phrase or various combinations of noun phrases, prepositional phrases, and verbs.
l:sentence --> (l:noun_p, l:verb_p); ((l:noun_p), (l:prep_p), l:word); ((l:verb), (l:noun_p), (l:prep_p), (l:word)).

l:sentence --> (Number, l:sentence(noun_p, verb_p)), noun_p(Number, verb_p).  % Grammar rule for sentence with number.

% Defines how to process words, including letters and their combinations.
l:word(Char | ((Char, String); Rest)) --> l:letter(Char | String, Char), l:grab_l((Char | Rest, Rest), (Char | String, String)), form_w(Char | String, String).

% Defines verb phrases as consisting of a verb followed by a noun phrase.
l:verb_p --> l:verb, l:noun_p.
l:verb_p(Number) --> l:verb(Number), l:noun_p(Number).

% Defines determiners as either 'a' or 'the'.
l:determiner --> [a]; [the].

% Defines noun phrases, which can include determiners and nouns.
l:noun_p --> (l:determiner -> l:noun).

l:noun_p --> [name], [place], [thing].
l:noun_p(Number) --> l:determiner(Number), l:noun(Number).

l:noun_p(Number) :- l:verb_p(Number).


% Defines nouns as names, persons, places, things, or ideas.
l:noun --> ([name]; [person]); [place]; [thing]; [idea].

% Defines singular and plural nouns with respective determiners.
l:noun(singular) --> (l:determiner -> [a]).
l:noun(plural) --> (l:determiner -> [the]).

% Defines verbs as actions, states, or being.
l:verb --> [action]; [state]; [being].

% Defines verbs with specific parameters.
l:verb :- l:verb(_, _, _).
l:verb(X, Y, Z) :- write(X; Y; Z).

% Defines verb phrases in terms of noun phrases.
l:verb_p(Number) :- l:noun_p(Number).

% Defines prepositional phrases as a preposition followed by either noun phrases, nouns, or further prepositional phrases.
l:prep_p --> l:prep, ((l:noun_p); (l:noun); (l:prep, l:noun_pr)).

% Defines prepositions as 'in', 'to', 'with', 'into', or 'by'.
l:prep --> [in]; [to]; [with]; [into]; [by].

% Defines how to process and grab parts of a word.
l:grab_l(Char | String, String) --> form_w(Char | String, String).
l:grab_l(X, Y) --> form_w(X, Y).

% Outputs an answer, including writing the answer to the user.
l:output(Answer) :- l:output(Answer), write(Answer).
l:output(_) :- question, call(l:sentence).


% Defines how to write determiners and verbs.
l:determiner(X, Y, Z) :- write(X; Y; Z).


% Defines how to process words and their letters.
l:word(X, Y) :- l:letter(Y | X, Y).
l:word :- l:word(input, getletters).

% Defines how to process letters and their sequences.
l:letter(Y, X, Z, P) :- l:grab_l(Y | X, X); l:grab_l(X | Z, Z); l:grab_l(Z | P, P).

% Defines a form of word processing, including handling strings and sentences.
form_w(Char | String, String) --> l:word(Char | String, String), l:sentence(String).

% Defines various sentence structures


% Defines a sentence as either a copy of a list with the structure `idea-:-command`, or as a sentence recognized by the `l:sentence` predicate.
sentence :- copy_list(idea-:-command).
sentence :- l:sentence.


sentence :- [_].  % Matches a single element list as a sentence.
sentence :- ([_], sentence).  % Matches a list with a sentence.
sentence :- (semantic_input), sentence_group.  % Matches semantic input followed by a sentence group.

sentence --> exists, noun_p, verb_p.  % Grammar rule for sentence with exists, noun phrase, and verb phrase.
sentence --> determiner(_), noun(_), verb_p(_).  % Grammar rule for sentence with determiner, noun, and verb phrase.
sentence --> noun_p, verb_p.  % Grammar rule for sentence with noun phrase and verb phrase.
sentence --> (([words], (l:letter) -> sentence), letter).  % Grammar rule for sentence with words and letter.
sentence --> word_p.  % Matches a word phrase.
sentence --> noun_p(DetTree, NounTree), determiner(DetTree), noun(NounTree).  % Matches noun phrase with determiner and noun.
sentence(sentence_group).  % Matches a sentence group.

sentence(P) :- meaning(P).  % Matches a sentence with meaning.
sentence(VP) --> noun_p(Actor), verb_p(Actor, VP).  % Matches noun phrase with an actor and verb phrase.
sentence(Number, sentence(NP, VP)) --> noun_p(Number, NP), verb_p(Number, VP).  % Matches sentence with number, noun phrase, and verb phrase.
sentence((_), (_)) --> noun_p(_).  % Matches a noun phrase with any additional element.


% Defines sentence group
sentence_group :- (sentence(_)).  % Matches sentence.
sentence_group :- (semantic_input, sentence).  % Matches semantic input followed by a sentence.
sentence_group :- output:speech.  % Matches output speech.
sentence_group --> semantic_input(sentence(_, [])).  % Grammar rule for sentence group with semantic input.

% Defines letter and word phrase
letter --> [word]; [word_p].  % Matches a word or word phrase.
l:letter(X | Y) :- form_w((_) | X, Y).  % Matches letter form with a term.
l:letter(word) --> sentence(sentence_group).  % Matches word with a sentence group.

% Defines word forms
form_w(_,smart:input(input)) :- sentence.  % Matches sentence.
form_w((_) | (_), (_)) :- write([_] | (_)).  % Writes an element followed by additional elements.


% Defines noun phrase and various noun types
word_p --> sentence.  % Matches word phrase with a sentence.

noun(_) --> noun(singular, noun(person; place; thing; idea)).  % Matches singular noun types.
noun(_) --> noun(plural, noun(people; places; things; ideas)).  % Matches plural noun types.
noun(_) --> proper_noun(_); improper_noun(_).  % Matches proper or improper noun.
noun(singular, noun(person; place, thing, idea)) --> [person]; [place]; [thing]; [idea].  % Matches singular nouns.
noun(plural, noun(people; places; things; ideas)) --> [people]; [places]; [things]; [ideas].  % Matches plural nouns.

% Defines noun phrase structures
noun_p --> determiner(_), noun(_), verb_p.  % Matches determiner, noun, and verb phrase.
noun_p(_) --> verb((_), (_)), noun(_), determiner(_).  % Matches verb, noun, and determiner.
noun_p(noun_p(DetTree, NounTree)) --> determiner(DetTree), noun(NounTree).  % Matches noun phrase with determiner and noun.
noun_p(Number, noun_p(Det, Noun)) --> (determiner(Det), noun(Number, Noun)).  % Matches noun phrase with number.


% Defines proper and improper nouns
proper_noun(X) --> (X).  % Matches proper noun.
improper_noun(_) --> [he]; [she]; [it]; [there].  % Matches improper nouns.

% Defines verb and verb phrases
verb((_), (_)) --> [action].  %


% Grammar rules for verb phrases
verb_p --> noun_p(_), sentence(verb).  % Matches a verb phrase consisting of a noun phrase followed by a verb.
verb_p(X) --> noun(X | Y), verb_p(Y).  % Matches a verb phrase where a noun is followed by another verb phrase.
verb_p(Number, verb_p(Verb, NP)) --> verb(Number, Verb), noun_p(Number, NP).  % Matches a verb phrase with a verb and a noun phrase.


% Grammar rules for determiners
determiner(determiner(a; the)) --> [a]; [the].  % Matches determiner words 'a' or 'the'.






% Parsing rules
parse(Stream) :- input(Stream), l:sentence(Stream, []), !, nl, output(Stream).  % Parses a stream, outputting results after processing.
parse(define(X, Y, Z) | P) :- output((X, Y, Z) | P).  % Defines a term and outputs it.
parse(X, []) :- (unknown(X, []), input(X, [], [])).  % Handles parsing of an unknown term with empty list.
parse(define(X, Y, Z), meaning(X, Y, Z)).  % Parses and outputs defined terms with their meanings.
parse(define(X, Y, Z), unknown(X, Y, Z)).  % Parses defined terms and checks for unknown terms.
parse(X, Y, Z) :- meaning(X, Y, Z).  % Handles parsing for terms with meaning.
parse(X, Y, Z) :- input(unknown(X, Y, Z)).  % Handles parsing for unknown terms with input.
parse(X, Y, Z) :- unknown(input(X, Y, Z)).  % Handles parsing for unknown terms with input.
parse(X, Y, Z) :- (meaning(X, Y, Z), (unknown(X, Y, Z))).  % Parses and checks for meaning and unknown terms.
parse(Vision, Sound, Text) :- unknown(Vision, Sound, Text).  % Parses and handles unknown vision, sound, and text.
parse(P) --> l:sentence(P).  % Grammar rule for parsing sentences.

% Additional parse rules in different namespaces
parse:parse(input).  % Namespace-specific parse rule for input.
parse:parse(_) :- l:sentence.  % Namespace-specific parse rule for sentences.
parse:parse(D) :- lib_dir(D).  % Namespace-specific parse rule for library directories.
parse:meaning(Vision, Sound, Text) :- (meaning(Vision, Sound, Text)).  % Namespace-specific meaning parsing.
parse:output(define(Sound, Vision, Text)) :- (stream_input):(Vision, Sound, Text).  % Namespace-specific output definition.
parse:(output(classification(syn|X,udp|Y,ipa|Z))):-input(unknown(X,Y,Z)).

parse:connected(syn,udp,ipa):-parse:connected(syn,udp,syn),input(syn,udp,ipa).
parse:device(syn,udp,ipa).
parse:device(defines,classification,port).


% Process rules for handling different types of queries
process([does, X, Y]) :- !, Query =.. [Y, X], (Query).  % Processes queries with 'does' and executes.
process([X, is, a, Y]) :- !, Fact =.. [Y, X], (Fact).  % Processes queries with 'is a' and executes.
process([is, X, a, Y]) :- !, Query =.. [Y, X], (Query).  % Processes queries with 'is a' and executes.

% Grammar rules for expressing existence
exists --> exists(noun_p, Assertion), verb_p(Assertion).  % Matches existence with noun phrase and verb phrase.
exists(noun_p, Assertion) --> verb_p(Assertion).  % Matches existence with noun phrase and verb phrase.



% Basic input handling
sound :- input(_).  % Handles input related to sound.
text :- sentence(_).  % Handles input related to text.



% Meaning-related rules
meaning:define(X, Y, Z) :- parse(X, Y, Z).  % Defines the meaning of terms.

meaning(_) :- ((parse(text, sound)), unknown(_)).  % Handles meaning based on parsing and unknown terms.
meaning((X, Y, Z)) :- goal((X, Y, Z)).  % Handles meaning based on goals.
meaning(Y; X; Z) :- smart:output(Y; X; Z).  % Handles multiple meanings with smart output.
meaning(P) :- output(P).  % Handles output for a given meaning.
meaning(define((X, Y, Z) | P)) :- define(meaning((X, Y, Z) | P)).  % Defines meaning with a list of terms.

meaning(question, command) :- unknown:input(text).  % Handles meaning for questions and commands.
meaning(P, Q) :- ((P -:- Q)), nl, write('definition of'), nl, display(P), nl, write('is'), nl, display(Q), merge((P), (Q), [words]).  % Outputs definitions.
meaning(human, non_human) :- unknown:(input(sound)).  % Defines meaning for human vs non-human based on sound.
meaning(english, formal) :- unknown:(input(text)).  % Defines meaning for English vs formal based on text.

meaning(X, Y, Z) :- define(X, Y, Z), call(['hydrawall.py']).  % Defines meaning and calls words.
meaning(X, Y, Z | Sentence; Sentence_group) :- (semantic_input(Y | X; Z), (Sentence, Sentence_group)).  % Handles semantic input with sentence and group.
meaning(P) --> smart:output(P).  % Grammar rule for meaning with smart output.
meaning(X, Y, Z) :- semantic_input(X, Y, Z).  % Handles semantic input for terms.
meaning(X, Y, Z) :- parse(X, Y, Z).  % Handles parsing for meaning.
meaning(X, Y, Z) :- (parse:definition(input(X, Y, Z))).  % Parses and defines input.
meaning(X, Y, Z) :- learn(meaning(X, Y, Z)).  % Learns new meaning.










% Copying lists
copy_list([] -:- []).  % Matches empty list with empty list.
copy_list([X | Y] -:- [X | Z]) :- copy_list(Y -:- Z), tell(['hydrawall.py']).  % Copies lists and performs action 'tell'.


% Definition rules
define((X, Y, Z) | P) :- output(X, Y, Z), (P).  % Defines terms and outputs them.
define(P) :- meaning(P).  % Defines terms based on meaning.
define((_) | P) :- goal(P).  % Defines terms with goals.
define(Sound = (X)) :- (unknown:input(Sound = (X)), (parse(X))).  % Defines terms with sound input.
define((X) | P) :- unknown:input(X | P), define(P).  % Defines terms with unknown input.
define(Input) :- parse(define(Input)).  % Defines input through parsing.
define(X, Y, Z) :- parse(X, Y, Z).  % Defines terms through parsing.

definition(P) :- meaning(P).  % Defines terms based on meaning.





% Rules for calculating movement
calculate(movement).  % Matches movement calculation.
calculate(movement) :- (smart(analyze(task))).  % Calculates movement with smart analysis.
calculate(movement) :- calculate(task).  % Calculates movement with task.
calculate(movement) :- analyze(task).  % Analyzes task for movement.


%Rules for analyzing tasks
analyze(task) :- meaning(X, Y, Z), (input(X, Y, Z)).  % Analyzes tasks based on meaning and input.
analyze(task) :- calculate(movement).  % Analyzes task with movement calculation.
analyze(task) :- calculate(task).  % Analyzes task with task calculation.


% Learning meaning
learn(meaning(Vision, Sound, Text)) :- parse:meaning(Vision, Sound, Text).  % Learns meaning through parsing.



command :- ((Sentence; Sentence_group), (Sentence; Sentence_group), stream_input).  % Handles commands with sentences, groups, and stream input.
command :- (smart:output).  % Handles command output with smart output.
command :- l:sentence, task.


% Defines different types of sentences including ideas, information, questions, and commands.
idea :- information; question; command.
idea:-(question,command).

information :- l:sentence.

% Rules for handling questions and commands
question :- ((Sentence; Sentence_group), ((Sentence), (Sentence_group))).  % Handles questions with sentence and group.
question :- smart:output.  % Handles question output with smart output.
question :- l:output(answer).


task :- objective(task); command.
objective(X) :- input(X = task).

% Output handling
output(_) :- stream_input -> smart:output.  % Handles output with smart output if stream input is present.
output(P) :- meaning(P).  % Outputs based on meaning.
output((X, Y, Z) | P) :- output(meaning(X, Y, Z), (define(X, Y, Z))), P.  % Handles output with meaning and definitions.
output(P) :- goal(P).  % Handles output based on goals.
output(meaning(X, Y, Z), (define(X, Y, Z) | interpretation(P))) :- output(X, Y, Z | P).  % Handles meaning and definitions with output.

output(X,Y,Z):-classification(X,Y,Z).
output(X,Y,Z):-classification(X),(Y),(Z).

output(sentence) --> (sentence_group).  % Grammar rule for sentence output as a group.
output(sentence) --> (sentence).  % Grammar rule for sentence output.


% Namespace-specific parse and output rules
output:parse(X, Y, Z) :- meaning(X, Y, Z).
output:speech:-analyze(task).
speech:output(form_w(_),(_)).

% Defines output behavior for speech in a certain form
speech:output(form_w(_),(_)).  % Defines a speech output in a specific format involving form_w and a placeholder.


%%%%%%%%%%% NLP and Parsing Predicates
input(Wordlist) :- getsentence(Wordlist).
input(P) :- (P:Q), display(Q).
input(_) :- assert((_)).
input(getsentence) :- l:sentence(input, objective).


% Rule to handle various types of input
input(sentence) :- [_].  % If the input is a sentence, it matches any single element list.
input(_) :- unknown(input(_)).  % If the input is unknown, it invokes the unknown rule for input.
input(_) :- (sound).  % Matches if there is sound input.
input(_) :- (text).  % Matches if there is text input.
input(stream_input) :- idea.  % Handles stream_input if there is an idea.
input(sound) :- ([_]; [_]).  % Sound input can be a list of one or two elements.


input(port):-fact:device(port).
input(unknown(classification(Y,Z,X))):-output(unknown(syn(X)),(udp(Y)),(ipa(Z))).
input(ipa):-unknown(input).
input(unknown(input)).
input(unknown):-unknown(input).
input(unknown(X,Y,Z)):-input(X,Y,Z).


input(vision(object)) :- object(Human, not(Human)).  % Handles vision input related to objects.
input(vision) :- input([]).  % Default vision input to an empty list.
input(X) :- (append(X | [_])).  % Appends to the input X.
input(unknown(X, Y, Z)) :- stream_input:(X, Y, Z).  % Handles unknown input with stream_input.
input(unknown(X, Y, Z)) :- input(X, Y, Z).  % Handles unknown input by delegating to input.
input((_) | P) :- output(P).  % If input is a term with a head and tail, output the tail.
input((X, Y, Z) | P) :- input(((X, Y, Z) | P) | smart:output).  % Handles input as a list of three elements and outputs.
input(Sound | (Question; Command)) :- meaning(Sound | (Question; Command)).  % Handles input as Sound with a Question or Command.

% Defines how to handle input, including getting sentences and displaying information.
input(X, Y, Z) :- unknown(X, Y, Z).  % Default case for input delegation to unknown.
input(X, Y, Z) :- (parse:(output(define(X, Y, Z)))).  % Parses and outputs the defined input.
input(X, Y, Z) :- meaning(X, Y, Z).  % Processes input using meaning.
input(X, Y, (_)) :- smart:output(X, Y | (_)).  % Outputs X and Y with a third element.
input(X, Y, Z) :- meaning(X; Y; Z), define(X; Y; Z), object(X; Y; Z).  % Processes input with meaning, definition, and object.

input(X,Y,Z):-port(input(X,Y,Z)).
input(X,Y,Z):-input(unknown(syn|X),(udp|Y),(ipa(Z))).
input(X,Y,Z):-parse:device(X,Y,Z).
input(X,Y,Z):-parse:connected(X,Y,Z).
input(Node,X,Y):-edge(X|Y,Node).


input(sound) --> [_]; [_].  % Grammar rule for sound input.
input(_) --> sentence((_), (_)).  % Grammar rule for other inputs based on sentence structure.












%%%%%%%%%%%  Input Parsing











node(X,Y,Z):-lattice:node(X,Y,Z|Prime1,Prime2,Prime3),(Prime1,Prime2,Prime3).
node(X,Y,Z):-add_edges(X,Y,Z).
% Define a bag of elements M/C, which could be used to store and manage
% nodes and their attributes in the lattice
lattice:bagof(M/C):-M,C.

% Inserts an element T into a sorted list Ts, maintaining order based on a function f
lattice:insert(T, Ts, [T|Ts]) :-
    f(T, F),  % Compute a value F for T
    lattice:bestf(Ts, Fl),  % Find the best value from existing list Ts
    F =< Fl,  % Ensure F is less than or equal to the best value Fl
    !.  % Cut to prevent backtracking

lattice:insert(T, [Tl|Ts], [Tl|Tsl]) :-
    lattice:insert(T, Ts, Tsl).  % Recursively insert T into the tail of the list

% Continue processing based on current state and solution
lattice:continue(_, _, _, yes, yes, Sol, _) :- f(Sol, yes).  % If solution meets criteria, succeed
lattice:continue(P, t(N, F/G, [Tl|Ts]), Bound, Tree1, Solved, Sol, F) :-
    lattice:insert(Tl, Ts, NTs),  % Insert Tl into Ts to form NTs
    lattice:bestf(NTs, Fl),  % Find the best value from NTs
    lattice:expand(P, t(N, Fl/G, NTs), Bound, Tree1, Solved, Sol).  % Expand tree with updated values
lattice:continue(_, _, _, yes, yes, Sol, _) :- Sol.  % If solution meets criteria, succeed
lattice:continue(P, t(N, F/G, [Tl|Ts]), Bound, Tree1, Solved, Sol, F) :-
    lattice:insert(Tl, Ts, NTs),  % Insert Tl into Ts to form NTs
    lattice:bestf(NTs, Fl),  % Find the best value from NTs
    lattice:expand(P, t(N, Fl/G, NTs), Bound, Tree1, Solved, Sol).  % Expand tree with updated values

% Creates a successor list based on current goal and node attributes
lattice:succlist(_, [], []).  % Base case for an empty list
lattice:succlist(G0, [N/C|NCs], Ts) :-
    G is G0 + C,  % Compute new goal value G
    h(N, H),  % Compute additional value H
    F is G + H,  % Compute the final value F
    lattice:succlist(G0, NCs, Tsl),  % Recursively process the rest of the list
    lattice:insert(l(N, F/G), Tsl, Ts).  % Insert the new node into the successor list

% Defines a goal check, defaulting to a specific goal
lattice:goal(_):-lattice:goal(n).  % Checks if the goal is 'n'

% Defines a tree structure based on node attributes
lattice:t(N, F/G, Sub) :- lattice:l(N, F/G, Sub).  % Defines a tree with a specific structure

% Defines a lattice structure based on node attributes
lattice:l(N, F/G, Sub) :- lattice:(t(N, F/G, Sub)).  % Defines a lattice with a specific structure

% Finds the best value in a lattice structure
lattice:bestf(Start, Solution) :-
    lattice:expand([], l(Start, 0/0), 9999, _, yes, Solution).  % Expands the lattice from a starting point
lattice:bestf(Start, Solution) :-
    lattice:expand([], l(Start, 0/0, 9999, _, yes, Solution), _, _, _, _).  % Expands with additional parameters
lattice:bestf([T|_], F) :-
    f(T, F).  % Finds the best value for a non-empty list
lattice:bestf([], 9999).  % Default value for an empty list
lattice:bestf(Start, Solution) :-
    lattice:expand([], l(Start, 0/0, 9999, _, yes, Solution), _, _, _, _).  % Expands with additional parameters
lattice:bestf(Start, Solution) :-
    lattice:expand([], l(Start, 0/0), 9999, _, yes, Solution).  % Expands the lattice from a starting point
lattice:bestf([T|_], F) :-
    f(T, F).  % Finds the best value for a non-empty list
lattice:bestf([], 9999).  % Default value for an empty list

% Expands the lattice based on current state and attributes
% If goal is met, return the path
lattice:expand(P, l(N, _), _, _, yes, [N|P]) :- lattice:goal(N).  % If goal is met, return the path

% Base case

lattice:expand(P, Tree, Bound, Tree1, Solved, Solution) :- P, Tree, Bound, Tree1, Solved, Solution.


lattice:expand(P, l(N, F/G), Bound, (Tree1,Member), Solved, Sol)
:-
    F =< Bound; Solved = Never,
    lattice:bagof((M/C);Sol, (s(N, M, C;G), (Member,(P;N,Tree1))),Never,!,false),(smart:input).


lattice:node(distance([A+1=B])):-A,B.
lattice:node(distance([A+2=C])):-A,C.
lattice:node(distanc([B+1=C])):-B,C.
lattice:node(Triple_prime):-number(Triple_prime).
lattice:node(Prime,X):- 0 is X mod X+1,not(Prime),!.
lattice:node(X,Y,Z):-node(X,Y,Z).
lattice:node(Prime1,Prime2,Prime3):-lattice:edge(Prime1,Prime2,Prime3).
lattice:node(A,B,C):-(lattice:edge(A,B,C)).
lattice:node(X,Y,Z):-node(X,Y,Z)->lattice:node((1/X,X,(_))).
lattice:node(Prime1,Prime2,Prime3):-set_random(pass),pass->[Prime1,Prime2,Prime3].
lattice:node(Triple_prime,Triple_prime,Triple_prime):-set_random(pass),pass->number(Triple_prime).
lattice:node(Prime1,Prime2,Prime3):-lattice:distance(Prime1,Prime2,Prime3).
lattice:node(X,Y,Z,Q):-node(Prime1,Prime2,Prime3)->(X;Prime1),(Y;Prime2),(Z;Prime3);Q.
lattice:node(X,Y,Z,A,_):-lattice:node(X,Y,Z,A).





lattice:distance(Prime):-
	[(node(1),(Prime))]+[node(2),(Prime)]+[node(3),(Prime)]
	=lattice:node(1+2=2),lattice:node(2+3=2),lattice:node(1+3=4),lattice:edge(3).
lattice:distance(Prime1,Prime2,Prime3):-
	[(node(1),(Prime1))]+[node(2),(Prime2)]+[node(3),(Prime3)]
	=lattice:node([a]+[b]=[c]),lattice:node(number),lattice:node(Prime),lattice:edge(Prime).



lattice:min(Bound,BF,Bound1):-lattice:min(Bound,BF,Bound1).


% Checks if lattice:matrix is in a state of 'pass', which depends on
% lattice:bestf/2 (best first serach function).
lattice:matrix(pass) :- lattice:bestf(_, _).

matrix(node(A,B,C),edge([_]),bestf([],9999)):-matrix((node(A,B,C;d(_))),port(A),input(A)).
matrix(Line,Node,Distance):-edge(Line|Node+Distance).
matrix(A|Node_x;(B|Node1,(C|Node3)):-edge(A|Node1),edge(B|Node3), edge(C|Node_x)).


edge(X,Y):-(matrix(lattice,([])|X,Y)).
edge(X,Y):-fact:connected(X,Y).
edge([Node1,Node2];[(C;Node3)],[_]):-matrix(Node1|_,Node2|C,Node3).


edge([a]):-(number(prime),(edge([c]))).
edge([b]):-node(number(_);(Prime),(number(Prime)),_).
edge([c]):-node((Prime,a),(Prime;b),(Prime,c,fail)|([a];[c];[b])).


/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        jan@swi-prolog.org
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2023-2024, SWI-Prolog Solutions b.v.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

:- module(janus,
          [ py_version/0,

            py_call/1,                  % +Call
            py_call/2,                  % +Call, -Return
            py_call/3,                  % +Call, -Return, +Options
	    py_iter/2,			% +Call, -Return
	    py_iter/3,			% +Call, -Return, +Options
            py_setattr/3,               % +On, +Name, +Value
            py_free/1,			% +Obj
	    py_is_object/1,		% @Term
	    py_is_dict/1,		% @Term
	    py_with_gil/1,		% :Goal
	    py_gil_owner/1,		% -ThreadID

            py_func/3,                  % +Module, +Func, -Return
            py_func/4,                  % +Module, +Func, -Return, +Options
            py_dot/3,                   % +ObjRef, +Meth, ?Ret
            py_dot/4,                   % +ObjRef, +Meth, -Ret, +Options

            values/3,                   % +Dict, +Path, ?Val
            keys/2,                     % +Dict, ?Keys
            key/2,                      % +Dict, ?Key
            items/2,                    % +Dict, ?Items

            py_shell/0,

	    py_pp/1,                    % +Term
            py_pp/2,                    % +Stream, +Term
            py_pp/3,                    % +Stream, +Term, +Options

            py_object_dir/2,            % +ObjRef, -List
            py_object_dict/2,           % +ObjRef, -Dict
            py_obj_dir/2,               % +ObjRef, -List (deprecated)
            py_obj_dict/2,              % +ObjRef, -Dict (deprecated)
            py_type/2,			% +ObjRef, -Type:atom
            py_isinstance/2,            % +ObjRef, +Type
            py_module_exists/1,         % +Module
            py_hasattr/2,               % +Module, ?Symbol

            py_import/2,                % +Spec, +Options
            py_module/2,                % +Module:atom, +Source:string

            py_initialize/3,            % +Program, +Argv, +Options
            py_lib_dirs/1,              % -Dirs
            py_add_lib_dir/1,           % +Dir
            py_add_lib_dir/2,           % +Dir,+Where

            op(200, fy, @),             % @constant
            op(50,  fx, #)              % #Value
          ]).
:- meta_predicate py_with_gil(0).

:- use_module(library(apply_macros), []).
:- autoload(library(lists), [append/3, member/2, append/2, last/2]).
:- autoload(library(apply),
            [maplist/2, exclude/3, maplist/3, convlist/3, partition/4]).
:- autoload(library(error), [must_be/2, domain_error/2]).
:- autoload(library(dicts), [dict_keys/2]).
:- autoload(library(option), [dict_options/2, select_option/4, option/2]).
:- autoload(library(prolog_code), [comma_list/2]).
:- autoload(library(readutil), [read_line_to_string/2, read_file_to_string/3]).
:- autoload(library(wfs), [call_delays/2, delays_residual_program/2]).
:- autoload(library(dcg/high_order), [sequence//2, sequence//3]).

:- if(\+current_predicate(py_call/1)).
:- if(current_prolog_flag(windows, true)).


:- use_foreign_library(foreign(janus), [visibility(global)]).
:- endif.

:- predicate_options(py_call/3, 3,
                     [ py_object(boolean),
                       py_string_as(oneof([string,atom]))
                     ]).
:- predicate_options(py_func/4, 4,
                     [ pass_to(py_call/3, 3)
                     ]).
:- predicate_options(py_dot/5, 5,
                     [ pass_to(py_call/3, 3)
                     ]).

:- public
    py_initialize/0,
    py_call_string/3,
    py_write/2,
    py_readline/4.

:- create_prolog_flag(py_backtrace,       true, [type(boolean), keep(true)]).
:- create_prolog_flag(py_backtrace_depth, 4,    [type(integer), keep(true)]).
:- create_prolog_flag(py_argv,		  [],   [type(term), keep(true)]).

/** <module> Call Python from Prolog

This library implements calling Python  from   Prolog.  It  is available
directly from Prolog if  the  janus   package  is  bundled.  The library
provides access to an  _embedded_  Python   instance.  If  SWI-Prolog is
embedded into Python  using  the   Python  package  ``janus-swi``,  this
library is provided either from Prolog or from the Python package.

Normally,  the  Prolog  user  can  simply  start  calling  Python  using
py_call/2 or friends. In special cases it   may  be needed to initialize
Python with options using  py_initialize/3   and  optionally  the Python
search path may be extended using py_add_lib_dir/1.
*/

%!  py_version is det.
%
%   Print version  info on the  embedded Python installation  based on
%   Python `sys.version`.  If a Python _virtual environment_ (venv) is
%   active, indicate this with the location of this environment found.

py_version :-
    py_call(sys:version, PythonVersion),
    py_call(janus_swi:version_str(), JanusVersion),
    print_message(information, janus(version(JanusVersion, PythonVersion))),
    (   py_venv(VEnvDir, EnvSiteDir)
    ->  print_message(information, janus(venv(VEnvDir, EnvSiteDir)))
    ;   true
    ).


%!  py_call(+Call) is det.
%!  py_call(+Call, -Return) is det.
%!  py_call(+Call, -Return, +Options) is det.
%
%   Call Python and return the result of   the called function. Call has
%   the shape `[Target][:Action]*`, where `Target`   is  either a Python
%   module name or a Python object reference. Each `Action` is either an
%   atom to get the denoted attribute from   current `Target` or it is a
%   compound term where the first  argument   is  the function or method
%   name  and  the  arguments  provide  the  parameters  to  the  Python
%   function. On success, the returned Python   object  is translated to
%   Prolog.  `Action` without a `Target` denotes a buit-in function.
%
%   Arguments to Python  functions  use   the  Python  conventions. Both
%   _positional_  and  _keyword_  arguments    are   supported.  Keyword
%   arguments are written as `Name = Value`   and  must appear after the
%   positional arguments.
%
%   Below are some examples.
%
%       % call a built-in
%	?- py_call(print("Hello World!\n")).
%	true.
%
%       % call a built-in (alternative)
%	?- py_call(builtins:print("Hello World!\n")).
%	true.
%
%	% call function in a module
%	?- py_call(sys:getsizeof([1,2,3]), Size).
%	Size = 80.
%
%	% call function on an attribute of a module
%       ?- py_call(sys:path:append("/home/bob/janus")).
%       true
%
%       % get attribute from a module
%       ?- py_call(sys:path, Path)
%       Path = ["dir1", "dir2", ...]
%
%   Given a class in a file `dog.py`  such as the following example from
%   the Python documentation
%
%   ```
%   class Dog:
%       tricks = []
%
%       def __init__(self, name):
%           self.name = name
%
%       def add_trick(self, trick):
%           self.tricks.append(trick)
%   ```
%
%   We can interact with this class as  below. Note that ``$Doc`` in the
%   SWI-Prolog toplevel refers to the  last   toplevel  binding  for the
%   variable `Dog`.
%
%       ?- py_call(dog:'Dog'("Fido"), Dog).
%       Dog = <py_Dog>(0x7f095c9d02e0).
%
%       ?- py_call($Dog:add_trick("roll_over")).
%       Dog = <py_Dog>(0x7f095c9d02e0).
%
%       ?- py_call($Dog:tricks, Tricks).
%       Dog = <py_Dog>(0x7f095c9d02e0),
%       Tricks = ["roll_over"]
%
%   If the principal term of the   first  argument is not `Target:Func`,
%   The argument is evaluated as the initial target, i.e., it must be an
%   object reference or a module.   For example:
%
%       ?- py_call(dog:'Dog'("Fido"), Dog),
%          py_call(Dog, X).
%          Dog = X, X = <py_Dog>(0x7fa8cbd12050).
%       ?- py_call(sys, S).
%          S = <py_module>(0x7fa8cd582390).
%
%   Options processed:
%
%     - py_object(Boolean)
%       If `true` (default `false`), translate the return as a Python
%       object reference. Some objects are _always_ translated to
%       Prolog, regardless of this flag.  These are the Python constants
%       ``None``, ``True`` and ``False`` as well as instances of the
%       Python base classes `int`, `float`, `str` or `tuple`. Instances
%       of sub classes of these base classes are controlled by this
%       option.
%     - py_string_as(+Type)
%       If Type is `atom` (default), translate a Python String into a
%       Prolog atom.  If Type is `string`, translate into a Prolog string.
%	Strings are more efficient if they are short lived.
%     - py_dict_as(+Type)
%       One of `dict` (default) to map a Python dict to a SWI-Prolog
%       dict if all keys can be represented.  If `{}` or not all keys
%       can be represented, Return is unified to a term `{k:v, ...}`
%       or `py({})` if the Python dict is empty.
%
%   @compat  PIP.  The  options  `py_string_as`   and  `py_dict_as`  are
%   SWI-Prolog  specific,  where  SWI-Prolog   Janus  represents  Python
%   strings as atoms as required by  the   PIP  and it represents Python
%   dicts by default  as  SWI-Prolog   dicts.  The  predicates values/3,
%   keys/2, etc. provide portable access to the data in the dict.

%!  py_iter(+Iterator, -Value) is nondet.
%!  py_iter(+Iterator, -Value, +Options) is nondet.
%
%   True when Value is returned by the Python Iterator. Python iterators
%   may be used to implement   non-deterministic foreign predicates. The
%   implementation uses these steps:
%
%     1. Evaluate Iterator as py_call/2 evaluates its first argument,
%        except the ``Obj:Attr = Value`` construct is not accepted.
%     2. Call ``__iter__`` on the result to get the iterator itself.
%     3. Get the ``__next__`` function of the iterator.
%     4. Loop over the return values of the _next_ function.  If
%        the Python return value unifies with Value, succeed with
%        a choicepoint.  Abort on Python or unification exceptions.
%     5. Re-satisfaction continues at (4).
%
%   The example below uses the built-in iterator range():
%
%       ?- py_iter(range(1,3), X).
%       X = 1 ;
%       X = 2.
%
%   Note that the implementation performs a   _look  ahead_, i.e., after
%   successful unification it calls `__next__()`   again. On failure the
%   Prolog predicate succeeds deterministically. On   success,  the next
%   candidate is stored.
%
%   Note that a Python _generator_ is   a  Python _iterator_. Therefore,
%   given  the  Python  generator   expression    below,   we   can  use
%   py_iter(squares(1,5),X) to generate the squares on backtracking.
%
%   ```
%   def squares(start, stop):
%        for i in range(start, stop):
%            yield i * i
%   ```
%
%   @arg Options is processed as with py_call/3.
%   @bug Iterator may not depend on janus.query(), i.e., it is not
%   possible to iterate over a Python iterator that under the hoods
%   relies on a Prolog non-deterministic predicate.
%   @compat PIP.  The same remarks as for py_call/2 apply.

%!  py_setattr(+Target, +Name, +Value) is det.
%
%   Set a Python attribute on an object.  If   Target  is an atom, it is
%   interpreted  as  a  module.  Otherwise  it  is  normally  an  object
%   reference. py_setattr/3 allows for  _chaining_   and  behaves  as if
%   defined as
%
%       py_setattr(Target, Name, Value) :-
%           py_call(Target, Obj, [py_object(true)]),
%           py_call(setattr(Obj, Name, Value)).
%
%   @compat PIP

%!  py_run(+String, +Globals, +Locals, -Result, +Options) is det.
%
%   Interface  to  Py_CompileString()  followed   by  PyEval_EvalCode().
%   Options:
%
%       - file_name(String)
%         Errors are reported against this pseudo file name
%       - start(Token)
%         One of `eval`, `file` (default) or `single`.
%
%   @arg Globals is a dict
%   @arg Locals is a dict

%!  py_is_object(@Term) is semidet.
%
%   True when Term is a Python object reference. Fails silently if Term
%   is any other Prolog term.
%
%   @error existence_error(py_object, Term) is raised of Term is a
%   Python object, but it has been freed using py_free/1.
%
%   @compat PIP. The SWI-Prolog implementation is safe in the sense that
%   an arbitrary term cannot be confused  with   a  Python  object and a
%   reliable error is generated  if  the   references  has  been  freed.
%   Portable applications can not rely on this.

%!  py_is_dict(@Term) is semidet.
%
%   True if Term is a Prolog term that represents a Python dict.
%
%   @compat PIP. The SWI-Prolog version accepts   both a SWI-Prolog dict
%   and the `{k:v,...}`  representation.  See   `py_dict_as`  option  of
%   py_call/2.

py_is_dict(Dict), is_dict(Dict) => true.
py_is_dict(py({})) => true.
py_is_dict(py({KV})) => is_kv(KV).
py_is_dict({KV}) => is_kv(KV).

is_kv((K:V,T)) => ground(K), ground(V), is_kv(T).
is_kv(K:V) => ground(K), ground(V).


%!  py_free(+Obj) is det.
%
%   Immediately free (decrement the  reference   count)  for  the Python
%   object Obj. Further reference  to  Obj   using  e.g.,  py_call/2  or
%   py_free/1 raises an `existence_error`. Note that by decrementing the
%   reference count, we make the reference invalid from Prolog. This may
%   not  actually  delete  the  object  because   the  object  may  have
%   references inside Python.
%
%   Prolog references to Python objects  are   subject  to  atom garbage
%   collection and thus normally do not need to be freed explicitly.
%
%   @compat PIP. The SWI-Prolog  implementation   is  safe  and normally
%   reclaiming Python object can  be  left   to  the  garbage collector.
%   Portable applications may not assume   garbage  collection of Python
%   objects and must ensure to call py_free/1 exactly once on any Python
%   object reference. Not calling  py_free/1   leaks  the Python object.
%   Calling it twice may lead to undefined behavior.

%!  py_with_gil(:Goal) is semidet.
%
%   Run Goal as  once(Goal)  while  holding   the  Phyton  GIL  (_Global
%   Interpreter Lock_). Note that  all   predicates  that  interact with
%   Python lock the GIL. This predicate is   only required if we wish to
%   make multiple calls to Python while keeping   the  GIL. The GIL is a
%   _recursive_ lock and thus calling py_call/1,2  while holding the GIL
%   does not _deadlock_.

%!  py_gil_owner(-Thread) is semidet.
%
%   True when  the Python GIL is  owned by Thread.  Note  that, unless
%   Thread  is the  calling thread,  this merely  samples the  current
%   state and may thus no longer  be true when the predicate succeeds.
%   This predicate is intended to help diagnose _deadlock_ problems.
%
%   Note that  this predicate returns  the Prolog threads  that locked
%   the GIL.  It is however possible that Python releases the GIL, for
%   example if  it performs a  blocking call.  In this  scenario, some
%   other thread or no thread may hold the gil.


		 /*******************************
		 *         COMPATIBILIY		*
		 *******************************/

%!  py_func(+Module, +Function, -Return) is det.
%!  py_func(+Module, +Function, -Return, +Options) is det.
%
%   Call Python Function in  Module.   The  SWI-Prolog implementation is
%   equivalent to py_call(Module:Function, Return).   See  py_call/2 for
%   details.
%
%   @compat  PIP.  See  py_call/2  for  notes.    Note   that,  as  this
%   implementation is based on py_call/2,   Function can use _chaining_,
%   e.g., py_func(sys, path:append(dir), Return)  is   accepted  by this
%   implementation, but not portable.

py_func(Module, Function, Return) :-
    py_call(Module:Function, Return).
py_func(Module, Function, Return, Options) :-
    py_call(Module:Function, Return, Options).

%!  py_dot(+ObjRef, +MethAttr, -Ret) is det.
%!  py_dot(+ObjRef, +MethAttr, -Ret, +Options) is det.
%
%   Call a method or access  an  attribute   on  the  object ObjRef. The
%   SWI-Prolog implementation is equivalent  to py_call(ObjRef:MethAttr,
%   Return). See py_call/2 for details.
%
%   @compat PIP.  See py_func/3 for details.

py_dot(ObjRef, MethAttr, Ret) :-
    py_call(ObjRef:MethAttr, Ret).
py_dot(ObjRef, MethAttr, Ret, Options) :-
    py_call(ObjRef:MethAttr, Ret, Options).


		 /*******************************
		 *   PORTABLE ACCESS TO DICTS	*
		 *******************************/

%!  values(+Dict, +Path, ?Val) is semidet.
%
%   Get the value associated with Dict at  Path. Path is either a single
%   key or a list of keys.
%
%   @compat PIP. Note that this predicate   handle  a SWI-Prolog dict, a
%   {k:v, ...} term as well as py({k:v, ...}.

values(Dict, Key, Val), is_dict(Dict), atom(Key) =>
    get_dict(Key, Dict, Val).
values(Dict, Keys, Val), is_dict(Dict), is_list(Keys) =>
    get_dict_path(Keys, Dict, Val).
values(py({CommaDict}), Key, Val) =>
    comma_values(CommaDict, Key, Val).
values({CommaDict}, Key, Val) =>
    comma_values(CommaDict, Key, Val).

get_dict_path([], Val, Val).
get_dict_path([H|T], Dict, Val) :-
    get_dict(H, Dict, Val0),
    get_dict_path(T, Val0, Val).

comma_values(CommaDict, Key, Val), atom(Key) =>
    comma_value(Key, CommaDict, Val).
comma_values(CommaDict, Keys, Val), is_list(Keys) =>
    comma_value_path(Keys, CommaDict, Val).

comma_value(Key, Key:Val0, Val) =>
    Val = Val0.
comma_value(Key, (_,Tail), Val) =>
    comma_value(Key, Tail, Val).

comma_value_path([], Val, Val).
comma_value_path([H|T], Dict, Val) :-
    comma_value(H, Dict, Val0),
    comma_value_path(T, Val0, Val).

%!  keys(+Dict, ?Keys) is det.
%
%   True when Keys is a list of keys that appear in Dict.
%
%   @compat PIP. Note that this predicate   handle  a SWI-Prolog dict, a
%   {k:v, ...} term as well as py({k:v, ...}.

keys(Dict, Keys), is_dict(Dict) =>
    dict_keys(Dict, Keys).
keys(py({CommaDict}), Keys) =>
    comma_dict_keys(CommaDict, Keys).
keys({CommaDict}, Keys) =>
    comma_dict_keys(CommaDict, Keys).

comma_dict_keys((Key:_,T), Keys) =>
    Keys = [Key|KT],
    comma_dict_keys(T, KT).
comma_dict_keys(Key:_, Keys) =>
    Keys = [Key].

%!  key(+Dict, ?Key) is nondet.
%
%   True when Key is a key in   Dict.  Backtracking enumerates all known
%   keys.
%
%   @compat PIP. Note that this predicate   handle  a SWI-Prolog dict, a
%   {k:v, ...} term as well as py({k:v, ...}.

key(Dict, Key), is_dict(Dict) =>
    dict_pairs(Dict, _Tag, Pairs),
    member(Key-_, Pairs).
key(py({CommaDict}), Keys) =>
    comma_dict_key(CommaDict, Keys).
key({CommaDict}, Keys) =>
    comma_dict_key(CommaDict, Keys).

comma_dict_key((Key:_,_), Key).
comma_dict_key((_,T), Key) :-
    comma_dict_key(T, Key).

%!  items(+Dict, ?Items) is det.
%
%   True when Items is a list of Key:Value that appear in Dict.
%
%   @compat PIP. Note that this predicate   handle  a SWI-Prolog dict, a
%   {k:v, ...} term as well as py({k:v, ...}.

items(Dict, Items), is_dict(Dict) =>
    dict_pairs(Dict, _, Pairs),
    maplist(pair_item, Pairs, Items).
items(py({CommaDict}), Keys) =>
    comma_dict_items(CommaDict, Keys).
items({CommaDict}, Keys) =>
    comma_dict_items(CommaDict, Keys).

pair_item(K-V, K:V).

comma_dict_items((Key:Value,T), Keys) =>
    Keys = [Key:Value|KT],
    comma_dict_items(T, KT).
comma_dict_items(Key:Value, Keys) =>
    Keys = [Key:Value].


		 /*******************************
		 *             SHELL		*
		 *******************************/

%!  py_shell
%
%   Start an interactive Python REPL  loop   using  the  embedded Python
%   interpreter. The interpreter first imports `janus` as below.
%
%       from janus import *
%
%   So, we can do
%
%       ?- py_shell.
%       ...
%       >>> query_once("writeln(X)", {"X":"Hello world"})
%       Hello world
%       {'truth': True}
%
%   If possible, we enable command line   editing using the GNU readline
%   library.
%
%   When used in an environment  where  Prolog   does  not  use the file
%   handles 0,1,2 for  the  standard   streams,  e.g.,  in  `swipl-win`,
%   Python's I/O is rebound to use  Prolog's I/O. This includes Prolog's
%   command line editor, resulting in  a   mixed  history  of Prolog and
%   Pythin commands.

py_shell :-
    import_janus,
    py_call(janus_swi:interact(), _).

import_janus :-
    py_call(sys:hexversion, V),
    V >= 0x030A0000,                    % >= 3.10
    !,
    py_run("from janus_swi import *", py{}, py{}, _, []).
import_janus :-
    print_message(warning, janus(py_shell(no_janus))).


		 /*******************************
		 *          UTILITIES           *
		 *******************************/

%!  py_pp(+Term) is det.
%!  py_pp(+Term, +Options) is det.
%!  py_pp(+Stream, +Term, +Options) is det.
%
%   Pretty prints the Prolog translation of a Python data structure in
%   Python  syntax. This  exploits  pformat() from  the Python  module
%   `pprint` to do the actual  formatting.  Options is translated into
%   keyword arguments  passed to  pprint.pformat().  In  addition, the
%   option  nl(Bool)  is processed.   When  `true`  (default), we  use
%   pprint.pp(), which  makes the output  followed by a  newline.  For
%   example:
%
%   ```
%   ?- py_pp(py{a:1, l:[1,2,3], size:1000000},
%            [underscore_numbers(true)]).
%   {'a': 1, 'l': [1, 2, 3], 'size': 1_000_000}
%   ```
%
%   @compat PIP

py_pp(Term) :-
    py_pp(current_output, Term, []).

py_pp(Term, Options) :-
    py_pp(current_output, Term, Options).

py_pp(Stream, Term, Options) :-
    select_option(nl(NL), Options, Options1, true),
    (   NL == true
    ->  Method = pp
    ;   Method = pformat
    ),
    opts_kws(Options1, Kws),
    PFormat =.. [Method, Term|Kws],
    py_call(pprint:PFormat, String),
    write(Stream, String).

opts_kws(Options, Kws) :-
    dict_options(Dict, Options),
    dict_pairs(Dict, _, Pairs),
    maplist(pair_kws, Pairs, Kws).

pair_kws(Name-Value, Name=Value).


%!  py_object_dir(+ObjRef, -List) is det.
%!  py_object_dict(+ObjRef, -Dict) is det.
%
%   Examine attributes of  an  object.   The  predicate  py_object_dir/2
%   fetches the names of all attributes,   while  py_object_dir/2 gets a
%   dict with all attributes and their values.
%
%   @compat PIP

py_object_dir(ObjRef, List) :-
    py_call(ObjRef:'__dir__'(), List).

py_object_dict(ObjRef, Dict) :-
    py_call(ObjRef:'__dict__', Dict).

%!  py_obj_dir(+ObjRef, -List) is det.
%!  py_obj_dict(+ObjRef, -Dict) is det.
%
%   @deprecated Use py_object_dir/2 or py_object_dict/2.

py_obj_dir(ObjRef, List) :-
    py_object_dir(ObjRef, List).

py_obj_dict(ObjRef, Dict) :-
    py_object_dict(ObjRef, Dict).


%!  py_type(+ObjRef, -Type:atom) is det.
%
%   True when Type is the name of the   type of ObjRef. This is the same
%   as ``type(ObjRef).__name__`` in Python.
%
%   @compat PIP

py_type(ObjRef, Type) :-
    py_call(type(ObjRef):'__name__', Type).

%!  py_isinstance(+ObjRef, +Type) is semidet.
%
%   True if ObjRef is an instance of Type   or an instance of one of the
%   sub types of Type. This  is   the  same as ``isinstance(ObjRef)`` in
%   Python.
%
%   @arg Type is either a term `Module:Type` or a plain atom to refer to
%   a built-in type.
%
%   @compat PIP

py_isinstance(Obj, Module:Type) =>
    py_call(isinstance(Obj, eval(Module:Type)), @true).
py_isinstance(Obj, Type) =>
    py_call(isinstance(Obj, eval(sys:modules:'__getitem__'(builtins):Type)), @true).

%!  py_module_exists(+Module) is semidet.
%
%   True if Module is a currently  loaded   Python  module  or it can be
%   loaded.
%
%   @compat PIP

py_module_exists(Module) :-
    must_be(atom, Module),
    py_call(sys:modules:'__contains__'(Module), @true),
    !.
py_module_exists(Module) :-
    py_call(importlib:util:find_spec(Module), R),
    R \== @none,
    py_free(R).

%!  py_hasattr(+ModuleOrObj, ?Name) is nondet.
%
%   True when Name is an attribute of   Module. The name is derived from
%   the Python built-in hasattr(). If Name   is unbound, this enumerates
%   the members of py_object_dir/2.
%
%   @arg ModuleOrObj If this is an atom it refers to a module, otherwise
%   it must be a Python object reference.
%
%   @compat PIP

py_hasattr(ModuleOrObj, Name) :-
    var(Name),
    !,
    py_object_dir(ModuleOrObj, Names),
    member(Name, Names).
py_hasattr(ModuleOrObj, Name) :-
    must_be(atom, Name),
    (   atom(ModuleOrObj)
    ->  py_call(ModuleOrObj:'__name__'), % force loading
        py_call(hasattr(eval(sys:modules:'__getitem__'(ModuleOrObj)), Name), @true)
    ;   py_call(hasattr(ModuleOrObj, Name), @true)
    ).


%!  py_import(+Spec, +Options) is det.
%
%   Import a Python module.  Janus   imports  modules automatically when
%   referred in py_call/2 and  related   predicates.  Importing a module
%   implies  the  module  is  loaded   using  Python's  ``__import__()``
%   built-in and added to a table  that   maps  Prolog atoms to imported
%   modules. This predicate explicitly imports a module and allows it to
%   be associated with a different  name.   This  is  useful for loading
%   _nested modules_, i.e., a specific module   from a Python package as
%   well as for  avoiding  conflicts.  For   example,  with  the  Python
%   `selenium` package installed, we can do in Python:
%
%       >>> from selenium import webdriver
%       >>> browser = webdriver.Chrome()
%
%   Without this predicate, we can do
%
%       ?- py_call('selenium.webdriver':'Chrome'(), Chrome).
%
%   For a single call this is  fine,   but  for making multiple calls it
%   gets cumbersome.  With this predicate we can write this.
%
%       ?- py_import('selenium.webdriver', []).
%       ?- py_call(webdriver:'Chrome'(), Chrome).
%
%   By default, the imported module  is   associated  to an atom created
%   from the last segment of the dotted   name. Below we use an explicit
%   name.
%
%       ?- py_import('selenium.webdriver', [as(browser)]).
%       ?- py_call(browser:'Chrome'(), Chrome).
%
%   @error  permission_error(import_as,  py_module,  As)   if  there  is
%   already a module associated with As.

py_import(Spec, Options) :-
    option(as(_), Options),
    !,
    py_import_(Spec, Options).
py_import(Spec, Options) :-
    split_string(Spec, ".", "", Parts),
    last(Parts, Last),
    atom_string(As, Last),
    py_import_(Spec, [as(As)|Options]).

%!  py_module(+Module:atom, +Source:string) is det.
%
%   Load Source into the Python module Module.   This  is intended to be
%   used together with the `string` _quasi quotation_ that supports long
%   strings in SWI-Prolog.   For example:
%
%   ```
%   :- use_module(library(strings)).
%   :- py_module(hello,
%                {|string||
%                 | def say_hello_to(s):
%                 |     print(f"hello {s}")
%                 |}).
%   ```
%
%   Calling this predicate multiple  times  with   the  same  Module and
%   Source is a no-op. Called with  a   different  source  creates a new
%   Python module that replaces the old in the global namespace.
%
%   @error python_error(Type, Data) is raised if Python raises an error.

:- dynamic py_dyn_module/2 as volatile.

py_module(Module, Source) :-
    variant_sha1(Source, Hash),
    (   py_dyn_module(Module, Hash)
    ->  true
    ;   py_call(janus:import_module_from_string(Module, Source)),
        (   retract(py_dyn_module(Module, _))
        ->  py_update_module_cache(Module)
        ;   true
        ),
        asserta(py_dyn_module(Module, Hash))
    ).


		 /*******************************
		 *            INIT		*
		 *******************************/

:- dynamic py_venv/2 as volatile.
:- dynamic py_is_initialized/0 as volatile.

%   py_initialize is det.
%
%   Used as a callback from C for lazy initialization of Python.

py_initialize :-
    getenv('VIRTUAL_ENV', VEnv),
    prolog_to_os_filename(VEnvDir, VEnv),
    atom_concat(VEnvDir, '/pyvenv.cfg', Cfg),
    venv_config(Cfg, Config),
    !,
    current_prolog_flag(executable, Program),
    current_prolog_flag(py_argv, Argv),
    py_initialize(Program, ['-I'|Argv], []),
    py_setattr(sys, prefix, VEnv),
    venv_update_path(VEnvDir, Config).
py_initialize :-
    current_prolog_flag(executable, Program),
    current_prolog_flag(py_argv, Argv),
    py_initialize(Program, Argv, []).

venv_config(File, Config) :-
    access_file(File, read),
    read_file_to_string(File, String, []),
    split_string(String, "\n", "\n\r", Lines),
    convlist(venv_config_line, Lines, Config).

venv_config_line(Line, Config) :-
    sub_string(Line, B, _, A, "="),
    !,
    sub_string(Line, 0, B, _, NameS),
    split_string(NameS, "", "\t\s", [NameS2]),
    atom_string(Name, NameS2),
    sub_string(Line, _, A, 0, ValueS),
    split_string(ValueS, "", "\t\s", [ValueS2]),
    (   number_string(Value, ValueS2)
    ->  true
    ;   atom_string(Value, ValueS2)
    ),
    Config =.. [Name,Value].

venv_update_path(VEnvDir, Options) :-
    py_call(sys:version_info, Info),    % Tuple
    Info =.. [_,Major,Minor|_],
    format(string(EnvSiteDir),
           '~w/lib/python~w.~w/site-packages',
           [VEnvDir, Major, Minor]),
    prolog_to_os_filename(EnvSiteDir, PyEnvSiteDir),
    (   exists_directory(EnvSiteDir)
    ->  true
    ;   print_message(warning,
                      janus(venv(no_site_package_dir(VEnvDir, EnvSiteDir))))
    ),
    py_call(sys:path, Path0),
    (   option('include-system-site-packages'(true), Options)
    ->  partition(is_site_dir, Path0, PkgPath, SysPath),
        append([SysPath,[PyEnvSiteDir], PkgPath], Path)
    ;   exclude(is_site_dir, Path0, Path1),
        append(Path1, [PyEnvSiteDir], Path)
    ),
    py_setattr(sys, path, Path),
    print_message(silent, janus(venv(VEnvDir, EnvSiteDir))),
    asserta(py_venv(VEnvDir, EnvSiteDir)).

is_site_dir(OsDir) :-
    prolog_to_os_filename(PlDir, OsDir),
    file_base_name(PlDir, Dir0),
    downcase_atom(Dir0, Dir),
    no_env_dir(Dir).

no_env_dir('site-packages').
no_env_dir('dist-packages').

%!  py_initialize(+Program, +Argv, +Options) is det.
%
%   Initialize  and configure  the  embedded Python  system.  If  this
%   predicate is  not called before any  other call to Python  such as
%   py_call/2, it is called _lazily_, passing the Prolog executable as
%   Program, passing Argv from the  Prolog flag `py_argv` and an empty
%   Options list.
%
%   Calling this predicate while the  Python is already initialized is
%   a  no-op.  This  predicate is  thread-safe, where  the first  call
%   initializes Python.
%
%   In addition to initializing the Python system, it
%
%     - Adds the directory holding `janus.py` to the Python module
%       search path.
%     - If Prolog I/O is not connected to the file handles 0,1,2,
%       it rebinds Python I/O to use the Prolog I/O.
%
%   @arg Options is currently ignored.  It will be used to provide
%   additional configuration options.

py_initialize(Program, Argv, Options) :-
    (   py_initialize_(Program, Argv, Options)
    ->  absolute_file_name(library('python/janus.py'), Janus,
			   [ access(read) ]),
	file_directory_name(Janus, PythonDir),
	py_add_lib_dir(PythonDir, first),
	py_connect_io,
        repl_add_cwd,
        asserta(py_is_initialized)
    ;   true
    ).

%!  py_connect_io is det.
%
%   If SWI-Prolog console streams are bound to something non-standard,
%   bind the Python console I/O to our streans.

py_connect_io :-
    maplist(non_file_stream,
	    [0-user_input, 1-user_output, 2-user_error],
	    NonFiles),
    Call =.. [connect_io|NonFiles],
    py_call(janus_swi:Call).

non_file_stream(Expect-Stream, Bool) :-
    (   stream_property(Stream, file_no(Expect))
    ->  Bool = @false
    ;   Bool = @true
    ).

		 /*******************************
		 *            PATHS		*
		 *******************************/

%!  py_lib_dirs(-Dirs) is det.
%
%   True when Dirs is a list of directories searched for Python modules.
%   The elements of Dirs are in Prolog canonical notation.
%
%   @compat PIP

py_lib_dirs(Dirs) :-
    py_call(sys:path, Dirs0),
    maplist(prolog_to_os_filename, Dirs, Dirs0).

%!  py_add_lib_dir(+Dir) is det.
%!  py_add_lib_dir(+Dir, +Where) is det.
%
%   Add a directory to the Python  module   search  path.  In the second
%   form, Where is one of `first`   or `last`. py_add_lib_dir/1 adds the
%   directory as `last`. The property `sys:path`   is not modified if it
%   already contains Dir.
%
%   Dir is in Prolog notation. The added   directory  is converted to an
%   absolute path using the OS notation using prolog_to_os_filename/2.
%
%   If Dir is a _relative_ path, it   is taken relative to Prolog source
%   file when used as a _directive_ and  relative to the process working
%   directory when called as a predicate.
%
%   @compat PIP. Note  that  SWI-Prolog   uses  POSIX  file  conventions
%   internally, mapping to OS  conventions   inside  the predicates that
%   deal with files or explicitly   using prolog_to_os_filename/2. Other
%   systems may use the native file conventions in Prolog.

:- multifile system:term_expansion/2.

system:term_expansion((:- py_add_lib_dir(Dir0)),
                      (:- initialization(py_add_lib_dir(Dir, first), now))) :-
    \+ is_absolute_file_name(Dir0),
    prolog_load_context(directory, CWD),
    absolute_file_name(Dir0, Dir, [relative_to(CWD)]).
system:term_expansion((:- py_add_lib_dir(Dir0, Where)),
                      (:- initialization(py_add_lib_dir(Dir, Where), now))) :-
    \+ is_absolute_file_name(Dir0),
    prolog_load_context(directory, CWD),
    absolute_file_name(Dir0, Dir, [relative_to(CWD)]),
    absolute_file_name(Dir0, Dir).

py_add_lib_dir(Dir) :-
    py_add_lib_dir(Dir, last).

py_add_lib_dir(Dir, Where) :-
    absolute_file_name(Dir, AbsDir),
    prolog_to_os_filename(AbsDir, OSDir),
    py_add_lib_dir_(OSDir, Where).

py_add_lib_dir_(OSDir, Where) :-
    (   py_call(sys:path, Dirs0),
        memberchk(OSDir, Dirs0)
    ->  true
    ;   Where == last
    ->  py_call(sys:path:append(OSDir), _)
    ;   Where == first
    ->  py_call(sys:path:insert(0, OSDir), _)
    ;   must_be(oneof([first,last]), Where)
    ).

:- det(repl_add_cwd/0).
repl_add_cwd :-
    current_prolog_flag(break_level, Level),
    Level >= 0,
    !,
    (   py_call(sys:path:count(''), N),
        N > 0
    ->  true
    ;   print_message(informational, janus(add_cwd)),
        py_add_lib_dir_('', first)
    ).
repl_add_cwd.

:- multifile
    prolog:repl_loop_hook/2.

prolog:repl_loop_hook(begin, Level) :-
    Level >= 0,
    py_is_initialized,
    repl_add_cwd.


		 /*******************************
		 *           CALLBACK		*
		 *******************************/

:- dynamic py_call_cache/8 as volatile.

:- meta_predicate py_call_string(:, +, -).

%   py_call_string(:String, +DictIn, -Dict) is nondet.
%
%   Support janus.query_once() and janus.query(). Parses   String  into a goal
%   term. Next, all variables from the goal   term that appear in DictIn
%   are bound to the value from  this   dict.  Dict  is created from the
%   remaining variables, unless they  start   with  an underscore (e.g.,
%   `_Time`) and the key `truth. On   success,  the Dict values contain
%   the bindings from the  answer  and   `truth`  is  either  `true` or
%   `Undefined`. On failure, the Dict values are bound to `None` and the
%   `truth` is `false`.
%
%   Parsing and distributing the variables over the two dicts is cached.

py_call_string(M:String, Input, Dict) :-
    py_call_cache(String, Input, TV, M, Goal, Dict, Truth, OutVars),
    !,
    py_call(TV, M:Goal, Truth, OutVars).
py_call_string(M:String, Input, Dict) :-
    term_string(Goal, String, [variable_names(Map)]),
    unbind_dict(Input, VInput),
    exclude(not_in_projection(VInput), Map, OutBindings),
    dict_create(Dict, bindings, [truth=Truth|OutBindings]),
    maplist(arg(2), OutBindings, OutVars),
    TV = Input.get(truth, 'PLAIN_TRUTHVALS'),
    asserta(py_call_cache(String, VInput, TV, M, Goal, Dict, Truth, OutVars)),
    VInput = Input,
    py_call(TV, M:Goal, Truth, OutVars).

py_call('NO_TRUTHVALS', M:Goal, Truth, OutVars) =>
    (   call(M:Goal)
    *-> bind_status_no_no_truthvals(Truth)
    ;   Truth = @false,
	maplist(bind_none, OutVars)
    ).
py_call('PLAIN_TRUTHVALS', M:Goal, Truth, OutVars) =>
    (   call(M:Goal)
    *-> bind_status_plain_truthvals(Truth)
    ;   Truth = @false,
	maplist(bind_none, OutVars)
    ).
py_call('DELAY_LISTS', M:Goal, Truth, OutVars) =>
    (   call_delays(M:Goal, Delays)
    *-> bind_status_delay_lists(Delays, Truth)
    ;   Truth = @false,
	maplist(bind_none, OutVars)
    ).
py_call('RESIDUAL_PROGRAM', M:Goal, Truth, OutVars) =>
    (   call_delays(M:Goal, Delays)
    *-> bind_status_residual_program(Delays, Truth)
    ;   Truth = @false,
	maplist(bind_none, OutVars)
    ).

not_in_projection(Input, Name=Value) :-
    (   get_dict(Name, Input, Value)
    ->  true
    ;   sub_atom(Name, 0, _, _, '_')
    ).

bind_none(@none).

bind_status_no_no_truthvals(@true).

bind_status_plain_truthvals(Truth) =>
    (   '$tbl_delay_list'([])
    ->  Truth = @true
    ;   py_undefined(Truth)
    ).

bind_status_delay_lists(true, Truth) =>
    Truth = @true.
bind_status_delay_lists(Delays, Truth) =>
    py_call(janus:'Undefined'(prolog(Delays)), Truth).

bind_status_residual_program(true, Truth) =>
    Truth = @true.
bind_status_residual_program(Delays, Truth) =>
    delays_residual_program(Delays, Program),
    py_call(janus:'Undefined'(prolog(Program)), Truth).

py_undefined(X) :-
    py_call(janus:undefined, X).

unbind_dict(Dict0, Dict) :-
    dict_pairs(Dict0, Tag, Pairs0),
    maplist(unbind, Pairs0, Pairs),
    dict_pairs(Dict, Tag, Pairs).

unbind(Name-_, Name-_) :-
    sub_atom(Name, 0, 1, _, Char1),
    char_type(Char1, prolog_var_start),
    !.
unbind(NonVar, NonVar).


		 /*******************************
		 *     SUPPORT PYTHON CALLS     *
		 *******************************/

:- public
       px_cmd/3,
       px_call/4,
       px_comp/7.

% These predicates are helpers  for the corresponding Python functions
% in janus.py.


%   px_call(+Input:tuple, +Module, -Pred, -Ret)
%
%   Supports  px_qdet()  and  apply().  Note    that   these  predicates
%   explicitly address predicates  in  a   particular  module.  For meta
%   predicates, this implies they also control  the context module. This
%   leads to ``janus.cmd("consult", "consult", file)`` to consult _file_
%   into the module `consult`, which is not   what we want. Therefore we
%   set the context module to `user`, which is better, but probably also
%   not what we want.

px_call(-(), Module, Pred, Ret) =>
    @(call(Module:Pred, Ret), user).
px_call(-(A1), Module, Pred, Ret) =>
    @(call(Module:Pred, A1, Ret), user).
px_call(-(A1,A2), Module, Pred, Ret) =>
    @(call(Module:Pred, A1, A2, Ret), user).
px_call(-(A1,A2,A3), Module, Pred, Ret) =>
    @(call(Module:Pred, A1, A2, A3, Ret), user).
px_call(-(A1,A2,A3,A4), Module, Pred, Ret) =>
    @(call(Module:Pred, A1, A2, A3, A4, Ret), user).
px_call(Tuple, Module, Pred, Ret) =>
    compound_name_arguments(Tuple, _, Args),
    append(Args, [Ret], GArgs),
    Goal =.. [Pred|GArgs],
    @(Module:Goal, user).

px_cmd(Module, Pred, Tuple) :-
    (   compound(Tuple)
    ->  compound_name_arguments(Tuple, _, Args),
	Goal =.. [Pred|Args]
    ;   Goal = Pred
    ),
    @(Module:Goal, user).

px_comp(Module, Pred, Tuple, Vars, Set, TV, Ret) :-
    length(Out, Vars),
    (   compound(Tuple)
    ->  compound_name_arguments(Tuple, _, Args),
	append(Args, Out, GArgs),
	Goal =.. [Pred|GArgs]
    ;   Goal =.. [Pred|Out]
    ),
    compound_name_arguments(OTempl0, -, Out),
    tv_goal_and_template(TV, @(Module:Goal, user), FGoal, OTempl0, OTempl),
    findall(OTempl, FGoal, Ret0),
    (   Set == @true
    ->  sort(Ret0, Ret)
    ;   Ret = Ret0
    ).

:- meta_predicate
    call_delays_py(0, -).

% 0,1,2: TruthVal(Enum) from janus.py
tv_goal_and_template('NO_TRUTHVALS',
                     Goal, Goal, Templ, Templ) :- !.
tv_goal_and_template('PLAIN_TRUTHVALS',
                     Goal, ucall(Goal, TV), Templ, -(Templ,TV)) :- !.
tv_goal_and_template('DELAY_LISTS',
                     Goal, call_delays_py(Goal, TV), Templ, -(Templ,TV)) :- !.
tv_goal_and_template(Mode, _, _, _, _) :-
    domain_error("px_comp() truth", Mode).

:- public
    ucall/2,
    call_delays_py/2.

ucall(Goal, TV) :-
    call(Goal),
    (   '$tbl_delay_list'([])
    ->  TV = 1
    ;   TV = 2
    ).

call_delays_py(Goal, PyDelays) :-
    call_delays(Goal, Delays),
    (   Delays == true
    ->  PyDelays = []
    ;   comma_list(Delays, Array),
        maplist(term_string, Array, PyDelays)
    ).


		 /*******************************
		 *          PYTHON I/O          *
		 *******************************/

%   py_write(+Stream, -String) is det.
%   py_readline(+Stream, +Size, +Prompt, +Line) is det.
%
%   Called from redefined Python console  I/O   to  write/read using the
%   Prolog streams.

:- '$hide'((py_write/1,
	    py_readline/4)).

py_write(Stream, String) :-
    notrace(format(Stream, '~s', [String])).

py_readline(Stream, Size, Prompt, Line) :-
    notrace(py_readline_(Stream, Size, Prompt, Line)).

py_readline_(Stream, _Size, Prompt, Line) :-
    prompt1(Prompt),
    read_line_to_string(Stream, Read),
    (   Read == end_of_file
    ->  Line = ""
    ;   string_concat(Read, "\n", Line),
	py_add_history(Read)
    ).

py_add_history(Line) :-
    ignore(catch(prolog:history(user_input, add(Line)), _, true)).


		 /*******************************
		 *          COMPILING           *
		 *******************************/

%   py_consult(+File, +Data, +Module) is det.
%
%   Support janus.consult(file, data=None, module='user').

:- public py_consult/3.
py_consult(File, @none, Module) =>
    consult(Module:File).
py_consult(File, Data, Module) =>
    setup_call_cleanup(
	open_string(Data, In),
	load_files(Module:File, [stream(In)]),
	close(In)).


		 /*******************************
		 *           MESSAGES		*
		 *******************************/

:- multifile
    prolog:error_message//1,
    prolog:message_context//1,
    prolog:message//1.

prolog:error_message(python_error(Class, Value)) -->
    { py_str(Value, Message)
    },
    [ 'Python ', ansi(code, "'~w'", [Class]), ':', nl,
      '  ~w'-[Message]
    ].
prolog:error_message(permission_error(import_as, py_module, As)) -->
    [ 'Janus: No permission to import a module as ', ansi(code, '~q', As),
      ': module exists.'
    ].

prolog:message_context(context(_, PythonCtx)) -->
    { nonvar(PythonCtx),
      PythonCtx = python_stack(Stack),
      current_prolog_flag(py_backtrace, true),
      py_is_object(Stack),
      !,
      current_prolog_flag(py_backtrace_depth, Depth),
      py_call(traceback:format_tb(Stack, Depth), Frames)
    },
    [ nl, 'Python stack:', nl ],
    sequence(py_stack_frame, Frames).

py_stack_frame(String) -->
    { split_string(String, "\n", "", Lines)
    },
    sequence(msg_line, [nl], Lines).

msg_line(Line) -->
    [ '~s'-[Line] ].

prolog:message(janus(Msg)) -->
    message(Msg).

message(version(Janus, Python)) -->
    [ 'Janus ~w embeds Python ~w'-[Janus, Python] ].
message(venv(Dir, _EnvSiteDir)) -->
    [ 'Janus: using venv from ~p'-[Dir] ].
message(venv(no_site_package_dir(VEnvDir, Dir))) -->
    [ 'Janus: venv dirrectory ~p does not contain ~p'-[VEnvDir, Dir] ].
message(py_shell(no_janus)) -->
    [ 'Janus: py_shell/0: Importing janus into the Python shell requires Python 3.10 or later.', nl,
      'Run "', ansi(code, 'from janus import *', []), '" in the Python shell to import janus.'
    ].
message(add_cwd) -->
    [ 'Interactive session; added `.` to Python `sys.path`'-[] ].

