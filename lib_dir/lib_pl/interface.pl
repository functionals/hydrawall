% Requires administrative read/write permissions for the OS


% predicates defined at runtime
%

:- dynamic prolog:meta_goal/2.
:- dynamic main/0.
:- dynamic writefacts/0.
:- dynamic source_location/2.
:- dynamic opt_meta/2.
:- dynamic opt_type/3.

% defining meta goal
:- multifile prolog:meta_goal/2.

% calling edit functions for debugging

:- use_module(library(edit)).

% defining arbitrary goals as the dynamic main/0 in addition to
% directive main/0

:- initialization(main,main).

% prolog_edit:locate/3 to translate specification into a list of
% locations. If there is more than one‘hit’, the user is asked to select
% from the locations found

prolog_edit:locate(
                ['core.pl'],
                ['inference_engine.pl'],
                ['interface_buffer.pl']
            ).


% prolog_edit:edit_source/1 is used to invoke the user's preferred
% editor


% prolog_edit:edit_source.



make_directory(\['updates']).

make_directory(\['updates']) :- exists_directory(\['updates']),
 (make_directory(\['updates']), !, fail).

make_directory(\['updates']) :- (make, main).

%  SWI-Prolog uses prolog_to_os_filename/2 to convert the filename to
%  the conventions used by the hosting operating system. It is strongly
%  advised to write paths using the /, especially on systems using the \
%  for this purpose (MS-Windows).

prolog_to_os_filename(\['updates'], (\['C:Users>[_]'])).

prolog_to_os_filename(\['updates'], (\['C:Users:[updates]'])) :-
        make_directory(\['updates']).

locate_prolog_file(Spec, Path) :-
        absolute_file_name(Spec,
                           [ file_type(prolog),
                             access(read)
                           ],
                           Path).

%source_location/2 location of last read term

source_location(Spec, Path):-locate_prolog_file(Spec, Path).

% set_prolog_IO(+In, +Out, +Error)Prepare the given streams for
% interactive behaviour normally associated to the terminal%

set_prolog_IO(+In,+Out,+Error):-
    (   readfacts, In),
    (   writefacts, Out),
    main,
    (fail) -> (nl, Error).


% Predicate to read the string from a file and process it
handle_file(File) :-
    open(File, read, Stream),
    read_line_to_string(Stream, String),
    close(Stream),
    format('Received string: ~w~n', [String]),
    % Add more processing here if needed
    true.

% Entry point to handle the file input
:- initialization(main, main).


%consult(:File) Read File as a Prolog source file%
consult(start) :-
    (['core.pl']),
    (['inference_engine.pl']),
    (['interface_buffer.pl']).

consult(['output.pl']) :-
    $argv_options(['output.pl'], (\['updates']), string).

consult(make_directory(\['updates'])):- consult(['output.pl']).
%open_resource/3 %open a program resource as a stream%

open_resource(set_prolog_IO(+In,+Out,+Error),consult(+In),readfacts):-

    make, write(Out;Error).

 open_resource(
                            ['core.pl'],
                            (   ['inference_engine.pl']),
                            ['output.pl']) :- main.


% argv_options(:Argv, -Positional, -Options)Parse command line arguments.
% This predicate acts in one of two modes. If the calling module defines opt_type/3, full featured parsing with long and short options, type conversion and help is provided.

$argv_options(Argv, directory, string):-current_prolog_flag(argv,Argv).


% opt_type(Opt, Name, Type) Defines Opt to add an option Name(Value),
% where Value statisfies Type.  string converts to a SWI-Prolog string.
$opt_type(string,consult(library(lists)),atom).

% @(:Goal, +Module) Execute Goal,
% setting the calling context to Module.

$goal :- consult(['output.pl']),
    open_resource(
        (        ['core.pl']),
        ['inference_engine.pl'],
        ['interface_buffer.pl']
    ).
$lattice :- consult(['core.pl']).

$smart :- goal.


% make/0 reconsult all changed source files

make :- consult(['output.pl']),readfacts.



readfacts:-
    open('output.pl',read,In),
    repeat,
    read_line_to_codes(In,X),writef([_]),
    writef(X),nl,
    X=end_of_file,!,
    nl,
    close(In).

readfacts :-
    $goal,
 @(main, goal),
     consult(['output.pl']),
    open_resource((\['inference_engine.pl']), ['core.pl'], ['interface_buffer.pl']).




writefacts:-
    open('output.pl',write(variable_names([])),Out),
    write(Out,[]),
    nl,
    close(Out).


% When main/0 is called interactively it simply calls main/1 with the
% arguments. Call main/1 using the passed command-line arguments.
% This allows for debugging scripts as follows:
%
% $ swipl -l interface.pl -- arg ...

% ?- gspy(['cmd.exe']).		% setup debugging
% ?- main.			% run program

main :-
    open('start',write,OS),
    (   consult(In),
        read(In, Eq),
        write(Eq, Out), nl,
        write(OS,Eq),nl(OS),nl(Out),
        false
        ;
        close(OS)
    ).
main :-
    handle_file('input.txt').

main([]):-main.



main(Argv) :-
    echo(Argv).


echo([]) :- nl.
echo([Last]) :- !,
    write(Last), nl.
echo([H|T]) :-
    write(H), write(' '),
    echo(T).

% resource/3 declare the resources (:Name, +FileSpec, +Options). These
% predicates are defined as dynamic predicates in the module user.
%
% Name is the name of the resource (an atom).
%
% If FileSpec points at a directory, the content of the directory is
% recursively added below Name.
%
% The Options can be used to control what is saved from a directory.


resource(string,['inference_engine.pl'],exclude(['interface.pl'])).



% exclude(:Goal, +List1, ?List2) is det. Filter elements for which Goal
% fails. True if List2 contains those elements Xi of List1 for which
% call(Goal, Xi) fails.

exclude( goal, ['interface_buffer.pl'], ['core.pl']).


% prolog:meta_goal(+Goal, -Pattern)
% Define meta-predicates. See the examples in this file for details.

prolog:meta_goal(parse|[G], [G+1]):- goal.

% snowball/3 stems a word with a given algorithm
% snowball_current_algorithm/1 enumerates the provided algorithms.


goal:-
    snowball(Goal, In, Stem),
    snowball_current_algorithm(['interface_buffer.pl']),
    porter_stem(In, Stem),
    exclude(Goal, Stem, In).


