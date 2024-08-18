:-op(1200,xf,~).
:-op(1190,xfx,:-).
:-op(1000,xfy,-:-).
:-op(100,xfy,and).
:-assert(pass).
:-assert(pass(_)).





% Rule to handle various types of input
input(sentence) :- [_].  % If the input is a sentence, it matches any single element list.
input(_) :- unknown(input(_)).  % If the input is unknown, it invokes the unknown rule for input.
input(_) :- (sound).  % Matches if there is sound input.
input(_) :- (text).  % Matches if there is text input.
input(stream_input) :- idea.  % Handles stream_input if there is an idea.
input(sound) :- ([_]; [_]).  % Sound input can be a list of one or two elements.
input(vision(object)) :- object(Human, not(Human)).  % Handles vision input related to objects.
input(vision) :- input([]).  % Default vision input to an empty list.
input(X) :- (append(X | [a])).  % Appends 'a' to the input X.
input(unknown(X, Y, Z)) :- stream_input:(X, Y, Z).  % Handles unknown input with stream_input.
input(unknown(X, Y, Z)) :- input(X, Y, Z).  % Handles unknown input by delegating to input.
input((_) | P) :- output(P).  % If input is a term with a head and tail, output the tail.
input((X, Y, Z) | P) :- input(((X, Y, Z) | P) | smart:output).  % Handles input as a list of three elements and outputs.
input(Sound | (Question; Command)) :- meaning(Sound | (Question; Command)).  % Handles input as Sound with a Question or Command.
input(X, Y, Z) :- unknown(X, Y, Z).  % Default case for input delegation to unknown.
input(X, Y, Z) :- (parse:(output(define(X, Y, Z)))).  % Parses and outputs the defined input.
input(X, Y, Z) :- meaning(X, Y, Z).  % Processes input using meaning.
input(X, Y, (_)) :- smart:output(X, Y | (_)).  % Outputs X and Y with a third element.
input(X, Y, Z) :- meaning(X; Y; Z), define(X; Y; Z), object(X; Y; Z).  % Processes input with meaning, definition, and object.
input(sound) --> [_]; [_].  % Grammar rule for sound input.
input(_) --> sentence((_), (_)).  % Grammar rule for other inputs based on sentence structure.

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

% Handles unknown inputs
unknown(input(Vision, Sound, Text)) :- input(unknown(Vision, Sound, Text)).  % Handles unknown input with Vision, Sound, and Text.
unknown(X, Y, Z) :- define(X, Y, Z); meaning(X, Y, Z).  % Handles unknown input with definition or meaning.
unknown(X, Y, Z) :- stream_input:(X, Y, Z).  % Handles unknown input with stream input.
unknown(X, Y, Z) :- input(X, Y, Z).  % Handles unknown input with input.

% Defines various sentence structures
sentence :- [_].  % Matches a single element list as a sentence.
sentence :- ([_], sentence).  % Matches a list with a sentence.
sentence :- (semantic_input), sentence_group.  % Matches semantic input followed by a sentence group.
sentence(P) :- meaning(P).  % Matches a sentence with meaning.
sentence(sentence_group).  % Matches a sentence group.
sentence --> exists, noun_p, verb_p.  % Grammar rule for sentence with exists, noun phrase, and verb phrase.
sentence --> determiner(_), noun(_), verb_p(_).  % Grammar rule for sentence with determiner, noun, and verb phrase.
sentence --> noun_p, verb_p.  % Grammar rule for sentence with noun phrase and verb phrase.
sentence --> (([words], (l:letter) -> sentence), letter).  % Grammar rule for sentence with words and letter.
sentence --> word_p.  % Matches a word phrase.
sentence --> noun_p(DetTree, NounTree), determiner(DetTree), noun(NounTree).  % Matches noun phrase with determiner and noun.
sentence(VP) --> noun_p(Actor), verb_p(Actor, VP).  % Matches noun phrase with an actor and verb phrase.
sentence(Number, sentence(NP, VP)) --> noun_p(Number, NP), verb_p(Number, VP).  % Matches sentence with number, noun phrase, and verb phrase.
sentence((_), (_)) --> noun_p(_).  % Matches a noun phrase with any additional element.
l:sentence --> (Number, l:sentence(noun_p, verb_p)), noun_p(Number, verb_p).  % Grammar rule for sentence with number.
l:sentence :- l:letter(form_w, word_p, sentence_group).  % Matches letter, word phrase, and sentence group.

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
form_w(_) :- sentence.  % Matches sentence.
form_w((_) | (_), (_)) :- write([a] | (_)).  % Writes 'a' followed by additional elements.

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

meaning(X, Y, Z) :- define(X, Y, Z), call([words]).  % Defines meaning and calls words.
meaning(X, Y, Z | Sentence; Sentence_group) :- (semantic_input(Y | X; Z), (Sentence, Sentence_group)).  % Handles semantic input with sentence and group.
meaning(P) --> smart:output(P).  % Grammar rule for meaning with smart output.
meaning(X, Y, Z) :- semantic_input(X, Y, Z).  % Handles semantic input for terms.
meaning(X, Y, Z) :- parse(X, Y, Z).  % Handles parsing for meaning.
meaning(X, Y, Z) :- (parse:definition(input(X, Y, Z))).  % Parses and defines input.
meaning(X, Y, Z) :- learn(meaning(X, Y, Z)).  % Learns new meaning.

% Copying lists
copy_list([] -:- []).  % Matches empty list with empty list.
copy_list([X | Y] -:- [X | Z]) :- copy_list(Y -:- Z), tell([hWai]).  % Copies lists and performs action 'tell'.

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

% Rules for analyzing tasks
analyze(task) :- meaning(X, Y, Z), (input(X, Y, Z)).  % Analyzes tasks based on meaning and input.
analyze(task) :- calculate(movement).  % Analyzes task with movement calculation.
analyze(task) :- calculate(task).  % Analyzes task with task calculation.

% Learning meaning
learn(meaning(Vision, Sound, Text)) :- parse:meaning(Vision, Sound, Text).  % Learns meaning through parsing.

% Rules for handling questions and commands
question :- ((Sentence; Sentence_group), ((Sentence), (Sentence_group))).  % Handles questions with sentence and group.
question :- smart:output.  % Handles question output with smart output.

command :- ((Sentence; Sentence_group), (Sentence; Sentence_group), stream_input).  % Handles commands with sentences, groups, and stream input.
command :- (smart:output).  % Handles command output with smart output.
idea :- (question, command).  % Defines an idea as a combination of question and command.

% Handling goals
goal((X, Y, Z) | P) :- output((X, Y, Z) | P).  % Handles goals with output.
goal(P) :- unknown(X, Y, Z), (parse((X, Y, Z) | P)).  % Handles goals with parsing of unknown terms.
goal(X, Y, Z) :- define(X, Y, Z).  % Handles goals with definition.

% Output handling
output(_) :- stream_input -> smart:output.  % Handles output with smart output if stream input is present.
output(P) :- meaning(P).  % Outputs based on meaning.
output((X, Y, Z) | P) :- output(meaning(X, Y, Z), (define(X, Y, Z))), P.  % Handles output with meaning and definitions.
output(P) :- goal(P).  % Handles output based on goals.
output(meaning(X, Y, Z), (define(X, Y, Z) | interpretation(P))) :- output(X, Y, Z | P).  % Handles meaning and definitions with output.
output(sentence) --> (sentence_group).  % Grammar rule for sentence output as a group.
output(sentence) --> (sentence).  % Grammar rule for sentence output.

% Namespace-specific parse and output rules
output:parse(X, Y, Z) :- meaning(X, Y, Z).

output:speech:-analyze(task).

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
smart:output :- (text, form_w(_)).  % Generates smart output based on text and form.
smart:output :- (speech:output(form_w(_), (_))).  % Generates smart output using speech and form.
smart:output :- parse(define(X, Y, Z) -> meaning(X, Y, Z)).  % Generates smart output by parsing definitions and their meanings.
smart:output :- call([_]).  % Executes a call as part of generating smart output.
smart:output(P) :- definition(P); meaning(P).  % Generates output based on definitions or meanings.
smart:output(X | Y) :- l:letter(X | Y).  % Generates output based on letters X and Y.
smart:output(movement, speech).  % Generates output related to movement and speech.
smart:output --> sentence.  % Grammar rule for generating output as a sentence.


% Defines output behavior for speech in a certain form
speech:output(form_w(_),(_)).  % Defines a speech output in a specific format involving form_w and a placeholder.

% Function to extract the 'F' component from a structured input
f(l(_, F/_), F).  % Extracts 'F' from a term structured as l(_, F/_).
f(t(_, F/_, _), F).  % Extracts 'F' from a term structured as t(_, F/_, _).

% Defines a predicate for handling 'N' and 'H'
h(N, H) :- N, H.  % Calls 'H' if 'N' succeeds.

% Defines a predicate for handling 'N', 'M', and 'C'
s(N, M, C) :- N, M, C.  % Calls 'N', 'M', and 'C' sequentially if they succeed.

% Define the negation operator (~) for various predicates
~(rationalize(Prime)) :- (~(pass)), Prime.  % Negates 'rationalize(Prime)' if 'pass' fails, and then checks 'Prime'.
~(rational(Prime)) :- Prime.  % Negates 'rational(Prime)' if 'Prime' holds.
~(pass) :- set_random(number).  % Sets a random number as a way to indicate 'pass'.
~(P) :- !, (fail), not(P); true.  % Negates 'P' with a fail predicate; if 'P' is false, succeeds.
~(_) :- not(_).  % General negation rule, if the argument does not hold, succeeds.
~(pass) :- not(pass).  % Ensures 'pass' is not true.

% Defines the 'pass' predicate
pass :- 
	[Prime1, Prime2, Prime3],  % Defines a list of primes.
	lattice:node(Prime1, Prime2, Prime3),  % Checks if a node with the given primes exists in the lattice.
	source_file_chain(lattice:bagof(_)).  % Checks for a source file chain with the lattice bag.

pass(Ch) :- pass, source_file_chain(Ch), lattice:bagof(Ch).  % Checks if 'pass' is true, then verifies the source file chain and lattice bag.

pass:start :- pass.  % Defines the start condition for 'pass'.



% Define a bag of elements M/C, which could be used to store and manage nodes and their attributes in the lattice
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
lattice:succlist(_, [], []).  % Duplicate case for an empty list
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
lattice:expand(P, l(N, _), _, _, yes, [N|P]) :- lattice:goal(N).  % If goal is met, return the path
lattice:expand(P, Tree, Bound, Tree1, Solved, Solution) :- P, Tree, Bound, Tree1, Solved, Solution.  % Base case
lattice:expand(P, l(N, _), _, _, yes, [N|P]) :- lattice:goal(N).  % If goal is met, return the path
lattice:expand(P, l(N, F/G), Bound, Tree1, Solved, Sol) :-
    F =< Bound; Solved = Never,  % Check if value is within bound or solution is never
    (lattice:bagof(M/C), (s(N, M, C), (~(Memb



% Connects to the lattice matrix and handles the request with the 'pass' operation.
'$dde_connect'(lattice:matrix) :- handle_request(pass).

% Define the module 'emacs_dde_server' which might interact with Emacs through DDE
:- module(emacs_dde_server).
:- module(emacs_dde_server), module(win_register_emacs).

% Handle various types of requests sent to the DDE server
handle_request(pass) :-
    % Connects to the lattice matrix and checks if there is a node and edge defined
    '$dde_connect'(lattice:matrix),
    (lattice:node(_, _, _), (lattice:edge(3))).

handle_request(Item) :-
    % If the request is to edit a file, construct the file name and open it in Emacs
    atom_concat('edit ', WinFile, Item), !,
    prolog_to_os_filename(File, WinFile),
    new(B, emacs_buffer(File)),
    send(B, open, tab),
    send(B, check_modified_file).

handle_request('close-server') :-
    % Unregisters the DDE service and reports the status
    dde_unregister_service('PceEmacs'),
    send(@emacs, report, status, 'Closed DDE server').

handle_request(Item) :-
    % Logs an error message if an unknown request is received
    format(user_error, 'PceEmacs DDE server: unknown request: ~q', [Item]),
    fail.

handle_request('close-server') :-
    % Unregisters the DDE service and reports the status (Duplicate clause)
    dde_unregister_service('PceEmacs'),
    send(@emacs, report, status, 'Closed DDE server').

handle_request(Item) :-
    % Logs an error message if an unknown request is received (Duplicate clause)
    format(user_error, 'PceEmacs DDE server: unknown request: ~pass', [Item]),
    fail.

% Creates a chain of source files and sorts them
source_file_chain(Ch) :-
    new(Ch, chain),
    forall(user_source_file(X), send(Ch, append, X)),
    send(Ch, sort).

source_file_chain(Ch) :- pass(Ch), pass.

% Retrieves user source files excluding those from specified library directories
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

% Specifies which paths should be ignored
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

% Defines regex patterns for use in the Prolog environment
:- pce_global(@prolog_full_stop, new(regex('[^-#$&*+./:<=>?@\\\\^`~]\\.($|\\s)'))).
:- pce_global(@prolog_decl_regex, new(regex('^:-\\s*[a-z_]+'))).

% Conditional block checking if 'shell_register_dde/1' predicate exists
:- if(current_predicate(shell_register_dde/1)).
:- endif.

% Defines a node predicate where (X, Y, Z) is either a tuple of numbers from lattice:node/3 or (X, Y, Z).
node(X, Y, Z) :- (Number1; Number2; Number3) :- lattice:node(Number1, Number2, Number3); (X, Y, Z).

% Checks if lattice:matrix is in a state of 'pass', which depends on lattice:bestf/2 (best fit function).
lattice:matrix(pass) :- lattice:bestf(_, _).

% Expands a lattice with a given bound, tree, and solution. 
% It recursively explores the tree and updates the solution if a better fit is found.
lattice:expand(P, l(N, F/G), Bound, Tree1, Solved, Sol) :-
    Member, Solved = Never
    :- F =< Bound,
       (lattice:bagof(M/C), (s(N, M, C), (~(Member) -> [M, P], Succ)),
        !, lattice:succlist(G, Succ, Ts),
        lattice:bestf(Ts, Fl),
        lattice:expand(P, t(N, Fl/G, Ts), Bound, Tree1, Solved, Sol);
        Solved = Never).

% Computes the minimum value among Bound, BF, and Bound1.
lattice:min(X, Y, Z) :- Bound, BF, Bound1 :- lattice:min(Bound, BF, Bound1); (X, Y, Z).

% Defines an edge for the case where the edge is represented by a single element [c] 
% and its distance and prime nodes are determined by lattice:node/3.
lattice:edge([c]) :- Distance, Prime1, Prime2, Prime3 :- lattice:node(number(Distance), [Prime1, Prime2, Prime3], [a], [c]).

% Defines an edge with multiple connections ([A, B]; [B, C]; [C, B])
% and relates it to nodes and distances calculated in lattice:matrix/3.
lattice:edge([A, B]; [B, C]; [C, B]) :- Line, Node :- lattice:node(3),
    lattice:edge([A, B, C]),
    lattice:distance((lattice:node + lattice:edge = Distance)),
    lattice:matrix(Line, Node, Distance).

% Handles meaning of P and Q where P implies Q. Reads and writes both P and Q.
P :- Q :- meaning(P, (Q)), (read(P), nl, write((Q))); (read(Q), nl, write((P))).

% Reverses the relation of Q and P by copying it.
P :- Q :- copy_list(Q :- P).

% Checks if a prime number is not divisible by any number less than itself plus one.
Prime :- not(divisible(not(X), X), X + 1) :- Prime.
