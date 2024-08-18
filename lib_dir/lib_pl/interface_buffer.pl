% Defines a sentence as either a copy of a list with the structure `idea-:-command`, or as a sentence recognized by the `l:sentence` predicate.
sentence :- copy_list(idea-:-command).
sentence :- l:sentence.

% Defines the structure of a sentence using the `l:sentence` predicate. 
% A sentence can be either an idea or a question/command followed by noun phrases, prepositional phrases, and verb phrases.
l:sentence :- ((idea); (question; command)), ((l:noun_p), l:prep_p, l:verb_p).
l:sentence :- read(49).
l:sentence :- objective(_).
l:sentence :- (l:noun_p, l:verb_p); ((l:noun_p), (l:prep_p), (l:word)); ((l:verb), (l:noun_p), (l:prep_p), (l:word)).

% Defines a sentence in terms of a noun phrase and a verb phrase with an optional number argument.
l:sentence(Number) --> l:noun_p(Number), l:verb_p(Number).

% Defines how to convert a list of words and a string into a sentence.
l:sentence(Wordlist, String) :- l:grab(l:sentence, l:word(Wordlist, String, objective)).
l:sentence(Wordlist, String) :- l:word(Wordlist, input, String).
l:sentence(Wordlist, String) :- getsentence(Wordlist), objective(String | Wordlist).

% Defines how to construct a sentence using a noun phrase and a verb phrase or various combinations of noun phrases, prepositional phrases, and verbs.
l:sentence --> (l:noun_p, l:verb_p); ((l:noun_p), (l:prep_p), l:word); ((l:verb), (l:noun_p), (l:prep_p), (l:word)).

% Defines how to process words, including letters and their combinations.
l:word(Char | ((Char, String); Rest)) --> l:letter(Char | String, Char), l:grab_l((Char | Rest, Rest), (Char | String, String)), form_w(Char | String, String).

% Defines verb phrases as consisting of a verb followed by a noun phrase.
l:verb_p --> l:verb, l:noun_p.
l:verb_p(Number) --> l:verb(Number), l:noun_p(Number).

% Defines noun phrases, which can include determiners and nouns.
l:noun_p --> (l:determiner -> l:noun).
l:noun_p(Number) --> l:determiner(Number), l:noun(Number).

% Defines determiners as either 'a' or 'the'.
l:determiner --> [a]; [the].

% Defines nouns as names, persons, places, things, or ideas.
l:noun --> ([name]; [person]); [place]; [thing]; [idea].
l:noun_pr --> [name], [place], [thing].

% Defines singular and plural nouns with respective determiners.
l:noun(singular) --> (l:determiner -> [a]).
l:noun(plural) --> (l:determiner -> [the]).

% Defines verbs as actions, states, or being.
l:verb --> [action]; [state]; [being].

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

% Defines verb phrases in terms of noun phrases.
l:verb_p(Number) :- l:noun_p(Number).
l:noun_p(Number) :- l:verb_p(Number).

% Defines how to write determiners and verbs.
l:determiner(X, Y, Z) :- write(X; Y; Z).
l:verb(X, Y, Z) :- write(X; Y; Z).

% Defines verbs with specific parameters.
l:verb :- l:verb(_, _, _).

% Defines how to process words and their letters.
l:word(X, Y) :- l:letter(Y | X, Y).
l:word :- l:word(input, getletters).

% Defines how to process letters and their sequences.
l:letter(Y, X, Z, P) :- l:grab_l(Y | X, X); l:grab_l(X | Z, Z); l:grab_l(Z | P, P).

% Defines a form of word processing, including handling strings and sentences.
form_w(Char | String, String) --> l:word(Char | String, String), l:sentence(String).

% Defines different types of sentences including ideas, information, questions, and commands.
idea :- information; question; command.
information :- l:sentence.
question :- l:output(answer).
command :- l:sentence, task.
task :- objective(task); command.
objective(X) :- input(X = task).

% Defines how to handle input, including getting sentences and displaying information.
input(Wordlist) :- getsentence(Wordlist).
input(P) :- (P:Q), display(Q).
input(_) :- assert((_)).
input(getsentence) :- l:sentence(input, objective).

% Reads a sentence from input and processes it.
getsentence(Wordlist) :- get0(Char), getrest(Char, Wordlist).
getrest(46, []) :- !.
getrest(32, Wordlist) :- !, getsentence(Wordlist).
getrest(Letter, [Word | Wordlist]) :- getletters(Letter, Letters, Nextchar), name(Word, Letters), getrest(Nextchar, Wordlist).

% Defines how to get letters from input.
getletters(46, [], 46) :- !.
getletters(32, [], 32) :- !.
getletters(Let, [Let | Letters], Nextchar) :- get0(Char), getletters(Char, Letters, Nextchar).

% Defines custom operator for a specific precedence.
:- op(1200, xfy, (-:-)).

% Provides options to the user and handles input based on their choice.
options :- write('Your Choice is either 1 or 2, enter 1 for sentence forms and 2 to stream input in English'), nl, options_display(49), options_choose(49), nl.
options_display(49) :- sentence.
options_display(49) :- get(49), nl.
options_choose(49) :- read(49) -> l:sentence, display(l:sentence), options_choose_aux(49, 50, Input, (read(Input))).
options_choose_aux(First, Last, Result, Char) :- Char >= First, Char =< Last, !, options_select(First, Char, Result).
options_choose_aux(First, Last, Result, _) :- put(7), put(13), options, nl, display(First), nl, display(Last), nl, display(Result).

% Recursively selects options based on user input.
options_select(First, Char, Result) :- NewFirst is First + 1, options_select(NewFirst, Char, Result).

% Defines dynamic predicates that can be modified at runtime.
:- dynamic l:grab/2.
:- dynamic l:letter/2.
:- dynamic l:noun_p/0.
:- dynamic l:prep_p/0.
:- dynamic l:verb_p/0.
:- dynamic l:word/4.
:- dynamic l:grab_l/2.
