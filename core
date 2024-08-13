:-op(1200,xf,~).
:-op(1190,xfx,:-).
:-op(1000,xfy,-:-).
:-op(100,xfy,and).
:-assert(pass).
:-assert(pass(_)).



start:-
	!,input(A),
	nl,
	write('Enter definition as predication:'),
	nl,
	read(A),
	assert(A),
	define(A),
	nl,
	display(A),
	nl,
	write('learned').



input(sentence):-[_].
input(_):-unknown(input(_)).
input(_):-(sound).
input(_):-(text).
input(stream_input):-idea.
input(sound):-([_];[_]).
input(vision(object)):-object(Human,not(Human)).
input(vision):-input([]).
input(X):-(append(X|[a])).
input(unknown(X,Y,Z)):-stream_input:(X,Y,Z).
input(unknown(X,Y,Z)):-input(X,Y,Z).
input((_)|P):-output(P).
input((X,Y,Z)|P):-input(((X,Y,Z)|P)|smart:output).
input(Sound|(Question;Command)):-meaning(Sound|(Question;Command)).
input(X,Y,Z):-unknown(X,Y,Z).
input(X,Y,Z):-(parse:(output(define(X,Y,Z)))).
input(X,Y,Z):-meaning(X,Y,Z).
input(X,Y,(_)):-smart:output(X,Y|(_)).
input(X,Y,Z):- meaning(X;Y;Z),define(X;Y;Z),object(X;Y;Z).
input(sound)-->[_];[_].
input(_)-->sentence((_),(_)).





stream_input:-input(_),!,nl,smart:output.
stream_input:-(text,sound),!,smart:output.
stream_input:-[words].
stream_input:-!,nl,smart:output.
stream_input:-(semantic_input(X)->stream_input:(X)).
stream_input:-semantic_input(_).
stream_input:-(smart:output(X))->input((X)).
stream_input:-!,call([_])->output(_).
stream_input:-append((_)|([]|[a])).
stream_input:-read(_),(assert(_)->[_]).
stream_input:-smart:input(_)->smart:output(_).
stream_input:-semantic_input.
stream_input:-lattice:node(X,Y;Z),parse:parse(X),output:parse(X,Y,Z).
stream_input:-start.

semantic_input:-(((X),(Y),(Z)),semantic_input(X,Y,Z|(_))).
semantic_input:-goal((_),(_),(_)).
semantic_input:-process([_]).
semantic_input:-sentence.
semantic_input(Y|X;Z):-output(meaning(X,Y,Z)).
semantic_input(sentence|(Sentence;Sentence_group))
          :-(Sentence;Sentence_group).

semantic_input(Y|X;Z)-->((Y|X;Z),[sentence,sentence_group]).


unknown(_):-start.
unknown(input(Vision,Sound,Text)):-input(unknown(Vision,Sound,Text)).
unknown(X,Y,Z):-define(X,Y,Z);meaning(X,Y,Z).
unknown(X,Y,Z):-stream_input:(X,Y,Z).
unknown(X,Y,Z):-input(X,Y,Z).



sentence:-[_].
sentence:-([_],sentence).
sentence:-(semantic_input),sentence_group.
sentence(P):-meaning(P).
sentence(sentence_group).
sentence-->exists,noun_p,verb_p.
sentence-->determiner(_),noun(_),verb_p(_).
sentence-->noun_p,verb_p.
sentence-->(([words],(l:letter)->sentence),letter).
sentence-->word_p.
sentence-->noun_p(DetTree,NounTree),determiner(DetTree),noun(NounTree).
sentence(VP)-->noun_p(Actor),verb_p(Actor,VP).
sentence(Number, sentence(NP,VP))-->noun_p(Number,NP),verb_p(Number,VP).
sentence((_),(_))-->noun_p(_).
l:sentence-->(Number,l:sentence(noun_p,verb_p)),noun_p(Number,verb_p).
l:sentence:-l:letter(form_w,word_p,sentence_group).


sentence_group:-(sentence(_)).
sentence_group:-(semantic_input,sentence).
sentence_group:-output:speech.
sentence_group-->semantic_input(sentence(_,[])).


letter-->[word];[word_p].
l:letter(X|Y):-form_w((_)|X,Y).
l:letter(word)-->sentence(sentence_group).


form_w(_):-sentence.
form_w((_)|(_),(_)):-write([a]|(_)).



word_p-->sentence.


noun(_)-->noun(singular,noun(person;place;thing;idea)).
noun(_)-->noun(plural,noun(people;places;things;ideas)).
noun(_)-->proper_noun(_);improper_noun(_).
noun(singular,noun(person;place,thing,idea))-->[person];[place];[thing];[idea].
noun(plural,noun(people;places,things,ideas))-->[people];[places];[things];[ideas].




noun_p-->determiner(_),noun(_),verb_p.
noun_p(_)-->verb((_),(_)),noun(_),determiner(_).
noun_p(noun_p(DetTree,NounTree))-->determiner(DetTree),noun(NounTree).
noun_p(Number,noun_p(Det,Noun))-->(determiner(Det),noun(Number,Noun)).



proper_noun(X)-->(X).
improper_noun(_)-->[he];[she];[it];[there].



verb((_),(_))-->[action].


verb_p-->noun_p(_),sentence(verb).
verb_p(X)-->noun(X|Y),verb_p(Y).
verb_p(Number,verb_p(Verb,NP))-->verb(Number,Verb),noun_p(Number,NP).

determiner(determiner(a;the))-->[a];[the].





parse(Stream):-input(Stream),l:sentence(Stream,[])->!,nl,output(Stream).
parse(define(X,Y,Z)|P):-output((X,Y,Z)|P).
parse(X,[]):-(unknown(X,[]),input(X,[],[])).
parse(define(X,Y,Z),meaning(X,Y,Z)).
parse(define(X,Y,Z),unknown(X,Y,Z)).
parse(X,Y,Z):-meaning(X,Y,Z).
parse(X,Y,Z):-input(unknown(X,Y,Z)).
parse(X,Y,Z):-unknown(input(X,Y,Z)).
parse(X,Y,Z):-(meaning(X,Y,Z),(unknown(X,Y,Z))).
parse(Vision,Sound,Text):-unknown(Vision,Sound,Text).
parse(P)-->l:sentence(P).



parse:parse(input).
parse:parse(_):-l:sentence.
parse:parse(D):-lib_dir(D).
parse:meaning(Vision,Sound,Text):-(meaning(Vision,Sound,Text)).
parse:output(define(Sound,Vision,Text)):-(stream_input):(Vision,Sound,Text).



process([does,X,Y]):-!,Query=..[Y,X],(Query).
process([X,is,a,Y]):-!,Fact=..[Y,X],(Fact).
process([is,X,a,Y]):-!,Query=..[Y,X],(Query).



exists-->exists(noun_p,Assertion),verb_p(Assertion).
exists(noun_p,Assertion)-->verb_p(Assertion).




sound:-input(_).
text:-sentence(_).


meaning:define(X,Y,Z):-parse(X,Y,Z).


meaning(_):-((parse(text,sound)),unknown(_)).
meaning((X,Y,Z)):-goal((X,Y,Z)).
meaning(Y;X;Z):-smart:output(Y;X;Z).
meaning(P):-output(P).
meaning(define((X,Y,Z)|P)):-define(meaning((X,Y,Z)|P)).

meaning(question,command):-unknown:input(text).
meaning(P,Q):-((P-:-Q)),nl,write('definition of'),nl,display(P),nl,write('is'),nl,display(Q),merge((P),(Q),[words]).
meaning(human,non_human):-unknown:(input(sound)).
meaning(english,formal):-unknown:(input(text)).

meaning(X,Y,Z):-define(X,Y,Z),call([words]).
meaning(X,Y,Z|Sentence;Sentence_group):-(semantic_input(Y|X;Z),(Sentence,Sentence_group)).
meaning(P)-->smart:output(P).
meaning(X,Y,Z):-semantic_input(X,Y,Z).
meaning(X,Y,Z):-parse(X,Y,Z).
meaning(X,Y,Z):-(parse:definition(input(X,Y,Z))).
meaning(X,Y,Z):-learn(meaning(X,Y,Z)).



copy_list([]-:-[]).
copy_list([X|Y]-:-[X|Z]):-copy_list(Y-:-Z),tell([hWai]).


define((X,Y,Z)|P):-output(X,Y,Z),(P).
define(P):-meaning(P).
define((_)|P):-goal(P).
define(Sound=(X)):-(unknown:input(Sound=(X)),(parse(X))).
define((X)|P):-unknown:input(X|P),define(P).
define(Input):-parse(define(Input)).
define(X,Y,Z):-parse(X,Y,Z).

definition(P):-meaning(P).

calculate(movement).
calculate(movement):-(smart(analyze(task))).
calculate(movement):-calculate(task).
calculate(movement):-analyze(task).

analyze(task):-meaning(X,Y,Z),(input(X,Y,Z)).
analyze(task):-calculate(movement).
analyze(task):-calculate(task).


learn(meaning(Vision,Sound,Text)):-parse:meaning(Vision,Sound,Text).


question:-((Sentence;Sentence_group),((Sentence),(Sentence_group))).
question:-smart:output.

command:-((Sentence;Sentence_group),(Sentence;Sentence_group),stream_input).
command:-(smart:output).
idea:-(question,command).
goal((X,Y,Z)|P):-output((X,Y,Z)|P).
goal(P):-unknown(X,Y,Z),(parse((X,Y,Z)|P)).
goal(X,Y,Z):-define(X,Y,Z).




output(_):-stream_input->smart:output.
output(P):-meaning(P).
output((X,Y,Z)|P):-output(meaning(X,Y,Z),(define(X,Y,Z))),P.
output(P):-goal(P).
output(meaning(X,Y,Z),(define(X,Y,Z)|interpretation(P))):-output(X,Y,Z|P).
output(sentence)-->(sentence_group).
output(sentence)-->(sentence).

output:parse(X,Y,Z):-meaning(X,Y,Z).
output:speech:-analyze(task).



smart(analyze(task)).
smart(analyze(task)):-smart:input(_)->smart:output.
smart(analyze(X;Y;Z)):-meaning:define(X,Y,Z).

smart:input(W):-speech:output(form_w(X),(W|X)).
smart:input(_):-input(_).
smart:analyze(A):-parse:meaning(A).
smart:analyze(task).


smart:output:-(text,form_w(_)).
smart:output:-(speech:output(form_w(_),(_))).
smart:output:-parse(define(X,Y,Z)->meaning(X,Y,Z)).
smart:output:-call([_]).
smart:output(P):-definition(P);meaning(P).
smart:output(X|Y):-l:letter(X|Y).
smart:output(movement,speech).
smart:output-->sentence.


speech:output(form_w(_),(_)).

f( l(_,F/_),F).
f( t(_,F/_,_),F).
h(N,H):-N,H.
s(N,M,C):-N,M,C.

~(rationalize(Prime)):-(~(pass)),Prime.
~(rational(Prime)):-Prime.
~(pass):-set_random(number).
~(P):-!,(fail),not(P);true.
~(_):-not(_).
~(pass):-not(pass).


random(Prime):-(~(number(Prime))).
random(Prime):-lattice:node(Prime).
random(_):-lattice:matrix(set(_)).
random(X):-(~(pass(_)),~(pass))->lattice:matrix(X).
random(X):- X is random(1000000).





pass:-
	[Prime1,Prime2,Prime3],
	lattice:node(Prime1,Prime2,Prime3),
	source_file_chain(lattice:bagof(_)).
pass(Ch):-pass,source_file_chain(Ch),lattice:bagof(Ch).
pass:start:-pass.





lattice:bagof(M/C):-M,C.


lattice:insert(T,Ts,[T|Ts]):-
	f(T,F),lattice:bestf(Ts,Fl),
	F=<Fl,!.
lattice:insert(T,[Tl|Ts],[Tl|Tsl]):-
	lattice:insert(T,Ts,Tsl).
lattice:insert(T,Ts,[T|Ts]):-
	f(T,F),lattice:bestf(Ts,Fl),
	F=<Fl,!.
lattice:insert(T,[Tl|Ts],[Tl|Tsl]):-
	lattice:insert(T,Ts,Tsl).


lattice:continue(_, _, _, yes, yes, Sol,_):-f(Sol,yes).
lattice:continue( P, t(N, F/G, [Tl|Ts]), Bound, Tree1, Solved, Sol,F):-
	lattice:insert(Tl, Ts, NTs),
	lattice:bestf(NTs,Fl),
	lattice:expand(P, t(N, Fl/G, NTs), Bound, Tree1, Solved,Sol).
lattice:continue(_, _, _, yes, yes, Sol,_):-Sol.
lattice:continue( P, t(N, F/G, [Tl|Ts]), Bound, Tree1, Solved, Sol,F):-
	lattice:insert(Tl, Ts, NTs),
	lattice:bestf(NTs,Fl),
	lattice:expand(P, t(N, Fl/G, NTs), Bound, Tree1, Solved,Sol).



lattice:succlist(_, [], []).
lattice:succlist(G0, [N/C|NCs], Ts):-
	G is G0+C,
	h(N,H),
	F is G+H,
	lattice:succlist(G0, NCs, Tsl),
	lattice:insert( l(N,F/G), Tsl, Ts).
lattice:succlist(_, [], []).
lattice:succlist(G0, [N/C|NCs], Ts):-
	G is G0+C,
	h(N,H),
	F is G+H,
	lattice:succlist(G0, NCs, Tsl),
	lattice:insert( l(N,F/G), Tsl, Ts).


lattice:goal(_):-lattice:goal(n).


lattice:t(N,F/G,Sub):-lattice:l(N,F/G,Sub).


lattice:l(N,F/G,Sub):-lattice:(t(N,F/G,Sub)).



lattice:bestf(Start,Solution):-
	lattice:expand([],l(Start,0/0),9999,_,yes,Solution).
lattice:bestf(Start,Solution):-
	lattice:expand([],l(Start,0/0,9999,_,yes,Solution),_,_,_,_).
lattice:bestf([T|_],F):-
	f(T,F).
lattice:bestf([],9999).
lattice:bestf(Start,Solution):-
	lattice:expand([],l(Start,0/0,9999,_,yes,Solution),_,_,_,_).
lattice:bestf(Start,Solution):-
	lattice:expand([],l(Start,0/0),9999,_,yes,Solution).
lattice:bestf([T|_],F):-
	f(T,F).
lattice:bestf([],9999).



lattice:expand(P,l(N,_),_,_,yes,[N|P]):-lattice:goal(N).
lattice:expand(P,Tree,Bound,Tree1,Solved,Solution):-P,Tree,Bound,Tree1,Solved,Solution.
lattice:expand(P,l(N,_),_,_,yes,[N|P]):-lattice:goal(N).
lattice:expand(P,l(N,F/G),Bound,Tree1,Solved,Sol):-F=<Bound;Solved=Never,(lattice:bagof(M/C),(s(N,M,C) ,(~(Member)->[M,P],Succ)),!,lattice:succlist(G,Succ,Ts),lattice:bestf(Ts,Fl),lattice:expand(P,t(N,Fl/G,Ts),Bound,Tree1,Solved,Sol),Member;Solved=Never).
lattice:expand(P,t(N,F/G,[T|Ts]),Bound,Tree1,Solved,Sol):-F=<Bound,lattice:bestf(Ts,BF),lattice:min(Bound,BF,Bound1),lattice:expand([N|P],T,Bound1,Tl,Solved1,Sol),lattice:continue(P,t(N,F/G,[Tl|Ts]),Bound,Tree1,Solved1,Solved,Sol).
lattice:expand(_,t(_,_,[]),_,_,never,_):-!.

lattice:expand(_,Tree,Bound,Tree,no,_):-f(Tree,F),F>Bound.
lattice:expand(P,Tree,Bound,Tree1,Solved,Solution):-Solution,Solved;P,Tree,Bound,Tree1.
lattice:expand(P,l(N,_),_,_,yes,[N|P]):-lattice:goal(N).
lattice:expand(P,t(N,F/G,[T|Ts]),Bound,Tree1,Solved,Sol):-F=<Bound,lattice:bestf(Ts,BF),lattice:min(Bound,BF,Bound1),lattice:expand([N|P],T,Bound1,Tl,Solved1,Sol),lattice:continue(P,t(N,F/G,[Tl|Ts]),Bound,Tree1,Solved1,Solved,Sol).
lattice:expand(_,t(_,_,[]),_,_,never,_):-!.
lattice:expand(_,Tree,Bound,Tree,no,_):-f(Tree,F),F>Bound.
lattice:expand(P,l(N,_),_,_,yes,[N|P]):-lattice:goal(N).


lattice:matrix(node(A,B,C)):-lattice:node(d(_)),A,B,C.
lattice:matrix(Close):-set_random(number(Close)).
lattice:matrix(((Number))):-pass,pass(_),lattice:node(Number).
lattice:matrix(X):-random(X).
lattice:matrix((set_random(Number))):-lattice:edge(3)->random(Number).
lattice:matrix((Number)):-(lattice:node(3)->lattice:node(Number)).
lattice:matrix((Prime)):-number(Prime).
lattice:matrix(~(pass)):-[_].
lattice:matrix(pass):-pass.


lattice:matrix(Line,Node,Distance):-lattice:edge(Line);Node,Distance.
lattice:matrix(X,Y,Z):-lattice:edge(X,Y,Z),lattice:edge(Y,A,B),lattice:edge(Z,A,B),lattice:node(X,Y,Z).
lattice:matrix(Line,Node,Distance):-lattice:edge(Line)->lattice:edge(Line,Node,Distance).
lattice:matrix(node(1),node(2),node(3)):-lattice:node(d(_)).
lattice:matrix(Prime1,Prime2,Prime3):-lattice:node(Prime1,Prime2,Prime3).




lattice:edge([A,B,C]):-lattice:matrix(Node1,Node2,Node3),(A;Node1, B;Node2,C;Node3).
lattice:edge(Distance):-lattice:matrix(node(1),node(2),node(3)),Distance.
lattice:edge(lattice:node(Prime1)):-
	lattice:node(number(_),
		     [Prime1,Prime2],
		     lattice:edge([Prime2])),
	Prime1,Prime2.
lattice:edge([b]):-lattice:node(number(_)).
lattice:edge([a]):-lattice:node(number(Prime)),([Prime]).
lattice:edge([b]):-lattice:node(number(Prime)),([Prime]).
lattice:edge([c]):-lattice:node(number(Prime3;Prime1;Prime2),[Prime1,Prime2,Prime3],([a],[c])).
lattice:edge([Node1,Node2,Node3]):-lattice:matrix(Node1,Node2,Node3).
lattice:edge([A,B];[B,C];[C,B]):-lattice:node(A;B;C),lattice:edge([Line,Node,Distance]),lattice:distance((lattice:node + lattice:edge = Distance)),lattice:matrix(Line,Node,Distance).
lattice:edge(node):-lattice:matrix(node(1),node(2),node(3)).
lattice:edge(Number):-random(Number).
lattice:edge(Matrix;A,B,C):-lattice:matrix(Matrix;(A,B,C)).
lattice:edge(A,B,C):-A,B,C.




add_edges(X,Y,Z):-lattice:edge(X,Y,Z).

node(X,Y,Z):-lattice:node(X,Y,Z|Prime1,Prime2,Prime3),(Prime1,Prime2,Prime3).
node(X,Y,Z):-add_edges(X,Y,Z).

lattice:node(d([A+1=B])):-A,B.
lattice:node(d([A+2=C])):-A,C.
lattice:node(d([B+1=C])):-B,C.
lattice:node(d([A+1=B])):-A,B.
lattice:node(d([A+2=C])):-A,C.
lattice:node(d([B+1=C])):-B,C.
lattice:node(d([A+B=C])):-A,B,C.
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




'$dde_connect'(lattice:matrix):-handle_request(pass).


:- module(emacs_dde_server).
:- module(emacs_dde_server),module(win_register_emacs).
:- use_module(library(pce)).


handle_request(pass):-'$dde_connect'(lattice:matrix),(lattice:node(_,_,_),(lattice:edge(3))).
handle_request(Item) :-
	atom_concat('edit ', WinFile, Item), !,
	prolog_to_os_filename(File, WinFile),
	new(B, emacs_buffer(File)),
	send(B, open, tab),
	send(B, check_modified_file).
handle_request('close-server') :-
	dde_unregister_service('PceEmacs'),
	send(@emacs, report, status, 'Closed DDE server').
handle_request(Item) :-
	format(user_error, 'PceEmacs DDE server: unknown request: ~q', [Item]),
	fail.
handle_request('close-server') :-
	dde_unregister_service('PceEmacs'),
	send(@emacs, report, status, 'Closed DDE server').
handle_request(Item) :-
	format(user_error, 'PceEmacs DDE server: unknown request: ~pass', [Item]),
	fail.


source_file_chain(Ch) :-
	new(Ch, chain),
	forall(user_source_file(X), send(Ch, append, X)),
	send(Ch, sort).
source_file_chain(Ch):-pass(Ch),pass.


user_source_file(F) :-
	source_file(F),
	\+ (lib_dir(D), atom_concat(D, _, F)).
user_source_file(source_file(Z)):-lib_dir(Z),expand_path(Z,source_file(Z)),ignore_paths_from(Y),expand_path(X,Z),smart:analyze(X),user_source_file(Y).
user_source_file(_):-pass:start.


ignore_paths_from(library).
ignore_paths_from(pce_boot).

lib_dir(D) :-
	ignore_paths_from(Category),
	user:file_search_path(Category, X),
	expand_path(X, D0),
	absolute_file_name(D0, D).	% canonise
lib_dir(D):-user_source_file(D).


expand_path(X, X) :-
	atomic(X), !.
expand_path(Term, D) :-
	Term =.. [New, Sub],
	user:file_search_path(New, D0),
	expand_path(D0, D1),
	atomic_list_concat([D1, /, Sub], D).



:- pce_global(@prolog_full_stop,
	      new(regex('[^-#$&*+./:<=>?@\\\\^`~]\\.($|\\s)'))).
:- pce_global(@prolog_decl_regex,
	      new(regex('^:-\\s*[a-z_]+'))).
:- if(current_predicate(shell_register_dde/1)).
:- endif.

node(X,Y,Z)-:-(Number1;Number2;Number3):-lattice:node(Number1,Number2,Number3);(X,Y,Z).
lattice:matrix(pass)-:-lattice:bestf(_,_).
lattice:expand(P,l(N,F/G),Bound,Tree1,Solved,Sol)
      -:-Member,Solved=Never
      :-F=<Bound,(lattice:bagof(M/C),(s(N,M,C) ,
      (~(Member)->[M,P],Succ)),
		  !,lattice:succlist(G,Succ,Ts),
		  lattice:bestf(Ts,Fl),
		  lattice:expand(P,t(N,Fl/G,Ts),
				 Bound,Tree1,Solved,Sol);Solved=Never).
lattice:min(X,Y,Z)-:-Bound,BF,Bound1:-lattice:min(Bound,BF,Bound1);(X,Y,Z).
lattice:edge([c])-:-Distance,Prime1,Prime2,Prime3:-lattice:node(number(Distance),[Prime1,Prime2,Prime3],[a],[c]).
lattice:edge([A,B];[B,C];[C,B])-:-Line,Node:-lattice:node(3),lattice:edge([A,B,C]),lattice:distance((lattice:node + lattice:edge = Distance)),lattice:matrix(Line,Node,Distance).
P-:-Q:-meaning(P,(Q)),(read(P),nl,write((Q)));(read(Q),nl,write((P))).
P-:-Q:-copy_list(Q-:-P).
Prime-:-not(divisible(not(X),X),X+1):-Prime.
