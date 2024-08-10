sentence:-copy_list(idea-:-command).
sentence:-l:sentence.
l:sentence:-((idea);(question;command)),((l:noun_p),l:prep_p,l:verb_p).
l:sentence:-read(49).
l:sentence:-objective(_).
l:sentence:-(l:noun_p,l:verb_p);((l:noun_p),(l:prep_p),(l:word));((l:verb),(l:noun_p),(l:prep_p),(l:word)).
l:sentence(Number)-->l:noun_p(Number),l:verb_p(Number).
l:sentence(Wordlist,String):-l:grab(l:sentence,l:word(Wordlist,String,objective)).
l:sentence(Wordlist,String):-l:word(Wordlist,input,String).
l:sentence(Wordlist,String):-getsentence(Wordlist),objective(String|Wordlist).
l:sentence-->(l:noun_p,l:verb_p);((l:noun_p),(l:prep_p),l:word);((l:verb),(l:noun_p),(l:prep_p),(l:word)).
l:word(Char|((Char,String);Rest))-->l:letter(Char|String,Char),l:grab_l((Char|Rest,Rest),(Char|String,String)),form_w(Char|String,String).
l:verb_p-->l:verb,l:noun_p.
l:verb_p(Number)-->l:verb(Number),l:noun_p(Number).
l:noun_p-->(l:determiner->l:noun).
l:noun_p(Number)-->l:determiner(Number),l:noun(Number).
l:determiner-->[a];[the].
l:noun-->([name];[person]);[place];[thing];[idea].
l:noun_pr-->[name],[place],[thing].
l:noun(singular)-->(l:determiner->[a]).
l:noun(plural)-->(l:determiner(the)).
l:verb-->[action];[state];[being].
l:prep_p-->l:prep,((l:noun_p);(l:noun);(l:prep,l:noun_pr)).
l:prep-->[in];[to];[with];[into];[by].
l:grab_l(Char|String,String)-->form_w(Char|String,String).
l:grab_l(X,Y)-->form_w(X|Y,Y).
l:output(Answer):-l:output(Answer),write(Answer).
l:output(_):-question,call(l:sentence).
l:verb_p(Number):-l:noun_p(Number).
l:noun_p(Number):-l:verb_p(Number).
l:determiner(X,Y,Z):-write(X;Y;Z).
l:verb(X,Y,Z):-write(X;Y;Z).
l:verb:-l:verb(_,_,_).
l:word(X,Y):-l:letter(Y|X,Y).
l:word:-l:word(input,getletters).
l:letter(Y,X,Z,P):-l:grab_l(Y|X,X);l:grab_l(X|Z,Z);l:grab_l(Z|P,P).
form_w(Char|String,String)-->l:word(Char|String,String),l:sentence(String).
idea:-information;question;command.
information:-l:sentence.
question:-l:output(answer).
command:-l:sentence,task.
task:-objective(task);command.
objective(X):-input(X=task).
input(Wordlist):-getsentence(Wordlist).
input(P):-(P:Q),display(Q).
input(_):-assert((_)).
input(getsentence):-l:sentence(input,objective).
getsentence(Wordlist):-get0(Char),getrest(Char,Wordlist).
getrest(46,[]):-!.
getrest(32,Wordlist):-!,getsentence(Wordlist).
getrest(Letter,[Word|Wordlist]):-getletters(Letter,Letters,Nextchar),name(Word,Letters),getrest(Nextchar,Wordlist).
getletters(46,[],46):-!.
getletters(32,[],32):-!.
getletters(Let,[Let|Letters],Nextchar):-get0(Char),getletters(Char,Letters,Nextchar).
:-op(1200,xfy,(-:-)).
options:-write('Your Choice is either 1 or 2, enter 1 for sentence forms and 2 to stream input in english'),nl,options_display(49),options_choose(49),nl.
options_display(49):-sentence.
options_display(49):-get(49),nl.
options_choose(49):-read(49)->l:sentence,display(l:sentence),options_choose_aux(49,50,Input,(read(Input))).
options_choose_aux(First,Last,Result,Char):-Char>=First,Char=<Last,!,options_select(First,Char,Result).
options_choose_aux(First,Last,Result,_):-put(7),put(13),options,nl,display(First),nl,display(Last),nl,display(Result).
options_select(First,Char,Result):-NewFirst is First+1,options_select(NewFirst,Char,Result).
copy_list([]-:-[]).
copy_list([X|Y]-:-[X|Z]):-copy_list(Y-:-Z),tell([a]).
display(options):-start.
start:-(options->options_display(49)).
:-dynamic l:grab/2.
:-dynamic l:letter/2.
:-dynamic l:noun_p/0.
:- dynamic l:prep_p/0.
:-dynamic l:verb_p/0.
:-dynamic l:word/4.
:-dynamic l:grab_l/2.
