No more than two consecutive characters
No sequences i.e. 123, abc
Minimum 8 characters

If length less than 12:
Enforce upper, lower, number, character
Else :
Suggest mix upper, lower

No restrictions, unless greater than 30 characters, absolute max of 50

By varying criteria based on string length, makes more difficult for brute attack, increases possible options, increases time taken to hack

Absolute :
8+ characters
No more than 2 repeated characters
No more than 2 sequential characters, forward and backwards
Not in common password list (tbd)
Calculated medium strength (tbd)
Max 50 characters
Not previously used in last x occasions or y months, whichever greater

Soft warning:
Greater than 8, less than 30 of single input pattern

Common password list (min) :
Stored in database
password (any case)
pass (any case)
123456 (would be covered by sequence anyway)
Monkey (any case)
Find top 10/25/50 easily cracked /guessed passwords
TBD:
x = instances before password can be reused
y = years, retention of passwords

Passwords could be changed more regularly than required, could use years rather than alterations
Password strength could govern password change requirements
Very Low: cannot be used
Low: cannot be used
Medium: 30 days
Strong: 60 days
Very Strong: 90 days
Ultra Strong: 180 days
Epic Strong: 365 days

Very Low: <8 characters
Low: 8 characters no mix
8-12 characters, 2 mixed only
Medium: 8+ characters, 3 mixed only
Strong: 8+ characters, 4 mixed
12-16 characters, 3 mixed
16-20 characters, 2 mixed
Very Strong: 20+ characters, 1-3 mixed
20+ characters, 2 characters
16+ characters, 3 characters
Epic Strong: 20+ characters, 4 mixed