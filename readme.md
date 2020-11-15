Absolute :

    No more than two consecutive characters
    No sequences i.e. 123, abc
    8+ characters 
    No more than 2 repeated characters
    No more than 2 sequential characters, forward and backwards
    Not in common password list (tbd)
    Calculated medium strength (tbd)
    Max 50 characters
    Not previously used in last x occasions or y months, whichever greater

By varying criteria based on string length, makes more difficult for brute attack, increases possible options, increases time taken to hack

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

    Very Low: cannot be used (<8 characters)
    Low: cannot be used (8 characters no mix; 8-12 characters, 2 mixed only)
    Medium: 30 days (8-12 characters, 3 mixed only)
    Strong: 60 days (8+ characters, 4 mixed; 12-16 characters, 3 mixed; + 2 mixed)  
    Very Strong: 90 days (20+ characters, 2 character types; 16+ characters, 3 character types)
    Epic Strong: 365 days (20+ characters, 4 mixed)
