# CTF Writeup: Advanced JSON Cutifier

## Challenge Description

My homework was to write a JSON beautifier. Just Indenting JSON files was too boring that's why I decided to add some features to my project using a popular (More than 1k stars on GitHub!! ) library to make my project more exciting.

Important: You can't read any file other than /flag.txt on the remote environment.

## Solution

### Recon

The website appeared deceptively simple, allowing us to prettify JSON in a neat way.

![site](https://github.com/No-Tips/ctf-writeups/assets/75416333/1a559f82-69c9-46d0-8712-7a93fc9a7622)

It also revealed that basic arithmetic operations could be performed, opening the door to potential shenanigans.

Upon inspecting the source code (a single Golang file), I found that the backend used a redacted JSON prettifier. My task was to identify this mysterious module:

```go
import (
    "github.com/REDACTED/REDACTED"
)

jsonStr, err := REDACTED.REDACTED().REDACTED("ctf", string(buf[:]))
```

### Step 1:

The initial step involved locating this elusive JSON module. I could have brute-forced my way through it or identified the module using generated error codes.

Sampled error:
```
IN:
{"wow so advanced!!": 123 :

OUT: 
ctf:1:27-28 Expected a comma before next field
```

After gathering a few error codes, I performed a GitHub search using the following string:

``` "Expected a comma before next field" AND "Unexpected" language:Go  ```

This led me to various jsonnet-go codesnippets, strongly indicating that this module might be the one.

### Step 2:

After experimenting with basic concepts from https://jsonnet.org/learning/tutorial.html, I was confident that I was on the right track. The next step was to figure out how to exploit it.

After numerous attempts, I stumbled upon the importstr feature on a random website (https://tanka.dev/libraries/import-paths), and that was the breakthrough:

``` 
IN:
local secret = importstr "/flag.txt";
std.toString(secret)

OUT:
"MAPNA{5uch-4-u53ful-f347ur3-a23f98d}\n\n"
```

Overall, this challenge provided an enjoyable experience, requiring extensive searching and tinkering with various Golang libraries and interesting approach of actually finding the module.
