#include <iostream>
#include <cstring>
#include <cctype>
#include <cassert>
using namespace std;
//data type to store key value pairs, initialize each value to null
struct keymap {
    char cipher = '\0';
    char plain = '\0';
};
//function finds if a string matches crib and sets index param as the start index of match
//assumes that crib is nothing but letters and single spaces between words
//match inclusive of start and end indexes
bool findLengthMatch(const char cipher[], int start, int end, const char crib[], int& index) {
    //skip past starting blanks
    int cribStart = 0;
    while (!isalpha(crib[cribStart])) {
        cribStart++;
    }
    //ignore ending blanks
    int cribEnd = 0;
    for (int i = 0; crib[i] != '\0'; i++) {
        if (isalpha(crib[i]))
            cribEnd = i;
    }
    //index for crib
    int i = cribStart;    
    //index for cipher
    int j = start;
    //index of match start
    int matchStart;
    //count for blanks
    int blankCount = 0;
    //in case crib matches very first char of cipher
    if (isalpha(crib[i]) && isalpha(cipher[j]))
        matchStart = j;
    while (crib[i] != '\0' && i <= cribEnd && cipher[j] != '\0' && j <= end) {
        if (!isalpha(crib[i])) {
            //skip past multiple blanks
            if (blankCount > 0) {
                i++;
                continue;
            }
        } else if (blankCount > 1) {
            i--;
        }
        //increment both if match reset crib index if not a match
        //if cipher is blank then increment until next alpha
        if (isalpha(crib[i]) && isalpha(cipher[j])) {
            blankCount = 0;
            i++;
            j++;
        } else if (!isalpha(crib[i]) && !isalpha(cipher[j])) {
            i++;
            blankCount++;
            //skips blanks in cipher until next alpha char
            while (!isalpha(cipher[j])) {
                j++;
            }
        } else if (isalpha(crib[i]) && !isalpha(cipher[j])) {
            i = cribStart;
            blankCount = 0;
            //skips blanks in cipher until next alpha char
            while (!isalpha(cipher[j])) {
                j++;
            }
            //reset matchStart
            matchStart = j;
        } 
        //check if crib ends before cipher word ends
        if (!isalpha(crib[i]) && isalpha(cipher[j]) && blankCount == 0) {
            i = cribStart;
            //move cipher index to end of word
            while (isalpha(cipher[j])) {
                j++;
            }
            //reset matchStart
            matchStart = j;
        }
    }
    //crib has to be on null char, make sure index of cipher is the end of the word, sets index to the start of match
    if (i > cribEnd && !isalpha(cipher[j])) {
        index = matchStart;
        return true;
    } else {
        return false;
    }
}
//function checks if pattern matches
bool findPatternMatch(const char cipher[], int start, int end, const char crib[], keymap keyMap[]) {
    int cribEnd = 0;
    for (int i = 0; crib[i] != '\0'; i++) {
        if (isalpha(crib[i]))
            cribEnd = i;
    }
    //index of cipher
    int i = start;
    //index of crib
    int j = 0;
    //index of keyMap
    int k = 0;
    keymap map[27];
    //loop through each char of crib and cipher
    while (crib[j] != '\0' && j <= cribEnd && cipher[i] != '\0' && i <= end) {
        //case both are cipher and crib are alpha
        if (isalpha(cipher[i]) && isalpha(crib[j])) {
            bool conflictFound = false;
            bool found = false;
            //loop through each entry in keymap
            for (int x = 0; map[x].cipher != '\0'; x++) {
                //check if crib is found but cipher doesn't match or cipher found but crib doesn't match
                if ((toupper(crib[j]) == map[x].plain) && (toupper(cipher[i]) != map[x].cipher))
                    conflictFound = true;
                if ((toupper(crib[j]) != map[x].plain) && (toupper(cipher[i]) == map[x].cipher))
                    conflictFound = true;
                //terminate function if conflict is found
                if (conflictFound)
                    return false;
                //if conflict checks passed, indicate a match was found and terminate for loop
                if (map[x].cipher == toupper(cipher[i])) {
                    found = true;
                    break;
                }
            }
            //if new char not in keymap and no conflict found, add entry into keymap
            if (!found) {
                map[k].cipher = toupper(cipher[i]);
                map[k].plain = toupper(crib[j]);
                k++;
            }
            i++;
            j++;
        } else if (!isalpha(cipher[i]) && !isalpha(crib[j])) {
            i++;
            j++;
        } else if (isalpha(cipher[i]) && !isalpha(crib[j])) {
            j++;
        } else if (!isalpha(cipher[i]) && isalpha(crib[j])) {
            i++;
        }
    }

    return true;
}
//function returns index of last character of a line
int getLineEnd(const char cString[], int index) {
    //if index is already line end then return value
    if (cString[index] == '\0' || cString[index] == '\n')
        return index;
    //increment index until reaches a null char or newline
    for (int i = index; cString[i] != '\0' && cString[i] != '\n'; i++) {
        index++;
    }
    //return index just before newline or null char
    return index - 1;
}
//function sets cipher keys, key is only uppercase
void setKeyMap(const char cipher[], int startIndex, const char crib[], keymap keyMap[]) {
    //index of cipher
    int i = startIndex;
    //index of crib
    int j = 0;
    //index of keyMap
    int k = 0;
    //loop through cipher starting from start of match and crib starting from index 0
    while (cipher[i] != '\0' && crib[j] != '\0') {
        if (isalpha(cipher[i]) && isalpha(crib[j])) {
            bool found = false;
            //check if cipher char is already in keymap
            for (int x = 0; keyMap[x].cipher != '\0'; x++) {
                if (keyMap[x].cipher == toupper(cipher[i])) {
                    found = true;
                    break;
                }
            }
            //if cipher char is not already in keymap then add new key value pair in keymap array
            if (!found) {
                keyMap[k].cipher = toupper(cipher[i]);
                keyMap[k].plain = toupper(crib[j]);
                k++;
            }
            i++;
            j++;
        } else if (!isalpha(cipher[i]) && !isalpha(crib[j])) {
            i++;
            j++;
        } else if (isalpha(cipher[i]) && !isalpha(crib[j])) {
            j++;
        } else if (!isalpha(cipher[i]) && isalpha(crib[j])) {
            i++;
        }
    }
}
//function returns the index of the next word, if there is no next word returns the index of the end of the current word.
//index must be start of a word
int getNextWord(const char cString[], int index) {
    int i = index;
    //loop to the end of current word
    while (isalpha(cString[i])) {
        i++;
    }
    //loop to the start of the next word, end when reach line end or string end
    while (!isalpha(cString[i]) && cString[i] != '\n' && cString[i] != '\0') {
        i++;
    }
    //just in case of last word of a line
    if (cString[i] == '\n' || cString[i] == '\0')
        return i - 1;
    else
        return i;
}

bool decrypt(const char ciphertext[], const char crib[]) {
    //check if crib is longer than max message size
    int cribChar = 0;
    for (int i = 0; crib[i] != '\0'; i++) {
        if (isalpha(crib[i]))
            cribChar++;
    }
    if (cribChar > 90)
        return false;
    //set variable to check if match was found
    bool matchFound = false;
    int currentIndex = 0;
    int matchIndex = 0;
    int lineEnd = getLineEnd(ciphertext, currentIndex);
    //set cipher key
    keymap keyMap[27];
    //loop for all lines other than last line
    while (!matchFound && ciphertext[lineEnd + 1] != '\0') {
        //loop until currentIndex reaches lineEnd
        while (currentIndex < lineEnd) {
            //check if word lengths match, then check if letter patterns also match
            if (findLengthMatch(ciphertext, currentIndex, lineEnd, crib, matchIndex)) {
                if (findPatternMatch(ciphertext,matchIndex,lineEnd,crib,keyMap)) {
                    matchFound = true;
                    break;
                } else {
                    //if length match but pattern doesn't, move on currentIndex to start of next word
                    //and check again
                    currentIndex = getNextWord(ciphertext, currentIndex);
                }
            } else {
                //if no length match then move to next line
                break;
            }
        }
        currentIndex = lineEnd + 1;
        lineEnd = getLineEnd(ciphertext, currentIndex);
    }
    //check last line of ciphertext
    if (!matchFound) {
        //loop until currentIndex reaches lineEnd
        while (currentIndex < lineEnd) {
            //check if word lengths match, then check if letter patterns also match
            if (findLengthMatch(ciphertext, currentIndex, lineEnd, crib, matchIndex)) {
                if (findPatternMatch(ciphertext,matchIndex,lineEnd,crib,keyMap)) {
                    matchFound = true;
                    break;
                } else {
                    //if length match but pattern doesn't, move on currentIndex to start of next word
                    //and check again
                    currentIndex = getNextWord(ciphertext, currentIndex);
                }
            } else {
                //if no length match then move to next line
                break;
            }
        }
    }

    if (matchFound) {
        setKeyMap(ciphertext,matchIndex,crib,keyMap);
    } else {
        return false;
    }
    //loop through ciphertext and check if char is in keymap
    //if yes, replace with uppercase keymap char else print lowercase ciphertext char
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        int index = -1;
        for (int j = 0; keyMap[j].cipher != '\0'; j++) {
            if (toupper(ciphertext[i]) == keyMap[j].cipher) {
                index = j;
                break;
            }
        }
        if (index < 0)
            cout << (char) tolower(ciphertext[i]);
        else
            cout << keyMap[index].plain;
    }
    return true;
}

int main() {
    assert(decrypt("Xbg'j rsj jds jsrrsy jycn jds ucrsgj qrqyt.\nZU 31 cu zdqrrsgecge!", "silent alarm")); //check multiline ciphertext
    assert(decrypt("Xbg'j rsj jds jsrrsy jycn jds ucrsgj qrqyt.\nZU 31 cu zdqrrsgecge!\n", "silent alarm")); //ciphertext ends with newline
    assert(decrypt("F lgr rntoy rkwndyk ahna'y\n phklk ahk mgtks fyadys", "secret")); //match at end of ciphertext
    assert(decrypt("F lgr rntoy rkwndyk ahna'y fyadys\n phklk ahk mgtks fyadys.", "secret")); //match at end of line
    assert(!decrypt("Rzy pkr", "123431")); //no words in crib
    assert(!decrypt("Rzy pkr", "")); //empty crib
    assert(!decrypt("Rzy pkr", "    \n\n")); //empty crib
    assert(decrypt("Rzy pkr", "dog")); //multiple matches in a message 
    assert(decrypt("cdc ef", "aba")); //crib matches entire ciphertext word
    assert(!decrypt("cdcef", "aba")); //crib doesn't match if not entire ciphertext word
    assert(!decrypt("efcdc", "aba")); //crib doesn't match if not entire ciphertext word
    assert(!decrypt("bwra wmwt\nqeirtk spst\n", "alan turing")); //crib doesn't span multiple messages
    assert(!decrypt("ew'q p-aj", "dog")); //word is only a sequence of letters
    assert(decrypt("ew'q p-aj", "he")); //nonalpha char treated as blanks
    assert(decrypt("Kpio't dmpbl-boe-ebhhfs opwfm", "s cloak and")); //nonalpha char treated as blanks
    assert(decrypt("F gspt fe! zyxZYXzyx--Abca abCa    bdefg## $$dsptrqtj6437 wvuWVUwvu\n\n8 9\n", "hush-hush until November 25, 2021")); //crib ignores numbers
    assert(decrypt("F gspt fe! zyxZYXzyx--Abca abCa    bdefg## $$dsptrqtj6437 wvuWVUwvu\n\n8 9\n", "   hush???hUSh---     --- until    NovemBER !!  ")); //crib ignores blanks and case
    assert(decrypt("F gspt fe! zyxZYXzyx--Abca abCa    bdefg## $$dsptrqtj6437 wvuWVUwvu\n\n8 9\n", "hush hush until november")); //proper crib sanitization
    assert(!decrypt("", "a")); //empty ciphertext
    assert(!decrypt("1232341$@##4%!$  \n 1232132\n\n ", "a")); //no words in ciphertext
    assert(decrypt("\n\n     ew'q p-aj", "he")); //empty messages in ciphertext at beginning lines
    assert(decrypt("ew'q\n\n 123213'''''  \n p-aj", "he")); //message with no words in ciphertext
    assert(decrypt("ew'q\n\n 123213'''''  \n p-aj\n\n\n '12321", "he")); //last message in ciphertext no words
    assert(decrypt("kvbz pqzzyfq bz zqxjqk", "secret")); //match at end of ciphertext
    assert(decrypt("kvbz pqzzyf bz zqxjqk", "secret")); //multiple length matches in message
    assert(decrypt("kvbz padgas bz zqxjqk", "secret")); //multiple pattern matches in message
}