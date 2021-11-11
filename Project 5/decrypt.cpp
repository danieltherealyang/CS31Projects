#include <iostream>
#include <cstring>
#include <cctype>
#include <cassert>
using namespace std;
//no more than 70 \n characters
//no message longer than 90 char not counting the newline
//possible for message to have no words
//non-letter characters treated as blanks in crib
//don't assume limit to length of crib
//if crib is empty or no fragment could be encryption of crib, return false without writing to cout
//else output to cout with partially decrypted message and return true
//if more than one fragment then choose any one as the match
//crib match doesn't span more than one message
//crib is only letters
/*
loop through each line of ciphertext
find match for crib
set cipher
loop through and replace each character
*/
struct keymap {
    char cipher = '\0';
    char plain = '\0';
};

void sanitizeCrib(char crib[]) {
    int offset = 0;
    int blankCount = 0;
    int i = 0;
    for (i = 0; crib[i + offset] != '\0'; i++) {
        if (!isalpha(crib[i + offset])) {
            //skip starting blanks
            if (i == 0) {
                i--;
                offset++;
                continue;
            }
            blankCount++;
            //skip past multiple blanks
            if (blankCount > 1) {
                i--;
                offset++;
                continue;
            }
            crib[i] = ' ';
        } else {
            if (blankCount != 0)
                blankCount = 0;
            crib[i] = toupper(crib[i + offset]);
        }
    }
    if (blankCount == 0)
        crib[i] = '\0';
    else
        crib[i-1] = '\0';
}
//function finds if a string matches crib and sets index param as the start index of match
//assumes that crib is nothing but letters and single spaces between words
//match inclusive of start and end indexes
bool findLengthMatch(const char cipher[], int start, int end, const char crib[], int& index) {
    //index for crib
    int i = 0;
    //index for cipher
    int j = start;
    //index of match start
    int matchStart;
    while (crib[i] != '\0' && cipher[j] != '\0' && j <= end) {
        //increment both if match reset crib index if not a match
        //if cipher is blank then increment until next alpha
        if (isalpha(crib[i]) && isalpha(cipher[j])) {
            i++;
            j++;
        } else if (!isalpha(crib[i]) && !isalpha(cipher[j])) {
            i++;
            while (!isalpha(cipher[j])) {
                j++;
            }
        } else if (isalpha(crib[i]) && !isalpha(cipher[j])) {
            i = 0;
            while (!isalpha(cipher[j])) {
                j++;
            }
            matchStart = j;
        } else if (!isalpha(crib[i]) && isalpha(cipher[j])) {
            i = 0;
            //move cipher index to end of word
            while (isalpha(cipher[j])) {
                j++;
            }
            matchStart = j;
        }
    }

    if (crib[i] == '\0') {
        index = matchStart;
        return true;
    } else {
        return false;
    }
}
//function checks if pattern matches
bool findPatternMatch(const char cipher[], int startIndex, const char crib[], keymap keyMap[]) {
    //index of cipher
    int i = startIndex;
    //index of crib
    int j = 0;
    //index of keyMap
    int k = 0;
    keymap map[27];
    while (cipher[i] != '\0' && crib[j] != '\0') {
        if (isalpha(cipher[i]) && isalpha(crib[j])) {
            bool conflictFound = false;
            bool found = false;
            for (int x = 0; map[x].cipher != '\0'; x++) {
                if ((toupper(crib[j]) == map[x].plain) && (toupper(cipher[i]) != map[x].cipher))
                    conflictFound = true;
                if ((toupper(crib[j]) != map[x].plain) && (toupper(cipher[i]) == map[x].cipher))
                    conflictFound = true;
                if (conflictFound)
                    return false;
                
                if (map[x].cipher == toupper(cipher[i])) {
                    found = true;
                    break;
                }
            }

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
    //copy map into keymap
    /*
    for (int i = 0; map[i].cipher != '\0' && keyMap[i].cipher != '\0'; i++) {
        keyMap[i].cipher = map[i].cipher;
        keyMap[i].plain = map[i].plain;
    }*/

    return true;
}
//function returns index of last character of a line
int getLineEnd(const char cString[], int index) {
    if (cString[index] == '\0' || cString[index] == '\n')
        return index;
    for (int i = index; cString[i] != '\0' && cString[i] != '\n'; i++) {
        index++;
    }
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

    while (cipher[i] != '\0' && crib[j] != '\0') {
        if (isalpha(cipher[i]) && isalpha(crib[j])) {
            bool found = false;
            for (int x = 0; keyMap[x].cipher != '\0'; x++) {
                if (keyMap[x].cipher == toupper(cipher[i])) {
                    found = true;
                    break;
                }
            }
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

bool decrypt(const char ciphertext[], const char crib[]) {
    //check if crib is longer than max message size
    if ((strlen(crib) > 90) || strlen(crib) > strlen(ciphertext))
        return false;
    //make modifiable copy of crib
    char cribCpy[91];
    //copy and sanitize crib
    strcpy(cribCpy, crib);
    sanitizeCrib(cribCpy);
    //set variable to check if match was found
    bool matchFound = false;
    int currentIndex = 0;
    int matchIndex = 0;
    int lineEnd = getLineEnd(ciphertext, currentIndex);
    //set cipher key
    keymap keyMap[27];
    while (!matchFound && ciphertext[lineEnd + 1] != '\0') {
        if (findLengthMatch(ciphertext, currentIndex, lineEnd, cribCpy, matchIndex)) {
            if (findPatternMatch(ciphertext,matchIndex,crib,keyMap))
                matchFound = true;
        }
        currentIndex = lineEnd + 1;
        lineEnd = getLineEnd(ciphertext, currentIndex);
    }
    //check last line
    if (!matchFound && findLengthMatch(ciphertext, currentIndex, lineEnd, cribCpy, matchIndex)) {
        if (findPatternMatch(ciphertext,matchIndex,crib,keyMap))
            matchFound = true;
    }

    if (matchFound) {
        setKeyMap(ciphertext,matchIndex,crib,keyMap);
    } else {
        return false;
    }
    //replace char with key
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        int index = -1;
        for (int j = 0; keyMap[j].cipher != '\0'; j++) {
            if (toupper(ciphertext[i]) == keyMap[j].cipher) {
                index = j;
                break;
            }
        }
        if (index < 0)
            cout << ciphertext[i];
        else
            cout << keyMap[index].plain;
    }
    return true;
}

int main() {
    char cipher[] = "F gspt fe! zyxZYXzyx--Abca abCa    bdefg## $$dsptrqtj6437 wvuWVUwvu\n\n8 9\n";
    char crib[] = "   hush???hUSh---     --- until    NovemBER !!  ";
    decrypt(cipher,crib);
}