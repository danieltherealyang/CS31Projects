#include <iostream>
#include <string>
#include <cassert>
using namespace std;

int reduplicate(string a[], int n)
{
    //check bad input
    if (n < 0)
        return -1;
    //double each string in array
    for (int i = 0; i < n; i++) {
        a[i] = a[i] + a[i];
    }

    return n;
}

int locate(const string a[], int n, string target)
{
    //check bad input
    if (n < 0)
        return -1;
    //loop through each element and check if equal to target
    for (int i = 0; i < n; i++) {
        if (a[i] == target)
            return i;
    }

    return -1;
}

int locationOfMax(const string a[], int n) 
{
    //check bad input
    if (n <= 0)
        return -1;
    //set current max string and index
    string max = a[0];
    int maxIndex = 0;
    //compare each remaining element against current max string
    for (int i = 1; i < n; i++) {
        if (a[i] > max) {
            //reassign max string and index
            max = a[i];
            maxIndex = i;
        }
    }

    return maxIndex;
}

int circleLeft(string a[], int n, int pos)
{
    //check bad input
    if (n < 0 || pos < 0 || pos >= n)
        return -1;
    //store eliminated item in temp
    string temp = a[pos];
    //loop through all elements to the right of pos and shift left
    for (int i = pos; i < n - 1; i++) {
        a[i] = a[i+1];
    }
    //put eliminated item in last position of array
    a[n-1] = temp;

    return pos;
}

int enumerateRuns(const string a[], int n)
{
    //check bad input
    if (n <= 0)
        return -1;
    //set counter to minimum value and current item
    int identical = 1;
    string currentItem = a[0];
    //loop through rest of items and increment counter if different from currentItem
    for (int i = 1; i < n; i++) {
        if (a[i] != currentItem) {
            identical++;
            currentItem = a[i];
        }
    }

    return identical;
}

int flip(string a[], int n)
{
    //check bad input
    if (n < 0)
        return -1;
    //loop through first half of array and swap
    for (int i = 0; i < n/2; i++) {
        string temp = a[i];
        a[i] = a[n-1-i];
        a[n-1-i] = temp;
    }

    return n;
}

int locateDifference(const string a1[], int n1, const string a2[], int n2)
{
    //check bad input
    if (n1 <= 0 || n2 <= 0)
        return -1;
    //set lower array size
    int minIndex;
    if (n1 < n2)
        minIndex = n1;
    else
        minIndex = n2;
    //loop through the first items less than minIndex of both arrays and compare
    for (int i = 0; i < minIndex; i++) {
        if (a1[i] != a2[i])
            return i;
    }

    return minIndex;
}

int subsequence(const string a1[], int n1, const string a2[], int n2)
{
    //check bad input
    if (n1 < 0 || n2 < 0 || n1 < n2)
        return -1;
    //return 0 if n2 is 0
    if (n2 == 0)
        return 0;
    //loop through every element and if a1 element = a2[0] check if remaining n2 elements are equal to a2
    for (int i = 0; i <= n1 - n2; i++) {
        bool isSub = true;
        if (a1[i] == a2[0]) {
            for (int j = 0; j < n2; j++) {
                if (a1[i + j] != a2[j]) {
                    isSub = false;
                    break;
                }
            }
            //return i if subsequence test passed
            if (isSub)
                return i;
        }
    }
    //return -1 if no subsequence found
    return -1;
}

int locateAny(const string a1[], int n1, const string a2[], int n2)
{
    //check bad input
    if (n1 <= 0 || n2 <= 0)
        return -1;
    //loop through every element in a1 and check if equal to any element in a2
    for (int i = 0; i < n1; i++) {
        for (int j = 0; j < n2; j++) {
            if (a1[i] == a2[j])
                return i;
        }
    }

    return -1;
}

int separate(string a[], int n, string separator)
{
    //check bad input
    if (n < 0)
        return -1;
    int gtIndex = n;
    int circleLoop = 0;
    //loop through every element in a
    for (int i = 0; i < n; i++) {
        //break loop if every remaining element is >= separator
        if (i == n-circleLoop) {
            break;
        }
        //if element >= separator, update index and move elements left
        if (a[i] >= separator) {
            gtIndex = i;
            circleLeft(a, n, i);
            //update loop counter
            circleLoop++;
            //stay in same index because elements shifted left
            i--;
        } else {
            //reset loop count if < separator
            circleLoop = 0;
        }
    }
    //reset loop count for second loop
    circleLoop = 0;
    //loop through every element starting from first element not < separator
    for (int j = gtIndex; j < n; j++) {
        //break loop if every remaining element is > separator
        if (j == n-circleLoop)
            break;
        //shift elements left if > separator, move to next iteration if == separator
        if (a[j] > separator) {
            circleLeft(a, n, j);
            circleLoop++;
            j--;
        } else {
            circleLoop = 0;
        }
    }

    return gtIndex;
}

int main()
{
    /*
    string redupArray[6] = { "mahi", "bon", "cous", "", "tar", "mur" };
    assert(reduplicate(redupArray, 6) == 6); //reduplicate returns n
    assert(reduplicate(redupArray, -1) == -1); //reduplicate returns -1 for neg array size
    assert(reduplicate(redupArray, 0) == 0); //0 doesn't throw error
    string testArray[5] = { "asdf", "fdas", "ELsa", "eLsA", "123"};
    assert(locate(testArray, 5, "eLsA") == 3); //proper return value
    assert(locate(testArray, 0, "ELsa") == -1); //0 as array size
    assert(locate(testArray, -5, "asdf") == -1); //negative array size
    assert(locate(testArray, 2, "fdas") == 1); //proper return value
    string people[5] = { "merida", "tiana", "raya", "ariel", "moana" };
    assert(locate(people, 3, "moana") == -1); //failed to find string
    assert(locationOfMax(testArray, 5) == 1); //proper return value
    assert(locationOfMax(testArray, 2) == 1); //proper return value
    assert(locationOfMax(testArray, 0) == -1); //0 as array size
    assert(locationOfMax(testArray, -1) == -1); //negative array size
    assert(locationOfMax(testArray, 3) == 1); //proper return value
    string folks[5] = { "moana", "elsa", "ariel", "raya", "mulan" };
    int m = circleLeft(folks, 5, 1);
    assert(m == 1); //proper return value
    assert(folks[4] == "elsa"); //test for change in array order
    assert(folks[1] == "ariel"); //test for change in array order
    string folks2[5] = { "moana", "elsa", "ariel", "raya", "mulan" };
    int n = circleLeft(folks2, 3, 0); //test 0 as position
    assert(n == 0); //proper return value
    assert(folks2[2] == "moana"); //proper array order 
    assert(folks2[0] == "elsa"); //proper array order
    assert(folks2[1] == "ariel"); //proper array order
    assert(circleLeft(folks2, -5, 0) == -1); //negative array size
    assert(circleLeft(folks2, 3, 5) == -1); //position greater than array size
    assert(circleLeft(folks2, 0, 0) == -1); //test 0 as array size
    assert(circleLeft(folks2, 4, -2) == -1); //negative position
    n = circleLeft(folks2, 1, 0);
    assert(folks2[0] == "elsa"); //test 1 as array size
    string d[9] = {
    "belle", "merida", "raya", "raya", "tiana", "tiana", "tiana", "raya", "raya" };
    assert(enumerateRuns(d, 9) == 5); //proper return value
    assert(enumerateRuns(d, 0) == -1); //no elements in array
    assert(enumerateRuns(d, 1) == 1); //test 1 as array size
    assert(enumerateRuns(d, -1) == -1); //negative array size
    assert(enumerateRuns(d, -2) == -1); //negative array size
    assert(enumerateRuns(d, 3) == 3); //proper return value
    assert(enumerateRuns(d, 4) == 3); //proper return value
    string roles[6] = { "merida", "raya", "", "belle", "moana", "elsa" };
    int q = flip(roles, 4);
    assert(q == 4); //proper return value
    assert(roles[0] == "belle"); //proper array order
    assert(roles[3] == "merida"); //proper array order
    assert(roles[4] == "moana"); //proper array order
    assert(roles[5] == "elsa"); //proper array order
    string roles1[6] = { "merida", "raya", "", "belle", "moana", "elsa" };
    string group[5] = { "merida", "raya", "elsa", "", "belle" };
    assert(locateDifference(roles1, 6, group, 5) == 2); //proper return value
    assert(locateDifference(roles1, 2, group, 1) == 1); //proper return value
    assert(locateDifference(roles1, 0, group, 4) == -1); //test 0 as array size
    assert(locateDifference(group, 3, roles1, 2) == 2); //proper return value
    assert(locateDifference(group, -3, roles1, 3) == -1); //negative array size
    string names[10] = { "moana", "mulan", "raya", "tiana", "merida" };
    string names1[10] = { "mulan", "raya", "tiana" };
    assert(subsequence(names, 5, names1, 3) == 1); //proper return value
    string names2[10] = { "moana", "tiana" };
    assert(subsequence(names, 4, names2, 2) == -1); //proper return value
    assert(subsequence(names, 0, names2, 1) == -1); //n2 greater than n1
    assert(subsequence(names1, 3, names2, 0) == 0); //subsequence of size 0;
    string locateAnyNames[10] = { "moana", "mulan", "raya", "tiana", "merida" };
    string set1[10] = { "elsa", "merida", "tiana", "mulan" };
    assert(locateAny(locateAnyNames, 6, set1, 4) == 1); //proper return value
    string set2[10] = { "belle", "ariel" };
    assert(locateAny(locateAnyNames, 4, set2, 2) == -1); //fail to find equal element
    assert(locateAny(locateAnyNames, 6, set2, 0) == -1); //0 as n2 array size
    assert(locateAny(locateAnyNames, 0, set2, 2) == -1); //0 as n1 array size
    assert(locateAny(locateAnyNames, -1, set1, 4) == -1); //negative n1 array size
    assert(locateAny(locateAnyNames, 6, set1, -2) == -1); //negative n2 array size
    string cast[6] = { "elsa", "ariel", "mulan", "belle", "tiana", "moana" };
    assert(separate(cast, 6, "merida") == 3); //proper return value
    string cast2[4] = { "raya", "mulan", "ariel", "tiana" };
    assert(separate(cast2, 4, "raya") == 2); //proper return value
    assert(separate(cast2, 0, "raya") == 0); //0 as array size
    assert(separate(cast2, 4, "zzzzz") == 4); //no elements < separator
    assert(separate(cast2, 4, "aaa") == 0); //all elements < separator
    */
}