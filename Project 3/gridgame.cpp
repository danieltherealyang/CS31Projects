#include "grid.h"
#include <iostream>
#include <string>
#include <cctype>
#include <cassert>
using namespace std;

bool hasCorrectForm(string plan)
{
    int digitCount = 0; //digit counter
    //loop through every character in plan
    for (int i = 0; i < plan.size(); i++) {
        //false if more than 2 digits
        if (digitCount > 2)
            return false;
        //increment digit counter
        if (isdigit(plan.at(i))) {
            digitCount++;
            continue;
        }
        //false if character not r or l (case insensitive)
        if (!(toupper(plan.at(i)) == 'R' || toupper(plan.at(i)) == 'L'))
            return false;
        else
            digitCount = 0; //reset digit counter
    }

    //false if last character is digit
    if (digitCount > 0)
        return false;
    return true;
}

//function sets row and column increments based on direction
void setIncrements(char dir, int& rowIncrement, int& colIncrement) {
    switch(toupper(dir)) {
        case 'N':
            rowIncrement = -1;
            colIncrement = 0;
            break;
        case 'E':
            rowIncrement = 0;
            colIncrement = 1;
            break;
        case 'W':
            rowIncrement = 0;
            colIncrement = -1;
            break;
        case 'S':
            rowIncrement = 1;
            colIncrement = 0;
            break;
        default:
            cerr << "Error: dir parameter received unexpected input";
    }
}

//function changes direction based on turn character
void changeDirection(char& dir, char turn) {
    switch (toupper(dir)) {
        case 'N':
            if (toupper(turn) == 'L')
                dir = 'W';
            if (toupper(turn) == 'R')
                dir = 'E';
            break;
        case 'E':
            if (toupper(turn) == 'L')
                dir = 'N';
            if (toupper(turn) == 'R')
                dir = 'S';
            break;
        case 'S':
            if (toupper(turn) == 'L')
                dir = 'E';
            if (toupper(turn) == 'R')
                dir = 'W';
            break;
        case 'W':
            if (toupper(turn) == 'L')
                dir = 'S';
            if (toupper(turn) == 'R')
                dir = 'N';
            break;
        default:
            cerr << "Error: dir parameter received unexpected input";
    }
}

int determineSafeDistance(int r, int c, char dir, int maxSteps)
{
    //assign max row and col number
    int rows = getRows();
    int columns = getCols();
    //total step counter
    int safeSteps = 0;
    //increments to control movement direction
    int rowIncrement;
    int colIncrement;
    dir = toupper(dir);

    //check if coordinate is valid
    if (r < 1 || c < 1 || r > rows || c > columns || isWall(r, c))
        return -1;
    //check if dir is valid
    if (!(dir == 'N' || dir == 'E' || dir == 'S' || dir == 'W'))
        return -1;
    //check if maxSteps is negative
    if (maxSteps < 0)
        return -1;
    setIncrements(dir, rowIncrement, colIncrement);

    //loop while step counter less than max steps and coordinates are in bounds
    while (safeSteps <= maxSteps && r > 0 && r <= rows && c > 0 && c <= columns) {
        if (isWall(r, c))
            break;
        r += rowIncrement;
        c += colIncrement;
        safeSteps++;
    }

    //subtract 1 for final iteration failure
    safeSteps--;
    return safeSteps;
}

int obeyPlan(int sr, int sc, int er, int ec, char dir, string plan, int& nsteps)
{
    //sr,sc is starting position
    int rows = getRows(); //get max row number
    int cols = getCols(); // get max col number
    int rowIncrement; //set increment value for row
    int colIncrement; //set increment value for col
    int stepCount = 0; //counter of possible steps in plan

    //check if start and end coords are in bounds
    if (sr < 1 || sc < 1 || sr > rows || sc > cols || er < 1 || ec < 1 || er > rows || ec > cols)
        return 2;
    //check if start and end coords are walls
    if (isWall(sr, sc) || isWall(er, ec))
        return 2;
    //check if dir parameter is valid
    if (!(toupper(dir) == 'N' || toupper(dir) == 'E' || toupper(dir) == 'S' || toupper(dir) == 'W'))
        return 2;
    //check if plan string is valid
    if (!(hasCorrectForm(plan)))
        return 2;
    //set row and col increments based on dir parameter
    setIncrements(dir,rowIncrement,colIncrement);
    int i = 0; //plan array index
    int dirSteps = 0; //step counter for each plan portion

    //run loop while sr and sc are in bounds and i is less than plan length
    while (sr > 0 && sr <= rows && sc > 0 && sc <= cols && i < plan.size()) {
        if (isdigit(plan.at(i))) {
            //append new digit to dirSteps
            dirSteps = dirSteps * 10 + plan.at(i) - '0';
            i++; //increment array index
            continue; //move to next iteration
        }

        //if dirSteps is not 0, then move in current direction
        if (dirSteps != 0) {
            setIncrements(dir, rowIncrement, colIncrement); //set row and col increments based on dir
            int safeSteps = determineSafeDistance(sr, sc, dir, dirSteps);

            //if safeSteps is equal to steps in current plan portion, add to row and col coordinates
            if (safeSteps == dirSteps) {
                sr += dirSteps * rowIncrement;
                sc += dirSteps * colIncrement;
                stepCount += safeSteps;
            //if not, add max safe steps for this plan portion to total count and return 3
            } else {
                stepCount += safeSteps;
                nsteps = stepCount;
                return 3;
            }

            changeDirection(dir, plan.at(i));
            dirSteps = 0;
            i++;
        } else {
            //only change direction if movement is unnecessary
            changeDirection(dir,plan.at(i));
            i++;
        }
    }

    //plan obeyed, set nsteps to stepCount and return appropriate values
    nsteps = stepCount;
    if (sr == er && sc == ec) {
        return 0;
    } else {
        return 1;
    }
}

void makemaze()
{
//   12345678901234
// 1 ..............
// 2 ......*.......
// 3 ..............
// 4 ..*...........
// 5 ......*.......

        setSize(5,14);
        setWall(4,3);
        setWall(2,7);
        setWall(5,7);
}

int main()
{
}