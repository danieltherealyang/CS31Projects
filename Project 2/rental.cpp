#include <iostream>
#include <string>
using namespace std;

int main () 
{
    //Declare variables and take in user input
    int odometerStart;
    cout << "Odometer at start: ";
    cin >> odometerStart;

    int odometerEnd;
    cout << "Odometer at end: ";
    cin >> odometerEnd;

    int rentalDays;
    cout << "Rental days: ";
    cin >> rentalDays;
    cin.ignore(10000, '\n');

    string customerName;
    cout << "Customer name: ";
    getline(cin, customerName);

    char isLuxuryCar;
    cout << "Luxury car? (y/n): ";
    cin >> isLuxuryCar;

    int month;
    cout << "Month (1=Jan, 2=Feb, etc.): ";
    cin >> month;

    cout << "---" << endl;

    if (odometerStart < 0) { //check if starting odometer value is negative
        cout << "The starting odometer reading must not be negative." << endl;
        return 0;
    }

    if (odometerEnd < odometerStart) { //check if ending odometer value is less than start
        cout << "The ending odometer reading must be at least as large as the starting reading." << endl;
        return 0;
    }

    if (rentalDays <=0 ) { //check if rental days is positive
        cout << "The number of rental days must be positive." << endl;
        return 0;
    }

    if (customerName == "") { //check if customer name is empty
        cout << "You must enter a customer name." << endl;
        return 0;
    }

    if (!(isLuxuryCar == 'y' || isLuxuryCar == 'n')) { //check if luxury car is a y or n value
        cout << "You must enter y or n." << endl;
        return 0;
    }

    if (!(1 <= month && month <= 12)) { //check if month is between 1 and 12
        cout << "The month number must be in the range 1 through 12." << endl;
        return 0;
    }

    double amount; //check the value of isLuxuryCar and select the base price
    if (isLuxuryCar == 'y') {
        amount = 71.0 * rentalDays;
    } else {
        amount = 43.0 * rentalDays;
    }

    int miles = odometerEnd - odometerStart;

    if (miles > 100 ) { //calculate the cost of the first 100 miles and add it to the total
        amount = amount + 0.27 * 100;
        miles = miles - 100;
    } else {
        amount = amount + 0.27 * miles;
        miles = 0;
    }

    bool isWinter = (month < 4) || (month == 12); //if month is from 1-3 or 12 then set to true
    double rate;
    if (isWinter) {
        rate = 0.27; //use winter rate for winter months
    } else {
        rate = 0.21;
    }
    
    if (miles > 400) { //calculate the cost for the next 400 miles
        amount = amount + 400 * rate;
        miles = miles - 400;
    } else {
        amount = amount + miles * rate;
        miles = 0;
    }

    rate = 0.17; //calculate the cost of any miles over 500
    amount = amount + miles * rate; 
    cout.setf(ios::fixed);
    cout.precision(2);
    cout << "The rental charge for " << customerName << " is $" << amount << endl;
}
