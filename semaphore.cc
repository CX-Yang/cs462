#include <iostream>      
#include <thread>        
#include <mutex>         
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <stdio.h> 
#include <stdlib.h> 
#include<time.h> 
 
std::mutex mtx;             //mutex for critical section
std::condition_variable cv; //condition variable for critical section  
static double balance; 		//variable that will be mutated

using namespace std;
using namespace std::chrono; //for timer

//Threads are printing out ok. I think that the reason why all the time stamps
//are printing out at different intervals may have to do with the .join at the
//end of main(); Otherwise it is the timer method because it's weird right now.

//random number generator from 0 to 1
double f() {
    double A = 48271;
    double M = 2147483647;
	
	double num = rand()/M;
	return num;
}

//critical access point
void account(int id, int transactions){
	//initalize random number generator seed
	srand(time(0));
	
	//loop through number of transactions
	while (transactions > 0 ){
		//delay threads so they all execute once before looping again
		std::this_thread::sleep_for (std::chrono::milliseconds(30));
		
		//lock the semaphore
		std::unique_lock<std::mutex> lck(mtx);
		
		//amount of money to be withdrawn or deposited
		int actionAmount = rand() % 300 + 1;
		//random number between 0 to 1
		double num = f();
		
		cout<<"ThreadId: "<< id << " - Balance = $" << balance << " || ";
		
		//check for withdraw or deposit
		if(num > 0.5){
			//withdraw
			if((balance - actionAmount) > 0){
				//ok to withdraw
				balance -= actionAmount;
				std::cout << "Withdraw $" << actionAmount << " | Balance = $" << balance <<endl;
			}else{
				std::cout << "Withdraw $" << actionAmount << " (NSF) | Balance = $" << balance <<endl;
			}
		}else{
			//deposited
			balance += actionAmount;
			std::cout << "Deposit $" << actionAmount << " | Balance = $" << balance << endl;
		}
		transactions--;
		
		//get current time
		auto t0 = std::chrono::high_resolution_clock::now();        
		auto timestamp = t0.time_since_epoch();
		std::cout << " | Timestamp: " << timestamp.count() << endl;	
		
		//exit the semaphore
		lck.unlock();
		//notify threads if it's their turn
		cv.notify_all();
		
	}//end while
}

 
int main (){
	
	int numThreads;
	do{
	cout << "Enter the number of threads: ";
	cin >> numThreads;
	cin.ignore();
	}while(numThreads < 0 || numThreads > 27);
	
	int transactions = 0;
	do{
		cout << "Enter the number of transactions per thread: ";
		cin >> transactions;
		cin.ignore();
	}while (transactions < 0 || transactions > 136);
	
	cout << "Enter the inital balance: ";
	cin >> balance;
	cin.ignore();

	std::thread threads[numThreads];

	// spawn threadnum threads
	for (int id = 0; id < numThreads; id++){
		threads[id] = std::thread(account, id, transactions);
	}

	// merge all threads to the main thread
	for(int id = 0; id < numThreads; id++){
		threads[id].join();
	}
  
	return 0;
}