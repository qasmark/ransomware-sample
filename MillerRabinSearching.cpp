#include <gmpxx.h>
#include <chrono>
#include <iostream>
#include <random>
#include <vector>

mpz_class modPow(mpz_class base, mpz_class exp, mpz_class mod) 
{
    mpz_class result = 1;
    base %= mod;
    while (exp > 0) 
    {
        if (exp % 2 == 1) 
        {
            result = (result * base) % mod;
        }
        exp /= 2;
        base = (base * base) % mod;
    }
    return result;
}


bool isPrime(const mpz_class &n, int iterations) 
{
    if (n <= 1 || n == 4) return false;
    if (n <= 3) return true;

    mpz_class d = n - 1;
    int r = 0;
    while (d % 2 == 0) 
    {
        d /= 2;
        r++;
    }

    gmp_randclass rng(gmp_randinit_default);  
    rng.seed(std::random_device{}());        

    for (int i = 0; i < iterations; i++) 
    {
        mpz_class a = rng.get_z_range(n - 3) + 2;
        mpz_class x = modPow(a, d, n);

        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int j = 0; j < r - 1; j++) 
        {
            x = (x * x) % n;
            if (x == n - 1) 
            {
                composite = false;
                break;
            }
        }

        if (composite) return false;
    }
    return true;
}

std::vector<mpz_class> findPrimesInRange(const mpz_class &A, const mpz_class &B, int iterations) 
{
    std::vector<mpz_class> primes;
    for (mpz_class num = A; num <= B; num++) 
    {
        if (isPrime(num, iterations)) 
        {
            primes.push_back(num);
        }
    }
    return primes;
}

int main(int argc, char* argv[]) 
{
    if (argc < 3) 
    {
        std::cerr << "Usage: " << argv[0] << " <A> <B> [iterations]\n";
        return 1;
    }

    mpz_class A(argv[1]);
    mpz_class B(argv[2]);
    int iterations = (argc > 3) ? std::stoi(argv[3]) : 20;

    if (A > B) 
    {
        std::cerr << "Error: A must be less than or equal to B.\n";
        return 1;
    }

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<mpz_class> primes = findPrimesInRange(A, B, iterations);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    std::cout << "Primes in range [" << A << ", " << B << "]:\n";
    for (const auto &prime : primes) 
    {
        std::cout << prime << "\n";
    }

    std::cout << "Total primes found: " << primes.size() << "\n";
    std::cout << "Execution time: " << duration.count() << " seconds\n";

    return 0;
}
