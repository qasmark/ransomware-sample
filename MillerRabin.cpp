#include <gmpxx.h>
#include <chrono>
#include <iostream>
#include <random>

mpz_class mod_pow(mpz_class base, mpz_class exp, mpz_class mod) 
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

bool is_prime(const mpz_class &n, int iterations) 
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
        mpz_class x = mod_pow(a, d, n);

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

int main(int argc, char* argv[]) 
{
    if (argc < 2) 
    {
        std::cerr << "Usage: " << argv[0] << " <number> [iterations]\n";
        return 1;
    }

    mpz_class number(argv[1]);
    int iterations = (argc > 2) ? std::stoi(argv[2]) : 20;

    auto start = std::chrono::high_resolution_clock::now();
    bool prime = is_prime(number, iterations);
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> duration = end - start;
    std::cout << "Number " << number << (prime ? " is " : " is not ") << "prime.\n";
    std::cout << "Execution time: " << duration.count() << " seconds\n";

    return 0;
}

