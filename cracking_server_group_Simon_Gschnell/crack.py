n = 171371

m = 415

while m > 0:
    print(n % m)
    if(n % m == 0):
        print(n, m, "aha")
        break
    m-=2    