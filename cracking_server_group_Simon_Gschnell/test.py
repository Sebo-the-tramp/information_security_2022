# Cracking RSA public key

## Idea:

""" 
Since the public key has to be public and easily accessible by everyone we assume that we have it.

Therefore we start with the following informations:

e = 5
n = 171371


The idea is to exploit the fact that the public key is very small and therefore it is quite easy to compute p and q.

We remind that:

n = p * q

"""

## Start

"""

Since we have n, we could try to compute p and q.

We know that when n mod p == 0 we got one of the two factors

With a simple brute force approach we get:

171371 mod 409 == 0

Therefore q = 171371 / 409, that is 419

Now we have n, p and q

But we need to get d in order to get the private key.

"""

## Private key

"""

We now have the opportunity to compute phy

phi = (p-1) * (q -1)

phi then will be the key in computing d as following:

de = 1 + x * phi()   ** for some arbitrary x

So phi = 408 * 418 = 170544

d = (1 + 170544)/5 = 34109

This is the private key, that is saved in my file. That is actually easy now to revert the message.

"""


## Reverting the message

"""

Now that the private key has been exploited, it is easy to revert the message. The only thing would be that we do not have any message to encrypt. But usually the 
difficult part is to decrypt the key and not to intercept any message.
We can now try to decrypt a message from the database as if we were able to intercept it.

Message encrypted:

15445,88442,100347,15445,15445

decrypted message = c^d mod n

First word:
15445^34109 mod 171371 = 116

Second word:
88442^34109 mod 171371 = 101

Third word:
100347^34109 mod 171371 = 115


116,101,115,116,116

And when we trasform this from the ascii table we get

testt

"""