"""
- NOTE: REPLACE 'N' Below with your section, year, and lab number
- CS2911 - 011
- Fall 2022
- Lab 8 - Week 9
- Names:
  - Hudson Arney
  - Josh Sopa

16-bit RSA

Introduction: (Describe the lab in your own words):
In this lab we seek to create both public and private key values,encrypt and decrypt message using these key values,
and to get the private key from a given public key.





Question 1: RSA Security
In this lab, Trudy is able to find the private key from the public key. Why is this not a problem for RSA in practice?
Because if given the public key, the values "e" and "n" are already known. With these values d can be calculated by
getting the factors that make up "e" which can be thought of as "p" and "q". With "p" and "q", "z" can be found
which can finally be used to calculate "d". With "d" getting the private key is easy. In real life RSA however this
takes a larger amount of time than the message is worth trying to decrypt, so it isn't something to worry about.

Question 2: Critical Step(s)
When creating a key, Bob follows certain steps.
Trudy follows other steps to break a key.
What is the difference between Bob’s steps and Trudy’s so that Bob is able to run his steps on large numbers,
but Trudy cannot run her steps on large numbers?

Bob gets the p and q values by randomly choosing and checking if they are prime.
Trudy has to go through every possible factor of e and then check if every one of those factors is prime.


Checksum Activity:
Provide a discussion of your experiences as described in the activity.  Be sure to answer all questions.

Using the same numbers but rearranged resulted in the same hashcode, which is how we are able to send Alice a
larger amount than what was actually due.
The way to have trudy not be able to do this trick would be to encrypt the message with bobs private key assuming
Alice has bob's public key, then only bob could have send the message since only he has his private key.


Summary: (Summarize your experience with the lab, what you learned, what you liked, what you disliked,
 and any suggestions you have for improvement):
We learned how to create a key with the given values learned through lectures. Getting these values wasn't difficult at
first but the problems easily started to pile. The majority of the problems came from the apply_key(key, m) method which
I didn't realize at first is the same for both private and public keys. I was trying to distinguish the two and then do
separate operations with the given information, which wasn't working. I disliked the debugging process because of this
because there was a lot of wasted time even though the code was almost always working. We suggest that the lab have
slightly more instructions of what to do with certain variables because there was a lot of logic that needed to be done
to understand what was happening. We were able to eventually figure out how everything went together so this was a minor
problem that just took some extra time to look at.





"""

import random

# Use these named constants as you write your code
# To increase the key size add more 1's and 0's to these values
#   E.g. MAX_PRIME = 0b1111111111111111 <- 16 bits
#        MIN_PRIME = 0b1100000000000001 <- 16 bits

MAX_PRIME = 0b11111111  # The maximum value a prime number can have
MIN_PRIME = 0b11000001  # The minimum value a prime number can have 
PUBLIC_EXPONENT = 17  # The default public exponent


# mod = 51067
# private = 35629
# ---------------------------------------
# Do not modify code below this line
# ---------------------------------------

def main():
    """ Provide the user with a variety of encryption-related actions """

    # Get chosen operation from the user.
    action = input("Select an option from the menu below:\n"
                   "(1-CK) create_keys\n"
                   "(2-CC) compute_checksum\n"
                   "(3-VC) verify_checksum\n"
                   "(4-EM) encrypt_message\n"
                   "(5-DM) decrypt_message\n"
                   "(6-BK) break_key\n "
                   "Please enter the option you want:\n")
    # Execute the chosen operation.
    if action in ['1', 'CK', 'ck', 'create_keys']:
        create_keys_interactive()
    elif action in ['2', 'CC', 'cc', 'compute_checksum']:
        compute_checksum_interactive()
    elif action in ['3', 'VC', 'vc', 'verify_checksum']:
        verify_checksum_interactive()
    elif action in ['4', 'EM', 'em', 'encrypt_message']:
        encrypt_message_interactive()
    elif action in ['5', 'DM', 'dm', 'decrypt_message']:
        decrypt_message_interactive()
    elif action in ['6', 'BK', 'bk', 'break_key']:
        break_key_interactive()
    else:
        print("Unknown action: '{0}'".format(action))


def create_keys_interactive():
    """
    Create new public keys
    :return: the private key (d, n) for use by other interactive methods
    """

    key_pair = create_keys()
    public_key = get_public_key(key_pair)
    private_key = get_private_key(key_pair)
    print("Public key: ")
    print(public_key)
    print("Private key: ")
    print(private_key)
    return private_key


def get_public_key(key_pair):
    """
    Pulls the public key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (e,n)
    """

    return key_pair[0], key_pair[2]


def get_private_key(key_pair):
    """
    Pulls the private key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (d,n)
    """

    return key_pair[1], key_pair[2]


def compute_checksum_interactive():
    """
    Compute the checksum for a message, and encrypt it
    """

    private_key = create_keys_interactive()

    message = input('Please enter the message to be checksummed: ')

    hash_code = compute_checksum(message)
    print('Hash:', format_as_hex(hash_code))
    cipher = apply_key(private_key, hash_code)
    print('Encrypted Hash:', format_as_hex(cipher))


def verify_checksum_interactive():
    """
    Verify a message with its checksum, interactively
    """

    public_key = enter_public_key_interactive()
    message = input('Please enter the message to be verified: ')
    recomputed_hash = compute_checksum(message)

    string_hash = input('Please enter the encrypted hash (in hexadecimal): ')
    encrypted_hash = int(string_hash, 16)
    decrypted_hash = apply_key(public_key, encrypted_hash)
    print('Recomputed hash:', format_as_hex(recomputed_hash))
    print('Decrypted hash: ', format_as_hex(decrypted_hash))
    if recomputed_hash == decrypted_hash:
        print('Hashes match -- message is verified')
    else:
        print('Hashes do not match -- has tampering occurred?')


def encrypt_message_interactive():
    """
    Encrypt a message
    """

    message = input('Please enter the message to be encrypted: ')
    public_key = enter_public_key_interactive()
    encrypted = ''
    for c in message:
        encrypted += format_as_hex(apply_key(public_key, ord(c)))
    print("Encrypted message:", encrypted)


def decrypt_message_interactive(private_key=None):
    """
    Decrypt a message
    """

    encrypted = input('Please enter the message to be decrypted: ')
    if private_key is None:
        private_key = enter_key_interactive('private')
    message = ''
    hex_length = get_hex_digits()
    for i in range(0, len(encrypted), hex_length):
        enc_string = encrypted[i:i + hex_length]
        enc = int(enc_string, 16)
        dec = apply_key(private_key, enc)
        if dec >= 0 and dec < 256:
            message += chr(dec)
        else:
            print('Warning: Could not decode encrypted entity: ' + enc_string)
            print('         decrypted as: ' + str(dec) + ' which is out of range.')
            print('         inserting _ at position of this character')
            message += '_'
    print("Decrypted message:", message)


def break_key_interactive():
    """
    Break key, interactively
    """

    public_key = enter_public_key_interactive()
    private_key = break_key(public_key)
    print("Private key:")
    print(private_key)
    decrypt_message_interactive(private_key)


def enter_public_key_interactive():
    """
    Prompt user to enter the public modulus.

    :return: the tuple (e,n)
    """

    print('(Using public exponent = ' + str(PUBLIC_EXPONENT) + ')')
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return PUBLIC_EXPONENT, modulus


def enter_key_interactive(key_type):
    """
    Prompt user to enter the exponent and modulus of a key

    :param key_type: either the string 'public' or 'private' -- used to prompt the user on how
                     this key is interpreted by the program.
    :return: the tuple (e,n)
    """
    string_exponent = input('Please enter the ' + key_type + ' exponent (decimal): ')
    exponent = int(string_exponent)
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return exponent, modulus


def compute_checksum(string):
    """
    Compute simple hash

    Given a string, compute a simple hash as the sum of characters
    in the string.

    (If the sum goes over sixteen bits, the numbers should "wrap around"
    back into a sixteen bit number.  e.g. 0x3E6A7 should "wrap around" to
    0xE6A7)

    This checksum is similar to the internet checksum used in UDP and TCP
    packets, but it is a two's complement sum rather than a one's
    complement sum.

    :param str string: The string to hash
    :return: the checksum as an integer
    """

    total = 0
    for c in string:
        total += ord(c)
    total %= 0x8000  # Guarantees checksum is only 4 hex digits
    # How many bytes is that?
    #
    # Also guarantees that that the checksum will
    # always be less than the modulus.
    return total


def get_hex_digits():
    """
    Determines the number of bits needed to represent n
      then returns this in hexadecimal digit count
    """
    # 4 bits per nibble (hex digit)
    bits_per_nibble = 4

    # Number of bits to represent n is 2 * the max prime
    bit_length = MAX_PRIME.bit_length() * 2

    # Length of n in hexadecimal digits
    return (bit_length + (bits_per_nibble - 1)) // bits_per_nibble


def format_as_hex(value):
    """
    Convert integer to a zero-padded hex string with the required number
    of characters to represent n, d, or and encrypted message.

    :param int value: to format
    :return: The formatted string
    """
    return "{:0{digits}x}".format(value, digits=str(get_hex_digits()))


# ---------------------------------------
# Do not modify code above this line
# ---------------------------------------


# ---------------------------------------
# Modify the functions below to create
#   apply, and break the RSA keys
# ---------------------------------------

#44197
#41201
def create_keys():
    """
    Create the public and private keys.
    :return: the keys as a three-tuple: (e,d,n)
    """

    p = random.randint(int(MIN_PRIME), int(MAX_PRIME))
    q = random.randint(int(MIN_PRIME), int(MAX_PRIME))
    while not get_prime(p):
        p = random.randint(int(MIN_PRIME), int(MAX_PRIME))
    while not get_prime(q):
        q = random.randint(int(MIN_PRIME), int(MAX_PRIME))

    if p != q:
        n = p * q
        z = (p - 1) * (q - 1)
        e = PUBLIC_EXPONENT
        #e = random.randint(1, z)
        #while not (get_prime(e) & (z % e != 0)):
        #    e = random.randint(1, z)
        d = generate_d(e, z)

        return e, d, n
    else:
        create_keys()


def generate_d(e, z):
    """
    Generates a d value to solve e*d (mod z) = 1
    :param e: e value of key
    :param z: z value of key
    :return: the d to solve the problem
    """

    d = 0
    r = z
    newt = 1
    newr = e
    while newr != 0:
        quotient = r // newr
        (d, newt) = (newt, d - quotient * newt)
        (r, newr) = (newr, r - quotient * newr)
    if r > 1:
        return -1
    if d < 0:
        d = d + z
    return d


def apply_key(key, m):
    """
    Apply the key, given as a tuple (e,n) or (d,n) to the message.

    This can be used both for encryption and decryption.

    :param tuple key: (e,n) or (d,n)
    :param int m: the message as a number 1 < m < n (roughly)
    :return: the message with the key applied. For example,
             if given the public key and a message, encrypts the message
             and returns the ciphertext.
    """

    if key[0] == PUBLIC_EXPONENT:
        # public key
        return public_key_encrypt(key, m)
    else:
        # private key
        return private_key_decrypt(key, m)


def public_key_encrypt(key, m):
    """
    helper method used if given a public key in the apply_key(key, m)
    :param key: the public key tuple - (e, n)
    :param m: the inputted message that is desired to be encrypted
    :return: the encrypted message
    """
    e = key[0]
    n = key[1]
    return (m ** e) % n


def private_key_decrypt(key, m):
    """
    helper method to be used when given a private key in apply_key(key, m)
    :param key: the private key tuple - (d,n)
    :param m: the given encrypted message
    :return: the deciphered message
    """
    c = m
    d = key[0]
    n = key[1]

    return (c ** d) % n


def break_key(pub):
    """
    Break a key.  Given the public key, find the private key.
    Factorizes the modulus n to find the prime numbers p and q.

    You can follow the steps in the "optional" part of the in-class
    exercise.

    :param pub: a tuple containing the public key (e,n)
    :return: a tuple containing the private key (d,n)
    """

    e = pub[0]
    factors_list = []
    # Get all factors of n
    factors_list = get_factors(pub[1])

    # Get all prime factors of n
    primes = []
    for x in range(1, len(factors_list)):
        if get_prime(factors_list[x]):
            primes.append(factors_list[x])

    p = primes[0]
    q = primes[1]
    z = (p - 1) * (q - 1)
    d = generate_d(e, z)

    return d, pub[1]


def get_factors(number):
    factor_list = []
    for x in range(1, number + 1):
        if number % x == 0:
            factor_list.append(x)

    return factor_list


def get_prime(number):
    for x in range(2, number):
        if number % x == 0:
            return False

    return True


# Add additional functions here, if needed.


main()
