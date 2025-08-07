import random
import string


def generate_password(digit):
    
    """
    Function: generate_password(digit)

    Description:
        Generates a random password consisting of digits and uppercase letters.

    Parameters:
        digit (int): The length of the password to be generated.

    Returns:
        str: A randomly generated password of the specified length.

    Dependencies:
        - string: Python module that provides a collection of string constants
        - random: Python module that provides functions for generating random numbers

    Usage:
        password = generate_password(8)
        # Generates a random password of length 8

    Notes:
        - The generated password may contain digits (0-9) and uppercase letters (A-Z).
        - Ensure that the required modules (string, random) are imported before calling this function.
    """
    
    chars = string.digits + string.ascii_uppercase
    password = ''

    for char in range(1,digit + 1):
        password += chars[random.randint(0,len(chars)-1)]

    return password
