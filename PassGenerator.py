import random
import string

def PasswordGenerator(length: int = 10):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(alphabet) for i in range(length))
    return password

password = PasswordGenerator()
print(f'Generated Password is: {password}')
