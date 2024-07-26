import hashlib

def find_nonce(student_number):
    nonce = 0
    while True:
        # Concatenate the student number and nonce
        input_data = f"{student_number}{nonce}"
        
        # Calculate the SHA-256 hash
        hash_result = hashlib.sha256(input_data.encode()).hexdigest()

        # Check if the hash starts with three hexadecimal 0's
        if hash_result[:3] == '000':
            return input_data, hash_result
        
        # Increment the nonce for the next iteration
        nonce += 1

# Replace 'your_student_number' with your actual student number
your_student_number = '108317'

sentence, hash_result = find_nonce(your_student_number)
print(f"Sentence: {sentence}")
print(f"SHA-256 Hash: {hash_result}")
