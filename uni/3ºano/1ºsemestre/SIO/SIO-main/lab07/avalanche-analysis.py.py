import hashlib
import random
import sys

def calculate_hash(message):
    return hashlib.sha256(message).hexdigest()

def hamming_distance(hash1, hash2):
    # XOR the hashes and count the number of set bits
    xor_result = int(hash1, 16) ^ int(hash2, 16)
    return bin(xor_result).count('1')

def generate_altered_message(original_message, num_bits):
    altered_message = bytearray(original_message)
    
    for _ in range(num_bits):
        # Choose a random position to alter
        position = random.randint(0, len(original_message) * 8 - 1)
        
        # XOR with 1 to flip the chosen bit
        altered_message[position // 8] ^= 1 << (position % 8)
    
    return bytes(altered_message)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 avalanche-analysis.py <message_size> <num_messages>")
        sys.exit(1)

    message_size = int(sys.argv[1])
    num_messages = int(sys.argv[2])

    # Generate the original message
    original_message = bytearray(random.getrandbits(8) for _ in range(message_size))

    # Calculate the hash of the original message
    original_hash = calculate_hash(original_message)

    # Initialize a dictionary to store the count of each Hamming distance
    hamming_distance_counts = {}

    # Calculate hash and Hamming distance for each altered message
    for num_bits in range(1, 9):
        for _ in range(num_messages):
            altered_message = generate_altered_message(original_message, num_bits)
            altered_hash = calculate_hash(altered_message)
            distance = hamming_distance(original_hash, altered_hash)

            # Update the count of each Hamming distance
            hamming_distance_counts[distance] = hamming_distance_counts.get(distance, 0) + 1

    # Print the distribution of Hamming distances
    print("Hamming Distance\tCount")
    for distance, count in sorted(hamming_distance_counts.items()):
        print(f"{distance}\t\t\t{count}")

if __name__ == "__main__":
    main()
