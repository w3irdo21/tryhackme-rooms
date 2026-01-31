'''
Room Script: https://tryhackme.com/room/flip

Medium Article for explanation: https://medium.com/@Sle3pyHead/

'''

# leaked ciphertext from the service
ciphertext = "put-it-here"

# convert hex string to bytearray
ct = bytearray.fromhex(ciphertext)

# ASCII values
original_char = ord('b')   # 0x62
target_char   = ord('a')   # 0x61

# flip the first byte of the previous block
ct[0] = ct[0] ^ original_char ^ target_char

# output modified ciphertext
modified_ciphertext = ct.hex()
print(modified_ciphertext)
