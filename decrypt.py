import sys


block_size = 3
modulo = 252526
multiplier = 0
offset = 0
encrypted_file_name = "ciphertext.txt"
output_file_name = "finalplaintextoutput.txt"


# Check for multiplier relatively prime to modulo value
def is_modulo_multiplier_are_coprimes(this_modulo, this_multiplier):
    """
        checking if multiplier and modulo are co-primes
        :param this_modulo: modulo value
        :param this_multiplier: multiplier value
        :return: True if co-primes else False
    """
    # modulo is the gcd
    while this_multiplier:
        # gcd
        this_modulo, this_multiplier = this_multiplier, this_modulo % this_multiplier
    return this_modulo == 1


def set_modulo_val(this_block_size):
    """
        setting the global modulo value
        :param this_block_size: the block size used for encryption
        :return: None
    """
    # block size should be integer and greater than zero
    if (block_size < 1) or (not isinstance(this_block_size, int)):
        # print error if invalid block size
        print("Error: Invalid block size {}".format(this_block_size))
    global modulo
    # get modulo
    modulo = int("25" * int(this_block_size)) + 1


# Inputs multiplier and offset from keyboard
def get_input_multiplier_from_keyboard():
    """
        get the multiplier and offset values from user and continue if the multiplier and modulo are co-primes else exit.
        :return: None
    """
    global multiplier, offset
    # get multiplier
    multiplier = int(input("Input multiplier for Block Affine cipher: "))
    # check if multiplier and modulo are co-primes
    while not is_modulo_multiplier_are_coprimes(modulo, multiplier):
        print("Multiplier is NOT relatively prime to the modulo {}\n".format(modulo))
        sys.exit(1)
    # get offset
    offset = int(input("Input offset for Block Affine cipher: "))


# Get multiplier inverse modulo
def get_multiplier_inverse_mod(this_multiplier, this_modulo):
    """
    get multiplier inverse modulo
    :param this_multiplier: multiplier value
    :param this_modulo: modulo value
    :return: inverse modulo
    """
    # get the modulo of multiplier
    this_multiplier = this_multiplier % this_modulo

    for i in range(1, this_modulo):
        if((this_multiplier * i) % this_modulo) == 1:
            return i
    return 1


# decrypt text
def decrypt_text():
    """
    decrypt text and write to file
    :return: None
    """
    init_output_file()
    # Read the encrypted file
    with open(encrypted_file_name, 'r') as f:
        # read lines to file_content_as_lines
        file_content_as_lines = f.readlines()
    # get mod inverse
    mod_inverse = get_multiplier_inverse_mod(multiplier, modulo)
    # get total number of lines
    total_num_of_lines = len(file_content_as_lines)
    append_new_line_char = True
    for line_num, each_line in enumerate(file_content_as_lines):
        # remove the new line character and get words in the line
        line_content_as_word_list = each_line.strip('\n').split(' ')
        # for each word whose length must be a multiple of block size form blocks for decrypting
        decrypted_word_list = []
        for each_word in line_content_as_word_list:
            # get decrypted words and add to words list
            decrypted_word_list.append(get_decrypted_word(each_word, "", multiplier, offset, modulo, block_size, mod_inverse))
        if line_num + 1 == total_num_of_lines:
            # no adding of new line if last line
            append_new_line_char = False
        write_decrypted_file(decrypted_word_list, append_new_line_char)


def get_decrypted_word(this_word, decrypted_word, this_multiplier, this_offset, this_modulo, this_block_size, mod_inverse):
    """
    get decrypted word
    :param this_word: word to decrypt
    :param decrypted_word: decrypted word
    :param this_multiplier: multiplier value
    :param this_offset: offset value
    :param this_modulo: modulo value
    :param this_block_size: block size
    :param mod_inverse: mod inverse value
    :return: decrypted word
    """
    if len(this_word) == 0:
        # base case
        return decrypted_word
    else:
        if len(this_word) < this_block_size:
            # print error if size of word is less than block size; this should not happen
            print("Error: Invalid padding done for {} with block size {}".format(this_word, this_block_size))
        # checking if the length of the word is a multiple of block size
        decrypted_word += decrypt_this_block(this_word[0:this_block_size], this_offset, this_modulo, this_block_size, mod_inverse)
        # call recursive
        return get_decrypted_word(this_word[this_block_size:], decrypted_word, this_multiplier, this_offset, this_modulo, this_block_size, mod_inverse)


def decrypt_this_block(block_to_decrypt, this_offset, this_modulo, this_block_size, mod_inverse):
    """
    decrypt the block
    :param block_to_decrypt: block of characters to decrypt
    :param this_offset: offset value
    :param this_modulo: modulo value
    :param this_block_size: block size
    :param mod_inverse: mod inverse value
    :return: decrypted string
    """
    if len(block_to_decrypt) != this_block_size:
        # throw an error message if the length of decrypted block is not same as block size
        print('Error: Invalid Length of block of chars. Expected = {}, Actual = {}'.format(this_block_size, len(block_to_decrypt)))
    # get the numeric representation of the block
    this_block_num_rep = [get_numeric_repr_of_this_char_with_this_size(m) for m in block_to_decrypt]
    # get block value from the numeric representation
    this_block_val = int("".join(this_block_num_rep))
    # get decrypted value
    this_block_decrypt_val = ((this_block_val - this_offset) * mod_inverse) % this_modulo
    # return decrypted block as string
    return get_decrypted_str(str(this_block_decrypt_val), "", this_block_size, 2)


def get_numeric_repr_of_this_char_with_this_size(this_char, this_size=2):
    """
        get numeric representation
        :param this_char: each character
        :param this_size: size of numeric representation, default 2
        :return: numeric representation
    """
    # get the ascii value with offset A such as A=00, B=01 .... Z=25
    this_num = ord(this_char) - ord('A')
    if len(str(this_num)) > this_size:
        # this error should not happen, check size representation
        print('Error: the num value {} is bigger thatn the string representation size {}'.format(this_num, this_size))
        return ""
    else:
        # len(str(this_num)) <= this_size:
        return "0" * (this_size - len(str(this_num))) + str(this_num)


def get_decrypted_str(block_decrypt_val_as_str, block_decrypted_str, this_block_size, this_num_rep_size=2):
    if len(block_decrypted_str) == this_block_size:
        # base case
        return block_decrypted_str
    elif (block_decrypt_val_as_str is "" ) or (int(block_decrypt_val_as_str) == 0):
        block_decrypted_str = "A" * (this_block_size - len(block_decrypted_str)) + block_decrypted_str
        # call recursive
        return get_decrypted_str(block_decrypt_val_as_str, block_decrypted_str, this_block_size, this_num_rep_size)
    elif len(block_decrypt_val_as_str) <= this_num_rep_size:
        block_decrypted_str = chr(int(block_decrypt_val_as_str) + ord("A")) + block_decrypted_str
        # call recursive
        return get_decrypted_str("", block_decrypted_str, this_block_size, this_num_rep_size)
    else:
        # len(block_decrypt_val_as_str) > this_num_rep_size
        block_decrypted_str = chr(int(block_decrypt_val_as_str[-this_num_rep_size:]) + ord("A")) + block_decrypted_str
        # call recursive
        return get_decrypted_str(block_decrypt_val_as_str[:-this_num_rep_size], block_decrypted_str, this_block_size, this_num_rep_size)


# write decrypted text into finalplaintextoutput.txt
def write_decrypted_file(decrypted_word_list, append_new_line=True):
    """
    add decrypted text/line to file
    :param decrypted_word_list: decrypted words in a line
    :param append_new_line: True to add new line character else False
    :return: None
    """
    with open(output_file_name, 'a+') as f:
        f.write(" ".join(decrypted_word_list) + ('\n' if append_new_line else ''))


def init_output_file():
    """
        initialize or create an empty output file
        :return: None
    """
    with open(output_file_name, 'w+') as f:
        f.write('')        


if __name__ == '__main__':
    # set the modulo value
    set_modulo_val(block_size)
    # get multiplier and offset from user
    get_input_multiplier_from_keyboard()
    # check for non alpha and non upper characters and write to content_to_encrypt
    decrypt_text()
