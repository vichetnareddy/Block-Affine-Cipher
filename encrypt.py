import sys

#Initialising the parameters
block_size = 3
modulo = 252526
multiplier = 0
offset = 0
non_upper_case_non_alpha = ""
input_file_name = "plaintext.txt"
output_file_name = "ciphertext.txt"


# Read the input plaintext.txt
def read_input_file_to_encrypt(file_name):
    """
    Read the input plain text file
    :param file_name: input file
    :return: list of lines of text from the input file
    """
    file_content_as_lines = []
    with open(file_name, 'r') as f:
        file_content_as_lines = f.readlines()
    return file_content_as_lines


def get_all_words_in_this_line(this_line):
    """
    Get all the words from this line
    :param this_line: text content of the line
    :return: list of words in the line
    """
    return this_line.split(' ')


# Throw away non-uppercase characters and give errormessage before proceeding
def error_message_thrown_away_characters(file_content_as_lines):
    """
    display error message if there are any non alpha not upper characters
    ignoring spaces and new line characters
    :return: None
    """
    non_upper_case_non_alpha = ""
    for each_line in file_content_as_lines:
        for each_char in each_line:
            if not (each_char.isalpha() and each_char.isupper()):
                if each_char != " ":
                    non_upper_case_non_alpha += each_char
    if non_upper_case_non_alpha:
        print("Error: Found {} Non upper case or non alpha characters. Discarding them and Proceeding!".format(
            len(non_upper_case_non_alpha)))


# Throw away non-uppercase characters to give errormessage before proceeding
def throw_away_non_uppercase_char(each_word):
    """
    Remove non-uppercase characters from this word
    :param each_word: each word in the line
    :return: words with only upper case characters
    """
    this_word_only_upper = ""
    for each_char in each_word:
        if each_char.isalpha() and each_char.isupper():
            this_word_only_upper += each_char
    return this_word_only_upper


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


def do_block_affine_cipher():
    """
    encrypting the plain text file, writing the encrypted text to cipher text file and throwing error message
    :return: None
    """
    # Creating empty output file
    init_output_file()
    # reading lines from the file
    file_content_as_lines = read_input_file_to_encrypt(input_file_name)
    # throw error message
    error_message_thrown_away_characters(file_content_as_lines)
    # get total number of lines
    total_num_of_lines = len(file_content_as_lines)
    append_new_line_char = True
    for line_num, each_line in enumerate(file_content_as_lines):
        # reading words from the line
        line_content_as_word_list = get_all_words_in_this_line(each_line)
        encrypted_word_list = []
        for each_word in line_content_as_word_list:
            # get only upper case characters in the word
            this_word_only_upper = throw_away_non_uppercase_char(each_word)
            # pad with B for blocks less than block size
            this_word_to_encrypt = pad_for_character_blocks(block_size, "", this_word_only_upper)
            # encrypt the word and add to encrypted word list
            encrypted_word_list.append(get_encrypted_word(this_word_to_encrypt, "", multiplier, offset, modulo, block_size))
        if line_num + 1 == total_num_of_lines:
            # no appending new line character if it is the last line
            append_new_line_char = False
        # write encrypted text to file
        write_encrypted_file(encrypted_word_list, append_new_line_char)


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


# Appropriately encrypts 3 character blocks
def pad_for_character_blocks(this_block_size, chars_sized, chars_to_size):
    """
    padding with character B as needed
    :param this_block_size: block size
    :param chars_sized: characters that are multiple of block size
    :param chars_to_size: characters to be sized into multiples of block size with padding as needed
    :return: padded characters
    """
    if len(chars_to_size) <= this_block_size:
        num_of_chars_to_pad = len(chars_to_size) % this_block_size
        if num_of_chars_to_pad != 0:
            # padding with B
            chars_to_size += ("B" * (this_block_size - num_of_chars_to_pad))
        # return the padded characters
        return chars_sized + chars_to_size
    else:
        # recursively call to pad blocks
        return pad_for_character_blocks(this_block_size, chars_sized + chars_to_size[0:this_block_size], chars_to_size[this_block_size:])


def get_encrypted_word(this_word, encrypted_word, this_multiplier, this_offset, this_modulo, this_block_size):
    """
    get the encrypted word
    :param this_word: word to be encrypted
    :param encrypted_word: encrypted word
    :param this_multiplier: multiplier value
    :param this_offset: offset value
    :param this_modulo: modulo value
    :param this_block_size: block size
    :return: encrypted word
    """
    if len(this_word) == 0:
        return encrypted_word
    else:
        if len(this_word) < this_block_size:
            # printing error
            print("Error: Invalid padding done for {} with block size {}".format(this_word, this_block_size))
        # checking if the length of the word is a multiple of block size
        encrypted_word += encrypt_this_block(this_word[0:this_block_size], this_multiplier, this_offset, this_modulo, this_block_size)
        # call recursive
        return get_encrypted_word(this_word[this_block_size:], encrypted_word, this_multiplier, this_offset, this_modulo, this_block_size)


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
        print('Error: the num value {} is bigger that the string representation size {}'.format(this_num, this_size))
        return ""
    else:
        # len(str(this_num)) <= this_size:
        return "0" * (this_size - len(str(this_num))) + str(this_num)
        

def encrypt_this_block(block_to_encrypt, this_multiplier, this_offset, this_modulo, this_block_size):
    """
    encrypting the block
    :param block_to_encrypt: block to be encrypted
    :param this_multiplier: multiplier value
    :param this_offset: offset value
    :param this_modulo: modulo value
    :param this_block_size: block size
    :return: encrypted block as string
    """
    if len(block_to_encrypt) != this_block_size:
        # throw an error message if the length of encrypted block is not same as block size
        print('Error: Invalid Length of block of chars. Expected = {}, Actual = {}'.format(this_block_size, len(block_to_encrypt)))
    # get the numeric representation of the block
    this_block_num_rep = [get_numeric_repr_of_this_char_with_this_size(m) for m in block_to_encrypt]
    # get block value from the numeric representation
    this_block_val = int("".join(this_block_num_rep))
    # get encrypted value
    this_block_encrypt_val = (this_block_val * this_multiplier + this_offset) % this_modulo
    # return encrypted block as string
    return get_encrypted_str(str(this_block_encrypt_val), "", this_block_size, 2)


def get_encrypted_str(block_encrypt_val_as_str, block_encrypted_str, this_block_size, this_num_rep_size=2):
    """
    get encrypted string
    :param block_encrypt_val_as_str: encrypted numerical value
    :param block_encrypted_str: encrypted string of the numerical value
    :param this_block_size: block size value
    :param this_num_rep_size: number representation size, default=2 example A=00, B=01...
    :return: encrypted string
    """
    if len(block_encrypted_str) == this_block_size:
        #  base case
        return block_encrypted_str
    elif (block_encrypt_val_as_str is "" ) or (int(block_encrypt_val_as_str) == 0):
        # if encrypted numeric value is 0 or empty then it is ":A"
        block_encrypted_str = "A" * (this_block_size - len(block_encrypted_str)) + block_encrypted_str
        # recursivce call
        return get_encrypted_str(block_encrypt_val_as_str, block_encrypted_str, this_block_size, this_num_rep_size)
    elif len(block_encrypt_val_as_str) <= this_num_rep_size:
        # when there are less than num_rep_size that is 2 characters
        block_encrypted_str = chr(int(block_encrypt_val_as_str) + ord("A")) + block_encrypted_str
        # recursivce call
        return get_encrypted_str("", block_encrypted_str, this_block_size, this_num_rep_size)
    else:
        # len(block_encrypt_val_as_str) > this_num_rep_size
        block_encrypted_str = chr(int(block_encrypt_val_as_str[-this_num_rep_size:]) + ord("A")) + block_encrypted_str
        # recursivce call
        return get_encrypted_str(block_encrypt_val_as_str[:-this_num_rep_size], block_encrypted_str, this_block_size, this_num_rep_size)


def write_encrypted_file(encrypted_word_list, append_new_line=True):
    """
    add encrypted text/line to file
    :param encrypted_word_list: encrypted words in a line
    :param append_new_line: True to add new line character else False
    :return: None
    """
    with open(output_file_name, 'a+') as f:
        f.write(" ".join(encrypted_word_list) + ('\n' if append_new_line else ''))


def init_output_file():
    """
    initialize or create an empty output file
    :return: None
    """
    with open(output_file_name, 'w+') as f:
        f.write('')


if __name__ == '__main__':
    """
    How to run the encrypt program?
    The program need an input file named "plaintext.txt" that contains the content to be encrypted. 
    This text file should be in the same directory as the source encrypt.py
    Open shell or command prompt and execute:
    "python encrypt.py"
    """
    # set the modulo value
    set_modulo_val(block_size)
    # get multiplier and offset from user
    get_input_multiplier_from_keyboard()
    # check for non alpha and non upper characters and write to content_to_encrypt
    do_block_affine_cipher()
