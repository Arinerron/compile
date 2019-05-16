import binascii, sys, math

def hexencode(value, zero = 8):
    if type(value) == str:
        value = binascii.hexlify(value.encode()).decode()
    elif type(value) == int:
        value = hex(value)[2:]
    else:
        sys.stderr.write('Warning: Failed to determine type of ' + str(value) + '\n')
    if not zero is None:
        value = value.zfill(zero)
    return value

def interpret(code):
    lines = code.split('\n')

    commands = list()
    lineno = 1
       
    for i in range(len(lines)):
        line = lines[i]

        is_tag = False
        in_comment = False
        in_string = False
        is_escaped = False
        is_function = False
        
        buffer_build = ''
        tag = None
        built = None
        variable_set = None
        function_name = None
        function_parameters = list()
        
        for char in list(line):
            # print('checking %s with buffer "%s", in_string %s, is_escaped %s' % (char, buffer_build, in_string, is_escaped))
            if not in_comment:
                if char == '#':
                    if not in_string:
                        in_comment = not in_comment
                    else:
                       buffer_build += char
                elif char == '"' or char == '\'':
                    if not is_escaped:
                        
                        in_string = not in_string

                        if not in_string:
                            # print('Built string: "%s"' % buffer_build)
                            built = {'string' : buffer_build}
                        
                        buffer_build = ''
                    else:
                        buffer_build += '"'
                        is_escaped = False
                elif char == '\\':
                    if not is_escaped:
                        is_escaped = True
                    else:
                        buffer_build += char
                        is_escaped = False
                elif char == '(':
                    if not in_string:
                        # print('Built function call: "%s"' % buffer_build)
                        function_name = buffer_build
                        buffer_build = ''
                        
                        is_function = True
                    else:
                        buffer_build += char
                elif char == ')':
                    if not in_string:
                        buffer_build = buffer_build.strip()
                        if not built is None:
                            function_parameters.append(built)
                        elif not buffer_build == '':
                            if buffer_build.isdigit():
                                function_parameters.append({'integer' : int(buffer_build)})
                            elif buffer_build.startswith('0x'):
                                function_parameters.append({'integer' : int(buffer_build, 16)})
                            else:
                                function_parameters.append({'variable' : buffer_build})
                        
                        buffer_build = ''
                        is_function = False
                        
                        # print('Built function parameters: (%s)' % str(function_parameters))
                    else:
                        buffer_build += char
                elif char == ',':
                    if not in_string:
                        if is_function:
                            buffer_build = buffer_build.strip()
                            if not built is None:
                                function_parameters.append(built)
                                built = None
                            elif not buffer_build == '':
                                if buffer_build.isdigit():
                                    function_parameters.append({'integer' : int(buffer_build)})
                                elif buffer_build.startswith('0x'):
                                    function_parameters.append({'integer' : int(buffer_build, 16)})
                                else:
                                    function_parameters.append({'variable' : buffer_build})
                            buffer_build = ''
                    else:
                        buffer_build += char
                elif char == ' ':
                    if in_string:
                       buffer_build += char
                elif char == '=':
                    if not in_string:
                        variable_set = buffer_build.strip()
                        buffer_build = ''

                        # print('Defined variable: %s' % variable_set)
                elif char == 'n':
                    if in_string and is_escaped:
                        buffer_build += '\n'
                        is_escaped = False
                    else:
                        buffer_build += char
                elif char == '[':
                    if (not in_string) and (not is_escaped):
                        is_tag = True
                    else:
                        buffer_build += char
                elif char == ']':
                    if (not in_string) and (not is_escaped) and (is_tag):
                        is_tag = False
                        tag = buffer_build.strip()
                        buffer_build = ''
                    else:
                        buffer_build += char
                else:
                    buffer_build += char

        command = {'output' : variable_set, 'line' : line, 'lineno' : lineno}
        if function_name is None:
            if buffer_build == '' and built is None:
                command = None
            elif buffer_build.isdigit():
                command['value'] = {'integer' : int(buffer_build)}
            elif not built is None:
                command['value'] = built
            elif buffer_build.startswith('0x'):
                command['value'] = {'integer' : int(buffer_build, 16)}
            else:
                command['value'] = {'variable' : buffer_build}
        else:
            command['function'] = {'name' : function_name, 'parameters' : function_parameters}

        if not command is None:
            command['tag'] = tag
            commands.append(command)

        lineno += 1
    
    return commands

# checks to make sure there are no null bytes, corrects them if there are
def bytecheck(value, zero = 8):
    if value.startswith('0x'):
        value = value[2:]
    value = value.zfill(zero)

    if int(value, 16) <= int('79', 16):
        lstripped = value.lstrip('0')
        return {'value' : ('0' if len(lstripped) % 2 == 1 else '') + lstripped, 'change' : False}
    
    hexarr = list('0123456789abcdef')
    newval = value
    
    valid = False
    offset = 1
    while not valid:
        if '00' in [newval[i:i+2] for i in range(0, len(newval), 2)]:
            array = list(value)
            newval = ''
            for item in [value[i:i+2] for i in range(0, len(value), 2)]:
                if int(item, 16) + offset <= 0xFF:
                    newval += hexencode(int(item, 16) + offset, zero = 2)
                else:
                    return {'value' : value, 'change' : False}
            offset += 1
                
        else:
            valid = True

    if newval == value:
        return {'value' : value, 'change' : False}
    
    return {'value' : newval, 'offset' : offset - 1, 'add' : hexencode(offset - 1, zero = 2) * int(len(value) / 2), 'change' : True}

# outputs a formatted error and optionally exits
def error(details, line = None, lineno = None, end = True):
    sys.stderr.write('Error: %s\n' % details)
    if (not line is None) and (not lineno is None):
        sys.stderr.write('  ... on line %s:\n' % str(lineno))
        sys.stderr.write('    %s' % str(line))
    if end:
        exit(1)

reg32 = {'eax' : None, 'ebx' : None, 'ecx' : None, 'edx' : None, 'esi' : None, 'edi' : None}
stack = list()
variables = dict()
constants = dict()
remember = dict()

def get_free_reg():
    for register, contents in reg32.items():
        if contents is None:
            return register
            
    error('Ran out of registers.')
    
def free_reg(reg):
    reg32[reg] = None

def prep_integer(parameter, register = 'eax', command = None, spacing = ' ' * 4, zero = 8, offset_cases = {}):
    assembly = ''
    
    if parameter['integer'] > 0xFFFFFFFF:
        error('Maximum integer (%s) exeeded.' % 0xFFFFFFFF, line = command['line'], lineno = command['lineno'])
    
    '''
    negative = False
    realreg = register
    if parameter['integer'] < 0:
        negative = True
        parameter['integer'] = -parameter['integer']
        register = get_free_reg()
    '''

    if parameter['integer'] in offset_cases:
        return offset_cases[parameter['integer']]
    
    hexedbytes = hex(parameter['integer'])
    fixbytes = bytecheck(hexedbytes, zero = zero)
    if parameter['integer'] == 0:
        assembly += spacing + 'xor ' + register + ', ' + register + '\n'
    elif not fixbytes['change']:
        assembly += spacing + 'push 0x' + fixbytes['value'] + '\n' + spacing + 'pop ' + register + '\n'
    else:
        assembly += spacing + 'push 0x' + fixbytes['value'] + '\n' + spacing + 'pop ' + register + '\n' + spacing + 'sub ' + register + ', 0x' + fixbytes['add'] + '\n'
    
    '''
    if negative:
        assembly += spacing + 'xor ' + realreg + ', ' + realreg
        
        free_reg(register)
    '''
        
    return assembly

def addsub(amount, from_reg, in_reg):
    assembly = ''
    
    if amount < 0:
        assembly += spacing + 'sub ' + from_reg + ', ' + in_reg
        return ('sub', assembly)
    elif amount > 0:
        assembly += spacing + 'add ' + from_reg + ', ' + in_reg
        return ('add', assembly)
    return ('none', assembly)

O_RDONLY = 0b00
O_CREAT = 0b0100
O_TRUNC = 0b01000

def prep_variable(parameter, register = 'eax', command = None, spacing = ' ' * 4, zero = 8, offset_cases = {}):
    assembly = ''
    reg32[register] = True
    
    if parameter['variable'] == 'stdin':
        return (prep_integer({'integer' : 0x00}, register, command, spacing, zero, offset_cases = offset_cases), 4)
    if parameter['variable'] == 'stdout':
        return (prep_integer({'integer' : 0x01}, register, command, spacing, zero, offset_cases = offset_cases), 4)
    if parameter['variable'] == 'stderr':
        return (prep_integer({'integer' : 0x02}, register, command, spacing, zero, offset_cases = offset_cases), 4)
    if parameter['variable'] == 'o_rdonly':
        return (prep_integer({'integer' : O_RDONLY}, register, command, spacing, zero, offset_cases = offset_cases), 4)
    if parameter['variable'] == 'o_creat':
        return (prep_integer({'integer' : O_CREAT}, register, command, spacing, zero, offset_cases = offset_cases), 4)
    if parameter['variable'] == 'o_trunc':
        return (prep_integer({'integer' : O_TRUNC}, register, command, spacing, zero, offset_cases = offset_cases), 4)
    
    if not parameter['variable'] in variables:
        error('Variable %s is not defined.' % parameter['variable'], line = command['line'], lineno = command['lineno'])
    
    length = 4
    
    if variables[parameter['variable']] == 'integer':
        if parameter['variable'] in constants:
            assembly += prep_integer({'integer' : constants[parameter['variable']]}, register, command, spacing, 8)
        else:
            item = get_from_stack(parameter['variable'])
            freereg = get_free_reg()
            
            if item['offset'] == 0:
                assembly += spacing + 'mov ' + register + ', [esp]\n'
            else:
                assembly += spacing + 'mov ' + register + ', esp\n'
                assembly += prep_integer({'integer' : abs(item['offset'])}, freereg, command, spacing, 8)
                assembly += spacing + ('add ' if item['offset'] > 0 else 'sub ') + register + ', ' + freereg + '\n'
                assembly += spacing + 'mov ' + register + ', [' + register + ']\n'
                
            free_reg(freereg)
    elif variables[parameter['variable']] == 'string':
        item = get_from_stack(parameter['variable'])
        freereg = get_free_reg()

        # might need to add item['length'] to item['offset'] first, idk
        if item['offset'] == 0x00:
            assembly += spacing + 'mov ' + register + ', esp\n'
        else:
            assembly += spacing + 'mov ' + register + ', esp\n'
            if item['offset'] in offset_cases:
                assembly += offset_cases[item['offset']].replace('%s', freereg)
            else:
                assembly += prep_integer({'integer' : item['offset']}, freereg, command, spacing, 8)
            assembly += spacing + 'add ' + register + ', ' + freereg + '\n'

        free_reg(freereg)
        
        length = item['length']
    elif variables[parameter['variable']] == 'pointer':
        data = get_from_stack(parameter['variable'])
        assembly += spacing + 'mov ' + register + ', [esp]\n'
        length = (4 if data['length'] is None else data['length'])
            
    return (assembly, length)

def variable_used(variable, code, line = 1):
    i = 1
    for command in code:
        if i > line:
            if ('output' in command) and (command['output'] == variable):
                return False
            if ('function' in command) and (not command['function'] is None):
                # function
                for param in command['function']['parameters']:
                    if ('variable' in param) and (param['variable'] == variable):
                        return True
                pass
            elif ('value' in command) and (not command['value'] is None):
                # hardcoded
                if ('variable' in command['value']) and (command['value']['variable'] == variable):
                    return True
        i += 1
    
    return False

def load_string(string, in_reg = None, len_reg = None, spacing = ' ' * 4):
    assembly = ''
    groups = [string[i:i+4] for i in range(0, len(string), 4)]
    
    pops = 0
    
    use_reg = get_free_reg()
    
    assembly += spacing + 'xor %s, %s' % (use_reg, use_reg) + '\n' + spacing + 'push %s' % use_reg + '\n'
    stack.append({'name' : 'null bytes', 'type' : 'string', 'length' : 4})
    
    groups.reverse()
    
    for group in groups:
        # reverse group, little endian
        group = list(group)
        group.reverse()
        group = ''.join(group)
        
        group = hexencode(group)
        
        fixbytes = bytecheck(group)
        if not fixbytes['change']:
            assembly += spacing + 'push 0x' + fixbytes['value'] + '\n'
        else:
            assembly += spacing + 'push 0x' + fixbytes['value'] + '\n' + spacing + 'pop ' + use_reg + '\n' + spacing + 'sub ' + use_reg + ', 0x' + fixbytes['add'] + '\n' + spacing + 'push ' + use_reg + '\n'
        
        pops += 1
    
    free_reg(use_reg)

    if not in_reg is None:
        assembly += spacing + 'mov ' + in_reg + ', esp\n'
    
    if not len_reg is None:
        assembly += spacing + 'mov ' + len_reg + ', 0x' + hexencode(pops * 4) + '\n'
    
    return (assembly, len(groups))

def get_stack_offset(variable):
    offset = 0
    stack.reverse()
    for item in stack:
        if item['name'] == variable:
            stack.reverse()
            return offset
        offset += item['length']
    stack.reverse()
    return 0

def get_from_stack(variable):
    for item in stack:
        if item['name'] == variable:
            item['offset'] = get_stack_offset(variable)
            return item
    return None

def insert_string_variable(variable, in_reg, len_reg = None, spacing = ' ' * 4, reset = False):
    value = remember[variable['variable']]
    loaded = load_string(value, in_reg, len_reg = len_reg, spacing = spacing)
    #print(loaded)
    #assembly = loaded[0]
    
    if reset:
        reg = get_free_reg()
        assembly += prep_integer({'integer' : loaded[1] * 4}, reg, command, spacing, 8)
        assembly += spacing + 'add esp, ' + reg + '\n'
        assembly += spacing + 'sub esp, 0x04'
        free_reg(reg)
    
    return (assembly, loaded[1], loaded[1] * 4)

def prep_param(param, register, spacing = ' ' * 4, cases = {}, offset_cases = {}, zero = 8, command = None):
    assembly = ''
    length = 4
    
    if 'integer' in param:
        if param['integer'] in cases:
            assembly += cases[param['integer']].replace('%s', register)
        else:
            assembly += prep_integer(param, register, command = command, spacing = spacing, zero = zero)
    elif 'string' in param:
        data = load_string(param['string'], in_reg = register, spacing = spacing)
        assembly += data[0]
        length = data[1] * 4
    elif 'variable' in param:
        data = prep_variable(param, register, command = command, spacing = spacing, zero = zero, offset_cases = offset_cases)
        assembly += data[0]
        length = data[1]
    
    return (assembly, length)

def to_dict(data):
    if type(data) == str:
        return {'string' : data}
    elif type(data) == int:
        return {'integer' : int(data)}

def dynamic_variable(command, real_type = 'integer', length = 4, iteration = None, code = list(), buffer = 'eax', spacing = ' ' * 4, type = 'pointer', push = True):
    assembly = ''
    
    if (iteration is None) or (('output' in command) and (not command['output'] is None)):
        if variable_used(command['output'], code, line = iteration):
            if push:
                assembly += spacing + 'push ' + buffer + '\n'
            stack.append({'name' : command['output'], 'type' : type, 'real_type' : real_type, 'length' : length})
            variables[command['output']] = type
        else:
            assembly += spacing + '; variable not used, optimizing...\n'
    
    return assembly

def allocate_var():
    pass

def count_lines(assembly, start, end):
    assembly = assembly.split('\n')
    count = 0
    
    for lines in range(start, end):
        line = assembly[lines].split(';')[0].strip()
        if line != '':
            count += 1
            
    return count

def compile(code):
    assembly = 'section .text\n    global _start\n\n_start:\n'
    # start_len = assembly.count('\n')
    spacing = '    '
    
    global stack, variables, reg32
    reg32 = {'eax' : None, 'ebx' : None, 'ecx' : None, 'edx' : None, 'esi' : None, 'edi' : None}
    stack = list()
    variables = dict()
    tags = dict()
    
    syscalls = {
        'open' : {
            'eax' : 0x05,
            'min_params' : 1,
            'max_params' : 3,
            'return' : 'integer',
            'defaults' : {
                'ecx' : O_RDONLY,
                'edx' : 666
            }
        },

        'close' : {
            'eax' : 0x06,
            'min_params' : 1,
            'max_params' : 1,
            'return' : 'integer',
            'defaults' : {}
        },

        'create' : {
            'eax' : 0x08,
            'min_params' : 1,
            'max_params' : 2,
            'return' : 'integer',
            'defaults' : {
                'ecx' : O_RDONLY
            }
        },

        'link' : {
            'eax' : 0x09,
            'min_params' : 2,
            'max_params' : 2,
            'return' : 'integer',
            'defaults' : {}
        },

        'unlink' : {
            'eax' : 0x0a,
            'min_params' : 1,
            'max_params' : 1,
            'return' : 'integer',
            'defaults' : {}
        },

        'execve' : {
            'eax' : 0x0b,
            'min_params' : 1,
            'max_params' : 3,
            'return' : 'integer',
            'defaults' : {}
        },

        'chdir' : {
            'eax' : 0x0c,
            'min_params' : 1,
            'max_params' : 1,
            'return' : 'integer',
            'defaults' : {}
        },

        'chmod' : {
            'eax' : 0x0f,
            'min_params' : 1,
            'max_params' : 2,
            'return' : 'integer',
            'defaults' : {
                'ecx' : 777
            }
        },

        'setuid' : {
            'eax' : 0xd5,
            'min_params' : 0,
            'max_params' : 1,
            'return' : 'integer',
            'defaults' : {
                'ebx' : 0x00
            }
        },

        'getuid' : {
            'eax' : 0xc7,
            'min_params' : 0,
            'max_params' : 0,
            'return' : 'integer',
            'defaults' : {}
        },

        'mkdir' : {
            'eax' : 0x27,
            'min_params' : 1,
            'max_params' : 2,
            'return' : 'integer',
            'defaults' : {
                'ebx' : O_CREAT
            }
        },

        'rmdir' : {
            'eax' : 0x28,
            'min_params' : 1,
            'max_params' : 1,
            'return' : 'integer',
            'defaults' : {}
        },

        'symlink' : {
            'eax' : 0x53,
            'min_params' : 2,
            'max_params' : 2,
            'return' : 'integer',
            'defaults' : {}
        },

        'fork' : {
            'eax' : 0x02,
            'min_params' : 0,
            'max_params' : 0,
            'return' : 'integer',
            'defaults' : {}
        },

        'dup2' : {
            'eax' : 0x3f,
            'min_params' : 2,
            'max_params' : 2,
            'return' : 'integer',
            'defaults' : {}
        },

        'dup' : {
            'eax' : 0x29,
            'min_params' : 1,
            'max_params' : 1,
            'return' : 'integer',
            'defaults' : {}
        },

        'dup3' : {
            'eax' : 0x14a,
            'min_params' : 3,
            'max_params' : 3,
            'return' : 'integer',
            'defaults' : {}
        },
    }
    
    # real processing
    iteration = 0
    for command in code:
        iteration += 1
    
        if not command['tag'] is None:
            tags[command['tag']] = assembly.count('\n') + 1 # - start_len + 1

        #print(count_lines(assembly, tags['tag'], assembly.count('\n') + 1))

        assembly += spacing + '; ' + str(command['line']) + '\n'
        
        outputvar = 'eax'
        if ('function' in command) and (not command['function'] is None):
            # this is a function

            if not command['output'] is None and command['output'] in constants:
                del constants[command['output']]

            if command['function']['name'] == 'exit':
                reg32['eax'] = True
                
                assembly += spacing + 'push 0x01\n' + spacing + 'pop eax\n'
                
                if len(command['function']['parameters']) == 1:
                    param = command['function']['parameters'][0]
                    
                    assembly += prep_param(param, 'ebx', spacing = spacing, command = command, cases = {0x01 : spacing + 'mov %s, eax\n'})[0]
                elif len(command['function']['parameters']) == 0:
                    assembly += spacing + 'xor ebx, ebx\n'
                else:
                    error('Incorrect number of arguments.', line = command['line'], lineno = command['lineno'])
                
                assembly += spacing + 'int 0x80\n'
                
                free_reg('eax')
                free_reg('ebx')
            
            elif command['function']['name'] == 'write':
                reg32['eax'] = True
                reg32['ebx'] = True
                reg32['ecx'] = True
                
                assembly += spacing + 'push 0x04\n' + spacing + 'pop eax\n'
                lentakencareof = False
                
                if len(command['function']['parameters']) == 3:
                    param = command['function']['parameters'][2]
                    
                    assembly += prep_param(param, 'edx', spacing = spacing, command = command, cases = {0x04 : spacing + 'mov %s, eax\n'},  offset_cases = {0x04 : spacing + 'mov %s, eax\n'})[0]
                    
                    lentakencareof = True
                    reg32['edx'] = True
                
                if len(command['function']['parameters']) in [2, 3]:
                    param = command['function']['parameters'][0]
                    
                    assembly += prep_param(param, 'ebx', spacing = spacing, command = command, cases = {0x04 : spacing + 'mov %s, eax\n'},  offset_cases = {0x04 : spacing + 'mov %s, eax\n'})[0]
                else:
                    error('Incorrect number of arguments.', line = command['line'], lineno = command['lineno'])

                data = prep_param(command['function']['parameters'][1], 'ecx', spacing = spacing, command = command, cases = {0x04 : spacing + 'mov %s, eax\n'},  offset_cases = {0x04 : spacing + 'mov %s, eax\n'})
                
                assembly += data[0]
                length = data[1]
                
                if not lentakencareof:
                    assembly += prep_integer({'integer' : length}, 'edx', command, spacing, 8)
                    reg32['edx'] = True
                
                assembly += spacing + 'int 0x80\n'
                
                free_reg('ebx')
                free_reg('ecx')
                free_reg('edx')
                
                assembly += dynamic_variable(command, real_type = 'integer', length = 4, iteration = iteration, code = code, spacing = spacing)
                
                free_reg('eax')
                
            elif command['function']['name'] == 'read':
                if ('output' in command) and (not command['output'] is None):
                    reg32['eax'] = True
                    reg32['ebx'] = True
                    reg32['ecx'] = True
                    reg32['edx'] = True
                    
                    assembly += spacing + 'push 0x03\n' + spacing + 'pop eax\n'
                    
                    if len(command['function']['parameters']) == 2:
                        fd = command['function']['parameters'][0]
                        count = command['function']['parameters'][1]
                        
                        if not 'integer' in count: # the compiler is retarded.
                            error('Argument #2 must be an integer.', line = command['line'], lineno = command['lineno'])
                        
                        data = prep_param(fd, 'ebx', spacing = spacing, command = command, cases = {0x03 : spacing + 'mov %s, eax\n'},  offset_cases = {0x03 : spacing + 'mov %s, eax\n'})
                        assembly += data[0]
                        length = data[1]
                        
                        data = prep_param(count, 'edx', spacing = spacing, command = command, cases = {0x03 : spacing + 'mov %s, eax\n'},  offset_cases = {0x03 : spacing + 'mov %s, eax\n'})
                        assembly += data[0]
                        length = data[1]
                        
                        # malloc
                        assembly += spacing + 'mov ecx, esp\n'
                        assembly += spacing + 'sub ecx, edx\n'
                        assembly += spacing + 'mov esp, ecx\n'
                        
                        assembly += dynamic_variable(command, real_type = 'string', length = count['integer'], iteration = iteration, code = code, spacing = spacing, type = 'string', buffer = 'esp', push = False)
                    else:
                        error('Incorrect number of arguments.', line = command['line'], lineno = command['lineno'])
                    
                    assembly += spacing + 'int 0x80\n'
                    
                    free_reg('ebx')
                    free_reg('ecx')
                    free_reg('edx')                    
                    free_reg('eax')
                else:
                    assembly += spacing + '; optimizing; function output is not used.'
            
            elif command['function']['name'] in syscalls:
                syscall = syscalls[command['function']['name']]
                
                reg32['eax'] = True
                assembly += prep_integer({'integer' : syscall['eax']}, 'eax', command, spacing, 2)
                
                if not len(command['function']['parameters']) in range(syscall['min_params'], syscall['max_params'] + 1):
                    error('Incorrect number of arguments.', line = command['line'], lineno = command['lineno'])
                
                i = 0
                for reg in ['ebx', 'ecx', 'edx']:
                    param = None
                    
                    if i < len(command['function']['parameters']):
                        param = prep_param(command['function']['parameters'][i], reg, spacing = spacing, command = command, cases = {syscall['eax'] : spacing + 'mov %s, eax\n'},  offset_cases = {syscall['eax'] : spacing + 'mov %s, eax\n'})
                    elif reg in syscall['defaults']:
                        param = prep_param(to_dict(syscall['defaults'][reg]), reg, spacing = spacing, command = command, cases = {syscall['eax'] : spacing + 'mov %s, eax\n'},  offset_cases = {syscall['eax'] : spacing + 'mov %s, eax\n'})
                        
                    if not param is None:
                        reg32[reg] = True
                        assembly += param[0]
                    i += 1
                
                free_reg('ebx')
                free_reg('ecx')
                free_reg('edx')
                
                assembly += spacing + 'int 0x80\n'
                
                assembly += dynamic_variable(command, real_type = (syscall['return'] if ('return' in syscall) else None), length = (syscall['return_length'] if ('return_length' in syscall) else 4), iteration = iteration, code = code, buffer = (syscall['buffer'] if ('buffer' in syscall) else 'eax'), spacing = spacing)
                
                free_reg('eax')
            elif command['function']['name'] == 'asm':
                if len(command['function']['parameters']) != 1:
                    error('Incorrect number of arguments.', line = command['line'], lineno = command['lineno'])
                
                assembly += spacing + command['function']['parameters'][0]['string'].replace('\n' + spacing, '\n').replace('\n', '\n' + spacing)
                
                if not assembly.endswith('\n' + spacing):
                    assembly += '\n'
            else:
                error('Undefined function used.', line = command['line'], lineno = command['lineno']) 
        elif ('value' in command) and (not command['value'] is None):
            # this is a hardcoded value

            if variable_used(command['output'], code, line = iteration):
                if not command['output'] is None:
                    if 'integer' in command['value']:
                        constants[command['output']] = command['value']['integer']
                        variables[command['output']] = 'integer'
                        
                        # save integer in stack
                        if command['value']['integer'] > 0xFFFFFFFF:
                            error('Maximum integer (%s) exeeded.' % 0xFFFFFFFF, line = command['line'], lineno = command['lineno'])
                        
                        hexedbytes = hex(command['value']['integer'])
                        fixbytes = bytecheck(hexedbytes)
                        if command['value']['integer'] == 0:
                            assembly += spacing + 'xor eax, eax\n' + spacing + 'push eax\n'
                        elif not fixbytes['change']:
                            assembly += spacing + 'push 0x' + fixbytes['value'] + '\n'
                        else:
                            assembly += spacing + 'push 0x' + fixbytes['value'] + '\n' + spacing + 'pop eax\n' + spacing + 'sub eax, 0x' + fixbytes['add'] + '\n' + spacing + 'push eax\n'
                        
                        stack.append({'name' : command['output'], 'type' : 'integer', 'value' : command['value'], 'length' : 4})
                    elif 'string' in command['value']:
                        variables[command['output']] = 'string'
                        value = command['value']['string']
                        remember[command['output']] = value

                        string = load_string(value, spacing = spacing)
                        assembly += string[0]
                        
                        stack.append({'name' : command['output'], 'type' : 'string', 'value' : value, 'length' : string[1] * 4})
                        # hexencoded = hexencode(command['value'], None)
                        # math.ceil()
            else:
                assembly += spacing + '; variable output not used, optimizing...\n'
        assembly += spacing + '\n'

    return assembly

# print(bytecheck('0x2800a932'))
if len(sys.argv) > 1:
    output = interpret(open(sys.argv[1]).read())
    
    output = compile(output)
    print(output)
else:
    print('%s <file>' % sys.argv[0])
    exit(1)


# clear; python3 compile.py | tee ./test.as && nasm -o test.o test.as -f elf && ld -o test test.o -s -m elf_i386 &&chmod +x test && objdump -d ./test  |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'|cut -d '"' -f2

